#!/bin/bash
#
# File     : deploy_direct_path.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#

set -euo pipefail

# --- 配置参数 ---
LAN_DEV="${LAN_DEV:-eth1}"
WAN_DEV="${WAN_DEV:-eth0}"
BPF_OBJ="${BPF_OBJ:-tc_direct_path.o}"
BPF_DIR="${BPF_DIR:-/sys/fs/bpf/tc_progs}"

# 程序固定点路径 (loadall 会在此目录下创建以 SEC 名称命名的文件)
PROG_BASE="${BPF_DIR}/tc_accel_prog"
# 具体的 SEC 名称决定了最终 tc 挂载的文件路径
TC_PROG_PIN="${PROG_BASE}/classifier"

# Map 固定路径
HOTPATH_PIN="${BPF_DIR}/hotpath_cache"
PRE_PIN="${BPF_DIR}/pre_cache"
BLACK_PIN="${BPF_DIR}/blklist_ip_map"
DIRECT_PIN="${BPF_DIR}/direct_ip_map"

# eBPF共享内存大小
HOTMAP_SIZE=${HOTMAP_SIZE:-65536}
PREMAP_SIZE=${PREMAP_SIZE:-65536}
BLACKMAP_SIZE=${BLACKMAP_SIZE:-8192}
DIRECTMAP_SIZE=${DIRECTMAP_SIZE:-16384}

DIRECT_PATH_MARK="${DIRECT_PATH_MARK:-0x88000000}"

# 必需命令列表
readonly REQUIRED_CMDS=(bpftool tc nft mount umount ip)

# --- 辅助函数 ---
err() { echo "ERROR: $*" >&2; }
info() { echo "INFO: $*"; }

# --- 环境检查 ---
if [[ $(id -u) -ne 0 ]]; then
    err "该脚本必须以 root 运行"
    exit 1
fi

for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        err "未找到必需命令: ${cmd}。请先安装或将其加入 PATH。"
        exit 2
    fi
done

for dev in "${LAN_DEV}" "${WAN_DEV}"; do
    if ! ip link show "${dev}" >/dev/null 2>&1; then
        err "网络接口 ${dev} 不存在。请检查配置。"
        exit 3
    fi
done

# --- 1. 清理阶段 ---
info "1. 彻底清理 BPF 虚拟文件系统（如存在）..."

# 清理 tc qdisc
tc qdisc del dev "${LAN_DEV}" clsact 2>/dev/null || true
tc qdisc del dev "${WAN_DEV}" clsact 2>/dev/null || true

# 卸载并重置 bpffs 目录
if mountpoint -q "${BPF_DIR}" 2>/dev/null || [[ -d "${BPF_DIR}" ]]; then
    umount -f "${BPF_DIR}" 2>/dev/null || true
    rm -rf "${BPF_DIR}"
fi

mkdir -p "${BPF_DIR}"

if ! mount -t bpf bpf "${BPF_DIR}" 2>/dev/null; then
    info "注意: 无法显式 mount bpffs（可能系统已处理）。继续尝试..."
fi

# --- 2. 创建 Map ---
info "2. 显式创建并固定 Map (确保内核对象先于程序存在)..."

# 封装 map 创建函数以符合规范
create_map() {
    local path=$1; local type=$2; local k=$3; local v=$4; local entries=$5; local name=$6; local flags=${7:-0}
    bpftool map create "$path" type "$type" key "$k" value "$v" entries "$entries" name "$name" flags "$flags" || {
        err "创建 Map $name 失败"; exit 4;
    }
}

create_map "${HOTPATH_PIN}" lru_hash 4 8 "${HOTMAP_SIZE}" hotpath_cache
create_map "${PRE_PIN}" lru_hash 4 16 "${PREMAP_SIZE}" pre_cache
create_map "${BLACK_PIN}" lpm_trie 8 4 "${BLACKMAP_SIZE}" blklist_ip_map 1
create_map "${DIRECT_PIN}" lpm_trie 8 4 "${DIRECTMAP_SIZE}" direct_ip_map 1

# --- 3. 使用 loadall 加载 ---
info "3. 使用 loadall 加载程序并重用已存在的 Maps..."

# loadall 会创建 ${PROG_BASE} 目录，并在其中放入以 SEC 命名的程序文件
bpftool prog loadall "${BPF_OBJ}" "${PROG_BASE}" \
    map name hotpath_cache pinned "${HOTPATH_PIN}" \
    map name pre_cache pinned "${PRE_PIN}" \
    map name direct_ip_map pinned "${DIRECT_PIN}" \
    map name blklist_ip_map pinned "${BLACK_PIN}" || {
        err "加载 BPF 程序失败，请检查 ${BPF_OBJ} 及 Map 名称。"
        exit 8
    }

# --- 4. TC 挂载 ---
info "4. 挂载 TC 过滤器..."

# 使用 find 查找目录下的第一个常规文件
# -maxdepth 1: 只看当前目录
# -type f: 只找文件
# -print -quit: 找到第一个就打印并退出，效率极高
FINAL_PIN_PATH=$(find "${PROG_BASE}" -maxdepth 1 -type f -print -quit)

if [[ -z "${FINAL_PIN_PATH}" ]]; then
    err "在 ${PROG_BASE} 下未发现加载的程序，请检查 bpftool 加载日志。"
    exit 9
fi

info "探测到程序固定点: ${FINAL_PIN_PATH}"

# 执行挂载
tc qdisc add dev "${LAN_DEV}" clsact
tc filter add dev "${LAN_DEV}" ingress bpf da pinned "${FINAL_PIN_PATH}"
tc filter add dev "${LAN_DEV}" egress bpf da pinned "${FINAL_PIN_PATH}"

tc qdisc add dev "${WAN_DEV}" clsact
tc filter add dev "${WAN_DEV}" ingress bpf da pinned "${FINAL_PIN_PATH}"

# --- 5. Nftables 联动 ---
info "5. 配置 nftables 联动 (安全加速模式) ..."

nft delete table inet bpf_accel 2>/dev/null || true
nft add table inet bpf_accel

# 开启 flowtable 加速引擎
nft "add flowtable inet bpf_accel ft { hook ingress priority 0; devices = { ${LAN_DEV}, ${WAN_DEV} }; }"

nft add counter inet bpf_accel accel_packets
nft "add chain inet bpf_accel forward { type filter hook forward priority 0; policy accept; }"
nft "add chain inet bpf_accel monitor_chain { type filter hook prerouting priority -301; policy accept; }"

# 监控与 Flow Offload 规则
nft "add rule inet bpf_accel monitor_chain meta mark & 0xff000000 == ${DIRECT_PATH_MARK} counter name accel_packets"
nft "add rule inet bpf_accel forward meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established flow add @ft"

echo "---------------------------------------"
echo "加速引擎已启动！"
echo "程序位置: ${TC_PROG_PIN}"
echo "---------------------------------------"
