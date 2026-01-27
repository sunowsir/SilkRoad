#!/bin/bash
#
# File     : deploy_direct_path.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#


set -euo pipefail

LAN_DEV="${LAN_DEV:-eth1}"
WAN_DEV="${WAN_DEV:-eth0}"
BPF_OBJ="${BPF_OBJ:-tc_direct_path.o}"
BPF_DIR="${BPF_DIR:-/sys/fs/bpf/tc_progs}"

# 具体的 Map 路径
HOTPATH_PIN="${BPF_DIR}/hotpath_cache"
PRE_PIN="${BPF_DIR}/pre_cache"
BLACK_PIN="${BPF_DIR}/blklist_ip_map"
DIRECT_PIN="${BPF_DIR}/direct_ip_map"

# eBPF共享内存大小（与C代码保持一致）
HOTMAP_SIZE=${HOTMAP_SIZE:-65536}
PREMAP_SIZE=${PREMAP_SIZE:-65536}
BLACKMAP_SIZE=${BLACKMAP_SIZE:-8192}
DIRECTMAP_SIZE=${DIRECTMAP_SIZE:-16384}

DIRECT_PATH_MARK="${DIRECT_PATH_MARK:-0x88000000}"

# 必需命令列表
REQUIRED_CMDS=(bpftool tc nft mount umount ip)

err() { echo "ERROR: $*" >&2; }

info() { echo "$*"; }

# 检查 root
if [ "$(id -u)" -ne 0 ]; then
    err "该脚本必须以 root 运行"
    exit 1
fi

# 检查命令可用性
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        err "未找到必需命令: ${cmd}。请先安装或将其加入 PATH。"
        exit 2
    fi
done

# 检查接口是否存在
for dev in "${LAN_DEV}" "${WAN_DEV}"; do
    if ! ip link show "${dev}" >/dev/null 2>&1; then
        err "网络接口 ${dev} 不存在。请检查配置。"
        exit 3
    fi
done

info "1. 彻底清理 BPF 虚拟文件系统（如存在）..."
# 清理 tc qdisc（忽略错误）
tc qdisc del dev "${LAN_DEV}" clsact 2>/dev/null || true
tc qdisc del dev "${WAN_DEV}" clsact 2>/dev/null || true

# 卸载并删除以前的 BPF pins（谨慎）
rm -f "${BPF_DIR}" 2>/dev/null || true
if mountpoint -q "${BPF_DIR}" 2>/dev/null || [ -d "${BPF_DIR}" ]; then
    # 尝试 umount（忽略错误），然后删除目录以确保后续创建干净
    umount -f "${BPF_DIR}" 2>/dev/null || true
    # 仅删除我们的专用目录（防止误删父级）
    if [ -d "${BPF_DIR}" ]; then
        rm -rf "${BPF_DIR}"
    fi
fi

mkdir -p "${BPF_DIR}"

# 挂载 bpffs (如果没挂载的话)
if ! mount -t bpf bpf "${BPF_DIR}" 2>/dev/null; then
    # 如果已经挂载到其他位置，则忽略（上面做了 umount）
    info "注意: 无法显式 mount bpffs 到 ${BPF_DIR}（可能已挂载或内核不支持）。继续尝试..."
fi

info "2. 显式创建并固定 Map (确保内核对象先于程序存在)..."

# 创建 hotpath_cache (LRU_HASH)
bpftool map create "${HOTPATH_PIN}" type lru_hash key 4 value 8 entries "${HOTMAP_SIZE}" name hotpath_cache || {
    err "创建 hotpath_cache 失败"
    exit 4
}

# 创建 pre_cache (LRU_HASH)  —— 修复：name 必须为 pre_cache
bpftool map create "${PRE_PIN}" type lru_hash key 4 value 16 entries "${PREMAP_SIZE}" name pre_cache || {
    err "创建 pre_cache 失败"
    exit 5
}

# 创建 blklist_ip_map (LPM_TRIE)
bpftool map create "${BLACK_PIN}" type lpm_trie key 8 value 4 entries "${BLACKMAP_SIZE}" name blklist_ip_map flags 1 || {
    err "创建 blklist_ip_map 失败"
    exit 6
}

# 创建 direct_ip_map (LPM_TRIE, NO_PREALLOC)
bpftool map create "${DIRECT_PIN}" type lpm_trie key 8 value 4 entries "${DIRECTMAP_SIZE}" name direct_ip_map flags 1 || {
    err "创建 direct_ip_map 失败"
    exit 7
}

info "3. 加载程序并重用已存在的 Maps..."
# 使用 map name 映射到刚才创建的文件上
# 使用 loadall 更稳健地加载包含多个 program 的 ELF，并把 ELF 中的 map 名称 pin 到我们创建的 pins 上
bpftool prog load "${BPF_OBJ}" "${BPF_DIR}/tc_accel_prog" \
    map name hotpath_cache pinned "${HOTPATH_PIN}" \
    map name pre_cache pinned "${PRE_PIN}" \
    map name direct_ip_map pinned "${DIRECT_PIN}" \
    map name blklist_ip_map pinned "${BLACK_PIN}" || {
        err "加载 BPF 程序失败，请检查 ${BPF_OBJ} 是否存在，或 map 名称是否与 ELF 中一致。"
        exit 8
    }

info "4. 挂载 TC 过滤器..."
tc qdisc add dev "${LAN_DEV}" clsact
tc filter add dev "${LAN_DEV}" ingress bpf da pinned "${BPF_DIR}/tc_accel_prog"
tc filter add dev "${LAN_DEV}" egress bpf da pinned "${BPF_DIR}/tc_accel_prog"

tc qdisc add dev "${WAN_DEV}" clsact
tc filter add dev "${WAN_DEV}" ingress bpf da pinned "${BPF_DIR}/tc_accel_prog"

info "5. 配置 nftables 联动 (安全加速模式) ..."

# 删除旧表（忽略错误）
nft delete table inet bpf_accel 2>/dev/null || true
nft add table inet bpf_accel

# 开启 flowtable 加速引擎
nft "add flowtable inet bpf_accel ft { hook ingress priority 0; devices = { ${LAN_DEV}, ${WAN_DEV} }; }"

nft add counter inet bpf_accel accel_packets
nft "add chain inet bpf_accel forward { type filter hook forward priority 0; policy accept; }"
nft "add chain inet bpf_accel monitor_chain { type filter hook prerouting priority -301; policy accept; }"

# 规则 1：仅监控统计
nft "add rule inet bpf_accel monitor_chain meta mark & 0xff000000 == ${DIRECT_PATH_MARK} counter name accel_packets"

# 规则 2：将带有标记且已建立 NAT 状态的包，丢进 flowtable 高速公路
# 这样既保证了第一包能正确 NAT，后续包又能起飞
nft "add rule inet bpf_accel forward meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established flow add @ft"

echo "---------------------------------------"
echo "加速引擎已启动！"
echo ""
echo "验证提示："
echo "  bpftool map show pinned ${BPF_DIR}"
echo "  bpftool prog show"
echo "  tc filter show dev ${LAN_DEV} ingress"
echo "  nft list ruleset"
