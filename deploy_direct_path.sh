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
LAN_IF="eth1"
WAN_IF="eth0"
BPF_OBJ="${BPF_OBJ:-tc_direct_path.o}"
BPF_DIR="${BPF_DIR:-/sys/fs/bpf/tc_progs}"

# 程序固定点路径
PROG_BASE="${BPF_DIR}/tc_accel_prog"
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

# 加速mark标记
DIRECT_PATH_MARK="${DIRECT_PATH_MARK:-0x88000000}"

# 优先级配置
# 抢在 OpenClash (-150/-100) 之前
BYPASS_PRIORITY="-151" 
BPF_ACCEL_FORWARD_PRIORITY="1"
BPF_ACCEL_INPUT_PRIORITY="1"
BPF_ACCEL_OUTPUT_PRIORITY="1"

# 必需命令列表
readonly REQUIRED_CMDS=(bpftool tc nft mount umount ip)

# --- 辅助函数 ---
function err() { echo "ERROR: $*" >&2; }
function info() { echo "INFO: $*"; }
function tc_pin_clean() {
    tc qdisc del dev "${LAN_IF}" clsact 2>/dev/null || true
    tc qdisc del dev "${WAN_IF}" clsact 2>/dev/null || true
}
function get_pin_path() {
    local path
    path=$(find "${PROG_BASE}" -maxdepth 1 -type f -print -quit 2>/dev/null)
    echo "$path"
}

# --- 环境检查 ---
function env_check() {
    info "0. 环境检查..."
    if [[ $(id -u) -ne 0 ]]; then err "该脚本必须以 root 运行"; exit 1; fi
    
    for cmd in "${REQUIRED_CMDS[@]}"; do
        command -v "${cmd}" >/dev/null 2>&1 || { err "未找到必需命令: ${cmd}"; exit 2; }
    done
}

# --- 2. 创建 Map ---
function do_create_map() {
    bpftool map create "$1" type "$2" key "$3" value "$4" entries "$5" name "$6" flags "${7:-0}"
}
function create_map() {
    info "2. 创建 eBPF Maps..."
    
    tc_pin_clean
    if mountpoint -q "${BPF_DIR}" 2>/dev/null || [[ -d "${BPF_DIR}" ]]; then
        umount -f "${BPF_DIR}" 2>/dev/null || true
        rm -rf "${BPF_DIR}"
    fi

    mkdir -p "${BPF_DIR}"
    mount -t bpf bpf "${BPF_DIR}" 2>/dev/null || info "bpffs 已就绪"

    do_create_map "${HOTPATH_PIN}" lru_hash 4 8 "${HOTMAP_SIZE}" hotpath_cache
    do_create_map "${PRE_PIN}" lru_hash 4 16 "${PREMAP_SIZE}" pre_cache
    do_create_map "${BLACK_PIN}" lpm_trie 8 4 "${BLACKMAP_SIZE}" blklist_ip_map 1
    do_create_map "${DIRECT_PIN}" lpm_trie 8 4 "${DIRECTMAP_SIZE}" direct_ip_map 1
}

# --- 3. 加载程序 ---
function load_ebpf_prog() {
    info "3. 加载 BPF 程序..."
    bpftool prog loadall "${BPF_OBJ}" "${PROG_BASE}" \
        map name hotpath_cache pinned "${HOTPATH_PIN}" \
        map name pre_cache pinned "${PRE_PIN}" \
        map name direct_ip_map pinned "${DIRECT_PIN}" \
        map name blklist_ip_map pinned "${BLACK_PIN}"

    local pin_path
    pin_path=$(get_pin_path)
    
    if [[ -z "${pin_path}" ]]; then
        err "找不到已加载的 BPF 程序固定点，加载失败"
        exit 9
    fi
}

# --- 4. TC 挂载 ---
function tc_pinning() {
    info "4. 挂载 TC 过滤器至 ${LAN_IF} 和 ${WAN_IF}..."

    tc_pin_clean

    local pin_path
    pin_path=$(get_pin_path)
    
    if [[ -z "${pin_path}" ]]; then
        err "找不到已加载的 BPF 程序固定点，请先执行 load_ebpf_prog"
        exit 9
    fi

    tc qdisc add dev "${LAN_IF}" clsact
    tc filter add dev "${LAN_IF}" ingress bpf da pinned "${pin_path}"
    tc filter add dev "${LAN_IF}" egress bpf da pinned "${pin_path}"

    tc qdisc add dev "${WAN_IF}" clsact
    tc filter add dev "${WAN_IF}" ingress bpf da pinned "${pin_path}"
    tc filter add dev "${WAN_IF}" egress bpf da pinned "${pin_path}"
}

# --- 5. Nftables 联动 ---
function nft_rule_set() {
    info "5. 配置 nftables 联动..."
    
    nft delete table inet bpf_accel 2>/dev/null || true
    nft add table inet bpf_accel
    
    # 定义 Flowtable (加速双向流量)
    nft "add flowtable inet bpf_accel ft { hook ingress priority 0; devices = { ${LAN_IF}, ${WAN_IF} }; }"
    
    # 定义计数器
    nft add counter inet bpf_accel bypass_clash_cnt
    nft add counter inet bpf_accel local_accel_in
    
    # 创建核心链
    nft "add chain inet bpf_accel early_bypass { type filter hook prerouting priority ${BYPASS_PRIORITY}; policy accept; }"
    nft "add chain inet bpf_accel forward { type filter hook forward priority ${BPF_ACCEL_FORWARD_PRIORITY}; policy accept; }"
    nft "add chain inet bpf_accel input { type filter hook input priority ${BPF_ACCEL_INPUT_PRIORITY}; policy accept; }"
    nft "add chain inet bpf_accel output { type filter hook output priority ${BPF_ACCEL_OUTPUT_PRIORITY}; policy accept; }"
    
    # --- 规则下发 ---
    
    # A. BYPASS 逻辑
    # 通过标记在 Prerouting 顶端截击
    # 这里的 accept 能够确保包跳过同一个 hook 点后面所有的表 
    nft "add rule inet bpf_accel early_bypass meta mark & 0xff000000 == ${DIRECT_PATH_MARK} counter name bypass_clash_cnt accept"
    
    # B. Forward 链：注册 Flowtable 实现真正的“内核旁路”
    # 当首包被绕过 OpenClash 正常路由后，后续包通过 flowtable 极速转发
    nft "add rule inet bpf_accel forward meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established flow add @ft"
    nft "add rule inet bpf_accel forward meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established accept"
    
    # C. 本地流量 (Input/Output)
    nft "add rule inet bpf_accel input meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established counter name local_accel_in accept"
    nft "add rule inet bpf_accel output meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established accept"
}

env_check
create_map 
load_ebpf_prog 
tc_pinning
nft_rule_set


info "---------------------------------------"
info "部署完成！请使用以下命令监控截流情况："
info "watch -n 1 'nft list counters inet bpf_accel'"
info "---------------------------------------"
