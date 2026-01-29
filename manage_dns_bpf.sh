#!/bin/bash
#
# File     : manage_dns_bpf.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-29 11:30:25
#

#!/bin/bash
set -euo pipefail

# --- 配置参数 ---
LAN_IF="br-lan"             # 你的内网网桥
BPF_OBJ="dns_steer.o"       # 编译生成的对象文件
BPF_DIR="/sys/fs/bpf/dns_steer"

# 固定点路径
MAP_PIN="${BPF_DIR}/domestic_domains"
PROG_PIN="${BPF_DIR}/dns_prog"

# 必需命令
readonly REQUIRED_CMDS=(bpftool tc mount umount)

# --- 辅助函数 ---
function info() { echo -e "\033[32mINFO:\033[0m $*"; }
function err()  { echo -e "\033[31mERROR:\033[0m $*" >&2; }

function clean_all() {
    info "清理旧环境 (接口: ${LAN_IF}, 目录: ${BPF_DIR})..."
    
    # 1. 移除 TC 钩子
    tc qdisc del dev "${LAN_IF}" clsact 2>/dev/null || true
    
    # 2. 清理 BPF 文件系统固定点
    if mountpoint -q "${BPF_DIR}" 2>/dev/null; then
        umount -f "${BPF_DIR}" 2>/dev/null || true
    fi
    rm -rf "${BPF_DIR}"
    info "清理完成。"
}

function init_env() {
    info "检查环境与挂载 bpffs..."
    for cmd in "${REQUIRED_CMDS[@]}"; do
        command -v "${cmd}" >/dev/null 2>&1 || { err "找不到命令: ${cmd}"; exit 1; }
    done

    if [[ ! -f "${BPF_OBJ}" ]]; then
        err "找不到 BPF 文件: ${BPF_OBJ}"
        exit 1
    fi

    mkdir -p "${BPF_DIR}"
    mount -t bpf bpf "${BPF_DIR}" || { err "挂载 bpffs 失败"; exit 1; }
}

function load_and_mount() {
    info "3. 创建并加载 eBPF Maps/Progs..."

    # 1. 创建 Map (LPM Trie 必须 flags 1)
    # 使用较短的名字 'dom_domains' 避免 bpftool 截断警告
    bpftool map create "${MAP_PIN}" \
        type lpm_trie key 68 value 4 entries 1024 \
        name dom_domains flags 1

    # 2. 加载程序
    # 调整位置：'type classifier' 紧跟在 OBJ 和 PIN 之后
    # 这是旧版 bpftool 最稳定的参数顺序
    info "执行 bpftool prog load..."
    bpftool prog load "${BPF_OBJ}" "${PROG_PIN}" \
        type classifier \
        map name domestic_domains pinned "${MAP_PIN}"

    # 验证是否成功生成了固定文件
    if [[ ! -f "${PROG_PIN}" ]]; then
        err "程序加载失败！请检查 C 代码中的 SEC(\"classifier\") 定义。"
        exit 1
    fi
    
    # 3. 挂载到 TC 钩子
    info "挂载 TC 过滤器..."
    tc qdisc add dev "${LAN_IF}" clsact
    
    # 使用 pinned 路径挂载，确保 Ingress 和 Egress 共享同一个程序实例和 Map
    tc filter add dev "${LAN_IF}" ingress bpf da pinned "${PROG_PIN}"
    tc filter add dev "${LAN_IF}" egress bpf da pinned "${PROG_PIN}"
    
    info "部署成功！双向劫持已开启。"
}

function show_status() {
    local map_id
    map_id=$(bpftool map show name dom_domains | cut -d: -f1)
    echo "------------------------------------------------"
    info "活跃 Map ID: ${map_id}"
    info "操作指南："
    info "  查看日志: ./manage_dns_bpf.sh log"
    info "  停止劫持: ./manage_dns_bpf.sh stop"
    echo "------------------------------------------------"
}

# --- 主逻辑 ---
case "${1:-start}" in
    "start")
        clean_all
        init_env
        load_and_mount
        show_status
        ;;
    "stop")
        clean_all
        info "已停止。"
        ;;
    "log")
        info "开始监控内核日志 (Ctrl+C 退出)..."
        cat /sys/kernel/debug/tracing/trace_pipe
        ;;
    *)
        echo "Usage: $0 {start|stop|log}"
        ;;
esac
