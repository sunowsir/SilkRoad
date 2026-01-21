#!/bin/bash
#
# File     : cleanup_env.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#

# 定义变量（需与部署脚本保持一致）
DEV="br-lan"
BPF_DIR="/sys/fs/bpf/tc_progs"
TABLE_NAME="bpf_accel"

echo "开始恢复环境..."

# 1. 清理 nftables 规则
echo "正在移除 nftables 加速表: $TABLE_NAME..."
if nft list table inet $TABLE_NAME >/dev/null 2>&1; then
    nft delete table inet $TABLE_NAME
    echo "-> nftables 表已删除。"
else
    echo "-> nftables 表不存在，跳过。"
fi

# 2. 移除 TC 挂载点上的 eBPF 程序
echo "正在从 $DEV 移除 TC 过滤器..."
# 清理 clsact qdisc 会自动删除其下的所有 filter (ingress/egress)
if tc qdisc show dev $DEV | grep -q "clsact"; then
    tc qdisc del dev $DEV clsact
    echo "-> TC clsact 已移除。"
else
    echo "-> 未发现 TC clsact，跳过。"
fi

# 3. 清理 BPF 系统路径
echo "正在清理 BPF 文件系统路径: $BPF_DIR..."
if [ -d "$BPF_DIR" ]; then
    rm -rf "$BPF_DIR"
    echo "-> BPF 映射文件已清理。"
else
    echo "-> BPF 路径不存在，跳过。"
fi

# 4. 验证恢复情况
echo "---------------------------------------"
echo "验证结果:"
echo "NFT 表状态: $(nft list table inet $TABLE_NAME 2>&1 || echo '已清理')"
echo "TC 状态: $(tc filter show dev $DEV ingress 2>&1 | grep "bpf" || echo '已清理')"
echo "---------------------------------------"
echo "环境恢复完成！系统现在完全由 OpenClash 原始规则控制。"
