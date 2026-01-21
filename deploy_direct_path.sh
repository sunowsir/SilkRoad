#!/bin/bash
#
# File     : deploy_direct_path.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#
set -e

DEV="br-lan"
BPF_OBJ="tc_direct_path.o"
BPF_DIR="/sys/fs/bpf/tc_progs"
PROG_PIN="$BPF_DIR/tc_accel_prog"
MAP_PIN="$BPF_DIR/direct_ip_map"

echo "1. 清理环境..."
tc qdisc del dev $DEV clsact 2>/dev/null || true
# 必须先解绑程序，才能删除 /sys/fs/bpf 下的文件
rm -rf $BPF_DIR
mkdir -p $BPF_DIR

echo "2. 使用 bpftool 加载程序并自动固定所有 Maps..."
# pinmaps $BPF_DIR 会把代码中定义的 direct_ip_map 自动创建在 $BPF_DIR/direct_ip_map
bpftool prog load $BPF_OBJ $PROG_PIN pinmaps $BPF_DIR

echo "3. 挂载到 $DEV 的 TC Ingress..."
tc qdisc add dev $DEV clsact
tc filter add dev $DEV ingress bpf da pinned $PROG_PIN

echo "4. 配置 nftables 加速规则..."
nft add table inet bpf_accel 2>/dev/null || true
nft flush table inet bpf_accel
nft add chain inet bpf_accel prerouting { type filter hook prerouting priority -300 \; }
nft add rule inet bpf_accel prerouting meta mark 0x88 notrack accept

echo "---------------------------------------"
if [ -e "$MAP_PIN" ]; then
    echo "成功: Map 已成功固定在 $MAP_PIN"
    echo "加速引擎已就绪！"
else
    echo "错误: Map 未能在预期位置生成，请检查 /sys/fs/bpf/tc_progs 内容："
    ls $BPF_DIR
fi
