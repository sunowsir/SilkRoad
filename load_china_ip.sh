#!/bin/bash
#
# File     : load_china_ip.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#


# 定义路径
IPSET_FILE="/etc/openclash/china_ip_route.ipset"
MAP_PATH="/sys/fs/bpf/tc_progs/direct_ip_map"
BATCH_FILE="/tmp/bpf_map_batch.txt"

if [ ! -f "$IPSET_FILE" ]; then
    echo "错误: 找不到文件 $IPSET_FILE"
    exit 1
fi

if [ ! -e "$MAP_PATH" ]; then
    echo "错误: BPF Map 未挂载，请先运行部署脚本。"
    exit 1
fi

echo "正在批量构造 eBPF 指令并注入 (Batch 模式)..."

# 1. 使用 awk 构造 batch 命令序列
# bpftool batch 格式: map update pinned PATH key hex ... value hex ...
awk -v path="$MAP_PATH" '
/\// {
    split($0, a, "/");
    ip = a[1];
    mask = a[2];
    if (ip != "" && mask != "") {
        split(ip, oct, ".");
        if (oct[4] != "") {
            # BPF LPM_TRIE 要求 key 包含 prefixlen(4字节) + 数据
            # printf 构造: key <prefixlen> <ip_bytes>
            printf "map update pinned %s key hex %02x 00 00 00 %02x %02x %02x %02x value hex 00 00 00 00\n", \
            path, mask, oct[1], oct[2], oct[3], oct[4]
        }
    }
}' "$IPSET_FILE" > "$BATCH_FILE"

# 2. 一次性通过 batch 执行
if [ -s "$BATCH_FILE" ]; then
    bpftool batch file "$BATCH_FILE"
    rm -f "$BATCH_FILE"
    echo "导入完成！"
else
    echo "错误: 未解析到有效的 IP 数据。"
    exit 1
fi
