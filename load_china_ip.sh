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

if [ ! -f "$IPSET_FILE" ]; then
    echo "错误: 找不到文件 $IPSET_FILE"
    exit 1
fi

if [ ! -e "$MAP_PATH" ]; then
    echo "错误: BPF Map 未挂载，请先运行部署脚本。"
    exit 1
fi

echo "正在解析 $IPSET_FILE 并逐条导入 eBPF Map..."

# 使用 awk 直接构造完整的十六进制命令串
awk '/\// {
    gsub(/[ ,{}]/, "", $0);
    split($0, a, "/");
    ip = a[1];
    mask = a[2];
    if (ip != "" && mask != "") {
        split(ip, oct, ".");
        if (oct[4] != "") {
            # 构造 8 字节 key: mask(4字节小端) + IP(4字节)
            # 构造 4 字节 value: 00 00 00 00
            printf "bpftool map update pinned %s key hex %02x 00 00 00 %02x %02x %02x %02x value hex 00 00 00 00\n", \
            MAP_PATH, mask, oct[1], oct[2], oct[3], oct[4]
        }
    }
}' MAP_PATH="$MAP_PATH" "$IPSET_FILE" | sh

echo "导入完成！"
