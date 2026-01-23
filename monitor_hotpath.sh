#!/bin/bash
#
# File     : monitor_hotpath.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-22 11:19:55
#


MAP_PATH="/sys/fs/bpf/tc_progs/hotpath_cache"

if [ ! -e "$MAP_PATH" ]; then
    echo "错误: Map 文件不存在: $MAP_PATH"
    exit 1
fi

# 获取基准时间
now_wall=$(date +%s)
now_up=$(cat /proc/uptime | awk '{print $1}')
# 计算系统启动的绝对秒数
boot_ts=$(awk -v nw="$now_wall" -v nu="$now_up" 'BEGIN {print nw - nu}')

echo "DirectPath 缓存监控 (修复溢出与字节序)"
echo "--------------------------------------------------------------------------------"
printf "%-16s | %-19s | %-20s\n" "IP 地址" "绝对访问时间" "距今时长"
echo "--------------------------------------------------------------------------------"

# bpftool dump 输出格式中，value 占据了 $7 到 $14 连续 8 个字节 (小端序)
bpftool map dump pinned "$MAP_PATH" | awk -v b_ts="$boot_ts" -v n_up="$now_up" '
/key:/ {
    # 1. 转换 IP
    ip = sprintf("%d.%d.%d.%d", strtonum("0x"$2), strtonum("0x"$3), strtonum("0x"$4), strtonum("0x"$5))
    
    # 2. 拼接完整的 64 位纳秒时间戳 (小端序: $14 是最高位, $7 是最低位)
    # 构造十六进制字符串进行转换
    v_hex = $14$13$12$11$10$9$8$7
    # 注意：某些 awk 处理 16 位十六进制可能会丢失精度，这里直接计算秒
    # 我们拆分成高 4 字节和低 4 字节计算秒，以确保 32 位系统兼容性
    high = strtonum("0x"$14$13$12$11)
    low  = strtonum("0x"$10$9$8$7)
    
    # 纳秒转秒: (high * 2^32 + low) / 10^9
    # 2^32 = 4294967296
    last_up_sec = (high * 4294967296 + low) / 1000000000

    # 3. 计算绝对时间
    abs_ts = b_ts + last_up_sec
    cmd = "date -d @\"" int(abs_ts) "\" \"+%Y-%m-%d %H:%M:%S\""
    cmd | getline real_time
    close(cmd)

    # 4. 计算人性化间隔
    diff = int(n_up - last_up_sec)
    if (diff < 0) diff = 0;

    d = int(diff / 86400)
    h = int((diff % 86400) / 3600)
    m = int((diff % 3600) / 60)
    s = int(diff % 60)

    h_rel = ""
    if (d > 0) h_rel = d "天 "
    if (h > 0 || d > 0) h_rel = h_rel h "时 "
    if (m > 0 || h > 0 || d > 0) h_rel = h_rel m "分 "
    h_rel = h_rel s "秒 前"

    printf "%-16s | %-19s | %-20s\n", ip, real_time, h_rel
}'
