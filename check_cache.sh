#!/bin/bash
#
# File     : check_cache.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#

MAP_PATH="/sys/fs/bpf/tc_progs/hotpath_cache"

if [ ! -e "$MAP_PATH" ]; then
    echo "错误: 找不到 Map 文件 $MAP_PATH"
    exit 1
fi

# 获取最大容量
MAX=$(bpftool map show pinned "$MAP_PATH" | grep -oE "max_entries [0-4]+" | awk '{print $2}')

# 获取当前条目数 (通过查找 key 关键字)
CUR=$(bpftool map dump pinned "$MAP_PATH" | grep -c "key:")

# 计算百分比
# OpenWrt 默认只有基本的 awk，我们可以用它做浮点运算
USAGE=$(awk -v c="$CUR" -v m="$MAX" 'BEGIN { printf "%.2f", (c/m)*100 }')

echo "---------------------------------------"
echo "缓存库状态监控 (DirectPath LRU Cache)"
echo "当前条目: $CUR"
echo "最大容量: $MAX"
echo "占用比例: $USAGE%"
echo "---------------------------------------"

# 诊断建议
if [ "$CUR" -eq "$MAX" ]; then
    echo "警告: 缓存已满！虽然 LRU 会自动淘汰旧数据，但如果"
    echo "      占用率长期 100%，建议将 max_entries 调大。"
elif [ "$CUR" -gt $((MAX * 8 / 10)) ]; then
    echo "提示: 缓存压力较大 (已超过 80%)。"
else
    echo "状态: 缓存运行良好。"
fi
