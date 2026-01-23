#!/bin/bash
#
# File     : deploy_direct_path.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#

set -e

LAN_DEV="br-lan"
WAN_DEV="br-wan"
BPF_OBJ="tc_direct_path.o"
BPF_DIR="/sys/fs/bpf/tc_progs"

# 具体的 Map 路径
HOTPATH_PIN="$BPF_DIR/hotpath_cache"
BLACK_PIN="$BPF_DIR/blklist_ip_map"
DIRECT_PIN="$BPF_DIR/direct_ip_map"

HOTMAP_SIZE=65536
BLACKMAP_SIZE=8192
DIRECTMAP_SIZE=16384

echo "1. 彻底清理 BPF 虚拟文件系统..."
tc qdisc del dev ${LAN_DEV} clsact 2>/dev/null || true
tc qdisc del dev ${WAN_DEV} clsact 2>/dev/null || true

umount -f ${BPF_DIR} 2> /dev/null || true
rm -rf $BPF_DIR

mkdir -p $BPF_DIR

# 挂载 bpffs (如果没挂载的话)
mount -t bpf bpf $BPF_DIR 2>/dev/null || true

echo "2. 显式创建并固定 Map (确保内核对象先于程序存在)..."

# 创建 hotpath_cache (LRU_HASH: type 9, key 4B, value 8B, max 1024)
bpftool map create $HOTPATH_PIN type lru_hash key 4 value 8 entries ${HOTMAP_SIZE} name hotpath_cache

# 创建 blklist_ip_map (LPM_TRIE: type 11, key 8B, value 4B, max 1024, flags 1)
bpftool map create $BLACK_PIN type lpm_trie key 8 value 4 entries ${BLACKMAP_SIZE} name blklist_ip_map flags 1

# 创建 direct_ip_map (LPM_TRIE: type 11, key 8B, value 4B, max 16384, flags 1[NO_PREALLOC])
bpftool map create $DIRECT_PIN type lpm_trie key 8 value 4 entries ${DIRECTMAP_SIZE} name direct_ip_map flags 1

echo "3. 加载程序并重用已存在的 Maps..."
# 使用 map name 映射到刚才创建的文件上
bpftool prog load $BPF_OBJ "$BPF_DIR/tc_accel_prog" \
    map name hotpath_cache pinned $HOTPATH_PIN \
    map name direct_ip_map pinned $DIRECT_PIN \
    map name blklist_ip_map pinned $BLACK_PIN

echo "4. 挂载 TC 过滤器..."
tc qdisc add dev ${LAN_DEV} clsact
tc filter add dev ${LAN_DEV} ingress bpf da pinned "$BPF_DIR/tc_accel_prog"
tc filter add dev ${LAN_DEV} egress bpf da pinned "$BPF_DIR/tc_accel_prog"

tc qdisc add dev ${WAN_DEV} clsact
tc filter add dev ${WAN_DEV} ingress bpf da pinned "$BPF_DIR/tc_accel_prog"

# ... nftables 逻辑保持不变 ...

echo "加速引擎已完美启动！"
