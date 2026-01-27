#!/bin/bash
#
# File     : deploy_direct_path.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#

set -e

LAN_DEV="eth1"
WAN_DEV="eth0"
BPF_OBJ="tc_direct_path.o"
BPF_DIR="/sys/fs/bpf/tc_progs"

# 具体的 Map 路径
HOTPATH_PIN="${BPF_DIR}/hotpath_cache"
PRE_PIN="${BPF_DIR}/pre_cache"
BLACK_PIN="${BPF_DIR}/blklist_ip_map"
DIRECT_PIN="${BPF_DIR}/direct_ip_map"

# eBPF共享内存大小（能存储多少个地址），请与C代码保持一致
#
# 缓存大小
HOTMAP_SIZE=65536
# 预缓存大小
PREMAP_SIZE=65536
# 黑名单大小
BLACKMAP_SIZE=8192
# 国内IP白名单大小
DIRECTMAP_SIZE=16384
# 快速通道Mark标记
DIRECT_PATH_MARK="0x88000000"

echo "1. 彻底清理 BPF 虚拟文件系统..."
tc qdisc del dev ${LAN_DEV} clsact 2>/dev/null || true
tc qdisc del dev ${WAN_DEV} clsact 2>/dev/null || true

umount -f ${BPF_DIR} 2> /dev/null || true
rm -rf ${BPF_DIR}

mkdir -p ${BPF_DIR}

# 挂载 bpffs (如果没挂载的话)
mount -t bpf bpf ${BPF_DIR} 2>/dev/null || true

echo "2. 显式创建并固定 Map (确保内核对象先于程序存在)..."

# 创建 hotpath_cache (LRU_HASH: type 9, key 4B, value 8B, max 1024)
bpftool map create ${HOTPATH_PIN} type lru_hash key 4 value 8 entries ${HOTMAP_SIZE} name hotpath_cache

# 创建 pre_cache (LRU_HASH: type 9, key 4B, value 16B, max 1024)
bpftool map create ${PRE_PIN} type lru_hash key 4 value 16 entries ${PREMAP_SIZE} name pre_cache

# 创建 blklist_ip_map (LPM_TRIE: type 11, key 8B, value 4B, max 1024, flags 1)
bpftool map create ${BLACK_PIN} type lpm_trie key 8 value 4 entries ${BLACKMAP_SIZE} name blklist_ip_map flags 1

# 创建 direct_ip_map (LPM_TRIE: type 11, key 8B, value 4B, max 16384, flags 1[NO_PREALLOC])
bpftool map create ${DIRECT_PIN} type lpm_trie key 8 value 4 entries ${DIRECTMAP_SIZE} name direct_ip_map flags 1

echo "3. 加载程序并重用已存在的 Maps..."
# 使用 map name 映射到刚才创建的文件上
bpftool prog load $BPF_OBJ "${BPF_DIR}/tc_accel_prog" \
    map name hotpath_cache pinned ${HOTPATH_PIN} \
    map name pre_cache pinned ${PRE_PIN} \
    map name direct_ip_map pinned ${DIRECT_PIN} \
    map name blklist_ip_map pinned ${BLACK_PIN}

echo "4. 挂载 TC 过滤器..."
tc qdisc add dev ${LAN_DEV} clsact
tc filter add dev ${LAN_DEV} ingress bpf da pinned "${BPF_DIR}/tc_accel_prog"
tc filter add dev ${LAN_DEV} egress bpf da pinned "${BPF_DIR}/tc_accel_prog"

tc qdisc add dev ${WAN_DEV} clsact
tc filter add dev ${WAN_DEV} ingress bpf da pinned "${BPF_DIR}/tc_accel_prog"

echo "5. 配置 nftables 联动 (安全加速模式) ..."

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
