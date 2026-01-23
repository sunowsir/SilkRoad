/*
 * File     : tc_direct_path.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-01-20 21:39:23
*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DIRECT_MARK 0x88

#define CACHE_IP_MAP_SIZE       65536
#define BLKLIST_IP_MAP_SIZE     8192
#define DIRECT_IP_MAP_SIZE      16384

/* 定义 LRU Hash Map (缓存) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CACHE_IP_MAP_SIZE);
    __uint(key_size, 4);
    __uint(value_size, 8);
} hotpath_cache SEC(".maps");

/* 黑名单 (LPM) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, BLKLIST_IP_MAP_SIZE);
    __uint(key_size, 8);
    __uint(value_size, 4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blklist_ip_map SEC(".maps");

/* 国内 IP 白名单 (LPM) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DIRECT_IP_MAP_SIZE);
    __uint(key_size, 8);
    __uint(value_size, 4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} direct_ip_map SEC(".maps");

typedef struct {
    __u32 prefixlen;
    __u32 ipv4;
} lpm_key_t;

/* 私网检查函数 */
static __always_inline int is_private_ip(__u32 ip) {
    __u32 host_ip = bpf_ntohl(ip);
    if ((host_ip & 0xFF000000) == 0x0A000000) return 1; // 10.0.0.0/8
    if ((host_ip & 0xFFF00000) == 0xAC100000) return 1; // 172.16.0.0/12
    if ((host_ip & 0xFFFF0000) == 0xC0A80000) return 1; // 192.168.0.0/16
    return 0;
}

static __always_inline int do_lookup_map(__u32 *addr, lpm_key_t *key) {
    if (unlikely(NULL == addr) || unlikely(NULL == key)) return 0;

    // 3. 检查缓存 
    if (bpf_map_lookup_elem(&hotpath_cache, addr)) {
        return 1;
    }

    // 4. 查白名单并更新缓存
    key->ipv4 = *addr;
    if (bpf_map_lookup_elem(&direct_ip_map, key)) {
        bpf_map_update_elem(&hotpath_cache, addr, &(__u64){bpf_ktime_get_ns()}, BPF_ANY);
        return 1;
    } 

    return 0;
}

/* 核心查找逻辑：直接操作具体 Map 避免指针丢失上下文 */
static __always_inline int do_lookup(struct iphdr *iph) {
    lpm_key_t key = {.prefixlen = 32};

    // 1. 过滤纯内网互访
    if (is_private_ip(iph->saddr) && is_private_ip(iph->daddr)) return 0;

    // 2. 检查黑名单 (源或目的在黑名单则不加速)
    key.ipv4 = iph->daddr;
    if (bpf_map_lookup_elem(&blklist_ip_map, &key)) return 0;
    key.ipv4 = iph->saddr;
    if (bpf_map_lookup_elem(&blklist_ip_map, &key)) return 0;

    if (!is_private_ip(iph->daddr) && do_lookup_map(&(iph->daddr), &key)) {
        // bpf_trace_printk("Direct path match daddr: %pI4 -> %pI4\n", sizeof("Direct path match daddr: %pI4 -> %pI4\n"), &iph->saddr, &iph->daddr);
        return 1;
    }

    if (!is_private_ip(iph->saddr) && do_lookup_map(&(iph->saddr), &key)) {
        // bpf_trace_printk("Direct path match saddr: %pI4 -> %pI4\n", sizeof("Direct path match daddr: %pI4 -> %pI4\n"), &iph->saddr, &iph->daddr);
        return 1;
    }

    return 0;
}

SEC("classifier")
int tc_direct_path(struct __sk_buff *skb) {
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (void *)(long)skb->data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    if (do_lookup(iph)) {
        skb->mark = DIRECT_MARK;
        // 调试打印可按需开启
        // bpf_trace_printk("Direct path session: %pI4 -> %pI4\n", sizeof("Direct path session: %pI4 -> %pI4\n"), &iph->saddr, &iph->daddr);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
