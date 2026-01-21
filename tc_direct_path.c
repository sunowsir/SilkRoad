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

/* 直连流量标记 */
#define DIRECT_MARK 0x88


/* 定义 LRU Hash Map (快车道缓存) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024); // 缓存 1024 个热点 IP
    __uint(key_size, 4);       // IPv4 地址
    __uint(value_size, 8);      // 存储最后访问的时间戳
} hotpath_cache SEC(".maps");

/* 定义 Map 时，key 的大小需要包含 prefixlen(4) + IPv4(4) = 8 字节 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __uint(key_size, 8); 
    __uint(value_size, 4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} direct_ip_map SEC(".maps");


/* 构造 LPM 查找 Key
   必须严格匹配内核定义的 8 字节结构：4字节前缀 + 4字节IP 
 */
typedef struct {
    __u32 prefixlen;
    __u32 ipv4;
} DIM_LPM_key;

static __always_inline int tc_direct_path_lookup_mark(struct __sk_buff *skb, struct iphdr *iph) {
    if (unlikely(NULL == skb) || unlikely(NULL == iph))
        return TC_ACT_OK;

    __u32 dest_ip = iph->daddr;
    __u64 now = bpf_ktime_get_ns();

    /* 先从缓存查找(Hash 查找比 Trie 更快) */
    if (bpf_map_lookup_elem(&hotpath_cache, &dest_ip)) {
        /* 命中cache，打上加速标记 */
        skb->mark = DIRECT_MARK;
        /* 打印调试信息 (正式使用时可注释) */
        bpf_trace_printk("Direct path: IP %pI4 hit cache!\n", sizeof("Direct path: IP %pI4 hit cache!\n"), &dest_ip);
        return TC_ACT_OK;
    }

    DIM_LPM_key lpm_key;
    lpm_key.prefixlen = 32;
    lpm_key.ipv4 = dest_ip;

    /* 查找： 从国内IP库静态大名单中查找 */
    __u32 *is_direct = bpf_map_lookup_elem(&direct_ip_map, &lpm_key);
    if (!is_direct) return TC_ACT_OK;

    /* 加入到缓存中 */
    bpf_map_update_elem(&hotpath_cache, &dest_ip, &now, BPF_ANY);
    /* 命中直连名单，打上加速标记 */
    skb->mark = DIRECT_MARK;
    /* 打印调试信息 (正式使用时可注释) */
    bpf_trace_printk("Direct path: IP %pI4 hit!\n", sizeof("Direct path: IP %pI4 hit!\n"), &dest_ip);

    return TC_ACT_OK;
}

SEC("classifier")
int tc_direct_path(struct __sk_buff *skb) {
    /* 协议解析（仅处理 IPv4） */
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = (void *)(long)skb->data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    return tc_direct_path_lookup_mark(skb, iph);
}

char _license[] SEC("license") = "GPL";
