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
#define PRE_CACHE_IP_MAP_SIZE   65536
#define BLKLIST_IP_MAP_SIZE     8192
#define DIRECT_IP_MAP_SIZE      16384

/* 总计收发20个包，且距离最开始的数据包的时间超过了 10秒，才被准入到缓存中 */
#define HOTPKG_NUM              20
#define HOTPKG_INV_TIME         10000000000ULL

/* 定义 LRU Hash Map 作为缓存 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CACHE_IP_MAP_SIZE);
    __uint(key_size, 4);
    __uint(value_size, 8);
} hotpath_cache SEC(".maps");

typedef struct {
    __u64 first_seen; // 第一次见到的纳秒时间戳
    __u32 count;      // 累计包量
} pre_val_t;

/* 定义 LRU Hash Map 作为预缓存 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, PRE_CACHE_IP_MAP_SIZE);
    __uint(key_size, 4);
    __uint(value_size, sizeof(pre_val_t)); 
} pre_cache SEC(".maps");

/* 黑名单 (LPM) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, BLKLIST_IP_MAP_SIZE);
    __uint(key_size, 8);
    __uint(value_size, 4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blklist_ip_map SEC(".maps");

typedef struct {
    __u32 prefixlen;
    __u32 ipv4;
} lpm_key_t;

/* 国内 IP 白名单 (LPM) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DIRECT_IP_MAP_SIZE);
    __uint(key_size, sizeof(lpm_key_t));
    __uint(value_size, 4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} direct_ip_map SEC(".maps");

/* 私网检查函数 */
static __always_inline int is_private_ip(__u32 *ip) {
    if ((bpf_ntohl(*ip) & 0xFF000000) == 0x0A000000) return 1; // 10.0.0.0/8
    if ((bpf_ntohl(*ip) & 0xFFF00000) == 0xAC100000) return 1; // 172.16.0.0/12
    if ((bpf_ntohl(*ip) & 0xFFFF0000) == 0xC0A80000) return 1; // 192.168.0.0/16
    return 0;
}

/* 查找Map */
static __always_inline int do_lookup_map(__u32 *addr) {
    if (unlikely(NULL == addr)) return 0;

    lpm_key_t key = {.prefixlen = 32, .ipv4 = *addr};

    /* 检查黑名单 (源或目的在黑名单则不加速) */
    if (bpf_map_lookup_elem(&blklist_ip_map, &key)) return 0;

    /* 查缓存一级白名单表之前检查地址是否是私网地址是为了防止缓存或国内IP白名单中混入私网地址 */
    if (is_private_ip(addr)) return 0;

    /* 检查缓存  */
    if (bpf_map_lookup_elem(&hotpath_cache, addr)) {
        return 1;
    }

    /* 预存区逻辑 */
    pre_val_t *pv = bpf_map_lookup_elem(&pre_cache, addr);
    __u64 now = bpf_ktime_get_ns();

   if (pv) {
        /* 原子操作，包计数递增 */
        /* __sync_fetch_and_add 返回的是自增前的值，因此需要加1进行判断 */
        __u32 c = __sync_fetch_and_add(&pv->count, 1) + 1;
        
        /* 加入缓存，判定标准：见过超过 HOTPKG_NUM 个包，且距离第一次见面已经过了 HOTPKG_INV_TIME 秒 */
        if (c >= HOTPKG_NUM && ((now - pv->first_seen) > HOTPKG_INV_TIME)) {
            bpf_map_update_elem(&hotpath_cache, addr, &now, BPF_ANY);
        }

        /* 只要命中白名单，无论命中白名单还是哪个缓存，当前包都要加速 */
        return 1; 
    }

    /* 查白名单并更新缓存 */
    if (bpf_map_lookup_elem(&direct_ip_map, &key)) {
        // bpf_map_update_elem(&hotpath_cache, addr, &(__u64){bpf_ktime_get_ns()}, BPF_ANY);
        /* 加入到预缓存 */
        pre_val_t first = {.first_seen = now, .count = 1};
        bpf_map_update_elem(&pre_cache, addr, &first, BPF_ANY);
        return 1;
    } 

    return 0;
}

/* 判断是否应当加速 */
static __always_inline int do_lookup(struct iphdr *iph) {
    if (unlikely(NULL == iph)) return 0;

    /* 过滤纯内网互访 */
    if (is_private_ip(&(iph->saddr)) && is_private_ip(&(iph->daddr))) return 0;

    /* 查询目的IP */
    if (do_lookup_map(&(iph->daddr))) {
        // bpf_trace_printk("Direct path match daddr: %pI4 -> %pI4\n", sizeof("Direct path match daddr: %pI4 -> %pI4\n"), &iph->saddr, &iph->daddr);
        return 1;
    }

    /* 查询源IP */
    if (do_lookup_map(&(iph->saddr))) {
        // bpf_trace_printk("Direct path match saddr: %pI4 -> %pI4\n", sizeof("Direct path match daddr: %pI4 -> %pI4\n"), &iph->saddr, &iph->daddr);
        return 1;
    }

    return 0;
}

SEC("classifier")
int tc_direct_path(struct __sk_buff *skb) {
    if (unlikely(NULL == skb)) return TC_ACT_OK;

    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (void *)(long)skb->data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    if (do_lookup(iph)) {
        skb->mark = bpf_htonl(DIRECT_MARK);
        // 调试打印可按需开启
        // bpf_trace_printk("Direct path session: %pI4 -> %pI4\n", sizeof("Direct path session: %pI4 -> %pI4\n"), &iph->saddr, &iph->daddr);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
