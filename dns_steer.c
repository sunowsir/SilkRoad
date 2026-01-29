/*
 * File     : dns_steer.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-01-29 10:51:35
*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NORMAOL_DNS_PORT        53
#define DIRECT_DNS_SERVER_PORT  15301

#define DOMAIN_MAX_LEN          64
#define DOMAIN_MAP_SIZE         1024

typedef struct domain_key {
    __u32 prefixlen;
    char domain[DOMAIN_MAX_LEN];
} domain_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DOMAIN_MAP_SIZE);
    __type(key, domain_key_t);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} domestic_domains SEC(".maps");

SEC("classifier")
int dns_port_steer(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // --- 解析头部 (省略重复代码，确保与原版一致) ---
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;

    if (udp->dest == bpf_htons(NORMAOL_DNS_PORT)) {
        unsigned char *dns_hdr = (void *)udp + sizeof(*udp);
        if (unlikely((void *)dns_hdr + 12 > data_end)) return TC_ACT_OK;

        unsigned char *cursor = dns_hdr + 12;
        unsigned char *ptr = cursor;

        domain_key_t key = {0};

        // 1. 计算长度（这个循环通常编译器能处理，因为 ptr 是 pkt 指针）
        __u32 i = 0;
        __u32 cp_idx = 0;
        #pragma unroll
        for (i = 0; i < DOMAIN_MAX_LEN; i++) {
            if ((void *)ptr + 1 > data_end) break;
            if (*ptr== 0) break;
            cp_idx = DOMAIN_MAX_LEN - i - 1;
            if (likely(cp_idx >= 0 && cp_idx < DOMAIN_MAX_LEN)) {
                key.domain[cp_idx] = *ptr;
            }
            ptr++;
        }

        if (unlikely(cp_idx == 0 || cp_idx >= DOMAIN_MAX_LEN)) return TC_ACT_OK;
        bpf_probe_read_kernel(key.domain, sizeof(key.domain), &(key.domain[cp_idx]));

        if (unlikely(NULL == ptr || NULL == cursor)) return TC_ACT_OK;
        __u32 len = (__u32)((void *)ptr - (void *)cursor);
        if (unlikely(len == 0 || len > DOMAIN_MAX_LEN)) return TC_ACT_OK;
        key.prefixlen = (len & (DOMAIN_MAX_LEN - 1)) * 8;

        // 4. 匹配
        __u32 *val = bpf_map_lookup_elem(&domestic_domains, &key);
        if (unlikely(!val)) return TC_ACT_OK;

        __u16 check_val = udp->check;
        __be16 old_dport = udp->dest;
        __be16 new_dport = bpf_htons(DIRECT_DNS_SERVER_PORT);

        // 1. 修改端口
        // 使用固定偏移量，避免指针计算误差
        __u32 dport_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, dest);
        bpf_skb_store_bytes(skb, dport_off, &new_dport, sizeof(new_dport), 0);

        // 增量修正校验和
        if (unlikely(check_val != 0)) {
            __u32 csum_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
            bpf_l4_csum_replace(skb, csum_off, old_dport, new_dport, sizeof(new_dport));
        }

        // bpf_printk("Ingress %s AFTER: %d -> %d\n", key.domain, bpf_ntohs(old_dport), bpf_ntohs(new_dport));
    } 

    // 回程包
    else if (udp->source == bpf_htons(DIRECT_DNS_SERVER_PORT)) {
        __u16 check_val = udp->check;
        __be16 old_sport = udp->source;
        __be16 new_sport = bpf_htons(NORMAOL_DNS_PORT);

        // 1. 修改端口
        // 使用固定偏移量，避免指针计算误差
        __u32 sport_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, source);
        bpf_skb_store_bytes(skb, sport_off, &new_sport, sizeof(new_sport), 0);

        if (unlikely(check_val != 0)) {
            __u32 csum_off  = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
            bpf_l4_csum_replace(skb, csum_off, old_sport, new_sport, sizeof(new_sport));
        }

        // bpf_printk("Egress AFTER: %d -> %d\n", bpf_ntohs(old_sport), bpf_ntohs(new_sport));
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
