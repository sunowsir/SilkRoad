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
#define DOMAIN_MAP_SIZE         10485760

typedef struct domain_key {
    __u32 prefixlen;
    unsigned char domain[DOMAIN_MAX_LEN];
} __attribute__((packed)) domain_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DOMAIN_MAP_SIZE);
    __type(key, domain_key_t);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, domain_key_t);
} domain_map_key SEC(".maps");

/* 增量更新 UDP 校验和 (RFC 1624) */
static __always_inline void udp_update_csum(__u16 old_val, __u16 new_val, __u16 *csum) {
    if (0 == *csum) return;
    __u32 res = *csum + old_val + (__u16)~new_val;
    *csum = (__u16)(res + (res >> 16));
}

/* 私网检查函数 */
static __always_inline int is_private_ip(__u32 ip) {
    if ((bpf_ntohl(ip) & 0xFF000000) == 0x7F000000) return 1; // 127.0.0.0/8
    if ((bpf_ntohl(ip) & 0xFF000000) == 0x0A000000) return 1; // 10.0.0.0/8
    if ((bpf_ntohl(ip) & 0xFFF00000) == 0xAC100000) return 1; // 172.16.0.0/12
    if ((bpf_ntohl(ip) & 0xFFFF0000) == 0xC0A80000) return 1; // 192.168.0.0/16
    return 0;
}

static __always_inline int do_lookup(struct xdp_md *ctx, struct iphdr *ip, void *data_end) {
    if (unlikely(NULL == ctx || NULL == ip || NULL == data_end)) return XDP_PASS;

    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (unlikely(NULL == udp)) return XDP_PASS;
    if (unlikely((void *)(udp + 1) > data_end)) return XDP_PASS;

    if (bpf_htons(NORMAOL_DNS_PORT) == udp->dest) {

        unsigned char *dns_hdr = (void *)(udp + 1);
        if ((void *)(dns_hdr + 12) > data_end) return XDP_PASS;

        unsigned char *cursor = dns_hdr + 12;
        unsigned char *ptr = cursor;

        __u32 kkey = 0;
        domain_key_t *key = bpf_map_lookup_elem(&domain_map_key, &kkey);
        if (unlikely(!key)) return XDP_PASS;
        __builtin_memset(key, 0, sizeof(domain_key_t));

        // bpf_probe_read_kernel_str(key->domain, sizeof(key->domain), cursor);

        __u32 len = 0;
        #pragma unroll
        for (; len < DOMAIN_MAX_LEN; len++) {
            if ((void *)ptr + 1 > data_end) break;
            if ((*ptr == 0 || (*ptr == ' '))) break;
            key->domain[len] = *ptr;
            ptr++;
        }

        if (unlikely(len == 0 || len > DOMAIN_MAX_LEN)) return XDP_PASS;
        key->prefixlen = (len & (DOMAIN_MAX_LEN - 1)) * 8;

        #pragma unroll
        for (int i = 0; i < DOMAIN_MAX_LEN / 2; i++) {
            int j = len - 1 - i;
            if (i >= j || j >= DOMAIN_MAX_LEN) break;
        
            char t = key->domain[i];
            key->domain[i] = key->domain[j];
            key->domain[j] = t;
        }

        // 4. 匹配
        __u32 *val = bpf_map_lookup_elem(&domain_map, key);
            if (unlikely(!val)) {

            // bpf_printk("key->prefixlen: [%02x]", key->prefixlen);
            // #pragma unroll
            // for (int i = 0; i < 16; i++) {
            //     bpf_printk("key->domain[%d]: [%02x]", i, key->domain[i]);
            // }
            // bpf_printk("DNS [%s][%s][%d] Direct Receive session: %pI4:%d -> %pI4:%d\n", 
            //     cursor, key->domain, key->prefixlen, 
            //     &ip->saddr, bpf_ntohs(udp->source), &ip->daddr, bpf_ntohs(udp->dest));

            return XDP_PASS;
        }

        __u16 check_val = udp->check;

        // 执行劫持
        __be16 old_dport = udp->dest;
        __be16 new_dport = bpf_htons(DIRECT_DNS_SERVER_PORT);
        udp->dest = new_dport;
        udp_update_csum(old_dport, new_dport, &udp->check);

        // bpf_printk("DNS Ingress Direct path session: %pI4 -> %pI4\n", &ip->saddr, &ip->daddr);
        // bpf_printk("Ingress [%s][%s] AFTER: %d -> %d\n", 
        //     cursor, key->domain, bpf_ntohs(old_dport), bpf_ntohs(new_dport));
    } 

    return XDP_PASS;
}

SEC("xdp")
int dns_port_steer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // --- 解析头部  ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    /* 如果源地址不是私网地址或者目的地址不是私网地址，则不予处理 */
    if (!is_private_ip(ip->saddr) || !is_private_ip(ip->daddr))
        return XDP_PASS;

    return do_lookup(ctx, ip, data_end);
}

char _license[] SEC("license") = "GPL";
