/*
 * File     : xdp_direct_path.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-01-29 10:51:35
*/


#include "direct_path_kernel.h"
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>

/* 定义 LRU Hash Map 作为预缓存 */
domain_cache_t domain_cache SEC(".maps");

/* 定义国内域名白名单 */
domain_map_t domain_map SEC(".maps");

/* 定义数组，作为域名白名单key */
domain_map_key_t domain_map_key SEC(".maps");


static __always_inline void error_debug_info(void *cursor, domain_lpm_key_t *key, struct iphdr *ip) {
    if (unlikely(NULL == cursor || NULL == key || NULL == ip)) return ;

    bpf_printk("DNS [%s][%s] Ingress Match failed: %pI4 -> %pI4", 
        cursor, key->domain, &ip->saddr, &ip->daddr);
    bpf_printk("key->prefixlen: [%02x]", key->prefixlen);

    #pragma unroll
    for (int i = 0; i < 16; i++) {
        bpf_printk("key->domain[%d]: [%02x]", i, key->domain[i]);
    }
    bpf_printk("\n");
}

/* 增量更新 TCP 校验和 (RFC 1624) */
static __always_inline void tcp_update_csum(__u16 old_val, __u16 new_val, __u16 *csum) {
    if (unlikely(NULL == csum)) return;
    __u32 new_csum_hash = (__u32)*csum + (__u32)old_val + (__u32)(__u16)~new_val;
    new_csum_hash = (new_csum_hash & 0xFFFF) + (new_csum_hash >> 16);
    *csum = (__u16)(new_csum_hash + (new_csum_hash >> 16));
}

/* 增量更新 UDP 校验和 (RFC 1624) */
static __always_inline void udp_update_csum(__u16 old_val, __u16 new_val, __u16 *csum) {
    if (unlikely(NULL == csum || 0 == *csum)) return;
    __u32 res = *csum + old_val + (__u16)~new_val;
    *csum = (__u16)(res + (res >> 16));
}

/* 私网检查函数 */
static __always_inline __u8 is_private_ip(__u32 ip) {
    if ((bpf_ntohl(ip) & 0xFF000000) == 0x7F000000) return 1; // 127.0.0.0/8
    if ((bpf_ntohl(ip) & 0xFF000000) == 0x0A000000) return 1; // 10.0.0.0/8
    if ((bpf_ntohl(ip) & 0xFFF00000) == 0xAC100000) return 1; // 172.16.0.0/12
    if ((bpf_ntohl(ip) & 0xFFFF0000) == 0xC0A80000) return 1; // 192.168.0.0/16
    return 0;
}

/* 域名字符合法性检查 */
static __always_inline __u8 is_valid_dns_char(unsigned char c) {
    if (c >= '0' && c <= '9') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if ('-' == c || '_' == c) return 1;
    return 0;
}

/* 根据 RFC1035 对 DNS 报文进行检查 */
static __always_inline __u8 dns_standard_query_pkt_check(unsigned char *dns_hdr, void *data_end) {
    if (unlikely(NULL == dns_hdr || NULL == data_end)) return 0;

    /* 检查数据包长度是否至少够 DNS Header + 最短域名(1字节长度+0字节结尾) */
    if ((void *)dns_hdr + (DNS_HEADER_BYTE + 2) > data_end) return 0;
    
    /* 只处理 1 个查询的包。QDCOUNT 是 Header 的第 5-6 字节 */
    __u16 qdcount = bpf_ntohs(*(__u16 *)((void *)dns_hdr + DNS_HEADER_QDCOUNT_BYTE_OFFSET));
    if (qdcount != 1) return 0; 

    /* 非请求不处理 */
    __u8 qr = dns_hdr[2] >> 7;
    if (unlikely(qr != DNS_HEADER_QR_QUERY)) return 0;

    /* 非标准查询不处理 */
    __u8 opcode = (dns_hdr[2] >> 3) & 0x0F;
    if (opcode != DNS_HEADER_OPCODE_STANDARD) return 0;

    return 1;
}

static __always_inline __u32 domain_copy(unsigned char *ptr, domain_lpm_key_t *key, void *data_end) {
    if (unlikely(NULL == ptr || NULL == key || NULL == data_end)) return 0;

    __u32 len = 0;
    __u8 remaining_label_len = 0;
    #pragma unroll
    for (int i = 0; i < DOMAIN_MAX_LEN; i++, ptr++) {
        if (unlikely(((void *)ptr + 1 > data_end) || (0 == *ptr))) break;

        if (0 == remaining_label_len) {
            if (*ptr >= DNS_LABEL_MAX_LEN) continue;
            remaining_label_len = *ptr;
        } else {
            if (!is_valid_dns_char(*ptr)) {
                remaining_label_len = 0;
                continue;
            }

            remaining_label_len--;
        }
        
        key->domain[len++] = *ptr;
    }

    return len;
}

static __always_inline void domain_reverse(domain_lpm_key_t *key, __u32 len) {
    if (unlikely(NULL == key || 0 == len)) return ;

    #pragma unroll
    for (int i = 0; i < DOMAIN_MAX_LEN >> 1; i++) {
        int j = len - 1 - i;
        if (unlikely(i >= j || j >= DOMAIN_MAX_LEN)) break;
    
        char t = key->domain[i];
        key->domain[i] = key->domain[j];
        key->domain[j] = t;
    }

    return ;
}

static __always_inline __u8 do_lookup_map(domain_lpm_key_t *key) {
    if (unlikely(NULL == key)) return 0;

    /* 命中缓存 */
    __u32 *cache_val = bpf_map_lookup_elem(&domain_cache, key);
    if (cache_val) {
        __sync_fetch_and_add(cache_val, 1);
        return 1;
    }

    /* 域名库中查不到 */
    if (!bpf_map_lookup_elem(&domain_map, key)) return 0;

    /* 命中域名库，写入缓存 */
    __u32 val = 1;
    bpf_map_update_elem(&domain_cache, key, &val, BPF_ANY);

    return 1;
}

static __always_inline __u8 is_domain_match(unsigned char *dns_hdr, void *data_end) {
    if (unlikely((NULL == dns_hdr) || (NULL == data_end))) return 0;
    if (unlikely(!dns_standard_query_pkt_check(dns_hdr, data_end))) return 0;

    unsigned char *cursor = dns_hdr + DNS_HEADER_LEN;

    /* 获取一个key结构用于查询 */
    __u32 kkey = 0;
    domain_lpm_key_t *key = bpf_map_lookup_elem(&domain_map_key, &kkey);
    if (unlikely(!key)) return 0;
    __builtin_memset(key, 0, sizeof(domain_lpm_key_t));

    /* 根据 RFC1035 标准 [长度][内容][长度][内容] 拷贝有效报文到key中用于查询 */
    __u32 len = domain_copy(cursor, key, data_end);
    if (unlikely(len == 0 || len > DOMAIN_MAX_LEN)) return 0;
    key->prefixlen = Byte_to_bit(LIMIT_BY_MASK(len, (DOMAIN_MAX_LEN - 1)));

    /* 翻转key拷贝好的报文，因为用于保存国内域名名单的共享内存数据结构是LPM，前缀树 */
    domain_reverse(key, len);

    /* 匹配 */
    if (!do_lookup_map(key)) return 0;

    return 1;
}

static __always_inline __u8 is_domain_match_tcp(struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
    if (unlikely(NULL == ip || NULL == tcp || NULL == data_end)) return 0;

    /* 计算 TCP 数据负载偏移 
     * TCP 头部长度是动态的，由 doff 字段决定 (单位是 4 字节)
     * */
    __u32 tcp_hdr_len = tcp->doff * 4;
    void *payload = (void *)tcp + tcp_hdr_len;

    /* 处理 TCP DNS 的特殊性：2字节长度字段
     * RFC 1035: TCP DNS 会话中，报文前有两个字节表示长度
     * */
    __u16 *dns_len_field = payload;
    if ((void *)(dns_len_field + 1) > data_end) return XDP_PASS;

    /* DNS 实际内容起始点 */
    unsigned char *dns_hdr = (void *)(dns_len_field + 1);
    if ((void *)(dns_hdr + 1) > data_end) return XDP_PASS;

    return is_domain_match(dns_hdr, data_end);
}

static __always_inline __u8 is_domain_match_udp(struct iphdr *ip, struct udphdr *udp, void *data_end) {
    if (unlikely(NULL == ip || NULL == udp || NULL == data_end)) return 0;
    return is_domain_match((void *)(udp + 1), data_end);
}

/* 修改端口 */
static __always_inline void tcp_dns_pkt_dport_modify(struct tcphdr *tcp, __be16 new_dport) {
    if (unlikely(NULL == tcp)) return ;

    __be16 old_dport = tcp->dest;
    tcp->dest = new_dport;
    tcp_update_csum(old_dport, new_dport, &tcp->check);

    return ;
}
static __always_inline void udp_dns_pkt_dport_modify(struct udphdr *udp, __be16 new_dport) {
    if (unlikely(NULL == udp)) return ;

    __be16 old_dport = udp->dest;
    udp->dest = new_dport;
    udp_update_csum(old_dport, new_dport, &udp->check);

    return ;
}

static __always_inline int do_lookup(struct xdp_md *ctx, void *l4_hdr, struct iphdr *ip, void *data_end) {
    if (unlikely(NULL == l4_hdr || NULL == ip || NULL == data_end)) return XDP_PASS;
    if (unlikely((l4_hdr + 4) > data_end)) return XDP_PASS;

    switch(ip->protocol) {
        case IPPROTO_UDP: {

            struct udphdr *udp = (struct udphdr *)l4_hdr;
            if ((void *)udp + sizeof(struct udphdr) > data_end) return XDP_PASS;
            if (bpf_htons(NORMAOL_DNS_PORT) != udp->dest) return XDP_PASS;

            if (is_domain_match_udp(ip, udp, data_end)) udp_dns_pkt_dport_modify(udp, bpf_htons(DIRECT_DNS_SERVER_PORT));
            else udp_dns_pkt_dport_modify(udp, bpf_htons(PROXY_DNS_SERVER_PORT));
        } break;
        case IPPROTO_TCP: {
            struct tcphdr *tcp = (struct tcphdr *)l4_hdr;
            if ((void *)tcp + sizeof(struct tcphdr) > data_end) return XDP_PASS;
            if (bpf_htons(NORMAOL_DNS_PORT) != tcp->dest) return XDP_PASS;

            if (is_domain_match_tcp(ip, tcp, data_end)) tcp_dns_pkt_dport_modify(tcp, bpf_htons(DIRECT_DNS_SERVER_PORT));
            else tcp_dns_pkt_dport_modify(tcp, bpf_htons(PROXY_DNS_SERVER_PORT));
        } break;
        default: return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_direct_path(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 解析头部 */
    struct ethhdr *eth = data;
    if ((unlikely((void *)(eth + 1) > data_end))) return XDP_PASS;
    if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP))) return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (unlikely((void *)(ip + 1) > data_end)) return XDP_PASS;

    /* 只处理下游设备向本网关设备发起的DNS请求 */
    if ((!is_private_ip(ip->saddr)) || (!is_private_ip(ip->daddr))) return XDP_PASS;

    return do_lookup(ctx, (void *)ip + (ip->ihl * 4), ip, data_end);
}

char _license[] SEC("license") = "GPL";
