/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Toke Høiland-Jørgensen <toke@toke.dk> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>
#include "../include/xdp/parsing_helpers.h"
#include "nat64.h"

char _license[] SEC("license") = "GPL";

struct nat64_config config;

struct
{
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, struct in6_addr);
        __type(value, struct v6_addr_state);
        __uint(max_entries, 1);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} v6_state_map SEC(".maps");

struct
{
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u32);
        __type(value, struct v4_addr_state);
        __uint(max_entries, 1);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} v4_state_map SEC(".maps");

struct
{
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 1);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} v4_reversemap SEC(".maps");

struct
{
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __uint(key_size, sizeof(struct in6_addr));
        __uint(value_size, sizeof(__u32));
        __uint(max_entries, 1);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_v6_src SEC(".maps");

struct
{
        __uint(type, BPF_MAP_TYPE_QUEUE);
        __uint(key_size, 0);
        __uint(value_size, sizeof(__u32));
        __uint(max_entries, 1);
} reclaimed_addrs SEC(".maps");

#ifdef DEBUG
#define DBG(fmt, ...)                                      \
        ({                                                 \
                char ____fmt[] = "nat64: " fmt;            \
                bpf_trace_printk(____fmt, sizeof(____fmt), \
                                 ##__VA_ARGS__);           \
        })
#else
#define DBG
#endif

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
        __u32 sum;
        sum = (csum >> 16) + (csum & 0xffff);
        sum += (sum >> 16);
        return ~sum;
}

static int nat64_handle_v4(struct __sk_buff *skb, struct hdr_cursor *nh)
{
        void *data_end = (void *)(unsigned long long)skb->data_end;
        void *data = (void *)(unsigned long long)skb->data;

        int ip_type, iphdr_len, ip_offset;
        int ret = TC_ACT_OK;
        struct iphdr *iph, dst_hdr;
        struct ethhdr *eth;
        __u32 old_dst_v4;
        __u32 *new_dst_v4;

        ip_offset = (nh->pos - data) & 0x1fff;

        ip_type = parse_iphdr(nh, data_end, &iph);
        if (ip_type < 0)
                goto out;

        old_dst_v4 = bpf_ntohl(iph->daddr);
        if ((old_dst_v4 & config.v4_mask) != config.v4_prefix)
                goto out;

        /* At this point we know the destination IP is within the configured
         * subnet, so if we can't rewrite the packet it should be dropped (so as
         * not to leak traffic in that subnet).
         */
        ret = TC_ACT_SHOT;

        /* we don't bother dealing with IP options or fragmented packets. The
         * latter are identified by the 'frag_off' field having a value (either
         * the MF bit, or the fragmet offset, or both). However, this field also
         * contains the "don't fragment" (DF) bit, which we ignore, so mask that
         * out. The DF is the second-most-significant bit (as bit 0 is
         * reserved).
         */
        iphdr_len = iph->ihl * 4;
        if (iphdr_len != sizeof(struct iphdr) ||
            (iph->frag_off & ~bpf_htons(1 << 14)))
        {
                DBG("v4: pkt src/dst %pI4/%pI4 has IP options or is fragmented, dropping\n",
                    &iph->daddr, &iph->saddr);
                goto out;
        }

        new_dst_v4 = (__u32*)bpf_map_lookup_elem(&v4_reversemap, &old_dst_v4);
        // new_dst_v4 = 1;
        if (!new_dst_v4)
        {
                DBG("v4: no mapping found for dst %pI4\n", &iph->daddr);
                goto out;
        }

        DBG("v4: Found mapping for dst %pI4 to %pI6c\n", &iph->daddr, new_dst_v4);

        // // src v4 as last octet of nat64 address
        dst_hdr.saddr = iph->saddr;
        dst_hdr.daddr = *new_dst_v4;
        dst_hdr.protocol = iph->protocol;
        dst_hdr.ttl = iph->ttl;

        dst_hdr.tos = iph->tos;         //->priority << 4 | (ip6h->flow_lbl[0] >> 4);
        dst_hdr.tot_len = iph->tot_len; // (bpf_ntohs(ip6h->payload_len) + sizeof(dst_hdr));
        dst_hdr.check = csum_fold_helper(bpf_csum_diff((__be32 *)&dst_hdr, 0, (__be32 *)&dst_hdr, sizeof(dst_hdr), 0));

        data = (void *)(unsigned long long)skb->data;
        data_end = (void *)(unsigned long long)skb->data_end;

        eth = data;
        iph = data + ip_offset;
        if (eth + 1 > data_end || iph + 1 > data_end)
                goto out;

        // eth->h_proto = bpf_htons(ETH_P_IPV6);
        *iph = dst_hdr;

        ret = bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
out:
        return ret;
}

static long check_item(struct bpf_map *map, const void *key, void *value, void *ctx)
{
        struct v6_addr_state *state = value;
        __u64 timeout = *((__u64 *)ctx);

        if (state->last_seen < timeout && !state->static_conf)
        {
                __u32 v4_addr = state->v4_addr;
                bpf_map_delete_elem(map, key);
                bpf_map_delete_elem(&v4_reversemap, &v4_addr);
                bpf_map_push_elem(&reclaimed_addrs, &v4_addr, 0);

                /* only reclaim one address at a time, so mappings don't expire
                 * until they absolutely have to
                 */
                return 1;
        }

        return 0;
}

static __u32 reclaim_v4_addr(void)
{
        __u64 timeout = bpf_ktime_get_ns() - config.timeout_ns;
        __u32 src_v4;

        if (bpf_map_pop_elem(&reclaimed_addrs, &src_v4) == 0)
                return src_v4;

        bpf_for_each_map_elem(&v4_state_map, check_item, &timeout, 0);

        return bpf_map_pop_elem(&reclaimed_addrs, &src_v4) ? 0 : src_v4;
}

static struct v4_addr_state *alloc_new_state(__u32 *internal_src_v4)
{
        struct v4_addr_state new_v4_state = {.last_seen = bpf_ktime_get_ns()};
        __u32 max_v4 = (config.v4_prefix | ~config.v4_mask) - 1;
        __u32 src_v4 = 0;
        int i;

        for (i = 0; i < 10; i++)
        {
                __u32 next_v4, next_addr;

                next_addr = __sync_fetch_and_add(&config.next_addr, 0);
                next_v4 = config.v4_prefix + next_addr;

                if (next_v4 >= max_v4)
                {
                        src_v4 = reclaim_v4_addr();
                        break;
                }

                if (__sync_val_compare_and_swap(&config.next_addr,
                                                next_addr,
                                                next_addr + 1) == next_addr)
                {
                        src_v4 = next_v4;
                        break;
                }
        }

        /* If src_v4 is 0 here, we failed to find an available addr */
        if (!src_v4)
                return NULL;

        new_v4_state.v4_addr = src_v4;
        if (bpf_map_update_elem(&v4_state_map, internal_src_v4, &new_v4_state, BPF_NOEXIST))
                goto err;
        if (bpf_map_update_elem(&v4_reversemap, &src_v4, internal_src_v4, BPF_NOEXIST))
                goto err_v4;

        return bpf_map_lookup_elem(&v4_state_map, internal_src_v4);

err_v4:
        bpf_map_delete_elem(&v4_state_map, internal_src_v4);
err:
        /* failed to insert entry in maps, put the address back in the queue for
         * reclaiming
         */
        bpf_map_push_elem(&reclaimed_addrs, &src_v4, 0);
        return NULL;
}

// Handle incoming ipv4 from internal network, Translate addr & send to public
static int nat64_handle_ingress(struct __sk_buff *skb, struct hdr_cursor *nh)
{
        DBG("v4_ingress: Got an IPV4 packet\n");
        void *data_end = (void *)(unsigned long long)skb->data_end;
        void *data = (void *)(unsigned long long)skb->data;

        __u32 new_src_v4, dst_v4;
        int ip_type, ip_offset, iphdr_len;

        // struct ipv6hdr *ip6h;
        struct iphdr *iph;

        int ret = TC_ACT_OK;
        struct ethhdr *eth;
        // struct iphdr *iph;

        struct v4_addr_state *v4_state;

        struct iphdr dst_hdr = {
            .version = 4,
            .ihl = 5,
            .frag_off = bpf_htons(1 << 14), /* set Don't Fragment bit */
        };

        ip_offset = (nh->pos - data) & 0x1fff; // first 16 bits

        ip_type = parse_iphdr(nh, data_end, &iph);
        // ip_type = parse_ip6hdr(nh, data_end, &ip6h);
        if (ip_type < 0)
                goto out;

        // TODO: Check if the destination addr is in
        dst_v4 = iph->daddr;
        DBG("v4_ingress: v4 dst %pI4 from src %pI4\n",
            &dst_v4, &iph->saddr);
        // subnet_v6 = *dst_v6;
        // /* v6 pxlen is always 96 */
        // subnet_v6.s6_addr32[3] = 0;
        // if (cmp_v6addr(&subnet_v6, &config.v6_prefix)) {
        //         DBG("v6: dst subnet %pI6c not in configured prefix %pI6c\n",
        //             &subnet_v6, &config.v6_prefix);
        //         goto out;
        // }

        /* At this point we know the destination IP is within the configured
         * subnet, so if we can't rewrite the packet it should be dropped (so as
         * not to leak traffic in that subnet).
         */

        // We can directly pass this packet to kernel to further process
        // ret = TC_ACT_SHOT;

        // /* drop packets with IP options - parser skips options */
        // if (ip_type != iph->nexthdr) {
        //         DBG("v6: dropping packet with IP options from %pI6c\n",
        //             &ip6h->saddr);
        //         goto out;
        // }

        iphdr_len = iph->ihl * 4;
        if (iphdr_len != sizeof(struct iphdr) ||
            (iph->frag_off & ~bpf_htons(1 << 14)))
        {
                DBG("v4: pkt src/dst %pI4/%pI4 has IP options or is fragmented, dropping\n",
                    &iph->daddr, &iph->saddr);
                goto out;
        }

        /* drop a few special addresses */
        // dst_v4 = ip6h->daddr.s6_addr32[3];
        // if (!dst_v4 || /* 0.0.0.0 */
        //     (dst_v4 & bpf_htonl(0xFF000000)) == bpf_htonl(0x7F000000) || /* 127.x.x.x */
        //     (dst_v4 & bpf_htonl(0xF0000000)) == bpf_htonl(0xe0000000)) { /* multicast */
        //         DBG("v6: dropping invalid v4 dst %pI4 from %pI6c\n",
        //             &dst_v4, &ip6h->saddr);
        //         goto out;
        // }

        // TODO: Check if the src ipv4 can be allowed
        // saddr_key.addr = iph->saddr;
        // allowval = bpf_map_lookup_elem(&allowed_v6_src, &saddr_key);
        // if (!allowval) {
        //         DBG("v6: saddr %pI6c not in allowed src\n", &ip6h->saddr);
        //         goto out;
        // }

        // TODO: Check the state & allocate new one
        v4_state = bpf_map_lookup_elem(&v4_state_map, &iph->saddr);
        if (!v4_state)
        {
                v4_state = alloc_new_state(&iph->saddr);
                if (!v4_state)
                {
                        DBG("v4_ingress: failed to allocate state for src %pI4\n",
                            &iph->saddr);
                        goto out;
                }
                new_src_v4 = bpf_htonl(v4_state->v4_addr);
                DBG("v4_ingress: created new state for v4 %pI4 -> %pI4\n",
                    &iph->saddr, &new_src_v4);
        }
        else
        {
                v4_state->last_seen = bpf_ktime_get_ns();
                bpf_map_update_elem(&v4_state_map, &iph->saddr, v4_state, BPF_EXIST);

                new_src_v4 = bpf_htonl(v4_state->v4_addr);
                DBG("v4_ingress: updated old state for v4 %pI4 -> %pI4\n",
                    &iph->saddr, &new_src_v4);
        }

        // TODO: Form the ipv4 packet for destination
        dst_hdr.daddr = dst_v4;
        dst_hdr.saddr = new_src_v4;
        dst_hdr.protocol = iph->protocol;
        dst_hdr.ttl = iph->ttl;
        dst_hdr.tos = iph->tos;         //->priority << 4 | (ip6h->flow_lbl[0] >> 4);
        dst_hdr.tot_len = iph->tot_len; // (bpf_ntohs(ip6h->payload_len) + sizeof(dst_hdr));
        dst_hdr.check = csum_fold_helper(bpf_csum_diff((__be32 *)&dst_hdr, 0, (__be32 *)&dst_hdr, sizeof(dst_hdr), 0));

        // if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0))
        //         goto out;

        data = (void *)(unsigned long long)skb->data;
        data_end = (void *)(unsigned long long)skb->data_end;

        eth = data;
        iph = data + ip_offset;
        if (eth + 1 > data_end || iph + 1 > data_end)
                goto out;

        // eth->h_proto = bpf_htons(ETH_P_IP);
        *iph = dst_hdr;

        // ret = bpf_redirect(skb->ifindex, BPF_F_INGRESS);
out:
        DBG("sending to kernel? %d", ret);
        return ret;
}

static int nat64_handler(struct __sk_buff *skb, bool egress)
{
        void *data_end = (void *)(unsigned long long)skb->data_end;
        void *data = (void *)(unsigned long long)skb->data;
        struct hdr_cursor nh = {.pos = data};
        struct ethhdr *eth;
        int eth_type;

        /* Parse Ethernet and IP/IPv6 headers */
        eth_type = parse_ethhdr(&nh, data_end, &eth);
        if (eth_type == bpf_htons(ETH_P_IP) && egress)
                // From outside network. Check if a mapping exists, then send to internal network
                return nat64_handle_v4(skb, &nh);
        // // ingress ipv4 handling. From inside network, allocate a state & send
        else if (eth_type == bpf_htons(ETH_P_IP) && !egress) {
                DBG("v4: ingress from inside network to public");
                return nat64_handle_ingress(skb, &nh);
        }

        return TC_ACT_OK;
}
SEC("classifier")
int nat64_egress(struct __sk_buff *skb)
{
        return nat64_handler(skb, true);
}

SEC("classifier")
int nat64_ingress(struct __sk_buff *skb)
{
        return nat64_handler(skb, false);
}