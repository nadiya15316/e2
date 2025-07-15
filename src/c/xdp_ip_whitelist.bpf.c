// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// Define byte order conversion macro if not already defined
#ifndef bpf_htons
#define bpf_htons(x)    __builtin_bswap16(x)
#endif

// Define a rate limit map to track packet counts per non-whitelisted IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);        // Least Recently Used hash map
    __uint(max_entries, 128);                   // Can track up to 128 IP addresses
    __type(key, __u32);                         // Key is source IP address
    __type(value, __u64);                       // Value is packet count
} rate_limit_map SEC(".maps");

// Define a whitelist map for IPs that bypass the rate limit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);            // Regular hash map
    __uint(max_entries, 16);                    // Up to 16 whitelisted IPs
    __type(key, __u32);                         // Key is source IP address
    __type(value, __u32);                       // Value is a dummy (not used)
} whitelist SEC(".maps");

// XDP program to enforce whitelist and rate limit
SEC("xdp")
int xdp_ip_whitelist(struct xdp_md *ctx) {
    // Pointers to packet data
    void *data_end = (void *)(long)ctx->data_end;    // End of packet
    void *data     = (void *)(long)ctx->data;        // Start of packet

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
         return XDP_PASS;    // Drop if packet is malformed

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;    // Drop if packet is malformed

    // Get source IP address
    __u32 src_ip = ip->saddr;

    // Check if IP is in the whitelist
    __u8 *allowed = bpf_map_lookup_elem(&whitelist, &src_ip);
    if (allowed) {
        return XDP_PASS;    // Allow packet if source IP is whitelisted
    }

    // If not whitelisted, check the rate limit map
    __u64 *count = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    __u64 new_count = 1;    // Start with 1 packet

    if (count) {
        new_count = *count + 1;   // Increment packet count if already seen
    }

    // Drop packet if it exceeds the threshold (more than 5 packets)
    if (new_count > 5) {
        return XDP_DROP;
    }

    // Update the rate limit map with the new packet count
    bpf_map_update_elem(&rate_limit_map, &src_ip, &new_count, BPF_ANY);

    // Allow packet through
    return XDP_PASS;
}

// License declaration for the eBPF program
char _license[] SEC("license") = "GPL";
