// xdp_ip_blacklist_bcc.c
// BCC-compatible XDP IP blacklist with dual blocking and per-drop logging
// For use with BCC Python loader

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>

// Maximum number of blacklisted IPs
#define MAX_BLACKLIST_ENTRIES 10000

// Structure to store blacklist entry metadata
struct blacklist_entry {
    u64 detection_event_id_high;  // UUID high 64 bits
    u64 detection_event_id_low;   // UUID low 64 bits
    u64 block_timestamp;          // When this IP was blacklisted
    u32 drop_count;               // Number of packets dropped from this IP
};

// Structure for per-drop event logging
struct drop_event {
    u32 src_ip;
    u64 timestamp;
    u64 detection_event_id_high;
    u64 detection_event_id_low;
    u8 drop_reason;  // 1=IP_BLACKLIST, 2=CONTENT_FILTER
};

// BPF Maps - BCC syntax
BPF_HASH(ip_blacklist, u32, struct blacklist_entry, MAX_BLACKLIST_ENTRIES);
BPF_PERCPU_ARRAY(drop_cnt, u64, 1);
BPF_PERF_OUTPUT(drop_events);

// Helper: Check if payload starts with "Test Data"
static inline int mem_match_testdata(void *ptr, void *end) {
    char pattern[] = "Test Data";
    int len = 9;  // Length of "Test Data"
    
    if ((void *)ptr + len > end)
        return 0;
    
    unsigned char *p = (unsigned char *)ptr;
    
    // Manual unrolled loop for BPF verifier
    if (len > 0 && p[0] != pattern[0]) return 0;
    if (len > 1 && p[1] != pattern[1]) return 0;
    if (len > 2 && p[2] != pattern[2]) return 0;
    if (len > 3 && p[3] != pattern[3]) return 0;
    if (len > 4 && p[4] != pattern[4]) return 0;
    if (len > 5 && p[5] != pattern[5]) return 0;
    if (len > 6 && p[6] != pattern[6]) return 0;
    if (len > 7 && p[7] != pattern[7]) return 0;
    if (len > 8 && p[8] != pattern[8]) return 0;
    
    return 1;
}

// Helper: Send drop event to userspace
static inline void log_drop_event(struct xdp_md *ctx, u32 src_ip, 
                                   struct blacklist_entry *entry, 
                                   u8 reason) {
    struct drop_event event = {};
    event.src_ip = src_ip;
    event.timestamp = bpf_ktime_get_ns();
    event.drop_reason = reason;
    
    if (entry) {
        event.detection_event_id_high = entry->detection_event_id_high;
        event.detection_event_id_low = entry->detection_event_id_low;
    }
    
    drop_events.perf_submit(ctx, &event, sizeof(event));
}

// Main XDP Program
int xdp_ip_blacklist_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    // Only process IPv4 packets
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;
    
    u32 src_ip = ip->saddr;  // Source IP in network byte order
    
    // ========================================
    // CHECK 1: IP Blacklist Lookup
    // ========================================
    struct blacklist_entry *entry = ip_blacklist.lookup(&src_ip);
    if (entry) {
        // IP is blacklisted - increment drop counter
        __sync_fetch_and_add(&entry->drop_count, 1);
        
        // Update global drop counter
        u32 key = 0;
        u64 *val = drop_cnt.lookup(&key);
        if (val)
            __sync_fetch_and_add(val, 1);
        
        // Log drop event with detection_event_id
        log_drop_event(ctx, src_ip, entry, 1);  // Reason: 1 = IP_BLACKLIST
        
        return XDP_DROP;
    }
    
    // ========================================
    // CHECK 2: Content-Based Filter (Smoke Test)
    // ========================================
    
    // Only check TCP packets for content
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    u32 ihl_len = ip->ihl * 4;
    if (ihl_len < sizeof(*ip))
        return XDP_PASS;
    
    struct tcphdr *tcp = (void *)ip + ihl_len;
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;
    
    // Get payload
    u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp))
        return XDP_PASS;
        
    void *payload = (void *)tcp + tcp_hdr_len;
    if (payload >= data_end)
        return XDP_PASS;
    
    // Check for "Test Data" pattern
    if (mem_match_testdata(payload, data_end)) {
        // Update global drop counter
        u32 key = 0;
        u64 *val = drop_cnt.lookup(&key);
        if (val)
            __sync_fetch_and_add(val, 1);
        
        // Log drop event (no detection_event_id for content filter)
        log_drop_event(ctx, src_ip, NULL, 2);  // Reason: 2 = CONTENT_FILTER
        
        return XDP_DROP;
    }
    
    return XDP_PASS;
}
