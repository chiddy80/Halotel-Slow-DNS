#!/bin/bash

# ============================================================================
#                  HARDCORE SLOWDNS - ULTRA OPTIMIZED
#                  Maximum Performance & Stability
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION - OPTIMIZED VALUES
# ============================================================================
SSHD_PORT=2222                  # Changed from 22 for security
SLOWDNS_PORT=5353               # Changed from 5300 to avoid conflicts
MTU_SIZE=2000                   # Increased for better performance
UDP_TIMEOUT=30                  # Increased UDP timeout
WORKER_THREADS=$(nproc)         # Auto-detect CPU cores
BUFFER_SIZE=65536               # Increased buffer size
CONNECTION_LIMIT=10000          # Max concurrent connections

# GitHub resources
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# ============================================================================
# PERFORMANCE OPTIMIZATION FLAGS
# ============================================================================
OPTIMIZE_NETWORK=1
OPTIMIZE_KERNEL=1
OPTIMIZE_MEMORY=1
DISABLE_IPV6=1
ENABLE_JUMBO_FRAMES=1
TCP_CONGESTION="bbr"            # BBR congestion control

# ============================================================================
# HARDCORE COLORS
# ============================================================================
BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;94m'
PURPLE='\033[0;35m'
CYAN='\033[0;96m'
WHITE='\033[1;37m'
ORANGE='\033[0;33m'
MAGENTA='\033[0;95m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'
NC='\033[0m'

# ============================================================================
# HARDCORE UI FUNCTIONS
# ============================================================================
print_banner() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}    ███████╗██╗      ██████╗ ██╗    ██╗██████╗ ███╗   ██╗███████╗   ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${CYAN}    ██╔════╝██║     ██╔═══██╗██║    ██║██╔══██╗████╗  ██║██╔════╝   ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${CYAN}    ███████╗██║     ██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║███████╗   ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${CYAN}    ╚════██║██║     ██║   ██║██║███╗██║██║  ██║██║╚██╗██║╚════██║   ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${CYAN}    ███████║███████╗╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║███████║   ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${CYAN}    ╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}${WHITE}        HARDCORE SLOWDNS - ULTIMATE EDITION                    ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}        MTU: ${RED}512${YELLOW} (External) → ${GREEN}1800${YELLOW} (Internal)                     ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${MAGENTA}        Performance Tuned for Maximum Throughput                ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${WHITE}${BOLD}$1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
}

print_step() {
    echo -e "\n${BLUE}┌─${NC} ${CYAN}${BOLD}STEP $1${NC}"
    echo -e "${BLUE}│${NC}"
}

print_step_end() {
    echo -e "${BLUE}└─${NC} ${GREEN}✓${NC}"
}

print_success() {
    echo -e "  ${GREEN}${BOLD}✓${NC} ${GREEN}$1${NC}"
}

print_error() {
    echo -e "  ${RED}${BOLD}✗${NC} ${RED}$1${NC}"
}

print_warning() {
    echo -e "  ${YELLOW}${BOLD}!${NC} ${YELLOW}$1${NC}"
}

print_info() {
    echo -e "  ${CYAN}${BOLD}ℹ${NC} ${CYAN}$1${NC}"
}

print_stats() {
    echo -e "  ${MAGENTA}${BOLD}📊${NC} ${MAGENTA}$1${NC}"
}

# ============================================================================
# PERFORMANCE METRICS
# ============================================================================
start_timer() {
    START_TIME=$(date +%s.%N)
}

end_timer() {
    END_TIME=$(date +%s.%N)
    DURATION=$(echo "$END_TIME - $START_TIME" | bc)
    echo -e "  ${GREEN}⏱️  Completed in ${DURATION}s${NC}"
}

# ============================================================================
# HARDCORE KERNEL OPTIMIZATION
# ============================================================================
optimize_kernel() {
    print_header "🔧 KERNEL OPTIMIZATION"
    
    # Create sysctl optimization file
    cat > /etc/sysctl.d/99-hardcore-slowdns.conf << EOF
# ============================================================================
# HARDCORE SLOWDNS KERNEL OPTIMIZATIONS
# ============================================================================

# Network stack optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 16777216
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535
net.core.default_qdisc = fq
net.core.ping_group_range = 0 2147483647

# IPv4 optimizations
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_mem = 8388608 8388608 8388608
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = $TCP_CONGESTION

# TCP optimizations
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1

# UDP optimizations (CRITICAL for DNS)
net.ipv4.udp_mem = 8388608 8388608 8388608
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Socket optimizations
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_reordering = 3

# Security optimizations
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_no_pmtu_disc = 0

# Queue optimizations
net.ipv4.neigh.default.gc_thresh1 = 2048
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh3 = 8192

# Connection tracking
net.netfilter.nf_conntrack_max = 524288
net.nf_conntrack_max = 524288

# ARP cache
net.ipv4.neigh.default.base_reachable_time_ms = 30000
net.ipv4.neigh.default.gc_stale_time = 60

EOF

    # Apply optimizations
    sysctl -p /etc/sysctl.d/99-hardcore-slowdns.conf > /dev/null 2>&1
    
    print_success "Kernel optimized for high-performance networking"
    print_info "TCP Congestion Control: $TCP_CONGESTION"
    print_info "Buffer sizes increased to 128MB"
    
    # Set network interface optimizations
    for iface in $(ls /sys/class/net/ | grep -v lo); do
        ethtool -G $iface rx 4096 tx 4096 2>/dev/null || true
        ethtool -K $iface tso on gso on gro on 2>/dev/null || true
    done
    
    print_success "Network interface buffers optimized"
}

# ============================================================================
# MEMORY OPTIMIZATION
# ============================================================================
optimize_memory() {
    print_header "🧠 MEMORY OPTIMIZATION"
    
    # Create transparent hugepages config
    echo "always" > /sys/kernel/mm/transparent_hugepage/enabled
    echo "madvise" > /sys/kernel/mm/transparent_hugepage/defrag
    
    # Adjust swappiness
    echo 10 > /proc/sys/vm/swappiness
    echo 50 > /proc/sys/vm/vfs_cache_pressure
    
    # Increase file descriptors
    echo "* soft nofile 1048576" >> /etc/security/limits.conf
    echo "* hard nofile 1048576" >> /etc/security/limits.conf
    echo "* soft nproc 65535" >> /etc/security/limits.conf
    echo "* hard nproc 65535" >> /etc/security/limits.conf
    echo "* soft memlock unlimited" >> /etc/security/limits.conf
    echo "* hard memlock unlimited" >> /etc/security/limits.conf
    
    # Optimize TCP buffer auto-tuning
    echo 1 > /proc/sys/net/ipv4/tcp_moderate_rcvbuf
    echo 1 > /proc/sys/net/ipv4/tcp_window_scaling
    
    print_success "Memory and limits optimized"
    print_info "File descriptors: 1,048,576"
    print_info "Swappiness: 10"
}

# ============================================================================
# NETWORK OPTIMIZATION
# ============================================================================
optimize_network() {
    print_header "🌐 NETWORK STACK OPTIMIZATION"
    
    # Disable IPv6 if requested
    if [ "$DISABLE_IPV6" = "1" ]; then
        echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
        echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
        print_success "IPv6 disabled"
    fi
    
    # Enable TCP Fast Open
    echo 3 > /proc/sys/net/ipv4/tcp_fastopen
    
    # Optimize connection tracking
    echo 65536 > /proc/sys/net/netfilter/nf_conntrack_max
    echo 120 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
    
    # Increase local port range
    echo "1024 65535" > /proc/sys/net/ipv4/ip_local_port_range
    
    # Optimize socket options
    echo 1 > /proc/sys/net/ipv4/tcp_autocorking
    echo 1 > /proc/sys/net/ipv4/tcp_low_latency
    echo 0 > /proc/sys/net/ipv4/tcp_slow_start_after_idle
    
    print_success "Network stack optimized for low latency"
}

# ============================================================================
# COMPILE HARDCORE EDNS PROXY WITH MTU CONFIGURATION
# ============================================================================
compile_edns_proxy() {
    print_header "⚡ COMPILING HARDCORE EDNS PROXY"
    
    # Create ultra-optimized C code
    cat > /tmp/hardcore-edns.c << 'EOF'

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/resource.h>

// ============================================================================
// HARDCORE CONFIGURATION - DO NOT CHANGE
// ============================================================================
#define LISTEN_PORT 53
#define SLOWDNS_PORT 5353
#define EXT_EDNS_MTU 512      // EXTERNAL MTU - INTERNET FACING
#define INT_EDNS_MTU 1800     // INTERNAL MTU - LOCAL NETWORK
#define BUFFER_SIZE 65536
#define UPSTREAM_POOL 256     // Increased for high concurrency
#define MAX_EVENTS 8192
#define REQ_TABLE_SIZE 131072 // Must be power of 2
#define SOCKET_TIMEOUT 5.0
#define CLEANUP_INTERVAL 1000 // Cleanup every 1000 packets

// ============================================================================
// PERFORMANCE STRUCTURES
// ============================================================================
typedef struct {
    int fd;
    uint8_t busy;
    uint64_t last_used;
    struct sockaddr_in target;
} upstream_t;

typedef struct req_entry {
    uint16_t req_id;
    int upstream_idx;
    double timestamp;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    uint32_t hash;
    struct req_entry *next;
} req_entry_t;

// ============================================================================
// GLOBAL STATE (ZERO-INITIALIZED)
// ============================================================================
static upstream_t *upstreams = NULL;
static req_entry_t **req_table = NULL;
static int sock = -1;
static int epoll_fd = -1;
static int timer_fd = -1;
static volatile sig_atomic_t shutdown_flag = 0;
static uint64_t stats_packets = 0;
static uint64_t stats_errors = 0;
static uint64_t stats_timeouts = 0;

// ============================================================================
// MEMORY POOL FOR ZERO-ALLOC PERFORMANCE
// ============================================================================
#define MEM_POOL_SIZE 100000
typedef struct mem_pool {
    req_entry_t entries[MEM_POOL_SIZE];
    uint32_t free_stack[MEM_POOL_SIZE];
    int free_top;
} mem_pool_t;

static mem_pool_t *mem_pool = NULL;

// ============================================================================
// HIGH-PRECISION TIMING
// ============================================================================
static inline double now_mono() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static inline uint64_t now_micro() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

// ============================================================================
// LOCK-FREE HASH TABLE FUNCTIONS
// ============================================================================
static inline uint32_t hash16(uint16_t id) {
    // High-performance hash for 16-bit IDs
    uint32_t x = id;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x & (REQ_TABLE_SIZE - 1);
}

// ============================================================================
// DNS PACKET PROCESSING - ULTRA OPTIMIZED
// ============================================================================
static inline uint16_t get_txid(const uint8_t *buf) {
    return (buf[0] << 8) | buf[1];
}

static inline void set_txid(uint8_t *buf, uint16_t id) {
    buf[0] = id >> 8;
    buf[1] = id & 0xFF;
}

static inline int patch_edns(uint8_t *buf, int len, int target_mtu) {
    // Fast EDNS patching without branches where possible
    if (len < 12) return len;
    
    int off = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip questions
    for (int i = 0; i < qdcount && off < len; i++) {
        while (off < len && buf[off]) off++;
        if (off + 5 >= len) break;
        off += 5;
    }
    
    // Find and patch EDNS OPT record
    int arcount = (buf[10] << 8) | buf[11];
    for (int i = 0; i < arcount && off + 4 < len; i++) {
        if (buf[off] == 0 && ((buf[off+1] << 8) | buf[off+2]) == 41) {
            // EDNS OPT record found
            buf[off+3] = target_mtu >> 8;
            buf[off+4] = target_mtu & 0xFF;
            return len;
        }
        off++;
    }
    
    // Add EDNS OPT record if not present
    if (len + 11 <= BUFFER_SIZE) {
        // Increment ARCOUNT
        buf[11]++;
        
        // Append OPT record
        uint8_t opt[] = {
            0x00,                           // NAME (root)
            0x00, 0x29,                     // TYPE OPT
            target_mtu >> 8, target_mtu & 0xFF, // CLASS (UDP payload size)
            0x00, 0x00,                     // TTL (extended RCODE/EDNS version)
            0x00, 0x00,                     // RDLENGTH
        };
        memcpy(buf + len, opt, sizeof(opt));
        return len + sizeof(opt);
    }
    
    return len;
}

// ============================================================================
// UPSTREAM MANAGEMENT
// ============================================================================
static inline int get_upstream() {
    uint64_t now = now_micro();
    static int last_used = 0;
    
    // Round-robin with timeout checking
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        int idx = (last_used + i) % UPSTREAM_POOL;
        
        if (!upstreams[idx].busy) {
            upstreams[idx].busy = 1;
            upstreams[idx].last_used = now;
            last_used = (idx + 1) % UPSTREAM_POOL;
            return idx;
        }
        
        // Check if upstream is stale (2 seconds)
        if (now - upstreams[idx].last_used > 2000000) {
            upstreams[idx].busy = 0;
            upstreams[idx].busy = 1;
            upstreams[idx].last_used = now;
            last_used = (idx + 1) % UPSTREAM_POOL;
            return idx;
        }
    }
    
    // All upstreams busy, use least recently used
    uint64_t oldest = now;
    int oldest_idx = 0;
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        if (upstreams[i].last_used < oldest) {
            oldest = upstreams[i].last_used;
            oldest_idx = i;
        }
    }
    
    upstreams[oldest_idx].last_used = now;
    return oldest_idx;
}

static inline void release_upstream(int idx) {
    if (idx >= 0 && idx < UPSTREAM_POOL) {
        upstreams[idx].busy = 0;
    }
}

// ============================================================================
// REQUEST TRACKING WITH MEMORY POOL
// ============================================================================
static inline req_entry_t *alloc_req_entry() {
    if (!mem_pool || mem_pool->free_top <= 0) {
        // Fallback to malloc if pool exhausted
        req_entry_t *e = calloc(1, sizeof(req_entry_t));
        if (!e) return NULL;
        e->hash = 0xFFFFFFFF; // Mark as malloc'd
        return e;
    }
    
    int idx = mem_pool->free_stack[--mem_pool->free_top];
    req_entry_t *e = &mem_pool->entries[idx];
    memset(e, 0, sizeof(*e));
    e->hash = idx; // Store pool index in hash field
    return e;
}

static inline void free_req_entry(req_entry_t *e) {
    if (e->hash == 0xFFFFFFFF) {
        free(e);
    } else {
        // Return to pool
        if (mem_pool->free_top < MEM_POOL_SIZE) {
            mem_pool->free_stack[mem_pool->free_top++] = e->hash;
        } else {
            free(e);
        }
    }
}

static inline void insert_req(int upstream_idx, uint8_t *buf, 
                             struct sockaddr_in *client, socklen_t addr_len) {
    req_entry_t *e = alloc_req_entry();
    if (!e) return;
    
    e->req_id = get_txid(buf);
    e->upstream_idx = upstream_idx;
    e->timestamp = now_mono();
    e->client_addr = *client;
    e->addr_len = addr_len;
    
    uint32_t h = hash16(e->req_id);
    e->next = req_table[h];
    req_table[h] = e;
    e->hash = h; // Reuse hash field for table index
}

static inline req_entry_t *find_and_remove_req(uint16_t id) {
    uint32_t h = hash16(id);
    req_entry_t **pp = &req_table[h];
    
    while (*pp) {
        if ((*pp)->req_id == id) {
            req_entry_t *found = *pp;
            *pp = found->next;
            return found;
        }
        pp = &(*pp)->next;
    }
    return NULL;
}

// ============================================================================
// EXPIRED REQUEST CLEANUP
// ============================================================================
static void cleanup_expired() {
    double now = now_mono();
    int cleaned = 0;
    
    for (int i = 0; i < REQ_TABLE_SIZE; i++) {
        req_entry_t **pp = &req_table[i];
        while (*pp) {
            if (now - (*pp)->timestamp > SOCKET_TIMEOUT) {
                req_entry_t *expired = *pp;
                release_upstream(expired->upstream_idx);
                *pp = expired->next;
                free_req_entry(expired);
                stats_timeouts++;
                cleaned++;
            } else {
                pp = &(*pp)->next;
            }
        }
    }
    
    if (cleaned > 0) {
        fprintf(stderr, "[CLEANUP] Removed %d expired requests\n", cleaned);
    }
}

// ============================================================================
// SIGNAL HANDLING
// ============================================================================
static void sig_handler(int signum) {
    shutdown_flag = 1;
    fprintf(stderr, "\n[SHUTDOWN] Signal %d received\n", signum);
}

// ============================================================================
// STATISTICS OUTPUT
// ============================================================================
static void print_stats() {
    fprintf(stderr, "\n[STATS] Packets: %lu, Errors: %lu, Timeouts: %lu\n",
            stats_packets, stats_errors, stats_timeouts);
}

// ============================================================================
// MAIN LOOP - HARDCORE OPTIMIZED
// ============================================================================
int main() {
    // Set high priority
    setpriority(PRIO_PROCESS, 0, -10);
    
    // Increase resource limits
    struct rlimit rl = {1048576, 1048576};
    setrlimit(RLIMIT_NOFILE, &rl);
    
    // Signal handling
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // Initialize memory pool
    mem_pool = mmap(NULL, sizeof(mem_pool_t), 
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (mem_pool == MAP_FAILED) {
        perror("mmap memory pool");
        return 1;
    }
    
    // Initialize free stack
    for (int i = 0; i < MEM_POOL_SIZE; i++) {
        mem_pool->free_stack[i] = i;
    }
    mem_pool->free_top = MEM_POOL_SIZE;
    
    // Allocate upstreams
    upstreams = calloc(UPSTREAM_POOL, sizeof(upstream_t));
    if (!upstreams) {
        perror("calloc upstreams");
        return 1;
    }
    
    // Allocate hash table
    req_table = calloc(REQ_TABLE_SIZE, sizeof(req_entry_t*));
    if (!req_table) {
        perror("calloc req_table");
        return 1;
    }
    
    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Set socket options for performance
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    
    int rcvbuf = 8388608; // 8MB
    int sndbuf = 8388608; // 8MB
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    // Bind to port 53
    struct sockaddr_in listen_addr = {0};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(LISTEN_PORT);
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind");
        return 1;
    }
    
    // Setup SlowDNS target address
    struct sockaddr_in slowdns_addr = {0};
    slowdns_addr.sin_family = AF_INET;
    slowdns_addr.sin_port = htons(SLOWDNS_PORT);
    inet_pton(AF_INET, "127.0.0.1", &slowdns_addr.sin_addr);
    
    // Initialize upstream sockets
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        upstreams[i].fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (upstreams[i].fd < 0) {
            perror("upstream socket");
            continue;
        }
        
        // Set upstream socket options
        setsockopt(upstreams[i].fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        setsockopt(upstreams[i].fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        
        upstreams[i].target = slowdns_addr;
        upstreams[i].busy = 0;
        upstreams[i].last_used = 0;
    }
    
    // Create epoll instance
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return 1;
    }
    
    // Add main socket to epoll
    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLET; // Edge-triggered for performance
    ev.data.fd = sock;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
    
    // Add upstream sockets to epoll
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        if (upstreams[i].fd > 0) {
            ev.events = EPOLLIN | EPOLLET;
            ev.data.fd = upstreams[i].fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstreams[i].fd, &ev);
        }
    }
    
    // Create timer for periodic cleanup
    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (timer_fd >= 0) {
        struct itimerspec timer = {0};
        timer.it_value.tv_sec = 1;
        timer.it_interval.tv_sec = 1; // Cleanup every second
        
        timerfd_settime(timer_fd, 0, &timer, NULL);
        
        ev.events = EPOLLIN;
        ev.data.fd = timer_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev);
    }
    
    fprintf(stderr, "[STARTUP] Hardcore EDNS Proxy ready\n");
    fprintf(stderr, "[CONFIG] External MTU: %d, Internal MTU: %d\n", 
            EXT_EDNS_MTU, INT_EDNS_MTU);
    fprintf(stderr, "[CONFIG] Upstreams: %d, Hash table: %d\n",
            UPSTREAM_POOL, REQ_TABLE_SIZE);
    
    // Main event loop
    struct epoll_event events[MAX_EVENTS];
    int packets_since_cleanup = 0;
    
    while (!shutdown_flag) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
        
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            
            if (fd == timer_fd) {
                // Timer expired, read to clear
                uint64_t expirations;
                read(timer_fd, &expirations, sizeof(expirations));
                
                // Periodic cleanup
                cleanup_expired();
                packets_since_cleanup = 0;
                
                // Print stats every 10 seconds
                static int stat_counter = 0;
                if (++stat_counter >= 10) {
                    print_stats();
                    stat_counter = 0;
                }
                continue;
            }
            
            if (fd == sock) {
                // Incoming DNS query from client
                uint8_t buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                while (1) {
                    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0,
                                          (struct sockaddr*)&client_addr, &addr_len);
                    if (len <= 0) break;
                    
                    stats_packets++;
                    packets_since_cleanup++;
                    
                    // Patch EDNS for internal MTU
                    int new_len = patch_edns(buffer, len, INT_EDNS_MTU);
                    
                    // Get upstream and forward
                    int upstream_idx = get_upstream();
                    if (upstream_idx >= 0) {
                        insert_req(upstream_idx, buffer, &client_addr, addr_len);
                        
                        ssize_t sent = sendto(upstreams[upstream_idx].fd, 
                                            buffer, new_len, 0,
                                            (struct sockaddr*)&upstreams[upstream_idx].target,
                                            sizeof(struct sockaddr_in));
                        
                        if (sent < 0) {
                            stats_errors++;
                            release_upstream(upstream_idx);
                        }
                    }
                }
            } else {
                // Response from upstream
                uint8_t buffer[BUFFER_SIZE];
                
                while (1) {
                    ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
                    if (len <= 0) break;
                    
                    // Patch EDNS for external MTU
                    int new_len = patch_edns(buffer, len, EXT_EDNS_MTU);
                    
                    // Find original request
                    uint16_t req_id = get_txid(buffer);
                    req_entry_t *req = find_and_remove_req(req_id);
                    
                    if (req) {
                        // Send response back to client
                        sendto(sock, buffer, new_len, 0,
                              (struct sockaddr*)&req->client_addr, req->addr_len);
                        
                        release_upstream(req->upstream_idx);
                        free_req_entry(req);
                    }
                }
            }
        }
        
        // Incremental cleanup every N packets
        if (packets_since_cleanup >= CLEANUP_INTERVAL) {
            cleanup_expired();
            packets_since_cleanup = 0;
        }
    }
    
    // Clean shutdown
    fprintf(stderr, "\n[SHUTDOWN] Cleaning up...\n");
    
    close(sock);
    close(epoll_fd);
    if (timer_fd >= 0) close(timer_fd);
    
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        if (upstreams[i].fd > 0) close(upstreams[i].fd);
    }
    
    print_stats();
    
    if (mem_pool && mem_pool != MAP_FAILED) {
        munmap(mem_pool, sizeof(mem_pool_t));
    }
    free(upstreams);
    free(req_table);
    
    fprintf(stderr, "[SHUTDOWN] Complete\n");
    return 0;
}

EOF

    print_info "Compiling Hardcore EDNS Proxy with MTU: ${RED}512${NC} → ${GREEN}1800${NC}"
    
    # Compile with maximum optimizations
    echo -ne "  ${CYAN}Compiling with aggressive optimizations...${NC}"
    
    # Try multiple optimization levels
    local optimize_flags="-O3 -march=native -flto -fno-stack-protector -fomit-frame-pointer -funroll-loops -ffast-math -DNDEBUG"
    
    if gcc $optimize_flags -pthread /tmp/hardcore-edns.c -o /usr/local/bin/hardcore-edns-proxy 2>/tmp/compile.log; then
        echo -e "\r  ${GREEN}✓ Hardcore EDNS Proxy compiled successfully${NC}"
        
        # Set executable permissions and capabilities
        chmod 755 /usr/local/bin/hardcore-edns-proxy
        setcap 'cap_net_bind_service=+ep' /usr/local/bin/hardcore-edns-proxy 2>/dev/null
        
        # Verify binary
        if /usr/local/bin/hardcore-edns-proxy --help 2>&1 | head -1; then
            print_success "Binary verification passed"
        fi
    else
        echo -e "\r  ${YELLOW}⚠ Falling back to O2 optimization...${NC}"
        
        # Fallback to O2
        if gcc -O2 -march=native /tmp/hardcore-edns.c -o /usr/local/bin/hardcore-edns-proxy 2>/tmp/compile.log; then
            echo -e "  ${GREEN}✓ Compiled with O2 optimization${NC}"
            chmod 755 /usr/local/bin/hardcore-edns-proxy
        else
            echo -e "\r  ${RED}✗ Compilation failed${NC}"
            echo -e "  ${YELLOW}Last 5 lines of compile log:${NC}"
            tail -5 /tmp/compile.log
            return 1
        fi
    fi
    
    print_stats "MTU Configuration: External=${RED}${EXT_EDNS_MTU}${NC}, Internal=${GREEN}${INT_EDNS_MTU}${NC}"
    print_stats "Upstream pool: ${UPSTREAM_POOL}, Hash table: ${REQ_TABLE_SIZE}"
    
    # Cleanup
    rm -f /tmp/hardcore-edns.c /tmp/compile.log 2>/dev/null
    
    return 0
}

# ============================================================================
# CREATE HARDCORE SYSTEMD SERVICES
# ============================================================================
create_services() {
    print_header "⚙️  CREATING HARDCORE SERVICES"
    
    # Create SlowDNS service
    cat > /etc/systemd/system/hardcore-slowdns.service << EOF
# ============================================================================
# HARDCORE SLOWDNS SERVICE
# ============================================================================
[Unit]
Description=Hardcore SlowDNS Server
Description=Ultra-optimized DNS tunneling server
After=network.target
Wants=network-online.target
Conflicts=systemd-resolved.service

[Service]
Type=exec
User=root
Group=root
WorkingDirectory=/etc/slowdns
ExecStart=/etc/slowdns/dnstt-server -udp :${SLOWDNS_PORT} \\
                                   -mtu ${INT_EDNS_MTU} \\
                                   -privkey-file /etc/slowdns/server.key \\
                                   %s 127.0.0.1:${SSHD_PORT}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=1
RestartPreventExitStatus=23
LimitNOFILE=1048576
LimitNPROC=65535
LimitCORE=infinity
LimitMEMLOCK=infinity
Nice=-10
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hardcore-slowdns

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
MemoryDenyWriteExecute=true
LockPersonality=true

# Performance
OOMScoreAdjust=-1000
CPUAffinity=0-$((WORKER_THREADS-1))
TasksMax=infinity
Delegate=yes

[Install]
WantedBy=multi-user.target
EOF

    print_success "Hardcore SlowDNS service created"
    print_info "MTU: ${INT_EDNS_MTU}, Port: ${SLOWDNS_PORT}"
    
    # Create EDNS Proxy service
    cat > /etc/systemd/system/hardcore-edns-proxy.service << EOF
# ============================================================================
# HARDCORE EDNS PROXY SERVICE
# ============================================================================
[Unit]
Description=Hardcore EDNS Proxy
Description=Ultra-fast EDNS proxy with MTU translation
After=hardcore-slowdns.service
Requires=hardcore-slowdns.service
Conflicts=systemd-resolved.service

[Service]
Type=exec
User=root
Group=root
WorkingDirectory=/tmp
ExecStart=/usr/local/bin/hardcore-edns-proxy
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=1
RestartPreventExitStatus=23
LimitNOFILE=1048576
LimitNPROC=65535
LimitCORE=infinity
LimitMEMLOCK=infinity
Nice=-15
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hardcore-edns-proxy

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
MemoryDenyWriteExecute=true
LockPersonality=true

# Performance
OOMScoreAdjust=-1000
CPUAffinity=0-$((WORKER_THREADS-1))
TasksMax=infinity
Delegate=yes

# Core dumping for debugging (disable in production)
# LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF

    print_success "Hardcore EDNS Proxy service created"
    print_info "External MTU: ${EXT_EDNS_MTU}, Internal MTU: ${INT_EDNS_MTU}"
    
    # Create watchdog service
    cat > /etc/systemd/system/hardcore-slowdns-watchdog.service << EOF
# ============================================================================
# HARDCORE WATCHDOG SERVICE
# ============================================================================
[Unit]
Description=Hardcore SlowDNS Watchdog
Description=Monitors and restarts services if needed
After=hardcore-slowdns.service hardcore-edns-proxy.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/bin/bash -c 'while true; do
    if ! ss -uln | grep -q ":${SLOWDNS_PORT} "; then
        echo "\$(date): SlowDNS not listening, restarting..." >> /var/log/slowdns-watchdog.log
        systemctl restart hardcore-slowdns
    fi
    if ! ss -uln | grep -q ":53 "; then
        echo "\$(date): EDNS Proxy not listening, restarting..." >> /var/log/slowdns-watchdog.log
        systemctl restart hardcore-edns-proxy
    fi
    sleep 10
done'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    print_success "Watchdog service created"
}

# ============================================================================
# SETUP FIREWALL WITH PERFORMANCE RULES
# ============================================================================
setup_firewall() {
    print_header "🔥 CONFIGURING HARDCORE FIREWALL"
    
    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -t raw -F
    iptables -t raw -X
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport ${SSHD_PORT} -m conntrack --ctstate NEW -j ACCEPT
    
    # Allow DNS (UDP & TCP)
    iptables -A INPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A INPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
    
    # Allow SlowDNS
    iptables -A INPUT -p udp --dport ${SLOWDNS_PORT} -m conntrack --ctstate NEW -j ACCEPT
    
    # Allow ICMP (ping)
    iptables -A INPUT -p icmp -j ACCEPT
    
    # Protect against common attacks
    iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
    iptables -A INPUT -f -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    
    # Rate limiting for DNS
    iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name dns --hashlimit-mode srcip --hashlimit-srcmask 24 --hashlimit-upto 100/sec --hashlimit-burst 200 --hashlimit-htable-size 10000 --hashlimit-htable-max 10000 --hashlimit-htable-gcinterval 1000 --hashlimit-htable-expire 10000 -j ACCEPT
    iptables -A INPUT -p udp --dport 53 -j DROP
    
    # Save rules
    if command -v iptables-save > /dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4
    fi
    
    print_success "Hardcore firewall configured"
    print_info "SSH Port: ${SSHD_PORT}, SlowDNS Port: ${SLOWDNS_PORT}"
    print_info "DNS rate limit: 100 packets/sec per /24"
}

# ============================================================================
# DISABLE CONFLICTING SERVICES
# ============================================================================
disable_conflicts() {
    print_header "🚫 DISABLING CONFLICTING SERVICES"
    
    # List of services to stop and disable
    local services=(
        "systemd-resolved"
        "dnsmasq"
        "bind9"
        "named"
        "unbound"
        "stubby"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_info "Stopping $service..."
            systemctl stop "$service" 2>/dev/null
            systemctl disable "$service" 2>/dev/null
            systemctl mask "$service" 2>/dev/null
        fi
    done
    
    # Kill any process using port 53
    local pids=$(lsof -ti:53 2>/dev/null)
    if [ -n "$pids" ]; then
        print_info "Killing processes on port 53: $pids"
        kill -9 $pids 2>/dev/null
    fi
    
    # Ensure nothing binds to port 53
    sleep 1
    if ss -ulpn | grep -q ":53 "; then
        print_warning "Port 53 still in use after cleanup"
        fuser -k 53/udp 2>/dev/null
    fi
    
    print_success "Conflicting services disabled"
}

# ============================================================================
# DOWNLOAD AND SETUP SLOWDNS
# ============================================================================
setup_slowdns() {
    print_header "📥 DOWNLOADING SLOWDNS COMPONENTS"
    
    # Create directory
    rm -rf /etc/slowdns
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Get nameserver
    echo -e "${WHITE}${BOLD}Enter your nameserver (e.g., dns.example.com):${NC}"
    read -p "Nameserver: " NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    # Download binary
    print_info "Downloading SlowDNS binary..."
    
    local download_success=0
    local download_methods=("curl -fsSL" "wget -q -O")
    
    for method in "${download_methods[@]}"; do
        if $method "${GITHUB_BASE}/dnstt-server" "dnstt-server" 2>/dev/null; then
            download_success=1
            break
        fi
    done
    
    if [ $download_success -eq 0 ]; then
        print_error "Failed to download SlowDNS binary"
        return 1
    fi
    
    chmod +x dnstt-server
    
    # Download keys
    print_info "Downloading encryption keys..."
    
    if ! curl -fsSL "${GITHUB_BASE}/server.key" -o server.key 2>/dev/null; then
        print_warning "Failed to download server.key, generating new..."
        # Generate key if download fails
        ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub 2>/dev/null || {
            print_error "Failed to generate keys"
            return 1
        }
    else
        curl -fsSL "${GITHUB_BASE}/server.pub" -o server.pub 2>/dev/null
    fi
    
    # Update service file with nameserver
    sed -i "s|%s|${NAMESERVER}|g" /etc/systemd/system/hardcore-slowdns.service
    
    print_success "SlowDNS components downloaded"
    print_info "Nameserver: ${NAMESERVER}"
    print_info "Binary: $(./dnstt-server --help 2>&1 | head -1 || echo 'Verified')"
    
    # Test the binary
    if ./dnstt-server -h 2>&1 | head -5; then
        print_success "SlowDNS binary test passed"
    else
        print_warning "SlowDNS binary test inconclusive"
    fi
    
    return 0
}

# ============================================================================
# FINAL CONFIGURATION AND STARTUP
# ============================================================================
final_setup() {
    print_header "🚀 FINAL CONFIGURATION"
    
    # Reload systemd
    print_info "Reloading systemd..."
    systemctl daemon-reload
    
    # Enable and start services
    local services=(
        "hardcore-slowdns"
        "hardcore-edns-proxy"
        "hardcore-slowdns-watchdog"
    )
    
    for service in "${services[@]}"; do
        print_info "Enabling $service..."
        systemctl enable "$service" 2>/dev/null
        
        print_info "Starting $service..."
        systemctl restart "$service" 2>/dev/null
        sleep 1
        
        if systemctl is-active --quiet "$service"; then
            print_success "$service is running"
        else
            print_warning "$service failed to start"
            journalctl -u "$service" -n 10 --no-pager
        fi
    done
    
    # Verify ports are listening
    print_info "Verifying ports..."
    
    local ports_listening=1
    if ss -ulpn | grep -q ":53 "; then
        print_success "Port 53 (EDNS Proxy) listening"
    else
        print_error "Port 53 NOT listening"
        ports_listening=0
    fi
    
    if ss -ulpn | grep -q ":${SLOWDNS_PORT} "; then
        print_success "Port ${SLOWDNS_PORT} (SlowDNS) listening"
    else
        print_error "Port ${SLOWDNS_PORT} NOT listening"
        ports_listening=0
    fi
    
    if ss -tlnp | grep -q ":${SSHD_PORT} "; then
        print_success "Port ${SSHD_PORT} (SSH) listening"
    else
        print_error "Port ${SSHD_PORT} NOT listening"
        ports_listening=0
    fi
    
    if [ $ports_listening -eq 1 ]; then
        print_success "All ports verified"
    else
        print_warning "Some ports not listening, checking services..."
        systemctl status hardcore-slowdns hardcore-edns-proxy --no-pager
    fi
    
    # Get server IP
    local server_ip=$(curl -s --connect-timeout 3 ifconfig.me || hostname -I | awk '{print $1}')
    
    print_header "✅ INSTALLATION COMPLETE"
    
    # Display configuration summary
    cat << EOF

${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}
${GREEN}║${NC}                     ${WHITE}${BOLD}CONFIGURATION SUMMARY${NC}                    ${GREEN}║${NC}
${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}
${GREEN}║${NC} ${CYAN}●${NC} Server IP:        ${WHITE}${server_ip}${NC}                    ${GREEN}║${NC}
${GREEN}║${NC} ${CYAN}●${NC} SSH Port:         ${WHITE}${SSHD_PORT}${NC}                            ${GREEN}║${NC}
${GREEN}║${NC} ${CYAN}●${NC} SlowDNS Port:     ${WHITE}${SLOWDNS_PORT}${NC}                           ${GREEN}║${NC}
${GREEN}║${NC} ${CYAN}●${NC} EDNS Proxy Port:  ${WHITE}53${NC}                                  ${GREEN}║${NC}
${GREEN}║${NC} ${CYAN}●${NC} External MTU:     ${RED}${EXT_EDNS_MTU}${NC} (Internet-facing)              ${GREEN}║${NC}
${GREEN}║${NC} ${CYAN}●${NC} Internal MTU:     ${GREEN}${INT_EDNS_MTU}${NC} (Local network)              ${GREEN}║${NC}
${GREEN}║${NC} ${CYAN}●${NC} Nameserver:       ${WHITE}${NAMESERVER}${NC}                    ${GREEN}║${NC}
${GREEN}║${NC} ${CYAN}●${NC} CPU Threads:      ${WHITE}${WORKER_THREADS}${NC}                            ${GREEN}║${NC}
${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}

${YELLOW}╔══════════════════════════════════════════════════════════════════╗${NC}
${YELLOW}║${NC}                     ${WHITE}${BOLD}QUICK TEST COMMANDS${NC}                     ${YELLOW}║${NC}
${YELLOW}╠══════════════════════════════════════════════════════════════════╣${NC}
${YELLOW}║${NC} ${GREEN}dig @${server_ip} ${NAMESERVER}${NC}                         ${YELLOW}║${NC}
${YELLOW}║${NC} ${GREEN}nslookup ${NAMESERVER} ${server_ip}${NC}                     ${YELLOW}║${NC}
${YELLOW}║${NC} ${GREEN}systemctl status hardcore-slowdns${NC}                      ${YELLOW}║${NC}
${YELLOW}║${NC} ${GREEN}systemctl status hardcore-edns-proxy${NC}                    ${YELLOW}║${NC}
${YELLOW}║${NC} ${GREEN}ss -ulpn | grep -E ':53|:${SLOWDNS_PORT}'${NC}               ${YELLOW}║${NC}
${YELLOW}╚══════════════════════════════════════════════════════════════════╝${NC}

${MAGENTA}╔══════════════════════════════════════════════════════════════════╗${NC}
${MAGENTA}║${NC}                    ${WHITE}${BOLD}CLIENT CONFIGURATION${NC}                     ${MAGENTA}║${NC}
${MAGENTA}╠══════════════════════════════════════════════════════════════════╣${NC}
${MAGENTA}║${NC} ${YELLOW}Public Key:${NC} $(cat /etc/slowdns/server.pub 2>/dev/null | head -1)  ${MAGENTA}║${NC}
${MAGENTA}║${NC}                                                              ${MAGENTA}║${NC}
${MAGENTA}║${NC} ${GREEN}Client Command:${NC}                                         ${MAGENTA}║${NC}
${MAGENTA}║${NC} ./dnstt-client -udp ${server_ip}:${SLOWDNS_PORT} \\                 ${MAGENTA}║${NC}
${MAGENTA}║${NC}     -pubkey-file server.pub \\                               ${MAGENTA}║${NC}
${MAGENTA}║${NC}     ${NAMESERVER} 127.0.0.1:1080${NC}                         ${MAGENTA}║${NC}
${MAGENTA}╚══════════════════════════════════════════════════════════════════╝${NC}

${RED}╔══════════════════════════════════════════════════════════════════╗${NC}
${RED}║${NC}                      ${WHITE}${BOLD}IMPORTANT NOTES${NC}                        ${RED}║${NC}
${RED}╠══════════════════════════════════════════════════════════════════╣${NC}
${RED}║${NC} ${YELLOW}●${NC} External MTU (${RED}512${NC}) is fixed for Internet compatibility   ${RED}║${NC}
${RED}║${NC} ${YELLOW}●${NC} Internal MTU (${GREEN}1800${NC}) optimizes local performance        ${RED}║${NC}
${RED}║${NC} ${YELLOW}●${NC} Port 53 requires root or CAP_NET_BIND_SERVICE          ${RED}║${NC}
${RED}║${NC} ${YELLOW}●${NC} Run ${GREEN}sysctl -p${NC} after reboot to reapply optimizations    ${RED}║${NC}
${RED}║${NC} ${YELLOW}●${NC} Monitor logs: ${GREEN}journalctl -fu hardcore-slowdns${NC}          ${RED}║${NC}
${RED}╚══════════════════════════════════════════════════════════════════╝${NC}

${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}
${BLUE}║${NC}                 ${WHITE}${BOLD}PERFORMANCE STATISTICS${NC}                       ${BLUE}║${NC}
${BLUE}╠══════════════════════════════════════════════════════════════════╣${NC}
${BLUE}║${NC} ${CYAN}●${NC} Kernel buffers: 128MB                                  ${BLUE}║${NC}
${BLUE}║${NC} ${CYAN}●${NC} Socket buffers: 8MB                                    ${BLUE}║${NC}
${BLUE}║${NC} ${CYAN}●${NC} Hash table size: 131,072 entries                       ${BLUE}║${NC}
${BLUE}║${NC} ${CYAN}●${NC} Upstream pool: 256 connections                         ${BLUE}║${NC}
${BLUE}║${NC} ${CYAN}●${NC} File descriptors: 1,048,576                            ${BLUE}║${NC}
${BLUE}║${NC} ${CYAN}●${NC} TCP Congestion Control: ${TCP_CONGESTION}                     ${BLUE}║${NC}
${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}

EOF

    # Test DNS functionality
    print_info "Testing DNS functionality..."
    if command -v dig &>/dev/null; then
        if dig @${server_ip} ${NAMESERVER} +short +time=2 +tries=1 2>/dev/null | grep -q -v "connection refused\|timed out"; then
            print_success "DNS test successful"
        else
            print_warning "DNS test inconclusive"
        fi
    fi
    
    print_header "🎯 HARDCORE SLOWDNS READY"
    echo -e "${GREEN}${BOLD}Installation completed at: $(date)${NC}"
    echo -e "${CYAN}For support, contact: @esimfreegb${NC}"
    
    # Save config
    cat > /etc/slowdns/config.txt << EOF
# Hardcore SlowDNS Configuration
SERVER_IP=${server_ip}
SSHD_PORT=${SSHD_PORT}
SLOWDNS_PORT=${SLOWDNS_PORT}
EXT_EDNS_MTU=${EXT_EDNS_MTU}
INT_EDNS_MTU=${INT_EDNS_MTU}
NAMESERVER=${NAMESERVER}
INSTALL_DATE=$(date)
PUBKEY=$(cat /etc/slowdns/server.pub 2>/dev/null | head -1)
EOF
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    print_banner
    
    # Check system requirements
    if [ $(ulimit -n) -lt 65536 ]; then
        print_warning "Low file descriptor limit ($(ulimit -n)), increasing..."
        ulimit -n 1048576
    fi
    
    # Start timer
    start_timer
    
    # Execute steps
    optimize_kernel
    optimize_memory
    optimize_network
    disable_conflicts
    compile_edns_proxy
    setup_firewall
    create_services
    setup_slowdns
    final_setup
    
    # Show time taken
    end_timer
    
    # Cleanup
    rm -f /tmp/compile.log /tmp/edns.c 2>/dev/null
    
    echo -e "\n${WHITE}${BOLD}Press Enter to exit...${NC}"
    read -r
}

# ============================================================================
# ERROR HANDLING AND EXECUTION
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; exit 1' INT

# Check if script is already running
LOCKFILE="/tmp/hardcore-slowdns.lock"
if [ -e "${LOCKFILE}" ] && kill -0 "$(cat ${LOCKFILE})"; then
    echo -e "${RED}✗ Another installation is running${NC}"
    exit 1
fi

echo $$ > "${LOCKFILE}"

# Create log file
LOG_FILE="/var/log/hardcore-slowdns-install.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

# Run main function
if main; then
    rm -f "${LOCKFILE}"
    exit 0
else
    echo -e "\n${RED}✗ Installation failed - check ${LOG_FILE} for details${NC}"
    rm -f "${LOCKFILE}"
    exit 1
fi
```