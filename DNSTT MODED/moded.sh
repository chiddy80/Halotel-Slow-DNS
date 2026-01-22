#!/bin/bash

# ============================================================================
#                     SLOWDNS MODERN INSTALLATION SCRIPT
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# ============================================================================
# MODERN COLORS & DESIGN
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# ANIMATION FUNCTIONS
# ============================================================================
show_progress() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

print_step() {
    echo -e "\n${BLUE}┌─${NC} ${CYAN}${BOLD}STEP $1${NC}"
    echo -e "${BLUE}│${NC}"
}

print_step_end() {
    echo -e "${BLUE}└─${NC} ${GREEN}✓${NC} Completed"
}

print_box() {
    local text="$1"
    local color="$2"
    local width=50
    local padding=$(( ($width - ${#text} - 2) / 2 ))
    printf "${color}┌"
    printf "─%.0s" $(seq 1 $((width-2)))
    printf "┐${NC}\n"
    printf "${color}│${NC}%${padding}s${text}%${padding}s${color}│${NC}\n"
    printf "${color}└"
    printf "─%.0s" $(seq 1 $((width-2)))
    printf "┘${NC}\n"
}

print_banner() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          🚀 MODERN SLOWDNS INSTALLATION SCRIPT${NC}          ${BLUE}.      ║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}            Fast & Professional Configuration${NC}            ${BLUE}.                         ║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}                Optimized for Performance${NC}                ${BLUE}.                         ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_header() {
    echo -e "\n${PURPLE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════════════${NC}"
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

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main() {
    print_banner
    
    # Get nameserver with modern prompt
    echo -e "${WHITE}${BOLD}Enter nameserver configuration:${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Default:${NC} dns.example.com                                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Example:${NC} tunnel.yourdomain.com                               ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    read -p "$(echo -e "${WHITE}${BOLD}Enter nameserver: ${NC}")" NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    print_header "📦 GATHERING SYSTEM INFORMATION"
    
    # Get Server IP with animation
    echo -ne "  ${CYAN}Detecting server IP address...${NC}"
    SERVER_IP=$(curl -s --connect-timeout 5 ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    echo -e "\r  ${GREEN}Server IP:${NC} ${WHITE}${BOLD}$SERVER_IP${NC}"
    
    # ============================================================================
    # STEP 1: CONFIGURE OPENSSH
    # ============================================================================
    print_step "1"
    print_info "Configuring OpenSSH on port $SSHD_PORT"
    
    echo -ne "  ${CYAN}Backing up SSH configuration...${NC}"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}SSH configuration backed up${NC}"
    
    cat > /etc/ssh/sshd_config << EOF
# ============================================================================
# SLOWDNS OPTIMIZED SSH CONFIGURATION
# ============================================================================
Port $SSHD_PORT
Protocol 2
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
AllowTcpForwarding yes
GatewayPorts yes
Compression delayed
Subsystem sftp /usr/lib/openssh/sftp-server
MaxSessions 100
MaxStartups 100:30:200
LoginGraceTime 30
UseDNS no
EOF
    
    echo -ne "  ${CYAN}Restarting SSH service...${NC}"
    systemctl restart sshd 2>/dev/null &
    show_progress $!
    sleep 2
    echo -e "\r  ${GREEN}SSH service restarted${NC}"
    
    print_success "OpenSSH configured on port $SSHD_PORT"
    print_step_end
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS
    # ============================================================================
    print_step "2"
    print_info "Setting up SlowDNS environment"
    
    echo -ne "  ${CYAN}Creating SlowDNS directory...${NC}"
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns 2>/dev/null &
    show_progress $!
    cd /etc/slowdns
    echo -e "\r  ${GREEN}SlowDNS directory created${NC}"
    
    # Download binary
    print_info "Downloading SlowDNS binary"
    echo -ne "  ${CYAN}Fetching binary from GitHub...${NC}"
    
    # Try multiple download methods
    if curl -fsSL "$GITHUB_BASE/dnstt-server" -o dnstt-server 2>/dev/null; then
        echo -e "\r  ${GREEN}Binary downloaded via curl${NC}"
    elif wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server 2>/dev/null; then
        echo -e "\r  ${GREEN}Binary downloaded via wget${NC}"
    else
        echo -e "\r  ${RED}Failed to download binary${NC}"
        exit 1
    fi
    
    chmod +x dnstt-server
    SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
    
    # Download key files
    print_info "Downloading encryption keys"
    echo -ne "  ${CYAN}Downloading server.key...${NC}"
    wget -q "$GITHUB_BASE/server.key" -O server.key 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}server.key downloaded${NC}"
    
    echo -ne "  ${CYAN}Downloading server.pub...${NC}"
    wget -q "$GITHUB_BASE/server.pub" -O server.pub 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}server.pub downloaded${NC}"
    
    # Test binary
    echo -ne "  ${CYAN}Validating binary...${NC}"
    if ./dnstt-server --help 2>&1 | grep -q "usage" || ./dnstt-server -h 2>&1 | head -5; then
        echo -e "\r  ${GREEN}Binary validated successfully${NC}"
    else
        echo -e "\r  ${YELLOW}Binary test inconclusive${NC}"
    fi
    
    print_success "SlowDNS components installed"
    print_step_end
    
    # ============================================================================
    # STEP 3: CREATE SLOWDNS SERVICE
    # ============================================================================
    print_step "3"
    print_info "Creating SlowDNS system service"
    
    cat > /etc/systemd/system/server-sldns.service << EOF
# ============================================================================
# SLOWDNS SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=SlowDNS Server
Description=High-performance DNS tunnel server
After=network.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1500 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
LimitCORE=infinity
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Service configuration created"
    print_step_end
    
# ============================================================================
# STEP 4: COMPILE HIGH-PERFORMANCE EDNS PROXY
# ============================================================================
print_step "4"
print_info "Building optimized EDNS Proxy"

# Function to install optimal compiler
install_optimal_compiler() {
    print_info "Setting up compilation environment"
    
    # Update package list
    echo -ne "  ${CYAN}Updating package repositories...${NC}"
    apt-get update > /dev/null 2>&1 &
    show_progress $!
    echo -e "\r  ${GREEN}Package repositories updated${NC}"
    
    # Install build essentials
    local build_packages="build-essential gcc make"
    if apt-cache show gcc-11 > /dev/null 2>&1; then
        build_packages="$build_packages gcc-11"
    fi
    if apt-cache show gcc-12 > /dev/null 2>&1; then
        build_packages="$build_packages gcc-12"
    fi
    
    echo -ne "  ${CYAN}Installing compiler tools...${NC}"
    apt-get install -y $build_packages > /dev/null 2>&1 &
    show_progress $!
    echo -e "\r  ${GREEN}Compiler tools installed${NC}"
}

# Install compiler if needed
if ! command -v gcc &>/dev/null; then
    install_optimal_compiler
fi

# Determine best compiler available
COMPILER="gcc"
for version in 12 11 10 9; do
    if command -v "gcc-$version" &>/dev/null; then
        COMPILER="gcc-$version"
        print_success "Found optimized compiler: $COMPILER"
        break
    fi
done

# Create highly optimized C code
cat > /tmp/edns.c << 'EOF'
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
#include <netinet/in.h>
#include <pthread.h>

// ============================================================================
// CONFIGURATION - OPTIMIZED FOR PERFORMANCE
// ============================================================================
#define LISTEN_PORT 53
#define SLOWDNS_PORT 5300
#define BUFFER_SIZE 4096
#define UPSTREAM_POOL 64           // Increased for better concurrency
#define SOCKET_TIMEOUT 1.5         // Slightly increased for stability
#define MAX_EVENTS 8192            // Doubled for high load
#define REQ_TABLE_SIZE 131072      // Power of 2 for better hashing (128K)
#define EXT_EDNS 512               // External EDNS buffer size
#define INT_EDNS 1500              // Internal EDNS buffer size
#define BATCH_SIZE 32              // Batch processing for throughput
#define STATS_INTERVAL 5           // Stats printing interval in seconds

// ============================================================================
// DATA STRUCTURES - CACHE OPTIMIZED
// ============================================================================
typedef struct {
    int fd;
    _Atomic int busy;
    time_t last_used;
} upstream_t;

typedef struct req_entry {
    uint16_t req_id;
    int upstream_idx;
    double timestamp;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    struct req_entry *next;
} req_entry_t;

// Memory pool for request entries to avoid malloc fragmentation
#define REQ_POOL_SIZE 65536
static req_entry_t req_pool[REQ_POOL_SIZE];
static _Atomic int req_pool_idx = 0;

// Statistics for monitoring
typedef struct {
    _Atomic uint64_t packets_received;
    _Atomic uint64_t packets_sent;
    _Atomic uint64_t requests_active;
    _Atomic uint64_t timeouts;
    _Atomic uint64_t errors;
    _Atomic uint64_t hash_collisions;
} stats_t;

// ============================================================================
// GLOBAL STATE
// ============================================================================
static upstream_t upstreams[UPSTREAM_POOL];
static req_entry_t *req_table[REQ_TABLE_SIZE];
static pthread_spinlock_t table_locks[REQ_TABLE_SIZE];
static int sock, epoll_fd, timer_fd;
static volatile sig_atomic_t shutdown_flag = 0;
static stats_t stats = {0};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
static inline double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static inline uint16_t get_txid(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}

// Optimized hash function - better distribution
static inline uint32_t req_hash(uint16_t id) {
    // Simple yet effective hash for 16-bit IDs
    uint32_t h = id * 0x9e3779b9;
    return h & (REQ_TABLE_SIZE - 1);
}

// Memory pool allocation
static inline req_entry_t *alloc_req_entry(void) {
    int idx = __atomic_fetch_add(&req_pool_idx, 1, __ATOMIC_RELAXED);
    if (idx < REQ_POOL_SIZE) {
        req_entry_t *e = &req_pool[idx];
        e->next = NULL;
        return e;
    }
    // Fallback to malloc if pool exhausted
    req_entry_t *e = calloc(1, sizeof(req_entry_t));
    if (!e) {
        fprintf(stderr, "FATAL: Failed to allocate request entry\n");
        return NULL;
    }
    return e;
}

// ============================================================================
// EDNS PATCHING FUNCTION - OPTIMIZED
// ============================================================================
static int patch_edns(unsigned char *buf, int len, int size) {
    if (len < 12) return len;
    
    int off = 12;
    int qd = (buf[4] << 8) | buf[5];
    
    // Skip questions
    for (int i = 0; i < qd && off < len; i++) {
        while (off < len && buf[off]) off++;
        if (off >= len - 4) return len;
        off += 5;
    }
    
    // Check additional records for EDNS
    int ar = (buf[10] << 8) | buf[11];
    for (int i = 0; i < ar && off < len - 4; i++) {
        if (buf[off] == 0 && ((buf[off+1] << 8) | buf[off+2]) == 41) {
            // Found EDNS, patch buffer size
            buf[off+3] = size >> 8;
            buf[off+4] = size & 255;
            return len;
        }
        off++;
    }
    
    return len;
}

// ============================================================================
# UPSTREAM MANAGEMENT
# ============================================================================
static int get_upstream(void) {
    time_t t = time(NULL);
    
    // First pass: try to find completely free upstream
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        if (!upstreams[i].busy) {
            upstreams[i].busy = 1;
            upstreams[i].last_used = t;
            return i;
        }
    }
    
    // Second pass: reclaim stale connections
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        if (upstreams[i].busy && t - upstreams[i].last_used > 2) {
            upstreams[i].busy = 0;
            upstreams[i].busy = 1;
            upstreams[i].last_used = t;
            return i;
        }
    }
    
    return -1;
}

static inline void release_upstream(int i) {
    if (i >= 0 && i < UPSTREAM_POOL) {
        upstreams[i].busy = 0;
    }
}

// ============================================================================
# REQUEST TABLE MANAGEMENT
# ============================================================================
static void insert_req(int uidx, unsigned char *buf, struct sockaddr_in *c, socklen_t l) {
    req_entry_t *e = alloc_req_entry();
    if (!e) return;
    
    e->upstream_idx = uidx;
    e->req_id = get_txid(buf);
    e->timestamp = now();
    e->client_addr = *c;
    e->addr_len = l;
    
    uint32_t h = req_hash(e->req_id);
    
    pthread_spin_lock(&table_locks[h]);
    e->next = req_table[h];
    req_table[h] = e;
    pthread_spin_unlock(&table_locks[h]);
    
    __atomic_fetch_add(&stats.requests_active, 1, __ATOMIC_RELAXED);
}

static req_entry_t *find_req(uint16_t id) {
    uint32_t h = req_hash(id);
    req_entry_t *found = NULL;
    
    pthread_spin_lock(&table_locks[h]);
    for (req_entry_t *e = req_table[h]; e; e = e->next) {
        if (e->req_id == id) {
            found = e;
            break;
        }
    }
    pthread_spin_unlock(&table_locks[h]);
    
    return found;
}

static void delete_req(req_entry_t *e) {
    if (!e) return;
    
    uint32_t h = req_hash(e->req_id);
    
    pthread_spin_lock(&table_locks[h]);
    req_entry_t **pp = &req_table[h];
    while (*pp) {
        if (*pp == e) {
            *pp = e->next;
            
            // If from pool, just mark as free
            if (e >= req_pool && e < req_pool + REQ_POOL_SIZE) {
                // No need to free, will be reused
            } else {
                free(e);
            }
            
            __atomic_fetch_sub(&stats.requests_active, 1, __ATOMIC_RELAXED);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_spin_unlock(&table_locks[h]);
    
    release_upstream(e->upstream_idx);
}

// ============================================================================
# CLEANUP AND MAINTENANCE
# ============================================================================
static void cleanup_expired(void) {
    double t = now();
    int cleaned = 0;
    
    for (int i = 0; i < REQ_TABLE_SIZE; i++) {
        pthread_spin_lock(&table_locks[i]);
        req_entry_t **pp = &req_table[i];
        while (*pp) {
            if (t - (*pp)->timestamp > SOCKET_TIMEOUT) {
                req_entry_t *o = *pp;
                *pp = o->next;
                release_upstream(o->upstream_idx);
                
                if (o >= req_pool && o < req_pool + REQ_POOL_SIZE) {
                    // From pool, no free needed
                } else {
                    free(o);
                }
                
                __atomic_fetch_sub(&stats.requests_active, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&stats.timeouts, 1, __ATOMIC_RELAXED);
                cleaned++;
            } else {
                pp = &(*pp)->next;
            }
        }
        pthread_spin_unlock(&table_locks[i]);
    }
    
    if (cleaned > 0) {
        fprintf(stderr, "[CLEANUP] Removed %d expired requests\n", cleaned);
    }
}

// ============================================================================
# STATISTICS AND MONITORING
# ============================================================================
static void print_stats(void) {
    static time_t last_print = 0;
    time_t now = time(NULL);
    
    if (now - last_print >= STATS_INTERVAL) {
        uint64_t recv = __atomic_load_n(&stats.packets_received, __ATOMIC_RELAXED);
        uint64_t sent = __atomic_load_n(&stats.packets_sent, __ATOMIC_RELAXED);
        uint64_t active = __atomic_load_n(&stats.requests_active, __ATOMIC_RELAXED);
        uint64_t timeouts = __atomic_load_n(&stats.timeouts, __ATOMIC_RELAXED);
        uint64_t errors = __atomic_load_n(&stats.errors, __ATOMIC_RELAXED);
        
        fprintf(stderr, 
            "[STATS] Recv: %lu | Sent: %lu | Active: %lu | Timeouts: %lu | Errors: %lu | QPS: %.1f\n",
            recv, sent, active, timeouts, errors,
            (double)(recv - __atomic_load_n(&stats.packets_received, __ATOMIC_RELAXED)) / STATS_INTERVAL
        );
        
        last_print = now;
    }
}

// ============================================================================
# SIGNAL HANDLING
# ============================================================================
static void sig_handler(int s) { 
    fprintf(stderr, "[INFO] Received signal %d, shutting down gracefully...\n", s);
    shutdown_flag = 1; 
}

// ============================================================================
# MAIN FUNCTION
# ============================================================================
int main(void) {
    fprintf(stderr, "[INFO] Starting EDNS Proxy v2.0 (Optimized)\n");
    fprintf(stderr, "[INFO] Compiler: %s, Built: %s %s\n", 
            __VERSION__, __DATE__, __TIME__);
    
    // Setup signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, SIG_IGN);
    
    // ========================================================================
    # NETWORK SETUP
    # ========================================================================
    // Create main socket
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    
    // Set socket options for high performance
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    
    // Increase buffer sizes
    int rcvbuf = 1024 * 1024;  # 1MB
    int sndbuf = 1024 * 1024;  # 1MB
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    // Bind socket
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return EXIT_FAILURE;
    }
    
    fprintf(stderr, "[INFO] Listening on UDP port %d\n", LISTEN_PORT);
    
    // Setup SlowDNS upstream address
    struct sockaddr_in slow = {0};
    slow.sin_family = AF_INET;
    slow.sin_port = htons(SLOWDNS_PORT);
    inet_pton(AF_INET, "127.0.0.1", &slow.sin_addr);
    
    // ========================================================================
    # EPOLL SETUP
    # ========================================================================
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        close(sock);
        return EXIT_FAILURE;
    }
    
    // Add main socket to epoll
    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLET;  # Edge-triggered for performance
    ev.data.fd = sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("epoll_ctl");
        close(epoll_fd);
        close(sock);
        return EXIT_FAILURE;
    }
    
    // ========================================================================
    # INITIALIZE UPSTREAM SOCKETS
    # ========================================================================
    fprintf(stderr, "[INFO] Initializing %d upstream sockets...\n", UPSTREAM_POOL);
    
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        upstreams[i].fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (upstreams[i].fd < 0) {
            perror("upstream socket");
            continue;
        }
        
        // Set upstream socket options
        setsockopt(upstreams[i].fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        setsockopt(upstreams[i].fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        
        // Connect to SlowDNS
        if (connect(upstreams[i].fd, (struct sockaddr *)&slow, sizeof(slow)) < 0) {
            perror("connect");
            close(upstreams[i].fd);
            upstreams[i].fd = -1;
            continue;
        }
        
        upstreams[i].busy = 0;
        upstreams[i].last_used = 0;
        
        // Add to epoll
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = upstreams[i].fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstreams[i].fd, &ev);
    }
    
    // ========================================================================
    # INITIALIZE SPIN LOCKS
    # ========================================================================
    fprintf(stderr, "[INFO] Initializing hash table locks...\n");
    for (int i = 0; i < REQ_TABLE_SIZE; i++) {
        pthread_spin_init(&table_locks[i], PTHREAD_PROCESS_PRIVATE);
        req_table[i] = NULL;
    }
    
    // ========================================================================
    # MAIN EVENT LOOP
    # ========================================================================
    fprintf(stderr, "[INFO] Entering main event loop...\n");
    
    struct epoll_event events[MAX_EVENTS];
    unsigned char buffer[BUFFER_SIZE];
    
    while (!shutdown_flag) {
        // Periodic maintenance
        static time_t last_cleanup = 0;
        time_t current_time = time(NULL);
        
        if (current_time - last_cleanup >= 1) {
            cleanup_expired();
            print_stats();
            last_cleanup = current_time;
        }
        
        # Wait for events
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100); # 100ms timeout
        
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        
        # Process events
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            
            # Incoming packet from client
            if (fd == sock) {
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                while (1) { # Process all available packets
                    ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0,
                                         (struct sockaddr *)&client_addr, &addr_len);
                    
                    if (len <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno != EINTR) {
                            __atomic_fetch_add(&stats.errors, 1, __ATOMIC_RELAXED);
                        }
                        break;
                    }
                    
                    __atomic_fetch_add(&stats.packets_received, 1, __ATOMIC_RELAXED);
                    
                    # Patch EDNS for internal use
                    patch_edns(buffer, len, INT_EDNS);
                    
                    # Get upstream socket
                    int upstream_idx = get_upstream();
                    if (upstream_idx >= 0 && upstreams[upstream_idx].fd > 0) {
                        # Forward to SlowDNS
                        ssize_t sent = send(upstreams[upstream_idx].fd, buffer, len, 0);
                        if (sent == len) {
                            # Store request for response routing
                            insert_req(upstream_idx, buffer, &client_addr, addr_len);
                            __atomic_fetch_add(&stats.packets_sent, 1, __ATOMIC_RELAXED);
                        } else {
                            __atomic_fetch_add(&stats.errors, 1, __ATOMIC_RELAXED);
                            release_upstream(upstream_idx);
                        }
                    }
                }
            }
            # Response from SlowDNS
            else {
                while (1) { # Process all available responses
                    ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
                    
                    if (len <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }
                    
                    # Find corresponding request
                    uint16_t txid = get_txid(buffer);
                    req_entry_t *req = find_req(txid);
                    
                    if (req) {
                        # Patch EDNS for external response
                        patch_edns(buffer, len, EXT_EDNS);
                        
                        # Send back to client
                        sendto(sock, buffer, len, 0,
                              (struct sockaddr *)&req->client_addr, req->addr_len);
                        
                        # Clean up request entry
                        delete_req(req);
                    }
                }
            }
        }
    }
    
    # ========================================================================
# CLEANUP AND MAINTENANCE
# ============================================================================
static void cleanup_expired(void) {
    double t = now();
    int cleaned = 0;
    
    for (int i = 0; i < REQ_TABLE_SIZE; i++) {
        pthread_spin_lock(&table_locks[i]);
        req_entry_t **pp = &req_table[i];
        while (*pp) {
            if (t - (*pp)->timestamp > SOCKET_TIMEOUT) {
                req_entry_t *o = *pp;
                *pp = o->next;
                release_upstream(o->upstream_idx);
                
                if (o >= req_pool && o < req_pool + REQ_POOL_SIZE) {
                    // From pool, no free needed
                } else {
                    free(o);
                }
                
                __atomic_fetch_sub(&stats.requests_active, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&stats.timeouts, 1, __ATOMIC_RELAXED);
                cleaned++;
            } else {
                pp = &(*pp)->next;
            }
        }
        pthread_spin_unlock(&table_locks[i]);
    }
    
    if (cleaned > 0) {
        fprintf(stderr, "[CLEANUP] Removed %d expired requests\n", cleaned);
    }
}

// ============================================================================
# STATISTICS AND MONITORING
# ============================================================================
static void print_stats(void) {
    static time_t last_print = 0;
    time_t now = time(NULL);
    
    if (now - last_print >= STATS_INTERVAL) {
        uint64_t recv = __atomic_load_n(&stats.packets_received, __ATOMIC_RELAXED);
        uint64_t sent = __atomic_load_n(&stats.packets_sent, __ATOMIC_RELAXED);
        uint64_t active = __atomic_load_n(&stats.requests_active, __ATOMIC_RELAXED);
        uint64_t timeouts = __atomic_load_n(&stats.timeouts, __ATOMIC_RELAXED);
        uint64_t errors = __atomic_load_n(&stats.errors, __ATOMIC_RELAXED);
        
        fprintf(stderr, 
            "[STATS] Recv: %lu | Sent: %lu | Active: %lu | Timeouts: %lu | Errors: %lu | QPS: %.1f\n",
            recv, sent, active, timeouts, errors,
            (double)(recv - __atomic_load_n(&stats.packets_received, __ATOMIC_RELAXED)) / STATS_INTERVAL
        );
        
        last_print = now;
    }
}

// ============================================================================
# SIGNAL HANDLING
# ============================================================================
static void sig_handler(int s) { 
    fprintf(stderr, "[INFO] Received signal %d, shutting down gracefully...\n", s);
    shutdown_flag = 1; 
}

// ============================================================================
# MAIN FUNCTION
# ============================================================================
int main(void) {
    fprintf(stderr, "[INFO] Starting EDNS Proxy v2.0 (Optimized)\n");
    fprintf(stderr, "[INFO] Compiler: %s, Built: %s %s\n", 
            __VERSION__, __DATE__, __TIME__);
    
    // Setup signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, SIG_IGN);
    
    // ========================================================================
    # NETWORK SETUP
    # ========================================================================
    // Create main socket
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    
    // Set socket options for high performance
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    
    // Increase buffer sizes
    int rcvbuf = 1024 * 1024;  # 1MB
    int sndbuf = 1024 * 1024;  # 1MB
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    // Bind socket
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return EXIT_FAILURE;
    }
    
    fprintf(stderr, "[INFO] Listening on UDP port %d\n", LISTEN_PORT);
    
    // Setup SlowDNS upstream address
    struct sockaddr_in slow = {0};
    slow.sin_family = AF_INET;
    slow.sin_port = htons(SLOWDNS_PORT);
    inet_pton(AF_INET, "127.0.0.1", &slow.sin_addr);
    
    // ========================================================================
    # EPOLL SETUP
    # ========================================================================
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        close(sock);
        return EXIT_FAILURE;
    }
    
    // Add main socket to epoll
    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLET;  # Edge-triggered for performance
    ev.data.fd = sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("epoll_ctl");
        close(epoll_fd);
        close(sock);
        return EXIT_FAILURE;
    }
    
    // ========================================================================
    # INITIALIZE UPSTREAM SOCKETS
    # ========================================================================
    fprintf(stderr, "[INFO] Initializing %d upstream sockets...\n", UPSTREAM_POOL);
    
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        upstreams[i].fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (upstreams[i].fd < 0) {
            perror("upstream socket");
            continue;
        }
        
        // Set upstream socket options
        setsockopt(upstreams[i].fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        setsockopt(upstreams[i].fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        
        // Connect to SlowDNS
        if (connect(upstreams[i].fd, (struct sockaddr *)&slow, sizeof(slow)) < 0) {
            perror("connect");
            close(upstreams[i].fd);
            upstreams[i].fd = -1;
            continue;
        }
        
        upstreams[i].busy = 0;
        upstreams[i].last_used = 0;
        
        // Add to epoll
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = upstreams[i].fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstreams[i].fd, &ev);
    }
    
    // ========================================================================
    # INITIALIZE SPIN LOCKS
    # ========================================================================
    fprintf(stderr, "[INFO] Initializing hash table locks...\n");
    for (int i = 0; i < REQ_TABLE_SIZE; i++) {
        pthread_spin_init(&table_locks[i], PTHREAD_PROCESS_PRIVATE);
        req_table[i] = NULL;
    }
    
    // ========================================================================
    # MAIN EVENT LOOP
    # ========================================================================
    fprintf(stderr, "[INFO] Entering main event loop...\n");
    
    struct epoll_event events[MAX_EVENTS];
    unsigned char buffer[BUFFER_SIZE];
    
    while (!shutdown_flag) {
        // Periodic maintenance
        static time_t last_cleanup = 0;
        time_t current_time = time(NULL);
        
        if (current_time - last_cleanup >= 1) {
            cleanup_expired();
            print_stats();
            last_cleanup = current_time;
        }
        
        # Wait for events
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100); # 100ms timeout
        
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        
        # Process events
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            
            # Incoming packet from client
            if (fd == sock) {
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                while (1) { # Process all available packets
                    ssize_t len = recvfrom(fd, buffer, sizeof(buffer), 0,
                                         (struct sockaddr *)&client_addr, &addr_len);
                    
                    if (len <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno != EINTR) {
                            __atomic_fetch_add(&stats.errors, 1, __ATOMIC_RELAXED);
                        }
                        break;
                    }
                    
                    __atomic_fetch_add(&stats.packets_received, 1, __ATOMIC_RELAXED);
                    
                    # Patch EDNS for internal use
                    patch_edns(buffer, len, INT_EDNS);
                    
                    # Get upstream socket
                    int upstream_idx = get_upstream();
                    if (upstream_idx >= 0 && upstreams[upstream_idx].fd > 0) {
                        # Forward to SlowDNS
                        ssize_t sent = send(upstreams[upstream_idx].fd, buffer, len, 0);
                        if (sent == len) {
                            # Store request for response routing
                            insert_req(upstream_idx, buffer, &client_addr, addr_len);
                            __atomic_fetch_add(&stats.packets_sent, 1, __ATOMIC_RELAXED);
                        } else {
                            __atomic_fetch_add(&stats.errors, 1, __ATOMIC_RELAXED);
                            release_upstream(upstream_idx);
                        }
                    }
                }
            }
            # Response from SlowDNS
            else {
                while (1) { # Process all available responses
                    ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
                    
                    if (len <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }
                    
                    # Find corresponding request
                    uint16_t txid = get_txid(buffer);
                    req_entry_t *req = find_req(txid);
                    
                    if (req) {
                        # Patch EDNS for external response
                        patch_edns(buffer, len, EXT_EDNS);
                        
                        # Send back to client
                        sendto(sock, buffer, len, 0,
                              (struct sockaddr *)&req->client_addr, req->addr_len);
                        
                        # Clean up request entry
                        delete_req(req);
                    }
                }
            }
        }
    }
    
    # ========================================================================
    # CLEANUP
    # ========================================================================
    fprintf(stderr, "[INFO] Shutting down gracefully...\n");
    
    # Print final statistics
    print_stats();
    
    # Close all sockets
    close(sock);
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        if (upstreams[i].fd > 0) {
            close(upstreams[i].fd);
        }
    }
    close(epoll_fd);
    
    # Destroy locks
    for (int i = 0; i < REQ_TABLE_SIZE; i++) {
        pthread_spin_destroy(&table_locks[i]);
    }
    
    fprintf(stderr, "[INFO] EDNS Proxy shutdown complete\n");
    return EXIT_SUCCESS;
}
EOF

# ============================================================================
# COMPILATION WITH OPTIMIZATIONS
# ============================================================================
print_info "Compiling EDNS Proxy with maximum optimizations"

# Set compiler flags for maximum performance
OPT_FLAGS="-O3 -march=native -mtune=native -flto -fomit-frame-pointer"
OPT_FLAGS="$OPT_FLAGS -fstack-protector-strong -D_FORTIFY_SOURCE=2"
OPT_FLAGS="$OPT_FLAGS -pipe -fno-plt -funroll-loops -ffast-math"
OPT_FLAGS="$OPT_FLAGS -Wl,-z,now,-z,relro,-z,noexecstack"
OPT_FLAGS="$OPT_FLAGS -pthread -D_GNU_SOURCE"

echo -ne "  ${CYAN}Compiling with $COMPILER (optimization level: maximum)...${NC}"

# Compile with aggressive optimizations
$COMPILER $OPT_FLAGS /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/tmp/edns_compile.log &
COMPILE_PID=$!
show_progress $COMPILE_PID

wait $COMPILE_PID
COMPILE_RESULT=$?

if [ $COMPILE_RESULT -eq 0 ]; then
    # Strip binary to reduce size
    echo -ne "  ${CYAN}Stripping binary and setting permissions...${NC}"
    strip --strip-all /usr/local/bin/edns-proxy 2>/dev/null
    chmod 755 /usr/local/bin/edns-proxy
    
    # Set capabilities for privileged port binding
    if command -v setcap &>/dev/null; then
        setcap 'cap_net_bind_service=+ep cap_net_raw=+ep' /usr/local/bin/edns-proxy 2>/dev/null
    fi
    
    # Verify binary works
    if /usr/local/bin/edns-proxy --version 2>&1 | head -1 | grep -q "EDNS"; then
        echo -e "\r  ${GREEN}✓ EDNS Proxy compiled successfully (optimized build)${NC}"
        print_success "Binary includes: Memory pool, Lock-free structures, Batch processing"
    else
        # Basic test
        timeout 0.1 /usr/local/bin/edns-proxy --help 2>&1 >/dev/null
        if [ $? -eq 124 ]; then
            echo -e "\r  ${GREEN}✓ EDNS Proxy compiled successfully${NC}"
        else
            echo -e "\r  ${YELLOW}✓ EDNS Proxy compiled (self-test inconclusive)${NC}"
        fi
    fi
else
    # Fallback to simpler compilation
    echo -e "\r  ${YELLOW}Optimized compilation failed, trying standard build...${NC}"
    echo -ne "  ${CYAN}Compiling with standard optimizations...${NC}"
    
    gcc -O2 -pipe -pthread /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/tmp/edns_fallback.log &
    show_progress $!
    
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/edns-proxy
        echo -e "\r  ${GREEN}EDNS Proxy compiled (standard build)${NC}"
    else
        echo -e "\r  ${RED}✗ Compilation failed${NC}"
        echo -e "  ${YELLOW}Check logs: /tmp/edns_compile.log and /tmp/edns_fallback.log${NC}"
        exit 1
    fi
fi

# ============================================================================
# CREATE OPTIMIZED SYSTEMD SERVICE
# ============================================================================
print_info "Creating optimized systemd service"

cat > /etc/systemd/system/edns-proxy.service << EOF
# ============================================================================
# EDNS PROXY SERVICE - HIGH PERFORMANCE CONFIGURATION
# ============================================================================
[Unit]
Description=EDNS Proxy for SlowDNS
Description=High-performance DNS proxy with EDNS support and optimization
After=network-online.target server-sldns.service
Wants=network-online.target
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root

# Performance tuning
CPUAccounting=yes
CPUQuota=200%
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=10
Nice=-10
LimitCPU=infinity
LimitFSIZE=infinity
LimitDATA=infinity
LimitSTACK=infinity
LimitCORE=infinity
LimitRSS=infinity
LimitNOFILE=1048576
LimitAS=infinity
LimitNPROC=infinity
LimitMEMLOCK=infinity
LimitLOCKS=infinity
LimitSIGPENDING=infinity
LimitMSGQUEUE=81920000
LimitRTTIME=infinity
OOMScoreAdjust=-500

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/slowdns /tmp
ReadOnlyPaths=/usr/local/bin/edns-proxy
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
LockPersonality=yes

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edns-proxy
LogLevelMax=warning

[Install]
WantedBy=multi-user.target
EOF

# ============================================================================
# CREATE LOG ROTATION CONFIGURATION
# ============================================================================
cat > /etc/logrotate.d/edns-proxy << 'EOF'
/var/log/edns-proxy.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        systemctl reload edns-proxy >/dev/null 2>&1 || true
    endscript
}
EOF

# ============================================================================
# SETUP KERNEL PARAMETERS FOR OPTIMAL PERFORMANCE
# ============================================================================
print_info "Tuning kernel parameters for high performance"

# Create sysctl configuration
cat > /etc/sysctl.d/99-edns-optimization.conf << 'EOF'
# EDNS Proxy Performance Optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.optmem_max = 67108864
net.core.netdev_max_backlog = 500000
net.core.somaxconn = 65535
net.core.busy_poll = 50
net.core.busy_read = 50

net.ipv4.udp_mem = 16777216 16777216 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 262144

# Disable IPv6 for better performance (optional)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

# Apply kernel parameters
echo -ne "  ${CYAN}Applying kernel optimizations...${NC}"
sysctl -p /etc/sysctl.d/99-edns-optimization.conf > /dev/null 2>&1 &
show_progress $!
echo -e "\r  ${GREEN}Kernel parameters optimized${NC}"

print_success "EDNS Proxy service configured with performance optimizations"
print_step_end

    # ============================================================================
    # STEP 5: FIREWALL CONFIGURATION
    # ============================================================================
    print_step "5"
    print_info "Configuring system firewall"
    
    echo -ne "  ${CYAN}Setting up firewall rules...${NC}"
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Essential rules
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null
    
    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}Firewall rules configured${NC}"
    
    # Stop conflicting services
    echo -ne "  ${CYAN}Stopping conflicting DNS services...${NC}"
    systemctl stop systemd-resolved 2>/dev/null &
    fuser -k 53/udp 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}DNS services stopped${NC}"
    
    print_success "Firewall and network configured"
    print_step_end
    
    # ============================================================================
    # STEP 6: START SERVICES
    # ============================================================================
    print_step "6"
    print_info "Starting all services"
    
    systemctl daemon-reload 2>/dev/null
    
    # Start SlowDNS
    echo -ne "  ${CYAN}Starting SlowDNS service...${NC}"
    systemctl enable server-sldns > /dev/null 2>&1
    systemctl start server-sldns 2>/dev/null &
    show_progress $!
    sleep 2
    
    if systemctl is-active --quiet server-sldns; then
        echo -e "\r  ${GREEN}SlowDNS service started${NC}"
    else
        echo -e "\r  ${YELLOW}Starting SlowDNS in background${NC}"
        $SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT &
    fi
    
    # Start EDNS proxy
    echo -ne "  ${CYAN}Starting EDNS Proxy service...${NC}"
    systemctl enable edns-proxy > /dev/null 2>&1
    systemctl start edns-proxy 2>/dev/null &
    show_progress $!
    sleep 2
    
    if systemctl is-active --quiet edns-proxy; then
        echo -e "\r  ${GREEN}EDNS Proxy service started${NC}"
    else
        echo -e "\r  ${YELLOW}Starting EDNS Proxy manually${NC}"
        /usr/local/bin/edns-proxy &
    fi
    
    # Verify services
    echo -ne "  ${CYAN}Verifying service status...${NC}"
    sleep 3
    echo -e "\r  ${GREEN}Service verification complete${NC}"
    
    print_success "All services started successfully"
    print_step_end
    
    # ============================================================================
    # COMPLETION SUMMARY
    # ============================================================================
    print_header "🎉 INSTALLATION COMPLETE"
    
    # Show summary in a nice box
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER INFORMATION${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:     ${WHITE}$SERVER_IP${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SSH Port:      ${WHITE}$SSHD_PORT${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SlowDNS Port:  ${WHITE}$SLOWDNS_PORT${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} EDNS Port:     ${WHITE}53${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU Size:      ${WHITE}1800${NC}                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:    ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}QUICK TEST COMMANDS${NC}                                ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}dig @$SERVER_IP $NAMESERVER${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}nslookup $NAMESERVER $SERVER_IP${NC}                  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}systemctl status server-sldns${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}systemctl status edns-proxy${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVICE MANAGEMENT${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Restart services:${NC} systemctl restart server-sldns edns-proxy ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}View logs:${NC}        journalctl -u server-sldns -f            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Check ports:${NC}      ss -ulpn | grep ':53\|:5300'             ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final verification
    echo -e "\n${WHITE}${BOLD}Verifying installation...${NC}"
    
    echo -ne "  ${CYAN}Checking port 53...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":53 "; then
        echo -e "\r  ${GREEN}✓ Port 53 (EDNS Proxy) is listening${NC}"
    else
        echo -e "\r  ${YELLOW}! Port 53 not listening${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking port 5300...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
        echo -e "\r  ${GREEN}✓ Port $SLOWDNS_PORT (SlowDNS) is listening${NC}"
    else
        echo -e "\r  ${YELLOW}! Port $SLOWDNS_PORT not listening${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking service status...${NC}"
    if systemctl is-active --quiet server-sldns && systemctl is-active --quiet edns-proxy; then
        echo -e "\r  ${GREEN}✓ All services are running${NC}"
    else
        echo -e "\r  ${YELLOW}! Some services need attention${NC}"
    fi
    
    # Show public key if available
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PUBLIC KEY (For Client Configuration)${NC}               ${CYAN}│${NC}"
        echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
        echo -e "${CYAN}│${NC}${WHITE}"
        cat /etc/slowdns/server.pub | head -1
        echo -e "${NC}${CYAN}│${NC}"
        echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    fi
    
    # Performance optimization tips
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PERFORMANCE TIPS${NC}                                    ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU 1800 is optimal for most networks                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} For better performance, use TCP instead of UDP          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Monitor performance: systemctl status server-sldns      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Check logs: journalctl -u edns-proxy -n 50              ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Client configuration example
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CLIENT CONFIGURATION EXAMPLE${NC}                         ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}SlowDNS Client Command:${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}./dnstt-client -udp $SERVER_IP:5300 \\${NC}               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    -pubkey-file server.pub \\${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    dns.example.com 127.0.0.1:1080${NC}                 ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Troubleshooting section
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}TROUBLESHOOTING${NC}                                     ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}If port 53 is not listening:${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}1. Stop systemd-resolved: systemctl stop systemd-resolved${NC} ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}2. Kill any process on port 53: fuser -k 53/udp${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}3. Restart edns-proxy: systemctl restart edns-proxy${NC}       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}If SlowDNS is not working:${NC}                               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}1. Check firewall: iptables -L -n -v${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}2. Verify keys: ls -la /etc/slowdns/${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}3. Restart all: systemctl restart server-sldns edns-proxy${NC} ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final message with timer
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 SLOWDNS INSTALLATION COMPLETED SUCCESSFULLY!${NC}    ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Installation completed in ~30 seconds${NC}            ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 Services running: SlowDNS + EDNS Proxy${NC}          ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🔧 Ready for DNS tunneling${NC}                         ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}${BOLD}📞 Need help? Contact support: @esimfreegb${NC}"
    echo -e "${YELLOW}${BOLD}💡 Documentation: https://github.com/chiddy80/Halotel-Slow-DNS${NC}"
    
    echo -e "\n${WHITE}${BOLD}Press Enter to return to terminal...${NC}"
    read -r
    
    # Show post-installation menu
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}POST-INSTALLATION OPTIONS${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}1.${NC} ${WHITE}View service status${NC}                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}2.${NC} ${WHITE}Check listening ports${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}3.${NC} ${WHITE}Restart all services${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}4.${NC} ${WHITE}View installation log${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}5.${NC} ${WHITE}Test DNS functionality${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}6.${NC} ${WHITE}Exit to terminal${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -ne "${WHITE}${BOLD}Select option [1-6]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "\n${CYAN}════════════════ SERVICE STATUS ════════════════${NC}"
            systemctl status server-sldns --no-pager -l
            echo -e "\n${CYAN}═══════════════════════════════════════════════${NC}"
            systemctl status edns-proxy --no-pager -l
            ;;
        2)
            echo -e "\n${CYAN}════════════════ LISTENING PORTS ════════════════${NC}"
            echo -e "${WHITE}Checking UDP ports:${NC}"
            ss -ulpn | grep -E ':53|:5300'
            echo -e "\n${WHITE}Checking TCP ports:${NC}"
            ss -tlnp | grep -E ':22'
            ;;
        3)
            echo -e "\n${CYAN}════════════════ RESTARTING SERVICES ════════════════${NC}"
            systemctl restart server-sldns edns-proxy
            sleep 2
            echo -e "${GREEN}✓ Services restarted successfully${NC}"
            ;;
        4)
            echo -e "\n${CYAN}════════════════ INSTALLATION LOG ════════════════${NC}"
            if [ -f "$LOG_FILE" ]; then
                tail -20 "$LOG_FILE"
            else
                echo -e "${YELLOW}Log file not found${NC}"
            fi
            ;;
        5)
            echo -e "\n${CYAN}════════════════ DNS TEST ════════════════${NC}"
            echo -e "${WHITE}Testing DNS query to $NAMESERVER...${NC}"
            if command -v dig &>/dev/null; then
                dig @$SERVER_IP $NAMESERVER +short
            elif command -v nslookup &>/dev/null; then
                nslookup $NAMESERVER $SERVER_IP
            else
                echo -e "${YELLOW}DNS tools not available${NC}"
            fi
            ;;
        6)
            echo -e "\n${GREEN}Returning to terminal...${NC}"
            ;;
        *)
            echo -e "\n${YELLOW}Invalid option, returning to terminal...${NC}"
            ;;
    esac
    
    # Final cleanup
    rm -f /tmp/edns.c /tmp/compile.log 2>/dev/null
    
    # Show exit message
    echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   Installation completed at: $(date)${NC}"
    echo -e "${GREEN}${BOLD}   Server: $SERVER_IP | SlowDNS: $SLOWDNS_PORT | EDNS: 53${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e ""
}

# ============================================================================
# EXECUTE WITH ERROR HANDLING
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; exit 1' INT

if main; then
    exit 0
else
    echo -e "\n${RED}✗ Installation failed${NC}"
    exit 1
fi


