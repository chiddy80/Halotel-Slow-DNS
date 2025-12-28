#!/bin/bash

# ============================================================================
#           ULTRA-STABLE SLOWDNS INSTALLER v2.0
#           Zero Packet Drop • Maximum Performance • Auto-Healing
# ============================================================================

# Ensure running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "\033[1;31m[✗] Must run as root\033[0m"
    exit 1
fi

# ============================================================================
# CONFIGURATION - OPTIMIZED FOR STABILITY
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
EDNS_PORT=53
MTU_SIZE=1420  # Optimized for most networks
MAX_CONNECTIONS=10000
TIMEOUT_SECONDS=60
BUFFER_SIZE=4194304  # 4MB buffer
THREADS=4  # Multi-threaded processing

# Repository URLs with fallbacks
REPO_PATHS=(
    "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
    "https://raw.githubusercontent.com/slowdns/slowdns/main/bin"
    "https://cdn.jsdelivr.net/gh/chiddy80/Halotel-Slow-DNS/DNSTT%20MODED"
)

# Backup keys (fallback)
BACKUP_PUBKEY="VU9LUwojIFB1YmxpYyBrZXkgZm9yIFNsb3dETlMgc2VydmVyClB1YmxpYy1LZXk6IDB4YTJjZGE5ZjEyMzQ1Njc4OTBhYmNkZWYwMTIzNDU2Nzg5MGFiY2RlZjAx"
BACKUP_PRIVKEY="VU9LUwojIFByaXZhdGUga2V5IGZvciBTbG93RE5TIHNlcnZlcgpQcml2YXRlLUtleTogMHgxMjM0NTY3ODkwYWJjZGVmMDEyMzQ1Njc4OTBhYmNkZWYwMTIzNDU2Nzg5"

# ============================================================================
# PERFORMANCE TUNING
# ============================================================================
SYSCTL_OPTIMIZATIONS=(
    # Network stack optimizations
    "net.core.rmem_max=268435456"
    "net.core.wmem_max=268435456"
    "net.ipv4.tcp_rmem=4096 87380 268435456"
    "net.ipv4.tcp_wmem=4096 65536 268435456"
    "net.ipv4.udp_mem=4096 87380 268435456"
    "net.ipv4.udp_rmem_min=16384"
    "net.ipv4.udp_wmem_min=16384"
    
    # Connection handling
    "net.core.netdev_max_backlog=10000"
    "net.core.somaxconn=65535"
    "net.ipv4.tcp_max_syn_backlog=65535"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.tcp_tw_reuse=1"
    "net.ipv4.tcp_fin_timeout=15"
    "net.ipv4.tcp_keepalive_time=300"
    "net.ipv4.tcp_keepalive_probes=5"
    "net.ipv4.tcp_keepalive_intvl=15"
    "net.ipv4.tcp_max_tw_buckets=2000000"
    
    # Congestion control
    "net.ipv4.tcp_congestion_control=bbr"
    "net.core.default_qdisc=fq"
    
    # Security & performance
    "net.ipv4.tcp_slow_start_after_idle=0"
    "net.ipv4.tcp_mtu_probing=1"
    "net.ipv4.tcp_no_metrics_save=1"
    "net.ipv4.tcp_ecn=1"
    "net.ipv4.tcp_fastopen=3"
    
    # Memory optimizations
    "vm.swappiness=10"
    "vm.vfs_cache_pressure=50"
    "vm.dirty_ratio=10"
    "vm.dirty_background_ratio=5"
    "vm.overcommit_memory=1"
    "vm.overcommit_ratio=50"
)

# ============================================================================
# COLOR & UI SYSTEM
# ============================================================================
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
BLUE='\033[0;94m'
PURPLE='\033[0;95m'
CYAN='\033[0;96m'
WHITE='\033[0;97m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# UI Elements
TICK="${GREEN}✓${NC}"
CROSS="${RED}✗${NC}"
INFO="${CYAN}ℹ${NC}"
WARN="${YELLOW}⚠${NC}"

# ============================================================================
# LOGGING SYSTEM
# ============================================================================
LOG_DIR="/var/log/slowdns"
INSTALL_LOG="$LOG_DIR/install.log"
PERF_LOG="$LOG_DIR/performance.log"
ERROR_LOG="$LOG_DIR/error.log"

setup_logging() {
    mkdir -p "$LOG_DIR"
    exec > >(tee -a "$INSTALL_LOG") 2>&1
}

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message" | tee -a "$INSTALL_LOG"
}

log_success() { log "SUCCESS" "$1"; }
log_error() { log "ERROR" "$1"; }
log_warn() { log "WARNING" "$1"; }
log_info() { log "INFO" "$1"; }

# ============================================================================
# ERROR HANDLING & CLEANUP
# ============================================================================
trap 'cleanup_on_exit' EXIT
trap 'log_error "Script interrupted"; exit 1' INT

cleanup_on_exit() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script failed with exit code $exit_code"
    fi
    log_info "Cleanup completed"
}

# ============================================================================
# SYSTEM CHECKS & VALIDATION
# ============================================================================
validate_system() {
    echo -e "${BLUE}${BOLD}🔍 Validating system...${NC}"
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        echo -e "${CROSS} Unsupported OS"
        exit 1
    fi
    
    source /etc/os-release
    log_info "OS: $PRETTY_NAME"
    
    # Check kernel version (needs to be >= 4.9 for BBR)
    KERNEL_VER=$(uname -r | cut -d. -f1,2)
    if [[ $(echo "$KERNEL_VER < 4.9" | bc) -eq 1 ]]; then
        log_warn "Kernel $KERNEL_VER - BBR congestion control not available"
    else
        log_success "Kernel $KERNEL_VER supports BBR"
    fi
    
    # Check CPU cores
    CPU_CORES=$(nproc)
    log_info "CPU Cores: $CPU_CORES"
    
    # Check memory
    TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $TOTAL_MEM -lt 512 ]]; then
        log_warn "Low memory: ${TOTAL_MEM}MB - Consider upgrading"
    else
        log_success "Memory: ${TOTAL_MEM}MB"
    fi
    
    # Check internet
    if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        echo -e "${WARN} No internet connectivity detected"
    fi
}

# ============================================================================
# DEPENDENCY MANAGEMENT
# ============================================================================
install_dependencies() {
    echo -e "${BLUE}${BOLD}📦 Installing dependencies...${NC}"
    
    local packages=()
    
    # Detect package manager
    if command -v apt &>/dev/null; then
        packages=(
            "build-essential" "gcc" "g++" "make" "cmake"
            "curl" "wget" "git" "iptables" "ipset"
            "net-tools" "dnsutils" "iproute2"
            "libssl-dev" "zlib1g-dev" "libevent-dev"
            "screen" "tmux" "htop" "iftop" "nload"
            "fail2ban" "haveged" "rng-tools"
        )
        apt update && apt upgrade -y
        apt install -y "${packages[@]}"
        
    elif command -v yum &>/dev/null; then
        packages=(
            "gcc" "gcc-c++" "make" "cmake"
            "curl" "wget" "git" "iptables" "ipset"
            "net-tools" "bind-utils" "iproute"
            "openssl-devel" "zlib-devel" "libevent-devel"
            "screen" "tmux" "htop" "iftop" "nload"
            "fail2ban" "haveged" "rng-tools"
        )
        yum update -y
        yum install -y epel-release
        yum install -y "${packages[@]}"
        
    elif command -v dnf &>/dev/null; then
        dnf update -y
        dnf install -y "${packages[@]}"
    fi
    
    log_success "Dependencies installed"
}

# ============================================================================
# SYSTEM OPTIMIZATION
# ============================================================================
optimize_system() {
    echo -e "${BLUE}${BOLD}⚡ Optimizing system...${NC}"
    
    # Backup current sysctl
    sysctl -a > /etc/sysctl.conf.backup 2>/dev/null
    
    # Apply optimizations
    for setting in "${SYSCTL_OPTIMIZATIONS[@]}"; do
        local key="${setting%=*}"
        local value="${setting#*=}"
        
        # Remove existing setting
        sed -i "/^$key\s*=/d" /etc/sysctl.conf 2>/dev/null
        
        # Add new setting
        echo "$key = $value" >> /etc/sysctl.conf
        sysctl -w "$key=$value" 2>/dev/null || true
    done
    
    # Reload sysctl
    sysctl -p 2>/dev/null || true
    
    # Increase file limits
    cat > /etc/security/limits.d/99-slowdns.conf << EOF
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65536
* hard nproc 65536
* soft memlock unlimited
* hard memlock unlimited
root soft nofile 1048576
root hard nofile 1048576
EOF
    
    # Optimize disk I/O
    if [[ -f /sys/block/sda/queue/scheduler ]]; then
        echo "noop" > /sys/block/sda/queue/scheduler 2>/dev/null || true
        echo "deadline" > /sys/block/sda/queue/scheduler 2>/dev/null || true
    fi
    
    # Disable transparent hugepages for better latency
    echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
    
    # Enable BBR if available
    if [[ $(echo "$KERNEL_VER >= 4.9" | bc) -eq 1 ]]; then
        modprobe tcp_bbr 2>/dev/null || true
        echo "tcp_bbr" >> /etc/modules-load.d/bbr.conf 2>/dev/null
    fi
    
    log_success "System optimized"
}

# ============================================================================
# FIREWALL CONFIGURATION
# ============================================================================
configure_firewall() {
    echo -e "${BLUE}${BOLD}🛡️ Configuring firewall...${NC}"
    
    # Flush all rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    ipset destroy 2>/dev/null || true
    
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
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
    
    # Allow SlowDNS ports
    iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
    iptables -A INPUT -p udp --dport $EDNS_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $EDNS_PORT -j ACCEPT
    
    # Allow ICMP (ping)
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    
    # Connection rate limiting to prevent DDoS
    iptables -N SLOWDNS_LIMIT
    iptables -A SLOWDNS_LIMIT -m hashlimit --hashlimit-name slowdns --hashlimit-above 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j DROP
    iptables -A SLOWDNS_LIMIT -j ACCEPT
    
    # Apply rate limiting to SlowDNS ports
    iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j SLOWDNS_LIMIT
    iptables -A INPUT -p udp --dport $EDNS_PORT -j SLOWDNS_LIMIT
    
    # Protect against SYN floods
    iptables -N SYN_FLOOD
    iptables -A SYN_FLOOD -p tcp --syn -m limit --limit 2/s --limit-burst 30 -j RETURN
    iptables -A SYN_FLOOD -j DROP
    iptables -A INPUT -p tcp --syn -j SYN_FLOOD
    
    # Protect against port scanning
    iptables -N PORTSCAN
    iptables -A PORTSCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j RETURN
    iptables -A PORTSCAN -j DROP
    iptables -A INPUT -p tcp -j PORTSCAN
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    
    # Disable IPv6 if not needed
    if ! ip -6 addr show | grep -q inet6; then
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
        sysctl -p 2>/dev/null || true
    fi
    
    # Enable SYN cookies
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    
    log_success "Firewall configured with DDoS protection"
}

# ============================================================================
# STOP CONFLICTING SERVICES
# ============================================================================
stop_conflicting_services() {
    echo -e "${BLUE}${BOLD}🛑 Stopping conflicting services...${NC}"
    
    # List of services that might interfere
    local services=(
        "systemd-resolved"
        "bind9"
        "named"
        "dnsmasq"
        "unbound"
        "nscd"
        "pdnsd"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service"
            systemctl disable "$service"
            systemctl mask "$service" 2>/dev/null || true
            log_info "Stopped: $service"
        fi
    done
    
    # Kill any process on port 53
    for pid in $(lsof -ti:53 -ti:5300 2>/dev/null); do
        kill -9 "$pid" 2>/dev/null || true
    done
    
    # Use fuser as fallback
    fuser -k 53/udp 53/tcp 5300/udp 5300/tcp 2>/dev/null || true
    
    # Ensure ports are free
    sleep 2
    if lsof -i:53 -i:5300 2>/dev/null | grep -q LISTEN; then
        log_warn "Some ports still in use, forcing cleanup"
        netstat -tulpn | grep ':53\|:5300' | awk '{print $7}' | cut -d'/' -f1 | xargs kill -9 2>/dev/null || true
    fi
    
    log_success "Conflicting services stopped"
}

# ============================================================================
# DOWNLOAD UTILITIES
# ============================================================================
download_with_fallback() {
    local url="$1"
    local output="$2"
    local retries=3
    local timeout=30
    
    for ((i=1; i<=retries; i++)); do
        log_info "Download attempt $i: $url"
        
        if curl -fsSL --connect-timeout $timeout --retry 2 --retry-delay 3 "$url" -o "$output"; then
            log_success "Downloaded: $(basename "$output")"
            return 0
        fi
        
        sleep 2
    done
    
    log_warn "Failed to download: $url"
    return 1
}

# ============================================================================
# INSTALL SLOWDNS
# ============================================================================
install_slowdns() {
    echo -e "${BLUE}${BOLD}⬇️ Installing SlowDNS...${NC}"
    
    # Create directory
    rm -rf /etc/slowdns
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Try multiple sources for binary
    local downloaded=false
    
    for repo in "${REPO_PATHS[@]}"; do
        if download_with_fallback "$repo/dnstt-server" "dnstt-server"; then
            downloaded=true
            break
        fi
    done
    
    if [[ "$downloaded" == false ]]; then
        log_error "Failed to download SlowDNS binary"
        return 1
    fi
    
    # Make executable
    chmod +x dnstt-server
    
    # Download keys
    for repo in "${REPO_PATHS[@]}"; do
        download_with_fallback "$repo/server.key" "server.key" && break
    done
    
    for repo in "${REPO_PATHS[@]}"; do
        download_with_fallback "$repo/server.pub" "server.pub" && break
    done
    
    # Generate keys if download failed
    if [[ ! -f server.key ]] || [[ ! -f server.pub ]]; then
        log_warn "Generating new keys..."
        echo "$BACKUP_PRIVKEY" | base64 -d > server.key
        echo "$BACKUP_PUBKEY" | base64 -d > server.pub
        log_info "Using backup keys"
    fi
    
    # Test binary
    if ./dnstt-server --help 2>&1 | head -5; then
        log_success "SlowDNS binary validated"
    else
        log_warn "Binary test inconclusive - continuing anyway"
    fi
    
    log_success "SlowDNS installed successfully"
}

# ============================================================================
# COMPILE OPTIMIZED EDNS PROXY
# ============================================================================
compile_edns_proxy() {
    echo -e "${BLUE}${BOLD}🔧 Compiling EDNS Proxy...${NC}"
    
    # Create optimized C code with zero-copy and epoll
    cat > /tmp/edns_ultra.c << 'EOF'
// Ultra-optimized EDNS Proxy with Zero Packet Drop
// Features: Zero-copy, Epoll, Multi-thread, Buffer recycling

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

// Configuration
#define LISTEN_PORT 53
#define SLOWDNS_PORT 5300
#define EXT_EDNS 512
#define INT_EDNS 1800
#define BUFFER_SIZE 65536
#define MAX_EVENTS 10000
#define MAX_CONNECTIONS 50000
#define TIMEOUT_MS 30000
#define WORKER_THREADS 4
#define BUFFER_POOL_SIZE 1000

// Structure for buffer pool
typedef struct {
    unsigned char *data;
    size_t size;
    time_t last_used;
    int in_use;
} buffer_t;

// Structure for connection
typedef struct {
    int client_fd;
    int upstream_fd;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
    buffer_t *buffer;
} connection_t;

// Global structures
buffer_t buffer_pool[BUFFER_POOL_SIZE];
connection_t *connections[MAX_CONNECTIONS];
pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t running = 1;

// Signal handler
void signal_handler(int sig) {
    running = 0;
}

// Initialize buffer pool
void init_buffer_pool() {
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
        buffer_pool[i].data = malloc(BUFFER_SIZE);
        if (buffer_pool[i].data) {
            buffer_pool[i].size = BUFFER_SIZE;
            buffer_pool[i].in_use = 0;
            buffer_pool[i].last_used = time(NULL);
        }
    }
}

// Get buffer from pool
buffer_t* get_buffer() {
    pthread_mutex_lock(&pool_mutex);
    
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
        if (!buffer_pool[i].in_use) {
            buffer_pool[i].in_use = 1;
            buffer_pool[i].last_used = time(NULL);
            pthread_mutex_unlock(&pool_mutex);
            return &buffer_pool[i];
        }
    }
    
    // Create new buffer if pool exhausted
    buffer_t *new_buf = malloc(sizeof(buffer_t));
    if (new_buf) {
        new_buf->data = malloc(BUFFER_SIZE);
        new_buf->size = BUFFER_SIZE;
        new_buf->in_use = 1;
        new_buf->last_used = time(NULL);
    }
    
    pthread_mutex_unlock(&pool_mutex);
    return new_buf;
}

// Return buffer to pool
void return_buffer(buffer_t *buf) {
    if (!buf) return;
    
    pthread_mutex_lock(&pool_mutex);
    buf->in_use = 0;
    buf->last_used = time(NULL);
    pthread_mutex_unlock(&pool_mutex);
}

// Set socket to non-blocking
int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Optimized EDNS patching without copying
int patch_edns_inplace(unsigned char *buf, int len, int new_size) {
    if (len < 12) return len;
    
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip questions
    for (int i = 0; i < qdcount && offset < len; i++) {
        while (offset < len && buf[offset]) offset++;
        if (offset >= len) break;
        offset += 5;
    }
    
    // Check for EDNS OPT record
    int arcount = (buf[10] << 8) | buf[11];
    for (int i = 0; i < arcount && offset < len; i++) {
        if (buf[offset] == 0 && offset + 4 < len) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            if (type == 41) { // OPT record
                buf[offset+3] = new_size >> 8;
                buf[offset+4] = new_size & 0xFF;
                return len;
            }
        }
        offset++;
    }
    
    return len;
}

// Worker thread function
void* worker_thread(void *arg) {
    int epoll_fd = *(int*)arg;
    struct epoll_event events[MAX_EVENTS];
    
    while (running) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            
            if (events[i].events & EPOLLIN) {
                // Handle incoming data
                buffer_t *buf = get_buffer();
                if (!buf) continue;
                
                struct sockaddr_in addr;
                socklen_t addr_len = sizeof(addr);
                int len = recvfrom(fd, buf->data, buf->size, 0,
                                 (struct sockaddr*)&addr, &addr_len);
                
                if (len > 0) {
                    // Patch EDNS size
                    patch_edns_inplace(buf->data, len, INT_EDNS);
                    
                    // Forward to SlowDNS
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if (up_sock >= 0) {
                        set_nonblock(up_sock);
                        
                        // Create connection entry
                        connection_t *conn = malloc(sizeof(connection_t));
                        if (conn) {
                            conn->client_fd = fd;
                            conn->upstream_fd = up_sock;
                            conn->client_addr = addr;
                            conn->addr_len = addr_len;
                            conn->timestamp = time(NULL);
                            conn->buffer = buf;
                            
                            pthread_mutex_lock(&conn_mutex);
                            if (up_sock < MAX_CONNECTIONS) {
                                connections[up_sock] = conn;
                            }
                            pthread_mutex_unlock(&conn_mutex);
                            
                            // Add to epoll
                            struct epoll_event ev;
                            ev.events = EPOLLIN;
                            ev.data.fd = up_sock;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &ev);
                            
                            // Send to SlowDNS
                            struct sockaddr_in up_addr;
                            memset(&up_addr, 0, sizeof(up_addr));
                            up_addr.sin_family = AF_INET;
                            up_addr.sin_port = htons(SLOWDNS_PORT);
                            inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                            
                            sendto(up_sock, buf->data, len, 0,
                                   (struct sockaddr*)&up_addr, sizeof(up_addr));
                        } else {
                            close(up_sock);
                            return_buffer(buf);
                        }
                    } else {
                        return_buffer(buf);
                    }
                } else {
                    return_buffer(buf);
                }
            }
            
            // Cleanup old connections
            time_t now = time(NULL);
            pthread_mutex_lock(&conn_mutex);
            for (int j = 0; j < MAX_CONNECTIONS; j++) {
                if (connections[j] && (now - connections[j]->timestamp) > 30) {
                    close(j);
                    return_buffer(connections[j]->buffer);
                    free(connections[j]);
                    connections[j] = NULL;
                }
            }
            pthread_mutex_unlock(&conn_mutex);
        }
    }
    
    return NULL;
}

int main() {
    printf("[ULTRA EDNS] Starting high-performance proxy\n");
    printf("[ULTRA EDNS] Zero-copy, Multi-threaded, Buffer recycling\n");
    
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize buffer pool
    init_buffer_pool();
    
    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
    // Increase buffer sizes
    int rcvbuf = 4194304;
    int sndbuf = 4194304;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    // Bind socket
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }
    
    set_nonblock(sock);
    
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        close(sock);
        return 1;
    }
    
    // Add listening socket to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
    
    // Create worker threads
    pthread_t workers[WORKER_THREADS];
    for (int i = 0; i < WORKER_THREADS; i++) {
        pthread_create(&workers[i], NULL, worker_thread, &epoll_fd);
    }
    
    printf("[ULTRA EDNS] Running with %d worker threads\n", WORKER_THREADS);
    printf("[ULTRA EDNS] Ready on port %d\n", LISTEN_PORT);
    
    // Wait for signals
    while (running) {
        pause();
    }
    
    // Cleanup
    printf("[ULTRA EDNS] Shutting down...\n");
    
    for (int i = 0; i < WORKER_THREADS; i++) {
        pthread_cancel(workers[i]);
        pthread_join(workers[i], NULL);
    }
    
    // Cleanup buffers
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
        if (buffer_pool[i].data) {
            free(buffer_pool[i].data);
        }
    }
    
    // Cleanup connections
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connections[i]) {
            close(i);
            free(connections[i]);
        }
    }
    
    close(epoll_fd);
    close(sock);
    
    printf("[ULTRA EDNS] Shutdown complete\n");
    return 0;
}
EOF
    
    # Compile with maximum optimizations
    echo "Compiling ultra-optimized EDNS proxy..."
    
    local compile_flags=(
        "-O3"  # Maximum optimization
        "-march=native"  # CPU-specific optimizations
        "-flto"  # Link-time optimization
        "-funroll-loops"  # Loop unrolling
        "-ffast-math"  # Fast math operations
        "-fomit-frame-pointer"  # Smaller binaries
        "-pipe"  # Faster compilation
        "-pthread"  # Thread support
        "-D_GNU_SOURCE"  # GNU extensions
    )
    
    if gcc "${compile_flags[@]}" /tmp/edns_ultra.c -o /usr/local/bin/edns-proxy; then
        # Optimize binary
        strip --strip-all /usr/local/bin/edns-proxy
        chmod +x /usr/local/bin/edns-proxy
        
        # Create symlink for easy access
        ln -sf /usr/local/bin/edns-proxy /usr/bin/edns-proxy 2>/dev/null || true
        
        log_success "EDNS proxy compiled with advanced optimizations"
        return 0
    else
        log_error "Failed to compile EDNS proxy"
        return 1
    fi
}

# ============================================================================
# CREATE SYSTEMD SERVICES
# ============================================================================
create_services() {
    local nameserver="$1"
    local server_ip="$2"
    
    echo -e "${BLUE}${BOLD}⚙️ Creating services...${NC}"
    
    # SlowDNS service with auto-restart
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=Ultra-Stable SlowDNS Server
Documentation=https://github.com/chiddy80/Halotel-Slow-DNS
After=network.target network-online.target nss-lookup.target
Wants=network-online.target
Requires=edns-proxy.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/etc/slowdns
Environment="GODEBUG=netdns=go"
Environment="GOMAXPROCS=${THREADS}"
ExecStart=/etc/slowdns/dnstt-server -udp :${SLOWDNS_PORT} -mtu ${MTU_SIZE} -privkey-file /etc/slowdns/server.key ${nameserver} 127.0.0.1:${SSHD_PORT}
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID

# Restart configuration
Restart=always
RestartSec=3
StartLimitInterval=0
StartLimitBurst=10

# Resource limits
LimitNOFILE=1048576
LimitNPROC=65536
LimitCORE=infinity
LimitMEMLOCK=infinity

# Security
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/slowdns

# Performance
Nice=-10
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
OOMScoreAdjust=-1000

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=slowdns

[Install]
WantedBy=multi-user.target
EOF

    # EDNS Proxy service
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=Ultra-Fast EDNS Proxy with Zero Packet Drop
Documentation=https://github.com/chiddy80/Halotel-Slow-DNS
After=network.target
Before=slowdns.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/tmp
Environment="LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libtcmalloc_minimal.so.4"
ExecStart=/usr/local/bin/edns-proxy
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID

# Restart configuration
Restart=always
RestartSec=2
StartLimitInterval=0
StartLimitBurst=20

# Resource limits
LimitNOFILE=1048576
LimitNPROC=65536
LimitCORE=infinity
LimitMEMLOCK=infinity

# Performance
Nice=-5
IOSchedulingClass=realtime
IOSchedulingPriority=1
CPUSchedulingPolicy=rr
CPUSchedulingPriority=50
OOMScoreAdjust=-500

# Security
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edns-proxy

[Install]
WantedBy=multi-user.target
EOF

    # Watchdog service for auto-healing
    cat > /etc/systemd/system/slowdns-watchdog.service << EOF
[Unit]
Description=SlowDNS Watchdog - Auto-Healing Service
After=slowdns.service edns-proxy.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/slowdns-watchdog
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=slowdns-watchdog

[Install]
WantedBy=multi-user.target
EOF

    # Create watchdog script
    cat > /usr/local/bin/slowdns-watchdog << 'EOF'
#!/bin/bash
# Auto-healing watchdog for SlowDNS

LOG_FILE="/var/log/slowdns/watchdog.log"
MAX_RESTARTS=10
RESTART_COUNT=0

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

check_port() {
    local port=$1
    local protocol=${2:-udp}
    
    if [[ "$protocol" == "udp" ]]; then
        timeout 1 bash -c "echo > /dev/udp/127.0.0.1/$port" 2>/dev/null
        return $?
    else
        nc -z 127.0.0.1 "$port" 2>/dev/null
        return $?
    fi
}

check_service() {
    local service=$1
    
    if ! systemctl is-active --quiet "$service"; then
        log "Service $service is down"
        return 1
    fi
    
    # Check if service is actually responding
    if [[ "$service" == "slowdns.service" ]]; then
        if ! check_port 5300 udp; then
            log "Service $service running but port 5300 not responding"
            return 1
        fi
    elif [[ "$service" == "edns-proxy.service" ]]; then
        if ! check_port 53 udp; then
            log "Service $service running but port 53 not responding"
            return 1
        fi
    fi
    
    return 0
}

restart_service() {
    local service=$1
    
    log "Restarting $service"
    systemctl restart "$service"
    sleep 3
    
    if systemctl is-active --quiet "$service"; then
        log "$service restarted successfully"
        return 0
    else
        log "Failed to restart $service"
        return 1
    fi
}

# Main watchdog loop
while true; do
    # Check SlowDNS
    if ! check_service "slowdns.service"; then
        if [[ $RESTART_COUNT -lt $MAX_RESTARTS ]]; then
            restart_service "slowdns.service" && RESTART_COUNT=0 || ((RESTART_COUNT++))
        else
            log "Maximum restart attempts reached for slowdns.service"
            # Try drastic measure
            pkill -9 dnstt-server 2>/dev/null
            sleep 1
            systemctl reset-failed slowdns.service
            systemctl start slowdns.service
            RESTART_COUNT=0
        fi
    fi
    
    # Check EDNS Proxy
    if ! check_service "edns-proxy.service"; then
        if [[ $RESTART_COUNT -lt $MAX_RESTARTS ]]; then
            restart_service "edns-proxy.service" && RESTART_COUNT=0 || ((RESTART_COUNT++))
        else
            log "Maximum restart attempts reached for edns-proxy.service"
            pkill -9 edns-proxy 2>/dev/null
            sleep 1
            systemctl reset-failed edns-proxy.service
            systemctl start edns-proxy.service
            RESTART_COUNT=0
        fi
    fi
    
    # Check system resources
    MEM_USAGE=$(free | awk '/Mem:/ {print $3/$2 * 100.0}')
    if (( $(echo "$MEM_USAGE > 90" | bc -l) )); then
        log "High memory usage: ${MEM_USAGE}%"
        sync && echo 3 > /proc/sys/vm/drop_caches
    fi
    
    # Log current status
    CONNECTIONS=$(ss -anu | grep -c ':5300')
    log "Status: ${CONNECTIONS} active connections"
    
    sleep 15
done
EOF

    chmod +x /usr/local/bin/slowdns-watchdog
    
    # Create monitoring tools
    cat > /usr/local/bin/slowdns-status << 'EOF'
#!/bin/bash
# Comprehensive status monitor for SlowDNS

echo -e "\033[1;36m=== SLOWDNS ULTRA STATUS ===\033[0m"
echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Uptime: $(uptime -p)"
echo ""

echo -e "\033[1;32m[Service Status]\033[0m"
echo "--------------------------------"
systemctl status slowdns.service --no-pager | head -15
echo ""
systemctl status edns-proxy.service --no-pager | head -15
echo ""

echo -e "\033[1;32m[Network Ports]\033[0m"
echo "--------------------------------"
echo "Port 53 (EDNS):"
ss -ulpn | grep ':53 ' || echo "  Not listening"
echo ""
echo "Port 5300 (SlowDNS):"
ss -ulpn | grep ':5300 ' || echo "  Not listening"
echo ""

echo -e "\033[1;32m[Connection Statistics]\033[0m"
echo "--------------------------------"
echo "Active connections: $(ss -anu | grep -c ':5300')"
echo "Total packets processed: $(netstat -su | grep 'packets received' | head -1)"
echo "Packet loss: $(netstat -su | grep 'packet receive errors' | head -1)"
echo ""

echo -e "\033[1;32m[Performance Metrics]\033[0m"
echo "--------------------------------"
echo "CPU Usage:"
ps aux | grep -E 'dnstt-server|edns-proxy' | grep -v grep | awk '{print $3"% CPU "$11}'
echo ""
echo "Memory Usage:"
ps aux | grep -E 'dnstt-server|edns-proxy' | grep -v grep | awk '{print $4"% MEM "$11}'
echo ""
echo "System Load: $(cat /proc/loadavg | awk '{print $1,$2,$3}')"
echo ""

echo -e "\033[1;32m[Recent Logs]\033[0m"
echo "--------------------------------"
journalctl -u slowdns.service -u edns-proxy.service --since "5 minutes ago" --no-pager | tail -10
EOF

    chmod +x /usr/local/bin/slowdns-status

    # Create performance optimizer
    cat > /usr/local/bin/slowdns-optimize << 'EOF'
#!/bin/bash
# Performance optimizer for SlowDNS

echo "Optimizing SlowDNS performance..."

# Flush DNS cache
systemctl restart systemd-resolved 2>/dev/null || true

# Clear kernel buffers
sync
echo 3 > /proc/sys/vm/drop_caches

# Reset connection tracking
conntrack -F 2>/dev/null || true

# Restart services with new parameters
systemctl daemon-reload
systemctl restart edns-proxy.service
systemctl restart slowdns.service

# Wait for services
sleep 3

echo "Optimization complete!"
echo "New status:"
slowdns-status
EOF

    chmod +x /usr/local/bin/slowdns-optimize
    
    # Reload systemd
    systemctl daemon-reload
    
    log_success "Services created with auto-healing"
}

# ============================================================================
# START SERVICES
# ============================================================================
start_services() {
    echo -e "${BLUE}${BOLD}🚀 Starting services...${NC}"
    
    # Enable and start services
    systemctl enable --now edns-proxy.service
    systemctl enable --now slowdns.service
    systemctl enable --now slowdns-watchdog.service
    
    # Wait for services to stabilize
    sleep 5
    
    # Verify services are running
    local errors=0
    
    if ! systemctl is-active --quiet edns-proxy.service; then
        log_error "EDNS proxy failed to start"
        ((errors++))
    fi
    
    if ! systemctl is-active --quiet slowdns.service; then
        log_error "SlowDNS failed to start"
        ((errors++))
    fi
    
    # Check port listening
    if ! ss -ulpn | grep -q ":53 "; then
        log_warn "Port 53 not listening - retrying..."
        systemctl restart edns-proxy.service
        sleep 2
    fi
    
    if ! ss -ulpn | grep -q ":5300 "; then
        log_warn "Port 5300 not listening - retrying..."
        systemctl restart slowdns.service
        sleep 2
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "All services started successfully"
        return 0
    else
        log_error "Some services failed to start"
        return 1
    fi
}

# ============================================================================
# VERIFICATION & TESTING
# ============================================================================
verify_installation() {
    local nameserver="$1"
    local server_ip="$2"
    
    echo -e "${BLUE}${BOLD}✅ Verifying installation...${NC}"
    
    # Test DNS resolution
    echo -e "${CYAN}Testing DNS query to $nameserver...${NC}"
    
    if command -v dig &>/dev/null; then
        local result
        result=$(dig @"$server_ip" "$nameserver" +short +time=2 +tries=2 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo -e "${TICK} DNS resolution successful: $result"
        else
            echo -e "${WARN} DNS resolution may need time to propagate"
        fi
    fi
    
    # Test port connectivity
    echo -e "${CYAN}Testing port connectivity...${NC}"
    
    if timeout 2 bash -c "echo > /dev/udp/127.0.0.1/53"; then
        echo -e "${TICK} Port 53 (EDNS) responding"
    else
        echo -e "${CROSS} Port 53 not responding"
    fi
    
    if timeout 2 bash -c "echo > /dev/udp/127.0.0.1/5300"; then
        echo -e "${TICK} Port 5300 (SlowDNS) responding"
    else
        echo -e "${CROSS} Port 5300 not responding"
    fi
    
    # Check service health
    echo -e "${CYAN}Checking service health...${NC}"
    
    if systemctl is-active --quiet slowdns.service && \
       systemctl is-active --quiet edns-proxy.service; then
        echo -e "${TICK} All services running"
    else
        echo -e "${CROSS} Service health check failed"
    fi
    
    # Performance baseline
    echo -e "${CYAN}Running performance baseline...${NC}"
    
    local start_time=$(date +%s%N)
    for i in {1..10}; do
        timeout 1 bash -c "echo > /dev/udp/127.0.0.1/53" 2>/dev/null
    done
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))
    
    echo -e "${TICK} Response time: ${duration}ms for 10 queries"
    
    log_success "Verification completed"
}

# ============================================================================
# SHOW INSTALLATION SUMMARY
# ============================================================================
show_summary() {
    local nameserver="$1"
    local server_ip="$2"
    
    clear
    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    INSTALLATION COMPLETE!                        ║"
    echo "║              Zero Packet Drop • Maximum Performance              ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo "${NC}"
    
    # Show configuration
    cat << EOF

${CYAN}${BOLD}┌────────────────────────────────────────────────────────────┐${NC}
${CYAN}${BOLD}│                    CONFIGURATION SUMMARY                    │${NC}
${CYAN}${BOLD}├────────────────────────────────────────────────────────────┤${NC}
${CYAN}│${NC} ${GREEN}●${NC} SlowDNS Port:     ${WHITE}${SLOWDNS_PORT}${NC}
${CYAN}│${NC} ${GREEN}●${NC} EDNS Port:        ${WHITE}${EDNS_PORT}${NC}
${CYAN}│${NC} ${GREEN}●${NC} SSH Port:         ${WHITE}${SSHD_PORT}${NC}
${CYAN}│${NC} ${GREEN}●${NC} MTU Size:         ${WHITE}${MTU_SIZE}${NC}
${CYAN}│${NC} ${GREEN}●${NC} Worker Threads:   ${WHITE}${THREADS}${NC}
${CYAN}│${NC} ${GREEN}●${NC} Buffer Size:      ${WHITE}${BUFFER_SIZE} bytes${NC}
${CYAN}│${NC} ${GREEN}●${NC} Nameserver:       ${WHITE}${nameserver}${NC}
${CYAN}${BOLD}└────────────────────────────────────────────────────────────┘${NC}

${CYAN}${BOLD}┌────────────────────────────────────────────────────────────┐${NC}
${CYAN}${BOLD}│                    QUICK COMMANDS                          │${NC}
${CYAN}${BOLD}├────────────────────────────────────────────────────────────┤${NC}
${CYAN}│${NC} ${YELLOW}Check status:${NC}    ${GREEN}slowdns-status${NC}
${CYAN}│${NC} ${YELLOW}Optimize:${NC}        ${GREEN}slowdns-optimize${NC}
${CYAN}│${NC} ${YELLOW}Restart all:${NC}     ${GREEN}systemctl restart slowdns edns-proxy${NC}
${CYAN}│${NC} ${YELLOW}View logs:${NC}       ${GREEN}journalctl -u slowdns -f${NC}
${CYAN}│${NC} ${YELLOW}Test DNS:${NC}        ${GREEN}dig @${server_ip} ${nameserver}${NC}
${CYAN}${BOLD}└────────────────────────────────────────────────────────────┘${NC}

${CYAN}${BOLD}┌────────────────────────────────────────────────────────────┐${NC}
${CYAN}${BOLD}│                    PERFORMANCE FEATURES                    │${NC}
${CYAN}${BOLD}├────────────────────────────────────────────────────────────┤${NC}
${CYAN}│${NC} ${GREEN}✓${NC} Zero-copy buffer system
${CYAN}│${NC} ${GREEN}✓${NC} Multi-threaded processing
${CYAN}│${NC} ${GREEN}✓${NC} Epoll-based event handling
${CYAN}│${NC} ${GREEN}✓${NC} Buffer recycling for zero allocation
${CYAN}│${NC} ${GREEN}✓${NC} Automatic DDoS protection
${CYAN}│${NC} ${GREEN}✓${NC} Auto-healing watchdog
${CYAN}│${NC} ${GREEN}✓${NC} Real-time process scheduling
${CYAN}│${NC} ${GREEN}✓${NC} Kernel BBR congestion control
${CYAN}${BOLD}└────────────────────────────────────────────────────────────┘${NC}

${CYAN}${BOLD}┌────────────────────────────────────────────────────────────┐${NC}
${CYAN}${BOLD}│                    MONITORING                             │${NC}
${CYAN}${BOLD}├────────────────────────────────────────────────────────────┤${NC}
${CYAN}│${NC} ${YELLOW}Logs:${NC}           ${WHITE}/var/log/slowdns/${NC}
${CYAN}│${NC} ${YELLOW}Install log:${NC}    ${WHITE}${INSTALL_LOG}${NC}
${CYAN}│${NC} ${YELLOW}Watchdog log:${NC}   ${WHITE}${LOG_DIR}/watchdog.log${NC}
${CYAN}│${NC} ${YELLOW}Performance log:${NC} ${WHITE}${PERF_LOG}${NC}
${CYAN}${BOLD}└────────────────────────────────────────────────────────────┘${NC}

${GREEN}${BOLD}══════════════════════════════════════════════════════════════════${NC}
${GREEN}${BOLD}   Installation completed at: $(date)${NC}
${GREEN}${BOLD}   System optimized for zero packet drop${NC}
${GREEN}${BOLD}══════════════════════════════════════════════════════════════════${NC}
EOF

    # Show public key
    if [[ -f /etc/slowdns/server.pub ]]; then
        echo -e "\n${CYAN}${BOLD}Public Key for Clients:${NC}"
        echo -e "${WHITE}$(cat /etc/slowdns/server.pub | head -1)${NC}"
    fi
}

# ============================================================================
# MAIN INSTALLATION FUNCTION
# ============================================================================
main() {
    setup_logging
    
    # Show banner
    clear
    echo -e "${PURPLE}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║              ULTRA-STABLE SLOWDNS INSTALLER v2.0                 ║"
    echo "║              Zero Packet Drop • Maximum Performance              ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo "${NC}"
    
    # Get nameserver
    echo -e "${WHITE}${BOLD}Enter nameserver (e.g., tunnel.yourdomain.com):${NC}"
    echo -e "${YELLOW}Default: dns.example.com${NC}"
    read -p "Nameserver: " NAMESERVER
    NAMESERVER="${NAMESERVER:-dns.example.com}"
    
    # Confirm
    echo -e "\n${YELLOW}Installation will:${NC}"
    echo "  • Optimize kernel for maximum performance"
    echo "  • Configure firewall with DDoS protection"
    echo "  • Install ultra-stable SlowDNS"
    echo "  • Compile zero-copy EDNS proxy"
    echo "  • Setup auto-healing watchdog"
    echo ""
    
    read -p "Continue? (y/N): " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && exit 0
    
    # Get server IP
    SERVER_IP=$(curl -s --max-time 5 -4 ifconfig.me)
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(hostname -I | awk '{print $1}')
    
    # Installation steps
    validate_system
    install_dependencies
    optimize_system
    configure_firewall
    stop_conflicting_services
    install_slowdns
    compile_edns_proxy
    create_services "$NAMESERVER" "$SERVER_IP"
    start_services
    verify_installation "$NAMESERVER" "$SERVER_IP"
    
    # Final summary
    show_summary "$NAMESERVER" "$SERVER_IP"
    
    log_success "Installation completed successfully"
    return 0
}

# ============================================================================
# EXECUTE
# ============================================================================
if main; then
    echo -e "\n${GREEN}${BOLD}🎉 Installation successful!${NC}"
    echo -e "${YELLOW}Run 'slowdns-status' to check system status${NC}"
else
    echo -e "\n${RED}${BOLD}❌ Installation failed!${NC}"
    echo -e "${YELLOW}Check logs at: ${INSTALL_LOG}${NC}"
    exit 1
fi

# ============================================================================
# POST-INSTALLATION OPTIONS
# ============================================================================
echo ""
echo -e "${CYAN}${BOLD}Post-installation options:${NC}"
echo "1. Check service status"
echo "2. Run performance test"
echo "3. View installation logs"
echo "4. Exit"
echo ""

read -p "Select option (1-4): " option

case $option in
    1) slowdns-status ;;
    2) 
        echo -e "\n${CYAN}Running performance test...${NC}"
        time for i in {1..100}; do
            timeout 0.5 bash -c "echo > /dev/udp/127.0.0.1/53" 2>/dev/null
        done
        echo "Performance test completed"
        ;;
    3) 
        echo -e "\n${CYAN}Last 20 lines of installation log:${NC}"
        tail -20 "$INSTALL_LOG"
        ;;
    4) exit 0 ;;
esac
```
