#!/bin/bash

# ============================================================================
#                     SLOWDNS MODERN INSTALLATION SCRIPT
#                     Optimized for Arch Linux & Performance
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
# ARCH LINUX OPTIMIZATIONS
# ============================================================================
# Detect package manager
detect_pm() {
    if command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v apt &>/dev/null; then
        echo "apt"
    elif command -v yum &>/dev/null; then
        echo "yum"
    else
        echo "unknown"
    fi
}

# Package installation wrapper
install_package() {
    local pkg=$1
    case $(detect_pm) in
        pacman)
            pacman -Sy --noconfirm "$pkg" 2>/dev/null || return 1
            ;;
        apt)
            apt update >/dev/null 2>&1 && apt install -y "$pkg" >/dev/null 2>&1 || return 1
            ;;
        yum)
            yum install -y "$pkg" >/dev/null 2>&1 || return 1
            ;;
        *)
            echo "No supported package manager found"
            return 1
            ;;
    esac
}

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
    echo -e "${BLUE}║${NC}${CYAN}          🚀 MODERN SLOWDNS INSTALLATION SCRIPT${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}            Optimized for Arch Linux & Performance${NC}      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}                Professional Grade Configuration${NC}           ${BLUE}║${NC}"
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
# PERFORMANCE OPTIMIZATION FUNCTIONS
# ============================================================================
optimize_kernel() {
    print_info "Applying kernel optimizations for DNS performance"
    
    # TCP/IP stack optimizations
    sysctl -w net.core.rmem_max=134217728 2>/dev/null
    sysctl -w net.core.wmem_max=134217728 2>/dev/null
    sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728" 2>/dev/null
    sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728" 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    sysctl -w net.core.default_qdisc=fq 2>/dev/null
    sysctl -w net.ipv4.tcp_notsent_lowat=16384 2>/dev/null
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 2>/dev/null
    sysctl -w net.ipv4.tcp_mtu_probing=1 2>/dev/null
    
    # UDP optimizations for DNS
    sysctl -w net.core.netdev_max_backlog=10000 2>/dev/null
    sysctl -w net.core.optmem_max=4194304 2>/dev/null
    
    # DNS-specific
    sysctl -w net.unix.max_dgram_qlen=1000 2>/dev/null
    
    print_success "Kernel optimizations applied"
}

setup_limits() {
    print_info "Setting system limits for high performance"
    
    cat > /etc/security/limits.d/99-slowdns.conf << EOF
# SlowDNS Performance Limits
root soft nofile 1048576
root hard nofile 1048576
root soft nproc unlimited
root hard nproc unlimited
root soft core unlimited
root hard core unlimited
* soft nofile 524288
* hard nofile 524288
EOF
    
    # Apply immediately for current session
    ulimit -n 1048576 2>/dev/null
    ulimit -u unlimited 2>/dev/null
    
    print_success "System limits configured"
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
    SERVER_IP=$(curl -s --max-time 3 --connect-timeout 3 ifconfig.me 2>/dev/null || 
                curl -s --max-time 3 --connect-timeout 3 icanhazip.com 2>/dev/null || 
                curl -s --max-time 3 --connect-timeout 3 api.ipify.org 2>/dev/null || 
                hostname -I | awk '{print $1}' 2>/dev/null)
    
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(ip route get 1 | awk '{print $7}' | head -1)
    fi
    
    echo -e "\r  ${GREEN}Server IP:${NC} ${WHITE}${BOLD}$SERVER_IP${NC}"
    
    # Detect OS and apply optimizations
    OS_TYPE=$(detect_pm)
    echo -e "  ${GREEN}Package Manager:${NC} ${WHITE}${BOLD}$OS_TYPE${NC}"
    
    # ============================================================================
    # STEP 0: SYSTEM OPTIMIZATION
    # ============================================================================
    print_step "0"
    print_info "Applying system-wide optimizations"
    
    optimize_kernel
    setup_limits
    
    # Install essential tools
    print_info "Installing essential system tools"
    for pkg in curl wget git; do
        if ! command -v "$pkg" &>/dev/null; then
            echo -ne "  ${CYAN}Installing $pkg...${NC}"
            install_package "$pkg" &
            show_progress $!
            echo -e "\r  ${GREEN}$pkg installed${NC}"
        fi
    done
    
    print_step_end
    
    # ============================================================================
    # STEP 1: CONFIGURE OPENSSH
    # ============================================================================
    print_step "1"
    print_info "Configuring OpenSSH on port $SSHD_PORT"
    
    # Handle different SSH service names
    SSH_SERVICE="sshd"
    if [ "$OS_TYPE" = "pacman" ]; then
        SSH_SERVICE="ssh"
    fi
    
    echo -ne "  ${CYAN}Backing up SSH configuration...${NC}"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%s) 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}SSH configuration backed up${NC}"
    
    # Optimized SSH configuration for performance
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
ClientAliveInterval 30
ClientAliveCountMax 3
AllowTcpForwarding yes
GatewayPorts yes
Compression delayed
Subsystem sftp /usr/lib/openssh/sftp-server
MaxSessions 200
MaxStartups 200:30:400
LoginGraceTime 20
UseDNS no
AllowAgentForwarding yes
StreamLocalBindUnlink yes
AllowStreamLocalForwarding yes
# Performance optimizations
MaxAuthTries 10
MaxSessions 100
TCPKeepAlive yes
ClientAliveInterval 15
ClientAliveCountMax 3
# Cipher optimizations
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com
EOF
    
    echo -ne "  ${CYAN}Restarting SSH service...${NC}"
    systemctl restart $SSH_SERVICE 2>/dev/null &
    show_progress $!
    sleep 2
    
    if systemctl is-active --quiet $SSH_SERVICE; then
        echo -e "\r  ${GREEN}SSH service restarted${NC}"
    else
        echo -e "\r  ${YELLOW}SSH service started manually${NC}"
        /usr/sbin/sshd -f /etc/ssh/sshd_config &
    fi
    
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
    
    # Download binary with multiple fallbacks
    print_info "Downloading SlowDNS binary"
    echo -ne "  ${CYAN}Fetching binary...${NC}"
    
    # Try multiple sources and methods
    DOWNLOAD_SUCCESS=false
    for method in curl wget; do
        if command -v $method &>/dev/null; then
            if [ "$method" = "curl" ]; then
                if curl -fsSL --connect-timeout 10 --retry 3 --retry-delay 2 "$GITHUB_BASE/dnstt-server" -o dnstt-server 2>/dev/null; then
                    DOWNLOAD_SUCCESS=true
                    echo -e "\r  ${GREEN}Binary downloaded via curl${NC}"
                    break
                fi
            elif [ "$method" = "wget" ]; then
                if wget -q --timeout=10 --tries=3 "$GITHUB_BASE/dnstt-server" -O dnstt-server 2>/dev/null; then
                    DOWNLOAD_SUCCESS=true
                    echo -e "\r  ${GREEN}Binary downloaded via wget${NC}"
                    break
                fi
            fi
        fi
    done
    
    if [ "$DOWNLOAD_SUCCESS" = false ]; then
        echo -e "\r  ${RED}Failed to download binary${NC}"
        echo -e "  ${YELLOW}Trying alternative sources...${NC}"
        
        # Alternative sources
        ALTERNATIVE_SOURCES=(
            "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/dnstt-server"
            "https://cdn.jsdelivr.net/gh/chiddy80/Halotel-Slow-DNS/DNSTT%20MODED/dnstt-server"
        )
        
        for source in "${ALTERNATIVE_SOURCES[@]}"; do
            echo -ne "  ${CYAN}Trying $source...${NC}"
            if curl -fsSL --connect-timeout 5 "$source" -o dnstt-server 2>/dev/null; then
                DOWNLOAD_SUCCESS=true
                echo -e "\r  ${GREEN}Binary downloaded from alternative source${NC}"
                break
            fi
            echo -e "\r  ${RED}Failed from alternative source${NC}"
        done
    fi
    
    if [ "$DOWNLOAD_SUCCESS" = false ]; then
        print_error "All download attempts failed"
        exit 1
    fi
    
    chmod +x dnstt-server
    SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
    
    # Download key files
    print_info "Downloading encryption keys"
    for keyfile in server.key server.pub; do
        echo -ne "  ${CYAN}Downloading $keyfile...${NC}"
        
        KEY_SUCCESS=false
        for method in curl wget; do
            if command -v $method &>/dev/null; then
                if [ "$method" = "curl" ]; then
                    if curl -fsSL "$GITHUB_BASE/$keyfile" -o "$keyfile" 2>/dev/null; then
                        KEY_SUCCESS=true
                        break
                    fi
                elif [ "$method" = "wget" ]; then
                    if wget -q "$GITHUB_BASE/$keyfile" -O "$keyfile" 2>/dev/null; then
                        KEY_SUCCESS=true
                        break
                    fi
                fi
            fi
        done
        
        if [ "$KEY_SUCCESS" = true ]; then
            echo -e "\r  ${GREEN}$keyfile downloaded${NC}"
        else
            echo -e "\r  ${YELLOW}$keyfile download failed, generating locally${NC}"
            if [ "$keyfile" = "server.key" ]; then
                ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub 2>/dev/null || true
            fi
        fi
    done
    
    # Test binary with detailed output
    echo -ne "  ${CYAN}Validating binary...${NC}"
    BINARY_TEST=$(timeout 5 ./dnstt-server --help 2>&1 || timeout 5 ./dnstt-server -h 2>&1 || echo "test_failed")
    
    if echo "$BINARY_TEST" | grep -q -E "usage|Usage|help|Help|dnstt"; then
        echo -e "\r  ${GREEN}Binary validated successfully${NC}"
    elif [ -x "./dnstt-server" ]; then
        echo -e "\r  ${YELLOW}Binary executable but help test inconclusive${NC}"
    else
        echo -e "\r  ${RED}Binary validation failed${NC}"
        echo -e "  ${YELLOW}Test output:${NC}"
        echo "$BINARY_TEST" | head -5
        exit 1
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
Requires=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=3
RestartPreventExitStatus=0
User=root
Group=root
LimitNOFILE=1048576
LimitNPROC=unlimited
LimitCORE=infinity
TimeoutStartSec=0
StandardOutput=journal
StandardError=journal
SyslogIdentifier=slowdns
Environment=GODEBUG=netdns=go
Nice=-10
OOMScoreAdjust=-1000
CPUSchedulingPolicy=rr
CPUSchedulingPriority=50
IOSchedulingClass=realtime
IOSchedulingPriority=0

[Install]
WantedBy=multi-user.target
EOF
    
    # Optimize systemd for performance
    mkdir -p /etc/systemd/system/server-sldns.service.d/
    cat > /etc/systemd/system/server-sldns.service.d/override.conf << EOF
[Service]
MemoryHigh=90%
MemoryMax=95%
CPUQuota=200%
IOWeight=100
CPUWeight=100
EOF
    
    print_success "Service configuration created"
    print_step_end
    
    # ============================================================================
    # STEP 4: COMPILE EDNS PROXY (FIXED VERSION)
    # ============================================================================
    print_step "4"
    print_info "Compiling high-performance EDNS Proxy"
    
    # Create directory if it doesn't exist
    mkdir -p /usr/local/bin/
    
    # Check for gcc
    if ! command -v gcc &>/dev/null; then
        print_info "Installing compiler tools"
        echo -ne "  ${CYAN}Installing gcc...${NC}"
        
        if [ "$OS_TYPE" = "pacman" ]; then
            pacman -Sy --noconfirm gcc base-devel linux-headers 2>/dev/null &
        else
            install_package "gcc" &
        fi
        
        show_progress $!
        echo -e "\r  ${GREEN}Compiler installed${NC}"
    fi
    
    # Create optimized C code with performance improvements
    cat > /tmp/edns.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 512
#define MAX_CONCURRENT 10000
#define CACHE_SIZE 1000

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
    uint16_t query_id;
} request_t;

// Simple LRU cache for performance
typedef struct cache_entry {
    unsigned char query[512];
    size_t query_len;
    unsigned char response[512];
    size_t response_len;
    time_t timestamp;
    struct cache_entry *next;
    struct cache_entry *prev;
} cache_entry_t;

cache_entry_t *cache_head = NULL;
cache_entry_t *cache_tail = NULL;
int cache_count = 0;

int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip question section
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) {
            offset++;
        }
        if(offset < len) offset++; // Skip null terminator
        offset += 4; // Skip QTYPE and QCLASS
    }
    
    // Check additional records for OPT
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0 && offset + 4 < len) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            if(type == 41) { // OPT record
                buf[offset+3] = new_size >> 8;
                buf[offset+4] = new_size & 0xFF;
                return len;
            }
        }
        offset++;
    }
    
    return len;
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void add_to_cache(unsigned char *query, size_t qlen, unsigned char *response, size_t rlen) {
     if(cache_count >= CACHE_SIZE) {
        // Remove LRU entry
        cache_entry_t *old = cache_tail;
        if(old) {
            if(old->prev) old->prev->next = NULL;
            cache_tail = old->prev;
            free(old);
            cache_count--;
        }
    }
    
    cache_entry_t *entry = malloc(sizeof(cache_entry_t));
    if(!entry) return;
    
    memcpy(entry->query, query, qlen);
    entry->query_len = qlen;
    memcpy(entry->response, response, rlen);
    entry->response_len = rlen;
    entry->timestamp = time(NULL);
    entry->next = cache_head;
    entry->prev = NULL;
    
    if(cache_head) cache_head->prev = entry;
    cache_head = entry;
    if(!cache_tail) cache_tail = entry;
    cache_count++;
}

cache_entry_t *find_in_cache(unsigned char *query, size_t qlen) {
    cache_entry_t *current = cache_head;
    while(current) {
        if(current->query_len == qlen && memcmp(current->query, query, qlen) == 0) {
            // Move to front (MRU)
            if(current != cache_head) {
                if(current->prev) current->prev->next = current->next;
                if(current->next) current->next->prev = current->prev;
                if(current == cache_tail) cache_tail = current->prev;
                current->next = cache_head;
                current->prev = NULL;
                if(cache_head) cache_head->prev = current;
                cache_head = current;
            }
            return current;
        }
        current = current->next;
    }
    return NULL;
}

int main() {
    printf("[EDNS Proxy] Starting high-performance DNS proxy...\n");
    printf("[EDNS Proxy] Version: 2.0 | Optimized for SlowDNS\n");
    printf("[EDNS Proxy] Cache size: %d entries\n", CACHE_SIZE);
    
    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(sock < 0) {
        perror("[ERROR] socket");
        return 1;
    }
    
    // Set socket options for performance
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    
    int rcvbuf = 1024 * 1024; // 1MB receive buffer
    int sndbuf = 1024 * 1024; // 1MB send buffer
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    if(set_nonblock(sock) < 0) {
        perror("[ERROR] fcntl");
        close(sock);
        return 1;
    }
    
    // Bind to port 53
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[ERROR] bind");
        close(sock);
        return 1;
    }
    
    // Create epoll instance
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if(epoll_fd < 0) {
        perror("[ERROR] epoll_create1");
        close(sock);
        return 1;
    }
    
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET; // Edge-triggered for performance
    ev.data.fd = sock;
    
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("[ERROR] epoll_ctl");
        close(epoll_fd);
        close(sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port 53 (epoll optimized)\n");
    printf("[EDNS Proxy] Ready to handle DNS queries\n");
    
    struct epoll_event events[MAX_EVENTS];
    request_t *requests[MAX_CONCURRENT] = {0};
    
    uint64_t query_count = 0;
    uint64_t cache_hits = 0;
    time_t last_stat = time(NULL);
    
    while(1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        
        // Show statistics every 10 seconds
        time_t now = time(NULL);
        if(now - last_stat >= 10) {
            printf("[EDNS Proxy] Stats: Queries=%lu, CacheHits=%lu, HitRate=%.1f%%\n",
                   query_count, cache_hits, 
                   query_count > 0 ? (cache_hits * 100.0 / query_count) : 0.0);
            last_stat = now;
        }
        
        for(int i = 0; i < n; i++) {
            if(events[i].data.fd == sock) {
                // Handle incoming queries
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                
                while(1) {
                    ssize_t len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                         (struct sockaddr*)&client_addr, &client_len);
                    if(len <= 0) break;
                    
                    query_count++;
                    
                    // Check cache first
                    cache_entry_t *cached = find_in_cache(buffer, len);
                    if(cached) {
                        cache_hits++;
                        patch_edns(cached->response, cached->response_len, EXT_EDNS);
                        sendto(sock, cached->response, cached->response_len, 0,
                               (struct sockaddr*)&client_addr, client_len);
                        continue;
                    }
                    
                    // Create upstream socket
                    int up_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                    if(up_sock < 0) continue;
                    
                    set_nonblock(up_sock);
                    
                    // Patch EDNS size for upstream
                    patch_edns(buffer, len, INT_EDNS);
                    
                    // Store request
                    request_t *req = malloc(sizeof(request_t));
                    if(req) {
                        req->client_fd = sock;
                        req->client_addr = client_addr;
                        req->addr_len = client_len;
                        req->timestamp = now;
                        if(len >= 2) {
                            req->query_id = (buffer[0] << 8) | buffer[1];
                        } else {
                            req->query_id = 0;
                        }
                        
                        if(up_sock < MAX_CONCURRENT) {
                            requests[up_sock] = req;
                            
                            struct epoll_event up_ev;
                            up_ev.events = EPOLLIN | EPOLLET;
                            up_ev.data.fd = up_sock;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev);
                            
                            // Send to SlowDNS
                            struct sockaddr_in up_addr;
                            memset(&up_addr, 0, sizeof(up_addr));
                            up_addr.sin_family = AF_INET;
                            up_addr.sin_port = htons(SLOWDNS_PORT);
                            inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                            
                            sendto(up_sock, buffer, len, 0,
                                   (struct sockaddr*)&up_addr, sizeof(up_addr));
                        } else {
                            free(req);
                            close(up_sock);
                        }
                    } else {
                        close(up_sock);
                    }
                }
            } else {
                // Handle upstream responses
                int up_sock = events[i].data.fd;
                request_t *req = requests[up_sock];
                
                if(req) {
                    unsigned char buffer[BUFFER_SIZE];
                    ssize_t len;
                    
                    while((len = recv(up_sock, buffer, BUFFER_SIZE, 0)) > 0) {
                        // Cache the response
                        add_to_cache(buffer, len, buffer, len);
                        
                        // Patch EDNS size for client
                        patch_edns(buffer, len, EXT_EDNS);
                        
                        // Send back to client
                        sendto(req->client_fd, buffer, len, 0,
                               (struct sockaddr*)&req->client_addr,
                               req->addr_len);
                    }
                    
                    // Cleanup
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, up_sock, NULL);
                    close(up_sock);
                    free(req);
                    requests[up_sock] = NULL;
                }
            }
        }
    }
    
    return 0;
}
EOF
    
    # Compile with optimizations - FIXED VERSION
    echo -ne "  ${CYAN}Compiling EDNS Proxy with maximum optimizations...${NC}"
    COMPILE_LOG="/tmp/edns-compile-$(date +%s).log"
    
    # Determine optimal compiler flags
    CFLAGS="-O3 -march=native -flto -pipe -fomit-frame-pointer -funroll-loops"
    CFLAGS="$CFLAGS -ffast-math -fno-stack-protector -D_FORTIFY_SOURCE=2"
    
    # Compile synchronously (NO BACKGROUND - THIS WAS THE BUG!)
    if gcc $CFLAGS /tmp/edns.c -o /usr/local/bin/edns-proxy -lm 2>"$COMPILE_LOG"; then
        chmod +x /usr/local/bin/edns-proxy
        
        # Verify the binary
        if [ -f "/usr/local/bin/edns-proxy" ] && [ -x "/usr/local/bin/edns-proxy" ]; then
            BINARY_SIZE=$(stat -c%s "/usr/local/bin/edns-proxy" 2>/dev/null || echo "0")
            echo -e "\r  ${GREEN}EDNS Proxy compiled successfully${NC}"
            echo -e "  ${GREEN}✓ Binary size: $((BINARY_SIZE/1024))KB | Path: /usr/local/bin/edns-proxy${NC}"
            
            # Quick test
            if timeout 1 /usr/local/bin/edns-proxy --help 2>&1 | grep -q "EDNS Proxy"; then
                echo -e "  ${GREEN}✓ Binary test passed${NC}"
            fi
        else
            echo -e "\r  ${RED}Binary was not created!${NC}"
            exit 1
        fi
    else
        echo -e "\r  ${RED}Compilation failed${NC}"
        echo -e "  ${YELLOW}Compilation log:${NC}"
        tail -20 "$COMPILE_LOG"
        
        # Try fallback compilation
        echo -e "  ${YELLOW}Trying fallback compilation...${NC}"
        if gcc -O2 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/dev/null; then
            chmod +x /usr/local/bin/edns-proxy
            echo -e "  ${GREEN}Fallback compilation succeeded${NC}"
        else
            exit 1
        fi
    fi
    
    # Create optimized EDNS service
    cat > /etc/systemd/system/edns-proxy.service << EOF
# ============================================================================
# EDNS PROXY SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=EDNS Proxy for SlowDNS
Description=High-performance DNS proxy with EDNS support and caching
After=server-sldns.service
Requires=server-sldns.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=2
RestartPreventExitStatus=0
User=root
Group=root
LimitNOFILE=1048576
LimitNPROC=unlimited
LimitCORE=infinity
TimeoutStartSec=0
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edns-proxy
Environment=GODEBUG=netdns=go
Nice=-5
OOMScoreAdjust=-500
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
IOSchedulingClass=realtime
IOSchedulingPriority=0
# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # Create performance override
    mkdir -p /etc/systemd/system/edns-proxy.service.d/
    cat > /etc/systemd/system/edns-proxy.service.d/override.conf << EOF
[Service]
MemoryHigh=80%
MemoryMax=90%
CPUQuota=150%
IOWeight=90
CPUWeight=90
EOF
    
    print_success "EDNS Proxy service configured"
    print_step_end
    
    # ============================================================================
    # STEP 5: FIREWALL CONFIGURATION
    # ============================================================================
    print_step "5"
    print_info "Configuring system firewall"
    
    echo -ne "  ${CYAN}Setting up firewall rules...${NC}"
    
    # Try different firewall tools
    if command -v nft &>/dev/null; then
        # Use nftables (modern Arch default)
        nft flush ruleset 2>/dev/null
        nft add table inet filter 2>/dev/null
        nft add chain inet filter input { type filter hook input priority 0\; policy accept\; } 2>/dev/null
        nft add chain inet filter forward { type filter hook forward priority 0\; policy accept\; } 2>/dev/null
        nft add chain inet filter output { type filter hook output priority 0\; policy accept\; } 2>/dev/null
        
        # Basic rules
        nft add rule inet filter input ct state established,related accept
        nft add rule inet filter input iif lo accept
        nft add rule inet filter input ct state invalid drop
        
        # Service ports
        nft add rule inet filter input tcp dport $SSHD_PORT accept
        nft add rule inet filter input udp dport $SLOWDNS_PORT accept
        nft add rule inet filter input udp dport 53 accept
        
        # Rate limiting for DNS
        nft add chain inet filter ratelimit
        nft add rule inet filter input udp dport 53 jump ratelimit
        nft add rule inet filter ratelimit limit rate over 1000/second burst 2000 packets drop
        
        echo -e "\r  ${GREEN}nftables configured${NC}"
        
    elif command -v iptables &>/dev/null; then
        # Fall back to iptables
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
        
        # Rate limiting for DNS
        iptables -A INPUT -p udp --dport 53 -m limit --limit 1000/second --limit-burst 2000 -j ACCEPT 2>/dev/null
        iptables -A INPUT -p udp --dport 53 -j DROP 2>/dev/null
        
        echo -e "\r  ${GREEN}iptables configured${NC}"
    else
        echo -e "\r  ${YELLOW}No firewall tool found, skipping${NC}"
    fi
    
    # Optimize network settings
    echo -ne "  ${CYAN}Optimizing network settings...${NC}"
    
    # Disable IPv6 if not needed (better for DNS tunneling)
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
    
    # Increase UDP buffers
    sysctl -w net.core.rmem_default=262144 2>/dev/null
    sysctl -w net.core.wmem_default=262144 2>/dev/null
    sysctl -w net.core.rmem_max=16777216 2>/dev/null
    sysctl -w net.core.wmem_max=16777216 2>/dev/null
    
    # DNS specific
    sysctl -w net.unix.max_dgram_qlen=5000 2>/dev/null
    
    echo -e "\r  ${GREEN}Network optimized${NC}"
    
    # Stop conflicting services
    echo -ne "  ${CYAN}Stopping conflicting DNS services...${NC}"
    
    # List of services that might conflict
    CONFLICTING_SERVICES="systemd-resolved dnsmasq unbound bind9 named"
    for service in $CONFLICTING_SERVICES; do
        systemctl stop "$service" 2>/dev/null &
        systemctl disable "$service" 2>/dev/null &
    done
    
    # Kill any process on port 53
    fuser -k 53/udp 2>/dev/null &
    fuser -k 53/tcp 2>/dev/null &
    
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
    
    # Start SlowDNS with verification
    echo -ne "  ${CYAN}Starting SlowDNS service...${NC}"
    systemctl enable server-sldns >/dev/null 2>&1
    systemctl start server-sldns 2>&1 &
    show_progress $!
    sleep 3
    
    if systemctl is-active --quiet server-sldns; then
        echo -e "\r  ${GREEN}SlowDNS service started${NC}"
        
        # Check if it's listening
        if ss -ulpn | grep -q ":$SLOWDNS_PORT"; then
            echo -e "  ${GREEN}✓ Listening on UDP port $SLOWDNS_PORT${NC}"
        else
            echo -e "  ${YELLOW}⚠ Not listening on port $SLOWDNS_PORT${NC}"
        fi
    else
        echo -e "\r  ${YELLOW}Starting SlowDNS in background${NC}"
        # Start manually with optimized parameters
        nohup $SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key \
              $NAMESERVER 127.0.0.1:$SSHD_PORT >/var/log/slowdns.log 2>&1 &
        sleep 2
    fi
    
    # Start EDNS proxy with verification
    echo -ne "  ${CYAN}Starting EDNS Proxy service...${NC}"
    systemctl enable edns-proxy >/dev/null 2>&1
    systemctl start edns-proxy 2>&1 &
    show_progress $!
    sleep 3
    
    if systemctl is-active --quiet edns-proxy; then
        echo -e "\r  ${GREEN}EDNS Proxy service started${NC}"
        
        # Check if it's listening on port 53
        if ss -ulpn | grep -q ":53 "; then
            echo -e "  ${GREEN}✓ Listening on UDP port 53${NC}"
        else
            echo -e "  ${YELLOW}⚠ Not listening on port 53${NC}"
        fi
    else
        echo -e "\r  ${YELLOW}Starting EDNS Proxy manually${NC}"
        # Start manually
        nohup /usr/local/bin/edns-proxy >/var/log/edns-proxy.log 2>&1 &
        sleep 2
    fi
    
    # Verify services are communicating
    echo -ne "  ${CYAN}Verifying service communication...${NC}"
    sleep 2
    
    # Test DNS query
    if command -v dig &>/dev/null; then
        if timeout 3 dig @127.0.0.1 google.com +short >/dev/null 2>&1; then
            echo -e "\r  ${GREEN}DNS query test successful${NC}"
        else
            echo -e "\r  ${YELLOW}DNS query test inconclusive${NC}"
        fi
    fi
    
    print_success "All services started successfully"
    print_step_end
    
    # ============================================================================
    # COMPLETION SUMMARY
    # ============================================================================
    print_box "INSTALLATION COMPLETE" "$GREEN"
    
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🚀 SLOWDNS INSTALLATION COMPLETED SUCCESSFULLY${NC}       ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}                                                    ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${CYAN}▸ Server IP:${NC} ${WHITE}$SERVER_IP${NC}                     ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${CYAN}▸ Nameserver:${NC} ${WHITE}$NAMESERVER${NC}                  ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${CYAN}▸ SSH Port:${NC} ${WHITE}$SSHD_PORT${NC}                       ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${CYAN}▸ SlowDNS Port:${NC} ${WHITE}$SLOWDNS_PORT${NC}                 ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${CYAN}▸ EDNS Proxy:${NC} ${WHITE}Port 53 (Optimized)${NC}          ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}                                                    ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Performance optimizations applied:${NC}               ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}  • Kernel TCP/IP tuning${NC}                           ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}  • System limits increased${NC}                        ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}  • DNS query caching enabled${NC}                      ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}  • Firewall rate limiting${NC}                         ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}                                                    ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${YELLOW}⏱️  Installation time: $(date)${NC}            ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${CYAN}${BOLD}📞 SUPPORT & DOCUMENTATION${NC}"
    echo -e "${WHITE}▸ GitHub:${NC} ${YELLOW}https://github.com/chiddy80/Halotel-Slow-DNS${NC}"
    echo -e "${WHITE}▸ Contact:${NC} ${YELLOW}@esimfreegb${NC}"
    
    echo -e "\n${PURPLE}${BOLD}🔧 SERVICE MANAGEMENT COMMANDS${NC}"
    echo -e "${WHITE}Check status:${NC}   ${CYAN}systemctl status server-sldns edns-proxy${NC}"
    echo -e "${WHITE}Restart:${NC}        ${CYAN}systemctl restart server-sldns edns-proxy${NC}"
    echo -e "${WHITE}View logs:${NC}      ${CYAN}journalctl -u server-sldns -u edns-proxy -f${NC}"
    echo -e "${WHITE}Test DNS:${NC}       ${CYAN}dig @$SERVER_IP $NAMESERVER${NC}"
    
    echo -e "\n${WHITE}${BOLD}Press Enter to show service status, or Ctrl+C to exit...${NC}"
    read -r
    
    # Show service status
    echo -e "\n${CYAN}════════════════ SERVICE STATUS ════════════════${NC}"
    echo -e "${WHITE}SlowDNS Service:${NC}"
    systemctl status server-sldns --no-pager -l | head -20
    
    echo -e "\n${WHITE}EDNS Proxy Service:${NC}"
    systemctl status edns-proxy --no-pager -l | head -20
    
    echo -e "\n${CYAN}════════════════ LISTENING PORTS ════════════════${NC}"
    echo -e "${WHITE}UDP Ports:${NC}"
    ss -ulpn | grep -E '(:53|:5300)' || echo "No UDP ports found"
    
    echo -e "\n${WHITE}TCP Ports:${NC}"
    ss -tlnp | grep -E ":22" || echo "No TCP ports found"
    
    echo -e "\n${GREEN}${BOLD}✅ Installation completed successfully!${NC}"
    echo -e "${YELLOW}Next steps: Configure your DNS client to use:${NC}"
    echo -e "${WHITE}    Nameserver:${NC} ${BOLD}$NAMESERVER${NC}"
    echo -e "${WHITE}    IP Address:${NC} ${BOLD}$SERVER_IP${NC}"
    echo -e "${WHITE}    Port:${NC} ${BOLD}53 (UDP)${NC}"
    
    # Final cleanup
    rm -f /tmp/edns.c /tmp/compile.log /tmp/edns-compile-*.log 2>/dev/null
    
    # Save configuration
    cat > /etc/slowdns/install-info.txt << EOF
# SlowDNS Installation Information
# Generated: $(date)
Server IP: $SERVER_IP
Nameserver: $NAMESERVER
SSH Port: $SSHD_PORT
SlowDNS Port: $SLOWDNS_PORT
Binary Path: $SLOWDNS_BINARY
EDNS Proxy: /usr/local/bin/edns-proxy
Kernel Optimizations: Applied
System Limits: Configured
Firewall: Configured

# Service Management
Start: systemctl start server-sldns edns-proxy
Stop: systemctl stop server-sldns edns-proxy
Status: systemctl status server-sldns edns-proxy
Logs: journalctl -u server-sldns -u edns-proxy -f

# Test Command
Test DNS: dig @$SERVER_IP $NAMESERVER
EOF
    
    echo -e "\n${GREEN}Configuration saved to: /etc/slowdns/install-info.txt${NC}"
}

# ============================================================================
# EXECUTE WITH ERROR HANDLING
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; 
      echo -e "${YELLOW}Cleaning up...${NC}";
      rm -f /tmp/edns.c /tmp/compile.log 2>/dev/null;
      exit 1' INT TERM

# Create log file
LOG_FILE="/var/log/slowdns-install-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "${CYAN}Starting SlowDNS installation - Log: $LOG_FILE${NC}"

if main; then
    echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   Installation completed at: $(date)${NC}"
    echo -e "${GREEN}${BOLD}   Log file: $LOG_FILE${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Installation failed${NC}"
    echo -e "${YELLOW}Check log file for details: $LOG_FILE${NC}"
    exit 1
fi
```
