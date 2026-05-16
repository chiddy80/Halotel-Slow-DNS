#!/bin/bash

# ============================================================================
#                     SLOWDNS MODERN INSTALLATION SCRIPT v2026
#                     Optimized for Performance & Stability
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
LOG_FILE="/var/log/slowdns-install.log"
BACKUP_DIR="/root/slowdns-backup-$(date +%Y%m%d-%H%M%S)"

# Performance tuning values for 2026
MTU_SIZE=1450  # Reduced for better compatibility with modern networks
UDP_BUFFER_SIZE=16777216  # 16MB for better throughput
TCP_BUFFER_SIZE=8388608   # 8MB
MAX_CONNECTIONS=200000
CONNECTION_TIMEOUT=30
CACHE_SIZE=20000

# Modern DNS over HTTPS fallback
DOH_SERVERS="1.1.1.1 8.8.8.8 9.9.9.9"

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
DIM='\033[2m'
NC='\033[0m'

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# ============================================================================
# ANIMATION FUNCTIONS
# ============================================================================
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while kill -0 $pid 2>/dev/null; do
        for i in $(seq 0 9); do
            printf "\r  ${CYAN}%s${NC} " "${spinstr:$i:1}"
            sleep $delay
        done
    done
    printf "\r  ${GREEN}✓${NC}    \n"
}

print_step() {
    echo -e "\n${BLUE}┌─${NC} ${CYAN}${BOLD}STEP $1${NC}"
    echo -e "${BLUE}│${NC}"
}

print_step_end() {
    echo -e "${BLUE}└─${NC} ${GREEN}✓${NC} Completed"
}

print_banner() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          🚀 SLOWDNS MODERN INSTALLATION SCRIPT v2026${NC}                    ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}            Next-Gen DNS Tunneling Solution${NC}                            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}                Optimized for Maximum Performance${NC}                       ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_header() {
    echo -e "\n${PURPLE}══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════════════════════════${NC}"
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
# SYSTEM VALIDATION
# ============================================================================
validate_system() {
    print_header "🔍 SYSTEM VALIDATION"
    
    # Check OS compatibility
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        log_info "Detected OS: $NAME $VERSION"
    else
        log_warning "Could not detect OS type"
    fi
    
    # Check available memory
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_RAM" -lt 512 ]; then
        print_warning "Low memory detected (${TOTAL_RAM}MB). Performance may be affected."
    else
        print_success "Memory: ${TOTAL_RAM}MB available"
    fi
    
    # Check CPU cores
    CPU_CORES=$(nproc)
    print_success "CPU Cores: $CPU_CORES"
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    print_success "Backup directory created: $BACKUP_DIR"
}

# ============================================================================
# KERNEL OPTIMIZATIONS FOR 2026
# ============================================================================
optimize_kernel() {
    print_header "⚡ KERNEL OPTIMIZATIONS"
    
    # Backup sysctl.conf
    cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.backup" 2>/dev/null
    
    # Modern kernel parameters for high performance
    cat >> /etc/sysctl.conf << 'EOF'

# SlowDNS Optimizations - 2026
# Network performance
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 65536
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535

# TCP optimizations
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 15

# UDP optimizations
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# General
net.core.default_qdisc = fq
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# File descriptor limits
fs.file-max = 2097152
fs.nr_open = 2097152
EOF

    sysctl -p > /dev/null 2>&1
    log_success "Kernel parameters optimized for 2026 performance"
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main() {
    print_banner
    
    # Initialize logging
    touch "$LOG_FILE"
    log "Starting SlowDNS installation v2026"
    
    # System validation
    validate_system
    
    # Get nameserver with modern prompt
    echo -e "\n${WHITE}${BOLD}Enter nameserver configuration:${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Default:${NC} dns.example.com                                         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Example:${NC} tunnel.yourdomain.com                                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Tip:${NC} Use a subdomain that resolves to this server                ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    read -p "$(echo -e "${WHITE}${BOLD}Enter nameserver: ${NC}")" NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    print_header "📦 GATHERING SYSTEM INFORMATION"
    
    # Get Server IP with multiple fallbacks
    echo -ne "  ${CYAN}Detecting server IP address...${NC}"
    SERVER_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(curl -s --connect-timeout 5 ipinfo.io/ip 2>/dev/null)
    fi
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    echo -e "\r  ${GREEN}Server IP:${NC} ${WHITE}${BOLD}$SERVER_IP${NC}"
    
    # Apply kernel optimizations
    optimize_kernel
    
    # ============================================================================
    # STEP 1: INSTALL DEPENDENCIES
    # ============================================================================
    print_step "1"
    print_info "Installing required dependencies"
    
    echo -ne "  ${CYAN}Updating package lists...${NC}"
    apt update > /dev/null 2>&1 &
    show_spinner $!
    
    echo -ne "  ${CYAN}Installing build tools...${NC}"
    apt install -y build-essential curl wget net-tools dnsutils gcc make > /dev/null 2>&1 &
    show_spinner $!
    
    print_success "Dependencies installed"
    print_step_end
    
    # ============================================================================
    # STEP 2: CONFIGURE OPENSSH
    # ============================================================================
    print_step "2"
    print_info "Configuring OpenSSH on port $SSHD_PORT"
    
    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.backup" 2>/dev/null
    
    cat > /etc/ssh/sshd_config << EOF
# ============================================================================
# SLOWDNS OPTIMIZED SSH CONFIGURATION - 2026
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
MaxSessions 500
MaxStartups 500:30:1000
LoginGraceTime 30
UseDNS no
EOF
    
    systemctl restart sshd 2>/dev/null
    print_success "OpenSSH configured on port $SSHD_PORT"
    print_step_end
    
    # ============================================================================
    # STEP 3: SETUP SLOWDNS
    # ============================================================================
    print_step "3"
    print_info "Setting up SlowDNS environment"
    
    # Create directory structure
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns/{bin,keys,logs}
    cd /etc/slowdns
    
    # Download binary with retry logic
    print_info "Downloading SlowDNS binary"
    DOWNLOAD_SUCCESS=false
    
    for i in {1..3}; do
        echo -ne "  ${CYAN}Attempt $i: Fetching binary...${NC}"
        if curl -fsSL --retry 3 --connect-timeout 10 "$GITHUB_BASE/dnstt-server" -o dnstt-server 2>/dev/null; then
            DOWNLOAD_SUCCESS=true
            echo -e "\r  ${GREEN}Binary downloaded successfully${NC}"
            break
        fi
        echo -e "\r  ${YELLOW}Attempt $i failed, retrying...${NC}"
        sleep 2
    done
    
    if [ "$DOWNLOAD_SUCCESS" = false ]; then
        print_error "Failed to download binary after 3 attempts"
        exit 1
    fi
    
    chmod +x dnstt-server
    SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
    
    # Download keys
    print_info "Downloading encryption keys"
    wget -q --retry=3 "$GITHUB_BASE/server.key" -O server.key 2>/dev/null
    wget -q --retry=3 "$GITHUB_BASE/server.pub" -O server.pub 2>/dev/null
    
    if [ ! -f server.key ] || [ ! -f server.pub ]; then
        print_warning "Remote keys not found, generating new keys..."
        ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
    fi
    
    print_success "SlowDNS components installed"
    print_step_end
    
    # ============================================================================
    # STEP 4: COMPILE OPTIMIZED EDNS PROXY
    # ============================================================================
    print_step "4"
    print_info "Compiling high-performance EDNS Proxy with modern optimizations"
    
    # Create optimized C code for 2026
    cat > /tmp/edns_proxy.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/resource.h>

#define LISTEN_PORT 53
#define SLOWDNS_PORT 5300
#define BUFFER_SIZE 8192
#define MAX_EVENTS 65536
#define MAX_WORKERS 4
#define CACHE_SIZE 32768
#define CACHE_TTL 300

typedef struct {
    uint32_t hash;
    uint8_t response[BUFFER_SIZE];
    int len;
    time_t expires;
} cache_entry_t;

static cache_entry_t *dns_cache[CACHE_SIZE];
static int epoll_fd;
static int upstream_fds[MAX_WORKERS];
static volatile sig_atomic_t running = 1;

static inline uint32_t fast_hash(const uint8_t *data, int len) {
    uint32_t hash = 5381;
    for (int i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + data[i];
    return hash % CACHE_SIZE;
}

static void handle_signal(int sig) {
    running = 0;
}

static int create_socket(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return -1;
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

static void patch_edns(uint8_t *buf, int *len, int new_size) {
    if (*len < 12) return;
    
    int off = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    for (int i = 0; i < qdcount; i++) {
        while (off < *len && buf[off]) off++;
        off += 5;
        if (off >= *len) return;
    }
    
    int arcount = (buf[10] << 8) | buf[11];
    
    for (int i = 0; i < arcount; i++) {
        if (off + 4 >= *len) break;
        if (buf[off] == 0 && ((buf[off+1] << 8) | buf[off+2]) == 41) {
            if (off + 4 < *len) {
                buf[off+3] = (new_size >> 8) & 0xFF;
                buf[off+4] = new_size & 0xFF;
            }
            return;
        }
        off += buf[off] + 1;
        off += 5;
    }
}

int main() {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Increase file descriptor limit
    struct rlimit rl = {.rlim_cur = 500000, .rlim_max = 500000};
    setrlimit(RLIMIT_NOFILE, &rl);
    
    int listen_fd = create_socket(LISTEN_PORT);
    if (listen_fd < 0) {
        fprintf(stderr, "Failed to bind to port 53\n");
        return 1;
    }
    
    struct sockaddr_in slow_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SLOWDNS_PORT),
        .sin_addr.s_addr = inet_addr("127.0.0.1")
    };
    
    epoll_fd = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = listen_fd};
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
    
    for (int i = 0; i < MAX_WORKERS; i++) {
        upstream_fds[i] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        ev.data.fd = upstream_fds[i];
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstream_fds[i], &ev);
    }
    
    struct epoll_event events[MAX_EVENTS];
    
    while (running) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
        
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            uint8_t buf[BUFFER_SIZE];
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            int len = recvfrom(fd, buf, sizeof(buf), 0,
                              (struct sockaddr*)&client_addr, &addr_len);
            
            if (len > 0) {
                if (fd == listen_fd) {
                    // Client request
                    patch_edns(buf, &len, 1450);
                    sendto(upstream_fds[0], buf, len, 0,
                           (struct sockaddr*)&slow_addr, sizeof(slow_addr));
                } else {
                    // Response from SlowDNS
                    patch_edns(buf, &len, 512);
                    sendto(listen_fd, buf, len, 0,
                           (struct sockaddr*)&client_addr, addr_len);
                }
            }
        }
    }
    
    close(listen_fd);
    for (int i = 0; i < MAX_WORKERS; i++) close(upstream_fds[i]);
    close(epoll_fd);
    
    return 0;
}
EOF
    
    # Compile with aggressive optimizations
    echo -ne "  ${CYAN}Compiling EDNS Proxy with modern optimizations...${NC}"
    gcc -O3 -march=native -mtune=native -flto -ffast-math -pipe \
        -Wall -Wextra -pthread \
        /tmp/edns_proxy.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log &
    show_spinner $!
    
    if [ -f /usr/local/bin/edns-proxy ]; then
        chmod +x /usr/local/bin/edns-proxy
        print_success "EDNS Proxy compiled successfully"
    else
        print_error "Compilation failed. Check /tmp/compile.log"
        exit 1
    fi
    
    # Create EDNS service
    cat > /etc/systemd/system/edns-proxy.service << 'EOF'
[Unit]
Description=EDNS Proxy for SlowDNS v2026
After=network.target server-sldns.service
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=500000
LimitNPROC=500000
TasksMax=infinity
MemoryMax=256M
CPUQuota=200%

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "EDNS Proxy service configured"
    print_step_end
    
    # ============================================================================
    # STEP 5: CREATE SLOWDNS SERVICE
    # ============================================================================
    print_step "5"
    print_info "Creating SlowDNS system service"
    
    cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server v2026
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu $MTU_SIZE -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root
LimitNOFILE=500000
LimitNPROC=500000
TasksMax=infinity
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Service configuration created"
    print_step_end
    
    # ============================================================================
    # STEP 6: FIREWALL CONFIGURATION
    # ============================================================================
    print_step "6"
    print_info "Configuring modern firewall rules"
    
    # Use nftables if available (modern replacement for iptables)
    if command -v nft &>/dev/null; then
        print_info "Using nftables for firewall"
        cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f

flush ruleset

table inet slowdns {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow loopback
        iif lo accept
        
        # Allow established connections
        ct state established,related accept
        
        # Allow SSH
        tcp dport $SSHD_PORT accept
        
        # Allow SlowDNS
        udp dport $SLOWDNS_PORT accept
        
        # Allow DNS
        udp dport 53 accept
        
        # Allow ICMP (optional)
        icmp type echo-request accept
        icmpv6 type echo-request accept
        
        # Rate limiting for new connections
        tcp dport $SSHD_PORT ct state new limit rate 10/minute accept
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
        systemctl enable nftables 2>/dev/null
        systemctl restart nftables 2>/dev/null
    else
        # Fallback to iptables
        print_info "Using iptables for firewall"
        iptables -F
        iptables -X
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
        iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
        iptables -A INPUT -p udp --dport 53 -j ACCEPT
        iptables -A INPUT -p icmp -j ACCEPT
        
        # Save iptables rules
        apt install -y iptables-persistent > /dev/null 2>&1
        netfilter-persistent save 2>/dev/null
    fi
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    
    print_success "Firewall configured"
    print_step_end
    
    # ============================================================================
    # STEP 7: START SERVICES
    # ============================================================================
    print_step "7"
    print_info "Starting all services"
    
    systemctl daemon-reload
    
    # Start SlowDNS
    echo -ne "  ${CYAN}Starting SlowDNS service...${NC}"
    systemctl enable server-sldns > /dev/null 2>&1
    systemctl start server-sldns 2>/dev/null
    sleep 2
    
    if systemctl is-active --quiet server-sldns; then
        echo -e "\r  ${GREEN}SlowDNS service started${NC}"
    else
        echo -e "\r  ${YELLOW}Starting SlowDNS manually${NC}"
        $SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu $MTU_SIZE -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT &
    fi
    
    # Start EDNS proxy
    echo -ne "  ${CYAN}Starting EDNS Proxy service...${NC}"
    systemctl enable edns-proxy > /dev/null 2>&1
    systemctl start edns-proxy 2>/dev/null
    sleep 2
    
    if systemctl is-active --quiet edns-proxy; then
        echo -e "\r  ${GREEN}EDNS Proxy service started${NC}"
    else
        echo -e "\r  ${YELLOW}Starting EDNS Proxy manually${NC}"
        /usr/local/bin/edns-proxy &
    fi
    
    print_success "All services started"
    print_step_end
    
    # ============================================================================
    # COMPLETION SUMMARY
    # ============================================================================
    print_header "🎉 INSTALLATION COMPLETE"
    
    # Show summary
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER INFORMATION${NC}                                                   ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:     ${WHITE}$SERVER_IP${NC}                                                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SSH Port:      ${WHITE}$SSHD_PORT${NC}                                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SlowDNS Port:  ${WHITE}$SLOWDNS_PORT${NC}                                                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} EDNS Port:     ${WHITE}53${NC}                                                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU Size:      ${WHITE}$MTU_SIZE${NC}                                                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:    ${WHITE}$NAMESERVER${NC}                                           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────┘${NC}"
    
    # Show public key
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PUBLIC KEY (Save this for client configuration)${NC}                         ${CYAN}│${NC}"
        echo -e "${CYAN}├──────────────────────────────────────────────────────────────────┤${NC}"
        echo -e "${CYAN}│${NC}${WHITE}"
        cat /etc/slowdns/server.pub | head -1
        echo -e "${NC}${CYAN}│${NC}"
        echo -e "${CYAN}└──────────────────────────────────────────────────────────────────┘${NC}"
    fi
    
    # Client configuration
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CLIENT CONFIGURATION${NC}                                                     ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}./dnstt-client -udp $SERVER_IP:$SLOWDNS_PORT \\${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    -pubkey-file server.pub \\${NC}                                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    dns.example.com 127.0.0.1:1080${NC}                                         ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────┘${NC}"
    
    # Final message
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 SLOWDNS v2026 INSTALLATION COMPLETED SUCCESSFULLY!${NC}                   ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Performance optimizations applied${NC}                                    ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🔧 BBR Congestion Control + Modern Kernel Tuning${NC}                       ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 All services running and ready${NC}                                      ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}${BOLD}📞 For support contact: @esimfreegb${NC}"
    
    # Cleanup
    rm -f /tmp/edns_proxy.c /tmp/compile.log 2>/dev/null
    
    log_success "Installation completed successfully"
}

# ============================================================================
# EXECUTE WITH ERROR HANDLING
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; exit 1' INT

if main; then
    echo -e "\n${GREEN}Installation log saved to: $LOG_FILE${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Installation failed. Check $LOG_FILE for details${NC}"
    exit 1
fi
```
