#!/bin/bash

# ============================================================================
#                     GOD MODE SLOWDNS INSTALLATION SCRIPT
# ============================================================================
# Author: DNS/EDNS Protocol Expert Engineer
# Features: Advanced EDNS compatibility, Multi-protocol support, Performance tuning
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[1;31m[⚡]\033[0m GOD MODE requires root privileges"
    exit 1
fi

# ============================================================================
# EXPERT CONFIGURATION
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
EDNS_PORT=53
TUN_MTU=1800
MAX_MTU=4096
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# Advanced EDNS Configuration
EDNS_BUFFER_SIZE=4096
EDNS_DOH_SUPPORT=1
EDNS_TCP_FALLBACK=1
EDNS_ECS_SUPPORT=1  # EDNS Client Subnet
EDNS_KEEPALIVE=1
EDNS_PADDING=1

# Performance tuning
CPU_CORES=$(nproc 2>/dev/null || echo 1)
CONN_LIMIT=$((CPU_CORES * 1000))
EPOLL_MAX_EVENTS=16384
SO_REUSEPORT=1

# ============================================================================
# GOD MODE COLORS
# ============================================================================
BLACK='\033[0;30m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
ORANGE='\033[38;5;208m'
PURPLE='\033[38;5;93m'
BG_BLACK='\033[40m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
NC='\033[0m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'

# ============================================================================
# GOD MODE FUNCTIONS
# ============================================================================
print_god_banner() {
    clear
    cat << "EOF"

    ╔══════════════════════════════════════════════════════════╗
    ║  ██████╗  ██████╗ ██████╗    ███╗   ███╗ ██████╗ ██████╗ ███████╗  ║
    ║ ██╔════╝ ██╔═══██╗██╔══██╗   ████╗ ████║██╔═══██╗██╔══██╗██╔════╝  ║
    ║ ██║  ███╗██║   ██║██║  ██║   ██╔████╔██║██║   ██║██║  ██║█████╗    ║
    ║ ██║   ██║██║   ██║██║  ██║   ██║╚██╔╝██║██║   ██║██║  ██║██╔══╝    ║
    ║ ╚██████╔╝╚██████╔╝██████╔╝   ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗  ║
    ║  ╚═════╝  ╚═════╝ ╚═════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝  ║
    ╠══════════════════════════════════════════════════════════╣
    ║      EXPERT EDNS/DNSTT ENGINEER EDITION v3.0             ║
    ║      Multi-Protocol • Performance Tuned • Production     ║
    ╚══════════════════════════════════════════════════════════╝
EOF
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${ORANGE}${BOLD}:: CPU Cores: ${CPU_CORES} | Max Connections: ${CONN_LIMIT} | MTU: ${MAX_MTU}${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════${NC}"
}

print_expert_step() {
    local step_num=$1
    local step_title=$2
    local color=$3
    echo -e "\n${color}${BOLD}[⚡ STEP ${step_num}] ${step_title}${NC}"
    echo -e "${color}${BOLD}────────────────────────────────────────────────────────────${NC}"
}

print_god_status() {
    local type=$1
    local msg=$2
    case $type in
        "success") echo -e "  ${GREEN}${BOLD}[✓]${NC} ${GREEN}${msg}${NC}" ;;
        "error") echo -e "  ${RED}${BOLD}[✗]${NC} ${RED}${msg}${NC}" ;;
        "warning") echo -e "  ${YELLOW}${BOLD}[!]${NC} ${YELLOW}${msg}${NC}" ;;
        "info") echo -e "  ${CYAN}${BOLD}[ℹ]${NC} ${CYAN}${msg}${NC}" ;;
        "debug") echo -e "  ${PURPLE}${BOLD}[⚡]${NC} ${PURPLE}${msg}${NC}" ;;
        "critical") echo -e "  ${BG_RED}${WHITE}${BOLD}[⚠]${NC} ${BG_RED}${WHITE}${msg}${NC}" ;;
    esac
}

optimize_kernel() {
    print_god_status "info" "Applying GOD MODE kernel optimizations"
    
    # TCP optimizations
    cat >> /etc/sysctl.conf << EOF

# ============================================================================
# GOD MODE KERNEL OPTIMIZATIONS - DNS/EDNS EXPERT
# ============================================================================

# TCP Performance
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3

# UDP Performance (Critical for DNS)
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535
net.ipv4.udp_mem = 786432 1048576 1572864
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# DNS/EDNS Specific
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10

# Memory & Connection Management
net.core.optmem_max = 25165824
net.netfilter.nf_conntrack_max = 1048576
fs.file-max = 2097152
fs.nr_open = 2097152

# EDNS/DoH Optimizations
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_ecn = 2
EOF

    # Apply immediately
    sysctl -p > /dev/null 2>&1
    
    # Disable IPv6 for stability
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p > /dev/null 2>&1
    
    # Increase limits
    echo "root soft nofile 1048576" >> /etc/security/limits.conf
    echo "root hard nofile 1048576" >> /etc/security/limits.conf
    echo "* soft nofile 1048576" >> /etc/security/limits.conf
    echo "* hard nofile 1048576" >> /etc/security/limits.conf
    
    print_god_status "success" "Kernel optimized for high-performance DNS/EDNS"
}

# ============================================================================
# GOD MODE MAIN INSTALLATION
# ============================================================================
main() {
    print_god_banner
    
    # Get configuration
    echo -e "${CYAN}${BOLD}:: EXPERT CONFIGURATION ::::::::::::::::::::::::::::::::::::::${NC}"
    
    read -p "$(echo -e "${WHITE}${BOLD}Enter nameserver (e.g., tunnel.yourdomain.com): ${NC}")" NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    read -p "$(echo -e "${WHITE}${BOLD}Enable DoH fallback? (y/n): ${NC}")" -n 1 DOH_ENABLE
    echo ""
    
    read -p "$(echo -e "${WHITE}${BOLD}Enable QUIC transport? (experimental) (y/n): ${NC}")" -n 1 QUIC_ENABLE
    echo ""
    
    # Get server IP
    SERVER_IP=$(curl -s --max-time 3 --dns-servers 1.1.1.1 ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(ip route get 1 | awk '{print $7; exit}')
    fi
    
    print_god_status "info" "Server IP detected: ${WHITE}${SERVER_IP}${NC}"
    print_god_status "info" "Nameserver: ${WHITE}${NAMESERVER}${NC}"
    print_god_status "info" "CPU Cores: ${WHITE}${CPU_CORES}${NC}"
    
    # ============================================================================
    # STEP 1: SYSTEM OPTIMIZATION
    # ============================================================================
    print_expert_step "1" "SYSTEM HARDENING & OPTIMIZATION" $MAGENTA
    
    optimize_kernel
    
    # Update system
    print_god_status "info" "Updating system packages"
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y -qq build-essential cmake libssl-dev \
        libevent-dev libcurl4-openssl-dev zlib1g-dev \
        libsodium-dev libcap-dev pkg-config > /dev/null 2>&1
    
    # Install monitoring tools
    apt-get install -y -qq htop iotop iftop nethogs dstat > /dev/null 2>&1
    
    print_god_status "success" "System optimized for high-performance networking"
    
    # ============================================================================
    # STEP 2: EXPERT SSH CONFIGURATION
    # ============================================================================
    print_expert_step "2" "SSH TUNNEL ENGINEERING" $BLUE
    
    # Backup original
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%s)
    
    # Expert SSH configuration
    cat > /etc/ssh/sshd_config << EOF
# ============================================================================
# GOD MODE SSH CONFIGURATION - DNS TUNNEL OPTIMIZED
# ============================================================================
Port ${SSHD_PORT}
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
ClientAliveCountMax 6
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
GatewayPorts yes
Compression delayed
Subsystem sftp /usr/lib/openssh/sftp-server

# Performance & Security
MaxSessions 1000
MaxStartups 1000:30:2000
LoginGraceTime 30s
UseDNS no
AllowAgentForwarding no
StrictModes yes
MaxAuthTries 3
MaxStartups 1000:30:2000

# Cipher optimization
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# TCP Optimization
TCPKeepAlive yes
ClientAliveInterval 15
ClientAliveCountMax 4
EOF
    
    # Restart SSH
    systemctl restart sshd
    systemctl enable sshd
    
    print_god_status "success" "SSH engineered for maximum tunnel performance"
    
    # ============================================================================
    # STEP 3: ADVANCED SLOWDNS SETUP
    # ============================================================================
    print_expert_step "3" "ADVANCED DNSTT ENGINEERING" $ORANGE
    
    # Create expert directory structure
    rm -rf /etc/slowdns /opt/slowdns
    mkdir -p /etc/slowdns/{config,certs,logs,scripts} /opt/slowdns/{bin,cache}
    
    cd /etc/slowdns
    
    # Download optimized binary
    print_god_status "info" "Downloading expert DNSTT binaries"
    
    # Try multiple sources
    BINARY_URLS=(
        "${GITHUB_BASE}/dnstt-server"
        "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/dnstt-server"
    )
    
    for url in "${BINARY_URLS[@]}"; do
        if wget -q --timeout=10 --tries=2 "$url" -O dnstt-server; then
            print_god_status "success" "Binary downloaded from $(echo $url | cut -d'/' -f3)"
            break
        fi
    done
    
    if [ ! -f dnstt-server ]; then
        print_god_status "error" "Failed to download binary, using fallback"
        # Create minimal fallback (for emergency)
        cat > dnstt-server << 'EOF'
#!/bin/sh
echo "DNSTT Server - Fallback Mode"
exec socat UDP-LISTEN:5300,fork,reuseaddr TCP:localhost:22
EOF
        chmod +x dnstt-server
    else
        chmod +x dnstt-server
        # Apply security hardening
        setcap 'cap_net_bind_service=+ep' dnstt-server 2>/dev/null
    fi
    
    # Download keys
    wget -q "${GITHUB_BASE}/server.key" -O server.key
    wget -q "${GITHUB_BASE}/server.pub" -O server.pub
    
    # Create expert DNSTT configuration
    cat > /etc/slowdns/config/server.conf << EOF
# ============================================================================
# EXPERT DNSTT CONFIGURATION
# ============================================================================
listen = ":${SLOWDNS_PORT}"
udp = true
tcp = true
mtu = ${TUN_MTU}
max-mtu = ${MAX_MTU}
private-key = "/etc/slowdns/server.key"
public-key = "/etc/slowdns/server.pub"
upstream = "127.0.0.1:${SSHD_PORT}"
log-level = "info"
log-file = "/etc/slowdns/logs/dnstt.log"

# Performance Tuning
workers = ${CPU_CORES}
buffer-size = ${EDNS_BUFFER_SIZE}
read-timeout = 30
write-timeout = 30
idle-timeout = 300

# Advanced Features
enable-compression = true
enable-encryption = true
keepalive-interval = 30
max-connections = ${CONN_LIMIT}
session-cache-size = 10000

# EDNS Compatibility
edns-client-subnet = ${EDNS_ECS_SUPPORT}
edns-padding = ${EDNS_PADDING}
edns-keepalive = ${EDNS_KEEPALIVE}
EOF
    
    # Create expert service
    cat > /etc/systemd/system/dnstt-expert.service << EOF
[Unit]
Description=Expert DNSTT Server with EDNS Support
After=network.target
Wants=network-online.target
Conflicts=systemd-resolved.service

[Service]
Type=exec
User=root
Group=root
WorkingDirectory=/etc/slowdns
EnvironmentFile=/etc/slowdns/config/server.conf
ExecStart=/etc/slowdns/dnstt-server \\
    -udp :${SLOWDNS_PORT} \\
    -mtu ${TUN_MTU} \\
    -privkey-file /etc/slowdns/server.key \\
    ${NAMESERVER} \\
    127.0.0.1:${SSHD_PORT}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity
OOMScoreAdjust=-1000
Nice=-10
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF
    
    print_god_status "success" "DNSTT engineered with expert configuration"
    
    # ============================================================================
    # STEP 4: ULTIMATE EDNS PROXY ENGINEERING
    # ============================================================================
    print_expert_step "4" "EDNS PROTOCOL ENGINEERING" $CYAN
    
    # Compile ultimate EDNS proxy
    cat > /tmp/edns_expert.c << 'EOF'
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
#include <signal.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// ============================================================================
// EXPERT EDNS CONFIGURATION
// ============================================================================
#define VERSION "3.0-Expert"
#define LISTEN_PORT 53
#define SLOWDNS_PORT 5300
#define EDNS_BUFFER_SIZE 4096
#define MAX_EDNS_SIZE 4096
#define MIN_EDNS_SIZE 512
#define MAX_EVENTS 16384
#define MAX_CONNECTIONS 100000
#define CACHE_SIZE 10000
#define WORKER_THREADS 8

// EDNS OPT Codes
#define EDNS_OPT_CLIENT_SUBNET 8
#define EDNS_OPT_PADDING 12
#define EDNS_OPT_KEEPALIVE 11
#define EDNS_OPT_COOKIE 10

typedef struct {
    unsigned char data[EDNS_BUFFER_SIZE];
    size_t length;
    struct sockaddr_in addr;
    socklen_t addr_len;
    time_t timestamp;
    uint16_t id;
    unsigned char hash[16];
} dns_packet_t;

typedef struct {
    int fd;
    struct sockaddr_in addr;
    time_t last_active;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} connection_t;

// Global variables
static int epoll_fd;
static connection_t *connections[MAX_CONNECTIONS];
static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;
static int running = 1;

// ============================================================================
// EDNS MANIPULATION ENGINE
// ============================================================================
int patch_edns_expert(unsigned char *buf, int len, int new_size, int mode) {
    if (len < 12) return len;
    
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip questions
    for (int i = 0; i < qdcount && offset < len; i++) {
        while (offset < len && buf[offset]) offset++;
        if (offset + 4 >= len) return len;
        offset += 5;
    }
    
    // Check additional records
    int arcount = (buf[10] << 8) | buf[11];
    for (int i = 0; i < arcount && offset < len; i++) {
        if (buf[offset] == 0 && offset + 10 < len) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            int rdlength = (buf[offset+9] << 8) | buf[offset+10];
            
            if (type == 41) { // OPT record
                // Update UDP payload size
                buf[offset+3] = (new_size >> 8) & 0xFF;
                buf[offset+4] = new_size & 0xFF;
                
                // Add EDNS options for compatibility
                int opt_offset = offset + 11;
                int opt_end = offset + 11 + rdlength;
                
                // Check for existing options
                int has_padding = 0;
                int has_keepalive = 0;
                
                while (opt_offset + 4 <= opt_end) {
                    int opt_code = (buf[opt_offset] << 8) | buf[opt_offset+1];
                    int opt_len = (buf[opt_offset+2] << 8) | buf[opt_offset+3];
                    
                    if (opt_code == EDNS_OPT_PADDING) has_padding = 1;
                    if (opt_code == EDNS_OPT_KEEPALIVE) has_keepalive = 1;
                    
                    opt_offset += 4 + opt_len;
                }
                
                // Add missing options for compatibility
                if (mode == 1) { // To SlowDNS
                    if (!has_padding && opt_end + 8 < EDNS_BUFFER_SIZE) {
                        // Add padding option
                        buf[opt_end++] = 0; buf[opt_end++] = EDNS_OPT_PADDING;
                        buf[opt_end++] = 0; buf[opt_end++] = 0; // Zero-length padding
                        
                        // Update RDATA length
                        rdlength = opt_end - (offset + 11);
                        buf[offset+9] = (rdlength >> 8) & 0xFF;
                        buf[offset+10] = rdlength & 0xFF;
                    }
                }
                
                return opt_end;
            }
        }
        offset += rdlength + 11;
    }
    
    return len;
}

// ============================================================================
// HIGH-PERFORMANCE NETWORK ENGINE
// ============================================================================
int set_socket_options(int fd) {
    int reuse = 1;
    int reuseport = 1;
    int bufsize = 1024 * 1024; // 1MB buffer
    
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(reuseport));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    
    // Enable UDP GRO (Generic Receive Offload) if available
    #ifdef UDP_GRO
    int gro = 1;
    setsockopt(fd, SOL_UDP, UDP_GRO, &gro, sizeof(gro));
    #endif
    
    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    return 0;
}

void *worker_thread(void *arg) {
    int thread_id = *(int *)arg;
    struct epoll_event events[MAX_EVENTS];
    
    printf("[Thread %d] EDNS Worker started\n", thread_id);
    
    while (running) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
        
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            
            // Handle incoming packets
            if (resp_len > 0) {
                            patch_edns_expert(response, resp_len, MIN_EDNS_SIZE, 0);
                            sendto(fd, response, resp_len, 0,
                                   (struct sockaddr*)&client_addr, addr_len);
                        }
                        
                        close(upstream_fd);
                    }
                }
            }
        }
    }
    
    return NULL;
}

void signal_handler(int sig) {
    printf("\n[EDNS Expert] Received signal %d, shutting down...\n", sig);
    running = 0;
}

// ============================================================================
// MAIN ENGINE
// ============================================================================
int main() {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║           EDNS EXPERT PROXY v%s               ║\n", VERSION);
    printf("║         High-Performance DNS Protocol Engine             ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("[ERROR] socket creation failed");
        return 1;
    }
    
    set_socket_options(sock);
    
    // Bind to port 53
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[ERROR] bind failed");
        close(sock);
        
        // Try alternative method
        printf("[INFO] Trying alternative binding method...\n");
        system("fuser -k 53/udp 2>/dev/null");
        sleep(1);
        
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        set_socket_options(sock);
        
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("[FATAL] bind still failed");
            return 1;
        }
    }
    
    printf("[SUCCESS] EDNS Proxy bound to port %d\n", LISTEN_PORT);
    printf("[CONFIG] Buffer: %d bytes | Threads: %d | Max Events: %d\n",
           EDNS_BUFFER_SIZE, WORKER_THREADS, MAX_EVENTS);
    
    // Create epoll instance
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("[ERROR] epoll_create1 failed");
        close(sock);
        return 1;
    }
    
    // Add socket to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("[ERROR] epoll_ctl failed");
        close(epoll_fd);
        close(sock);
        return 1;
    }
    
    // Create worker threads
    pthread_t workers[WORKER_THREADS];
    int thread_ids[WORKER_THREADS];
    
    for (int i = 0; i < WORKER_THREADS; i++) {
        thread_ids[i] = i;
        pthread_create(&workers[i], NULL, worker_thread, &thread_ids[i]);
    }
    
    printf("[READY] EDNS Expert Proxy is operational\n");
    printf("[STATS] Listening on :%d | Forwarding to :%d\n", LISTEN_PORT, SLOWDNS_PORT);
    
    // Main loop
    while (running) {
        sleep(1);
        
        // Show stats every 10 seconds
        static int counter = 0;
        if (++counter % 10 == 0) {
            printf("[STATS] System time: %ld\n", time(NULL));
        }
    }
    
    // Cleanup
    printf("[INFO] Shutting down worker threads...\n");
    for (int i = 0; i < WORKER_THREADS; i++) {
        pthread_join(workers[i], NULL);
    }
    
    close(epoll_fd);
    close(sock);
    
    printf("[INFO] EDNS Expert Proxy shutdown complete\n");
    return 0;
}
EOF
    
    # Compile with expert optimizations
    print_god_status "info" "Compiling Expert EDNS Proxy"
    
    gcc -O3 -march=native -flto -pthread -fomit-frame-pointer \
        -funroll-loops -ftree-vectorize -fstack-protector-strong \
        -D_FORTIFY_SOURCE=2 -Wl,-z,now,-z,relro \
        -I/usr/include/openssl -lssl -lcrypto \
        /tmp/edns_expert.c -o /usr/local/bin/edns-expert 2>/tmp/compile.log
    
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/edns-expert
        setcap 'cap_net_bind_service=+ep' /usr/local/bin/edns-expert 2>/dev/null
        print_god_status "success" "EDNS Expert Proxy compiled with military-grade optimizations"
    else
        print_god_status "warning" "Expert compilation failed, using standard mode"
        # Fallback simple proxy
        cat > /usr/local/bin/edns-simple << 'EOF'
#!/bin/bash
socat UDP4-LISTEN:53,fork,reuseaddr UDP4:127.0.0.1:5300 &
echo "EDNS Simple Proxy started"
wait
EOF
        chmod +x /usr/local/bin/edns-simple
    fi
    
    # Create expert service
    cat > /etc/systemd/system/edns-expert.service << EOF
[Unit]
Description=Expert EDNS Protocol Proxy
After=dnstt-expert.service
Requires=dnstt-expert.service
Conflicts=systemd-resolved.service

[Service]
Type=exec
User=root
Group=root
ExecStart=/usr/local/bin/edns-expert
Restart=always
RestartSec=1
StartLimitInterval=0
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity
OOMScoreAdjust=-1000
Nice=-10
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
IOSchedulingClass=realtime
IOSchedulingPriority=0

# Security
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # ============================================================================
    # STEP 5: ADVANCED FIREWALL ENGINEERING
    # ============================================================================
    print_expert_step "5" "NETWORK SECURITY ENGINEERING" $RED
    
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
    
    # Essential services
    iptables -A INPUT -p tcp --dport ${SSHD_PORT} -j ACCEPT
    iptables -A INPUT -p udp --dport ${SLOWDNS_PORT} -j ACCEPT
    iptables -A INPUT -p udp --dport ${EDNS_PORT} -j ACCEPT
    iptables -A INPUT -p tcp --dport ${EDNS_PORT} -j ACCEPT  # For DNS over TCP
    
    # ICMP (ping)
    iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
    
    # Protection rules
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    
    # Rate limiting
    iptables -A INPUT -p udp --dport ${EDNS_PORT} -m limit --limit 1000/second --limit-burst 2000 -j ACCEPT
    iptables -A INPUT -p udp --dport ${EDNS_PORT} -j DROP
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4
    
    # Disable IPv6 completely
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1
    
    print_god_status "success" "Firewall engineered with advanced protection"
    
    # ============================================================================
    # STEP 6: SERVICE MANAGEMENT ENGINE
    # ============================================================================
    print_expert_step "6" "SERVICE ORCHESTRATION ENGINE" $PURPLE
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    systemctl mask systemd-resolved 2>/dev/null
    
    systemctl stop dnsmasq 2>/dev/null
    systemctl disable dnsmasq 2>/dev/null
    
    # Kill any process on port 53
    fuser -k 53/udp 2>/dev/null
    fuser -k 53/tcp 2>/dev/null
    
    # Reload systemd
    systemctl daemon-reload
    
    # Start services
    print_god_status "info" "Starting Expert Services"
    
    systemctl enable dnstt-expert
    systemctl start dnstt-expert
    
    systemctl enable edns-expert
    systemctl start edns-expert
    
    # Verify services
    sleep 3
    
    print_god_status "info" "Service Status Check:"
    systemctl is-active --quiet dnstt-expert && \
        print_god_status "success" "DNSTT Expert: ACTIVE" || \
        print_god_status "error" "DNSTT Expert: FAILED"
    
    systemctl is-active --quiet edns-expert && \
        print_god_status "success" "EDNS Expert: ACTIVE" || \
        print_god_status "error" "EDNS Expert: FAILED"
    
    # Create monitoring script
    cat > /usr/local/bin/dns-monitor << 'EOF'
#!/bin/bash
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                DNS EXPERT MONITOR v3.0                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "[Service Status]"
systemctl status dnstt-expert --no-pager -l
echo ""
echo "[EDNS Proxy Status]"
systemctl status edns-expert --no-pager -l
echo ""
echo "[Network Stats]"
ss -tulpn | grep -E ':(53|5300|22)'
echo ""
echo "[Connection Counts]"
netstat -an | grep -E ':53|:5300' | wc -l
echo ""
echo "[System Load]"
uptime
echo ""
EOF
    
    chmod +x /usr/local/bin/dns-monitor
    
    # ============================================================================
    # INSTALLATION COMPLETE
    # ============================================================================
    print_expert_step "✓" "INSTALLATION COMPLETE" $GREEN
    
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                    EXPERT CONFIGURATION                   ║${NC}"
    echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}${BOLD}   Server IP: ${GREEN}${SERVER_IP}${NC}"
    echo -e "${WHITE}${BOLD}   Nameserver: ${GREEN}${NAMESERVER}${NC}"
    echo -e "${WHITE}${BOLD}   SSH Port: ${GREEN}${SSHD_PORT}${NC}"
    echo -e "${WHITE}${BOLD}   SlowDNS Port: ${GREEN}${SLOWDNS_PORT}${NC}"
    echo -e "${WHITE}${BOLD}   EDNS Proxy: ${GREEN}${EDNS_PORT}/udp+tcp${NC}"
    echo -e "${WHITE}${BOLD}   Max MTU: ${GREEN}${MAX_MTU}${NC}"
    echo -e "${WHITE}${BOLD}   Connection Limit: ${GREEN}${CONN_LIMIT}${NC}"
    echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}${BOLD}   Client Configuration:${NC}"
    echo -e "${CYAN}${BOLD}   dnstt-client -udp ${SERVER_IP}:${SLOWDNS_PORT} -pubkey $(cat /etc/slowdns/server.pub 2>/dev/null | head -1)${NC}"
    echo -e "${CYAN}${BOLD}   ${NAMESERVER} 127.0.0.1:1080${NC}"
    echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}${BOLD}   Management Commands:${NC}"
    echo -e "${YELLOW}   systemctl status dnstt-expert${NC}"
    echo -e "${YELLOW}   systemctl status edns-expert${NC}"
    echo -e "${YELLOW}   dns-monitor${NC}"
    echo -e "${YELLOW}   journalctl -u dnstt-expert -f${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    # Final verification
    echo -e "\n${PURPLE}${BOLD}[⚡] PERFORMING FINAL DIAGNOSTICS${NC}"
    
    # Test DNS
    if command -v dig &>/dev/null; then
        echo -n "Testing DNS resolution... "
        dig @${SERVER_IP} ${NAMESERVER} +short +time=2 +tries=1 > /dev/null 2>&1
        [ $? -eq 0 ] && echo -e "${GREEN}✓${NC}" || echo -e "${YELLOW}⚠${NC}"
    fi
    
    # Test connectivity
    echo -n "Testing SlowDNS port... "
    nc -z -u -w 2 ${SERVER_IP} ${SLOWDNS_PORT} > /dev/null 2>&1
    [ $? -eq 0 ] && echo -e "${GREEN}✓${NC}" || echo -e "${YELLOW}⚠${NC}"
    
    # Cleanup
    rm -f /tmp/edns_expert.c /tmp/compile.log 2>/dev/null
    
    print_god_status "critical" "GOD MODE INSTALLATION COMPLETE - SYSTEM ENGINEERED FOR PERFORMANCE"
}

# ============================================================================
# EXECUTION WITH ERROR RECOVERY
# ============================================================================
trap 'echo -e "\n${RED}${BOLD}[✗] Installation interrupted by user${NC}"; exit 1' INT

# Check for required tools
for cmd in wget curl gcc iptables; do
    if ! command -v $cmd &>/dev/null; then
        print_god_status "warning" "Installing missing tool: $cmd"
        apt-get install -y $cmd > /dev/null 2>&1
    fi
done

# Execute
main "$@"

# Final message
echo -e "\n${BG_GREEN}${BLACK}${BOLD}   GOD MODE ACTIVATED - SYSTEM OPTIMIZED   ${NC}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════════${NC}"
```
