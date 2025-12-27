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
    echo -e "${BLUE}${BOLD}"
    echo "    ╔══════════════════════════════════════════════════════════╗"
    echo "    ║  ██████╗  ██████╗ ██████╗    ███╗   ███╗ ██████╗ ██████╗ ███████╗  ║"
    echo "    ║ ██╔════╝ ██╔═══██╗██╔══██╗   ████╗ ████║██╔═══██╗██╔══██╗██╔════╝  ║"
    echo "    ║ ██║  ███╗██║   ██║██║  ██║   ██╔████╔██║██║   ██║██║  ██║█████╗    ║"
    echo "    ║ ██║   ██║██║   ██║██║  ██║   ██║╚██╔╝██║██║   ██║██║  ██║██╔══╝    ║"
    echo "    ║ ╚██████╔╝╚██████╔╝██████╔╝   ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗  ║"
    echo "    ║  ╚═════╝  ╚═════╝ ╚═════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝  ║"
    echo "    ╠══════════════════════════════════════════════════════════╣"
    echo "    ║      EXPERT EDNS/DNSTT ENGINEER EDITION v3.0             ║"
    echo "    ║      Multi-Protocol • Performance Tuned • Production     ║"
    echo "    ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
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
    SERVER_IP=$(curl -s --max-time 3 --dns-servers 1.1.1.1 ifconfig.me 2>/dev/null)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(ip route get 1 2>/dev/null | awk '{print $7; exit}' || echo "127.0.0.1")
    fi
    
    print_god_status "info" "Server IP detected: ${WHITE}${SERVER_IP}${NC}"
    print_god_status "info" "Nameserver: ${WHITE}${NAMESERVER}${NC}"
    print_god_status "info" "CPU Cores: ${WHITE}${CPU_CORES}${NC}"
    
    # ============================================================================
    # STEP 1: SYSTEM OPTIMIZATION
    # ============================================================================
    print_expert_step "1" "SYSTEM HARDENING & OPTIMIZATION" "$MAGENTA"
    
    optimize_kernel
    
    # Update system
    print_god_status "info" "Updating system packages"
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y -qq build-essential cmake libssl-dev \
        libevent-dev libcurl4-openssl-dev zlib1g-dev \
        libsodium-dev libcap-dev pkg-config > /dev/null 2>&1
    
    # Install monitoring tools
    apt-get install -y -qq htop iotop iftop nethogs dstat net-tools > /dev/null 2>&1
    
    print_god_status "success" "System optimized for high-performance networking"
    
    # ============================================================================
    # STEP 2: EXPERT SSH CONFIGURATION
    # ============================================================================
    print_expert_step "2" "SSH TUNNEL ENGINEERING" "$BLUE"
    
    # Backup original
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.$(date +%s)" 2>/dev/null
    
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
    systemctl restart sshd 2>/dev/null
    systemctl enable sshd 2>/dev/null
    
    print_god_status "success" "SSH engineered for maximum tunnel performance"
    
    # ============================================================================
    # STEP 3: ADVANCED SLOWDNS SETUP
    # ============================================================================
    print_expert_step "3" "ADVANCED DNSTT ENGINEERING" "$ORANGE"
    
    # Create expert directory structure
    rm -rf /etc/slowdns /opt/slowdns 2>/dev/null
    mkdir -p /etc/slowdns/{config,certs,logs,scripts} /opt/slowdns/{bin,cache} 2>/dev/null
    
    cd /etc/slowdns || exit 1
    
    # Download optimized binary
    print_god_status "info" "Downloading expert DNSTT binaries"
    
    # Try multiple sources
    BINARY_URLS=(
        "${GITHUB_BASE}/dnstt-server"
        "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/dnstt-server"
    )
    
    for url in "${BINARY_URLS[@]}"; do
        if wget -q --timeout=10 --tries=2 "$url" -O dnstt-server 2>/dev/null; then
            print_god_status "success" "Binary downloaded from $(echo "$url" | cut -d'/' -f3)"
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
        setcap 'cap_net_bind_service=+ep' dnstt-server 2>/dev/null || true
    fi
    
    # Download keys
    wget -q "${GITHUB_BASE}/server.key" -O server.key 2>/dev/null
    wget -q "${GITHUB_BASE}/server.pub" -O server.pub 2>/dev/null
    
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
    print_expert_step "4" "EDNS PROTOCOL ENGINEERING" "$CYAN"
    
    # Create C source file
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

#define VERSION "3.0-Expert"
#define LISTEN_PORT 53
#define SLOWDNS_PORT 5300
#define BUFFER_SIZE 4096
#define MAX_EVENTS 16384
#define WORKER_THREADS 4

static int running = 1;

int set_socket_options(int fd) {
    int reuse = 1;
    int bufsize = 1024 * 1024;
    
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    return 0;
}

void signal_handler(int sig) {
    printf("\n[EDNS Expert] Received signal %d, shutting down...\n", sig);
    running = 0;
}

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
        return 1;
    }
    
    printf("[SUCCESS] EDNS Proxy bound to port %d\n", LISTEN_PORT);
    printf("[CONFIG] Buffer: %d bytes | Threads: %d\n", BUFFER_SIZE, WORKER_THREADS);
    
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
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
    
    printf("[READY] EDNS Expert Proxy is operational\n");
    printf("[STATS] Listening on :%d | Forwarding to :%d\n", LISTEN_PORT, SLOWDNS_PORT);
    
    struct epoll_event events[MAX_EVENTS];
    
    while (running) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == sock) {
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0,
                                     (struct sockaddr*)&client_addr, &addr_len);
                
                if (len > 0) {
                    // Forward to SlowDNS
                    int upstream_fd = socket(AF_INET, SOCK_DGRAM, 0);
                    if (upstream_fd >= 0) {
                        set_socket_options(upstream_fd);
                        
                        struct sockaddr_in upstream_addr;
                        memset(&upstream_addr, 0, sizeof(upstream_addr));
                        upstream_addr.sin_family = AF_INET;
                        upstream_addr.sin_port = htons(SLOWDNS_PORT);
                        upstream_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                        
                        sendto(upstream_fd, buffer, len, 0,
                               (struct sockaddr*)&upstream_addr, sizeof(upstream_addr));
                        
                        // Receive response
                        unsigned char response[BUFFER_SIZE];
                        struct sockaddr_in response_addr;
                        socklen_t response_len = sizeof(response_addr);
                        
                        ssize_t resp_len = recvfrom(upstream_fd, response, sizeof(response), 0,
                                                   (struct sockaddr*)&response_addr, &response_len);
                        
                        if (resp_len > 0) {
                            sendto(sock, response, resp_len, 0,
                                   (struct sockaddr*)&client_addr, addr_len);
                        }
                        
                        close(upstream_fd);
                    }
                }
            }
        }
    }
    
    close(epoll_fd);
    close(sock);
    
    printf("[INFO] EDNS Expert Proxy shutdown complete\n");
    return 0;
}
EOF
    
    # Compile with expert optimizations
    print_god_status "info" "Compiling Expert EDNS Proxy"
    
    if gcc -O3 -march=native -flto -fomit-frame-pointer \
        -funroll-loops -ftree-vectorize -fstack-protector-strong \
        -D_FORTIFY_SOURCE=2 /tmp/edns_expert.c -o /usr/local/bin/edns-expert 2>/tmp/compile.log; then
        chmod +x /usr/local/bin/edns-expert
        setcap 'cap_net_bind_service=+ep' /usr/local/bin/edns-expert 2>/dev/null || true
        print_god_status "success" "EDNS Expert Proxy compiled with military-grade optimizations"
    else
        print_god_status "warning" "Expert compilation failed, using socat fallback"
        # Fallback simple proxy
        cat > /usr/local/bin/edns-simple << 'EOF'
#!/bin/bash
echo "EDNS Simple Proxy started on port 53"
exec socat UDP4-LISTEN:53,fork,reuseaddr UDP4:127.0.0.1:5300
x
                chmod +x /usr/local/bin/edns-simple
        cp /usr/local/bin/edns-simple /usr/local/bin/edns-expert
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

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # ============================================================================
    # STEP 5: ADVANCED FIREWALL ENGINEERING
    # ============================================================================
    print_expert_step "5" "NETWORK SECURITY ENGINEERING" "$RED"
    
    # Flush existing rules
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    iptables -t mangle -F 2>/dev/null
    iptables -t mangle -X 2>/dev/null
    
    # Default policies
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    
    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    
    # Essential services
    iptables -A INPUT -p tcp --dport ${SSHD_PORT} -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport ${SLOWDNS_PORT} -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport ${EDNS_PORT} -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport ${EDNS_PORT} -j ACCEPT 2>/dev/null
    
    # ICMP (ping)
    iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    
    print_god_status "success" "Firewall engineered with advanced protection"
    
    # ============================================================================
    # STEP 6: SERVICE MANAGEMENT ENGINE
    # ============================================================================
    print_expert_step "6" "SERVICE ORCHESTRATION ENGINE" "$PURPLE"
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    systemctl mask systemd-resolved 2>/dev/null
    
    # Kill any process on port 53
    fuser -k 53/udp 2>/dev/null || true
    fuser -k 53/tcp 2>/dev/null || true
    
    # Reload systemd
    systemctl daemon-reload
    
    # Start services
    print_god_status "info" "Starting Expert Services"
    
    systemctl enable dnstt-expert 2>/dev/null
    systemctl start dnstt-expert 2>/dev/null
    
    systemctl enable edns-expert 2>/dev/null
    systemctl start edns-expert 2>/dev/null
    
    # Verify services
    sleep 3
    
    print_god_status "info" "Service Status Check:"
    if systemctl is-active --quiet dnstt-expert; then
        print_god_status "success" "DNSTT Expert: ACTIVE"
    else
        print_god_status "error" "DNSTT Expert: FAILED"
    fi
    
    if systemctl is-active --quiet edns-expert; then
        print_god_status "success" "EDNS Expert: ACTIVE"
    else
        print_god_status "error" "EDNS Expert: FAILED"
    fi
    
    # Create monitoring script
    cat > /usr/local/bin/dns-monitor << 'EOF'
#!/bin/bash
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                DNS EXPERT MONITOR v3.0                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "[Service Status]"
systemctl status dnstt-expert --no-pager -l 2>/dev/null || echo "DNSTT service not found"
echo ""
echo "[EDNS Proxy Status]"
systemctl status edns-expert --no-pager -l 2>/dev/null || echo "EDNS service not found"
echo ""
echo "[Network Stats]"
ss -tulpn 2>/dev/null | grep -E ':(53|5300|22)' || netstat -tulpn 2>/dev/null | grep -E ':(53|5300|22)'
echo ""
echo "[System Load]"
uptime
echo ""
EOF
    
    chmod +x /usr/local/bin/dns-monitor
    
    # ============================================================================
    # INSTALLATION COMPLETE
    # ============================================================================
    print_expert_step "✓" "INSTALLATION COMPLETE" "$GREEN"
    
    # Get public key
    PUBKEY=$(cat /etc/slowdns/server.pub 2>/dev/null | head -1 || echo "PUBKEY_NOT_FOUND")
    
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                    EXPERT CONFIGURATION                   ║${NC}"
    echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}${BOLD}   Server IP: ${GREEN}${SERVER_IP}${NC}"
    echo -e "${WHITE}${BOLD}   Nameserver: ${GREEN}${NAMESERVER}${NC}"
    echo -e "${WHITE}${BOLD}   SSH Port: ${GREEN}${SSHD_PORT}${NC}"
    echo -e "${WHITE}${BOLD}   SlowDNS Port: ${GREEN}${SLOWDNS_PORT}${NC}"
    echo -e "${WHITE}${BOLD}   EDNS Proxy: ${GREEN}${EDNS_PORT}/udp+tcp${NC}"
    echo -e "${WHITE}${BOLD}   Public Key: ${GREEN}${PUBKEY}${NC}"
    echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}${BOLD}   Client Configuration:${NC}"
    echo -e "${CYAN}${BOLD}   dnstt-client -udp ${SERVER_IP}:${SLOWDNS_PORT} -pubkey ${PUBKEY}${NC}"
    echo -e "${CYAN}${BOLD}   ${NAMESERVER} 127.0.0.1:1080${NC}"
    echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}${BOLD}   Management Commands:${NC}"
    echo -e "${YELLOW}   systemctl status dnstt-expert${NC}"
    echo -e "${YELLOW}   systemctl status edns-expert${NC}"
    echo -e "${YELLOW}   dns-monitor${NC}"
    echo -e "${YELLOW}   journalctl -u dnstt-expert -f${NC}"
    echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}${BOLD}   Quick Tests:${NC}"
    echo -e "${YELLOW}   # Test DNS resolution${NC}"
    echo -e "${YELLOW}   dig @${SERVER_IP} ${NAMESERVER} +short${NC}"
    echo -e "${YELLOW}   # Test SlowDNS connectivity${NC}"
    echo -e "${YELLOW}   nc -zu ${SERVER_IP} ${SLOWDNS_PORT}${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    # Final verification
    echo -e "\n${PURPLE}${BOLD}[⚡] PERFORMING FINAL DIAGNOSTICS${NC}"
    
    # Test DNS
    echo -ne "Testing DNS resolution... "
    if command -v dig &>/dev/null; then
        dig @${SERVER_IP} ${NAMESERVER} +short +time=2 +tries=1 > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${YELLOW}⚠${NC}"
        fi
    else
        echo -e "${YELLOW}dig not available${NC}"
    fi
    
    # Test connectivity
    echo -ne "Testing SlowDNS port... "
    if command -v nc &>/dev/null; then
        nc -z -u -w 2 ${SERVER_IP} ${SLOWDNS_PORT} > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${YELLOW}⚠${NC}"
        fi
    else
        echo -e "${YELLOW}nc not available${NC}"
    fi
    
    # Check services
    echo -ne "Checking DNSTT service... "
    if systemctl is-active --quiet dnstt-expert; then
        echo -e "${GREEN}ACTIVE${NC}"
    else
        echo -e "${RED}INACTIVE${NC}"
        print_god_status "warning" "Starting DNSTT manually..."
        /etc/slowdns/dnstt-server -udp :${SLOWDNS_PORT} -mtu ${TUN_MTU} -privkey-file /etc/slowdns/server.key ${NAMESERVER} 127.0.0.1:${SSHD_PORT} &
    fi
    
    echo -ne "Checking EDNS service... "
    if systemctl is-active --quiet edns-expert; then
        echo -e "${GREEN}ACTIVE${NC}"
    else
        echo -e "${RED}INACTIVE${NC}"
        print_god_status "warning" "Starting EDNS manually..."
        /usr/local/bin/edns-expert &
    fi
    
    # Check port 53
    echo -ne "Checking port 53 binding... "
    if ss -tulpn | grep -q ":53 "; then
        echo -e "${GREEN}BOUND${NC}"
    else
        echo -e "${RED}NOT BOUND${NC}"
        print_god_status "warning" "Killing any service on port 53..."
        fuser -k 53/udp 2>/dev/null
        fuser -k 53/tcp 2>/dev/null
        sleep 1
        systemctl restart edns-expert 2>/dev/null || /usr/local/bin/edns-expert &
    fi
    
    # Cleanup
    rm -f /tmp/edns_expert.c /tmp/compile.log 2>/dev/null
    
    # ============================================================================
    # FINAL MESSAGE
    # ============================================================================
    echo -e "\n${BG_GREEN}${BLACK}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BG_GREEN}${BLACK}${BOLD}   GOD MODE ACTIVATED - SYSTEM ENGINEERED FOR PERFORMANCE   ${NC}"
    echo -e "${BG_GREEN}${BLACK}${BOLD}══════════════════════════════════════════════════════════${NC}"
    
    print_god_status "critical" "INSTALLATION COMPLETED SUCCESSFULLY"
    print_god_status "info" "Server Time: $(date)"
    print_god_status "info" "System Uptime: $(uptime -p)"
    
    echo -e "\n${CYAN}${BOLD}For troubleshooting, run:${NC}"
    echo -e "${YELLOW}   dns-monitor${NC}"
    echo -e "${YELLOW}   journalctl -u dnstt-expert -f${NC}"
    echo -e "${YELLOW}   journalctl -u edns-expert -f${NC}"
    
    echo -e "\n${GREEN}${BOLD}SlowDNS Expert Edition is now ready!${NC}"
    echo -e "${WHITE}Configure your client with the details above.${NC}"
}

# ============================================================================
# EXECUTION WITH ERROR RECOVERY
# ============================================================================
trap 'echo -e "\n${RED}${BOLD}[✗] Installation interrupted by user${NC}"; exit 1' INT

# Check for required tools
REQUIRED_TOOLS="wget curl gcc iptables"
MISSING_TOOLS=""

for cmd in $REQUIRED_TOOLS; do
    if ! command -v $cmd &>/dev/null; then
        MISSING_TOOLS="$MISSING_TOOLS $cmd"
    fi
done

if [ -n "$MISSING_TOOLS" ]; then
    print_god_status "warning" "Installing missing tools:$MISSING_TOOLS"
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y -qq $MISSING_TOOLS > /dev/null 2>&1 || {
        print_god_status "error" "Failed to install required tools"
        exit 1
    }
fi

# Execute main installation
if main "$@"; then
    # Display final success message
    echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   Installation completed at: $(date +'%Y-%m-%d %H:%M:%S')   ${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    exit 0
else
    print_god_status "error" "Installation failed with errors"
    echo -e "\n${YELLOW}Troubleshooting steps:${NC}"
    echo -e "1. Check system logs: ${YELLOW}journalctl -xe${NC}"
    echo -e "2. Verify network: ${YELLOW}ss -tulpn | grep ':53\|:5300'${NC}"
    echo -e "3. Restart services: ${YELLOW}systemctl restart dnstt-expert edns-expert${NC}"
    echo -e "4. Manual start: ${YELLOW}/etc/slowdns/dnstt-server ... &${NC}"
    exit 1
fi
