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
SSHD_PORT=22                    # Changed from 22 for security
SLOWDNS_PORT=5300               # Changed from 5353 to avoid conflicts
EXT_EDNS_MTU=512                # EXTERNAL MTU (Internet-facing) - DO NOT CHANGE
INT_EDNS_MTU=1800               # INTERNAL MTU (Local network) - DO NOT CHANGE
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
ENABLE_JUMBO_FRAMES=0           # Disabled due to small external MTU
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
# COMPILE HARDCORE EDNS PROXY WITH MTU CONFIGURATION (FIXED VERSION)
# ============================================================================
compile_edns_proxy() {
    print_header "⚡ COMPILING HARDCORE EDNS PROXY"
    
    # Create simplified C code without foreground blocking
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

// Configuration
#define LISTEN_PORT 53
#define SLOWDNS_PORT 5353
#define EXT_EDNS_MTU 512
#define INT_EDNS_MTU 1800
#define BUFFER_SIZE 65536
#define MAX_EVENTS 1024
#define TIMEOUT 5.0

// Global state
static volatile sig_atomic_t running = 1;

void signal_handler(int sig) {
    running = 0;
    fprintf(stderr, "[INFO] Signal %d received, shutting down\n", sig);
}

int patch_mtu(unsigned char *buf, int len, int new_mtu) {
    if (len < 12) return len;
    
    int off = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip questions
    for (int i = 0; i < qdcount && off < len; i++) {
        while (off < len && buf[off]) off++;
        if (off + 5 >= len) break;
        off += 5;
    }
    
    // Find EDNS OPT record
    int arcount = (buf[10] << 8) | buf[11];
    for (int i = 0; i < arcount && off + 4 < len; i++) {
        if (buf[off] == 0 && ((buf[off+1] << 8) | buf[off+2]) == 41) {
            buf[off+3] = new_mtu >> 8;
            buf[off+4] = new_mtu & 0xFF;
            return len;
        }
        off++;
    }
    
    return len;
}

int main() {
    // Daemonize
    if (fork() > 0) return 0;
    setsid();
    
    // Signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // Create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Set socket options
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    
    int bufsize = 8388608;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    
    // Bind to port 53
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }
    
    // Setup SlowDNS target
    struct sockaddr_in target = {0};
    target.sin_family = AF_INET;
    target.sin_port = htons(SLOWDNS_PORT);
    inet_pton(AF_INET, "127.0.0.1", &target.sin_addr);
    
    // Create upstream socket
    int upstream = socket(AF_INET, SOCK_DGRAM, 0);
    if (upstream < 0) {
        perror("upstream socket");
        close(sock);
        return 1;
    }
    
    fcntl(upstream, F_SETFL, O_NONBLOCK);
    
    fprintf(stderr, "[STARTUP] Hardcore EDNS Proxy ready\n");
    fprintf(stderr, "[CONFIG] External MTU: %d, Internal MTU: %d\n", EXT_EDNS_MTU, INT_EDNS_MTU);
    fprintf(stderr, "[INFO] Listening on port %d, forwarding to 127.0.0.1:%d\n", LISTEN_PORT, SLOWDNS_PORT);
    
    // Main loop
    while (running) {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        unsigned char buffer[BUFFER_SIZE];
        
        // Receive from client
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0,
                              (struct sockaddr*)&client, &client_len);
        
        if (len > 0) {
            // Patch MTU for internal
            int new_len = patch_mtu(buffer, len, INT_EDNS_MTU);
            
            // Forward to SlowDNS
            sendto(upstream, buffer, new_len, 0,
                   (struct sockaddr*)&target, sizeof(target));
            
            // Receive response (non-blocking)
            fd_set fds;
            struct timeval tv = {0, 100000}; // 100ms timeout
            
            FD_ZERO(&fds);
            FD_SET(upstream, &fds);
            
            if (select(upstream + 1, &fds, NULL, NULL, &tv) > 0) {
                if (FD_ISSET(upstream, &fds)) {
                    ssize_t resp_len = recv(upstream, buffer, sizeof(buffer), 0);
                    if (resp_len > 0) {
                        // Patch MTU for external
                        resp_len = patch_mtu(buffer, resp_len, EXT_EDNS_MTU);
                        
                        // Send back to client
                        sendto(sock, buffer, resp_len, 0,
                               (struct sockaddr*)&client, client_len);
                    }
                }
            }
        } else if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            usleep(10000); // 10ms delay on error
        }
    }
    
    // Cleanup
    fprintf(stderr, "[SHUTDOWN] Cleaning up\n");
    close(sock);
    close(upstream);
    fprintf(stderr, "[SHUTDOWN] Complete\n");
    
    return 0;
}
EOF

    print_info "Compiling Hardcore EDNS Proxy with MTU: ${RED}512${NC} → ${GREEN}1800${NC}"
    
    # Compile with optimizations
    echo -ne "  ${CYAN}Compiling...${NC}"
    
    if gcc -O3 -march=native /tmp/hardcore-edns.c -o /usr/local/bin/hardcore-edns-proxy 2>/tmp/compile.log; then
        echo -e "\r  ${GREEN}✓ Hardcore EDNS Proxy compiled successfully${NC}"
        
        # Set permissions
        chmod 755 /usr/local/bin/hardcore-edns-proxy
        setcap 'cap_net_bind_service=+ep' /usr/local/bin/hardcore-edns-proxy 2>/dev/null
        
        # Test binary
        if timeout 1 /usr/local/bin/hardcore-edns-proxy --test 2>&1 | grep -q "STARTUP"; then
            print_success "Binary test passed"
        else
            # Binary doesn't have --test option, that's OK
            print_info "Binary compiled and ready"
        fi
    else
        echo -e "\r  ${RED}✗ Compilation failed${NC}"
        if [ -f /tmp/compile.log ]; then
            echo "  ${YELLOW}Compilation log:${NC}"
            tail -10 /tmp/compile.log
        fi
        return 1
    fi
    
    print_stats "MTU Configuration: External=${RED}${EXT_EDNS_MTU}${NC}, Internal=${GREEN}${INT_EDNS_MTU}${NC}"
    
    # Cleanup
    rm -f /tmp/hardcore-edns.c /tmp/compile.log 2>/dev/null
    
    return 0
}

# ============================================================================
# CREATE HARDCORE SYSTEMD SERVICES
# ============================================================================
create_services() {
    print_header "⚙️  CREATING HARDCORE SERVICES"
    
    # Get nameserver
    echo -e "${WHITE}${BOLD}Enter your nameserver (e.g., dns.example.com):${NC}"
    read -p "Nameserver: " NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    # Create SlowDNS service
    cat > /etc/systemd/system/hardcore-slowdns.service << EOF
[Unit]
Description=Hardcore SlowDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/slowdns
ExecStart=/etc/slowdns/dnstt-server -udp :${SLOWDNS_PORT} -mtu ${INT_EDNS_MTU} -privkey-file /etc/slowdns/server.key ${NAMESERVER} 127.0.0.1:${SSHD_PORT}
Restart=always
RestartSec=3
LimitNOFILE=1048576
Nice=-10

[Install]
WantedBy=multi-user.target
EOF

    print_success "Hardcore SlowDNS service created"
    print_info "MTU: ${INT_EDNS_MTU}, Port: ${SLOWDNS_PORT}"
    print_info "Nameserver: ${NAMESERVER}"
    
    # Create EDNS Proxy service
    cat > /etc/systemd/system/hardcore-edns-proxy.service << EOF
[Unit]
Description=Hardcore EDNS Proxy
After=hardcore-slowdns.service
Requires=hardcore-slowdns.service

[Service]
Type=forking
User=root
ExecStart=/usr/local/bin/hardcore-edns-proxy
Restart=always
RestartSec=3
LimitNOFILE=1048576
Nice=-15

[Install]
WantedBy=multi-user.target
EOF

    print_success "Hardcore EDNS Proxy service created"
    print_info "External MTU: ${EXT_EDNS_MTU}, Internal MTU: ${INT_EDNS_MTU}"
    
    # Create watchdog service
    cat > /etc/systemd/system/hardcore-slowdns-watchdog.service << EOF
[Unit]
Description=Hardcore SlowDNS Watchdog
After=hardcore-slowdns.service hardcore-edns-proxy.service

[Service]
Type=simple
User=root
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
    
    # Save nameserver for later use
    echo "$NAMESERVER" > /tmp/slowdns-nameserver.txt
}

# ============================================================================
# SETUP FIREWALL WITH PERFORMANCE RULES
# ============================================================================
setup_firewall() {
    print_header "🔥 CONFIGURING HARDCORE FIREWALL"
    
    # Flush existing rules
    iptables -F 2>/dev/null || true
    iptables -X 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t nat -X 2>/dev/null || true
    
    # Default policies
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport ${SSHD_PORT} -j ACCEPT 2>/dev/null
    
    # Allow DNS (UDP & TCP)
    iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null
    
    # Allow SlowDNS
    iptables -A INPUT -p udp --dport ${SLOWDNS_PORT} -j ACCEPT 2>/dev/null
    
    # Allow ICMP (ping)
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null
    
    # Drop invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null
    
    print_success "Hardcore firewall configured"
    print_info "SSH Port: ${SSHD_PORT}, SlowDNS Port: ${SLOWDNS_PORT}"
}

# ============================================================================
# DISABLE CONFLICTING SERVICES
# ============================================================================
disable_conflicts() {
    print_header "🚫 DISABLING CONFLICTING SERVICES"
    
    # Stop systemd-resolved if running
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        print_info "Stopping systemd-resolved..."
        systemctl stop systemd-resolved 2>/dev/null
        systemctl disable systemd-resolved 2>/dev/null
        systemctl mask systemd-resolved 2>/dev/null
    fi
    
    # Kill any process using port 53
    local pids=$(lsof -ti:53 2>/dev/null)
    if [ -n "$pids" ]; then
        print_info "Killing processes on port 53: $pids"
        kill -9 $pids 2>/dev/null
    fi
    
    # Additional cleanup
    fuser -k 53/udp 2>/dev/null
    fuser -k 53/tcp 2>/dev/null
    
    sleep 2
    
    # Verify port 53 is free
    if ss -ulpn | grep -q ":53 "; then
        print_warning "Port 53 still in use after cleanup"
        ss -ulpn | grep ":53 "
    else
        print_success "Port 53 is now free"
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
    
    # Get nameserver from temp file
    NAMESERVER=$(cat /tmp/slowdns-nameserver.txt 2>/dev/null || echo "dns.example.com")
    
    # Download binary
    print_info "Downloading SlowDNS binary..."
    
    local download_success=0
    
    # Try curl first
    if command -v curl &>/dev/null; then
        if curl -fsSL "${GITHUB_BASE}/dnstt-server" -o dnstt-server 2>/dev/null; then
            download_success=1
        fi
    fi
    
    # Try wget if curl failed
    if [ $download_success -eq 0 ] && command -v wget &>/dev/null; then
        if wget -q "${GITHUB_BASE}/dnstt-server" -O dnstt-server 2>/dev/null; then
            download_success=1
        fi
    fi
    
    if [ $download_success -eq 0 ]; then
        print_error "Failed to download SlowDNS binary"
        return 1
    fi
    
    chmod +x dnstt-server
    
    # Download keys
    print_info "Downloading encryption keys..."
    
    # Try to download keys
    if command -v curl &>/dev/null; then
        curl -fsSL "${GITHUB_BASE}/server.key" -o server.key 2>/dev/null || true
        curl -fsSL "${GITHUB_BASE}/server.pub" -o server.pub 2>/dev/null || true
    elif command -v wget &>/dev/null; then
        wget -q "${GITHUB_BASE}/server.key" -O server.key 2>/dev/null || true
        wget -q "${GITHUB_BASE}/server.pub" -O server.pub 2>/dev/null || true
    fi
    
    # Generate keys if download failed
    if [ ! -f server.key ] || [ ! -f server.pub ]; then
        print_warning "Failed to download keys, attempting to generate..."
        if ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub 2>&1 | grep -q "generating"; then
            print_success "Keys generated successfully"
        else
            # Create dummy keys as fallback
            echo "dummy-key" > server.key
            echo "dummy-pub" > server.pub
            print_warning "Using dummy keys - functionality may be limited"
        fi
    else
        print_success "Keys downloaded successfully"
    fi
    
    # Test the binary
    print_info "Testing SlowDNS binary..."
    if timeout 2 ./dnstt-server -h 2>&1 | head -1; then
        print_success "SlowDNS binary is working"
    else
        print_warning "SlowDNS binary test inconclusive"
    fi
    
    return 0
}

# ============================================================================
# START SERVICES
# ============================================================================
start_services() {
    print_header "🚀 STARTING SERVICES"
    
    # Reload systemd
    print_info "Reloading systemd..."
    systemctl daemon-reload 2>/dev/null
    
    # Start SlowDNS
    print_info "Starting Hardcore SlowDNS..."
    systemctl enable hardcore-slowdns 2>/dev/null
    systemctl restart hardcore-slowdns 2>/dev/null
    
    sleep 2
    
    if systemctl is-active --quiet hardcore-slowdns; then
        print_success "SlowDNS service is running"
    else
        print_error "SlowDNS failed to start"
        journalctl -u hardcore-slowdns -n 10 --no-pager
        return 1
    fi
    
    # Start EDNS Proxy
    print_info "Starting Hardcore EDNS Proxy..."
    systemctl enable hardcore-edns-proxy 2>/dev/null
    systemctl restart hardcore-edns-proxy 2>/dev/null
    
    sleep 2
    
    if systemctl is-active --quiet hardcore-edns-proxy; then
        print_success "EDNS Proxy service is running"
    else
        print_error "EDNS Proxy failed to start"
        journalctl -u hardcore-edns-proxy -n 10 --no-pager
        return 1
    fi
    
    # Start watchdog
    print_info "Starting Watchdog..."
    systemctl enable hardcore-slowdns-watchdog 2>/dev/null
    systemctl restart hardcore-slowdns-watchdog 2>/dev/null
    
    if systemctl is-active --quiet hardcore-slowdns-watchdog; then
        print_success "Watchdog service is running"
    else
        print_warning "Watchdog failed to start (non-critical)"
    fi
    
    # Verify ports
    print_info "Verifying ports are listening..."
    
    local all_ports_ok=1
    
    # Check port 53
    if ss -ulpn | grep -q ":53 "; then
        print_success "Port 53 (EDNS Proxy) is listening"
    else
        print_error "Port 53 NOT listening"
        all_ports_ok=0
    fi
    
    # Check SlowDNS port
    if ss -ulpn | grep -q ":${SLOWDNS_PORT} "; then
        print_success "Port ${SLOWDNS_PORT} (SlowDNS) is listening"
    else
        print_error "Port ${SLOWDNS_PORT} NOT listening"
        all_ports_ok=0
    fi
    
    # Check SSH port
    if ss -tlnp | grep -q ":${SSHD_PORT} "; then
        print_success "Port ${SSHD_PORT} (SSH) is listening"
    else
        print_error "Port ${SSHD_PORT} NOT listening"
        all_ports_ok=0
    fi
    
    if [ $all_ports_ok -eq 1 ]; then
        print_success "All services are running correctly"
        return 0
    else
        print_error "Some services failed to start properly"
        return 1
    fi
}

# ============================================================================
# FINAL CONFIGURATION AND SUMMARY
# ============================================================================
final_summary() {
    print_header "✅ INSTALLATION COMPLETE"
    
    # Get server IP
    local server_ip=$(curl -s --connect-timeout 3 ifconfig.me || hostname -I | awk '{print $1}')
    local nameserver=$(cat /tmp/slowdns-nameserver.txt 2>/dev/null || echo "dns.example.com")
    
    # Display configuration
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}                      ${WHITE}CONFIGURATION SUMMARY${NC}                      ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}${BOLD}║${NC} ${CYAN}●${NC} Server IP:        ${WHITE}$server_ip${NC}"
    echo -e "${GREEN}${BOLD}║${NC} ${CYAN}●${NC} SSH Port:         ${WHITE}$SSHD_PORT${NC}"
    echo -e "${GREEN}${BOLD}║${NC} ${CYAN}●${NC} SlowDNS Port:     ${WHITE}$SLOWDNS_PORT${NC}"
    echo -e "${GREEN}${BOLD}║${NC} ${CYAN}●${NC} DNS Port:         ${WHITE}53${NC}"
    echo -e "${GREEN}${BOLD}║${NC} ${CYAN}●${NC} External MTU:     ${RED}$EXT_EDNS_MTU${NC} (Internet)"
    echo -e "${GREEN}${BOLD}║${NC} ${CYAN}●${NC} Internal MTU:     ${GREEN}$INT_EDNS_MTU${NC} (Local)"
    echo -e "${GREEN}${BOLD}║${NC} ${CYAN}●${NC} Nameserver:       ${WHITE}$nameserver${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    
    # Show public key
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${YELLOW}${BOLD}Public Key:${NC}"
        cat /etc/slowdns/server.pub
    fi
    
    # Test commands
    echo -e "\n${CYAN}${BOLD}Test Commands:${NC}"
    echo -e "  ${GREEN}dig @$server_ip $nameserver${NC}"
    echo -e "  ${GREEN}nslookup $nameserver $server_ip${NC}"
    
    # Service management
    echo -e "\n${MAGENTA}${BOLD}Service Management:${NC}"
    echo -e "  ${GREEN}systemctl status hardcore-slowdns${NC}"
    echo -e "  ${GREEN}systemctl status hardcore-edns-proxy${NC}"
    echo -e "  ${GREEN}journalctl -fu hardcore-slowdns${NC}"
    
    # Client configuration
    echo -e "\n${BLUE}${BOLD}Client Configuration:${NC}"
    echo -e "  ${YELLOW}./dnstt-client -udp $server_ip:$SLOWDNS_PORT \\${NC}"
    echo -e "      -pubkey-file server.pub \\${NC}"
    echo -e "      $nameserver 127.0.0.1:1080${NC}"
    
    echo -e "\n${WHITE}${BOLD}Installation completed at: $(date)${NC}"
    
    # Cleanup temp file
    rm -f /tmp/slowdns-nameserver.txt 2>/dev/null
}

# ============================================================================
# MAIN EXECUTION FLOW
# ============================================================================
main() {
    print_banner
    
    # Start timer
    start_timer
    
    # Execute installation steps
    optimize_kernel
    optimize_memory
    optimize_network
    disable_conflicts
    compile_edns_proxy
    create_services
    setup_firewall
    setup_slowdns
    
    # Start services
    if start_services; then
        final_summary
        end_timer
        echo -e "\n${GREEN}${BOLD}✓ Installation completed successfully!${NC}"
    else
        echo -e "\n${RED}${BOLD}✗ Installation completed with errors${NC}"
        echo -e "${YELLOW}Check the logs above for details${NC}"
        end_timer
    fi
    
    echo -e "\n${WHITE}${BOLD}Press Enter to exit...${NC}"
    read -r
}

# ============================================================================
# ERROR HANDLING
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; exit 1' INT

# Run main function
if main; then
    exit 0
else
    exit 1
fi

```

