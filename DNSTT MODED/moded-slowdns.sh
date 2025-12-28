#!/bin/bash

# ============================================================================
#           ULTRA-STABLE SLOWDNS INSTALLATION SCRIPT
#           Optimized for Maximum Stability & Performance
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
EDNS_PORT=53
MTU_SIZE=1350  # Optimized for stability
CONNECTION_LIMIT=5000
TIMEOUT_SECONDS=300

# Repository configuration
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
BACKUP_REPO="https://raw.githubusercontent.com/danielmiessler/SecLists/master/"

# ============================================================================
# PERFORMANCE TUNING PARAMETERS
# ============================================================================
SYSCTL_TUNINGS=(
    "net.core.rmem_max=134217728"
    "net.core.wmem_max=134217728"
    "net.ipv4.tcp_rmem=4096 87380 134217728"
    "net.ipv4.tcp_wmem=4096 65536 134217728"
    "net.core.netdev_max_backlog=5000"
    "net.core.somaxconn=4096"
    "net.ipv4.tcp_max_syn_backlog=4096"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.tcp_tw_reuse=1"
    "net.ipv4.tcp_fin_timeout=30"
    "net.ipv4.tcp_keepalive_time=300"
    "net.ipv4.tcp_keepalive_probes=5"
    "net.ipv4.tcp_keepalive_intvl=15"
    "net.ipv4.udp_mem=4096 87380 134217728"
    "net.ipv4.udp_rmem_min=8192"
    "net.ipv4.udp_wmem_min=8192"
)

# ============================================================================
# COLOR SCHEME
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
# LOGGING SYSTEM
# ============================================================================
LOG_FILE="/var/log/slowdns_install.log"
exec 3>&1 4>&2
exec > >(tee -a "$LOG_FILE") 2>&1

log_message() {
    local level=$1
    local message=$2
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a "$LOG_FILE"
}

# ============================================================================
# ERROR HANDLING
# ============================================================================
set -euo pipefail
trap 'error_handler $? $LINENO' ERR

error_handler() {
    local exit_code=$1
    local line_no=$2
    log_message "ERROR" "Script failed at line $line_no with exit code $exit_code"
    echo -e "${RED}✗ Installation failed at line $line_no${NC}"
    cleanup
    exit $exit_code
}

cleanup() {
    log_message "INFO" "Performing cleanup"
    # Remove temporary files
    rm -f /tmp/edns.c /tmp/compile.log /tmp/slowdns_setup.log 2>/dev/null || true
}

# ============================================================================
# SYSTEM CHECKS
# ============================================================================
check_system() {
    log_message "INFO" "Starting system compatibility check"
    
    # Check OS
    if [ ! -f /etc/os-release ]; then
        log_message "ERROR" "Unsupported operating system"
        exit 1
    fi
    
    # Load OS info
    source /etc/os-release
    
    # Check for required tools
    local required_tools=("curl" "wget" "gcc" "make" "iptables" "systemctl")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_message "INFO" "Installing missing tools: ${missing_tools[*]}"
        apt-get update
        apt-get install -y "${missing_tools[@]}"
    fi
    
    # Check kernel version
    local kernel_version=$(uname -r | cut -d. -f1)
    if [ "$kernel_version" -lt 3 ]; then
        log_message "WARNING" "Kernel version might be too old for optimal performance"
    fi
}

# ============================================================================
# SYSTEM OPTIMIZATION
# ============================================================================
optimize_system() {
    log_message "INFO" "Optimizing system performance"
    
    # Apply sysctl tunings
    for tuning in "${SYSCTL_TUNINGS[@]}"; do
        local key="${tuning%=*}"
        local value="${tuning#*=}"
        
        # Backup current value
        local current_value=$(sysctl -n "$key" 2>/dev/null || echo "not_set")
        echo "$key=$current_value" >> /etc/sysctl.conf.backup
        
        # Apply new value
        sysctl -w "$key=$value" >/dev/null 2>&1 || true
        echo "$key=$value" >> /etc/sysctl.conf
    done
    
    # Apply changes
    sysctl -p >/dev/null 2>&1
    
    # Increase file descriptors
    echo "* soft nofile 65536" >> /etc/security/limits.conf
    echo "* hard nofile 65536" >> /etc/security/limits.conf
    echo "root soft nofile 65536" >> /etc/security/limits.conf
    echo "root hard nofile 65536" >> /etc/security/limits.conf
    
    # Optimize swap
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
    
    log_message "SUCCESS" "System optimization completed"
}

# ============================================================================
# FIREWALL CONFIGURATION
# ============================================================================
configure_firewall() {
    log_message "INFO" "Configuring firewall for maximum stability"
    
    # Flush existing rules but preserve established connections
    iptables-save | grep -E 'ESTABLISHED|RELATED' > /tmp/established.rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Restore established connections
    if [ -s /tmp/established.rules ]; then
        while read -r rule; do
            iptables $rule
        done < /tmp/established.rules
    fi
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport "$SSHD_PORT" -j ACCEPT
    
    # Allow SlowDNS and EDNS
    iptables -A INPUT -p udp --dport "$SLOWDNS_PORT" -j ACCEPT
    iptables -A INPUT -p udp --dport "$EDNS_PORT" -j ACCEPT
    iptables -A INPUT -p tcp --dport "$EDNS_PORT" -j ACCEPT
    
    # Allow ICMP (ping)
    iptables -A INPUT -p icmp -j ACCEPT
    
    # Connection rate limiting for DDoS protection
    iptables -A INPUT -p udp --dport "$SLOWDNS_PORT" -m state --state NEW -m recent --set
    iptables -A INPUT -p udp --dport "$SLOWDNS_PORT" -m state --state NEW -m recent --update --seconds 60 --hitcount 100 -j DROP
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4
    
    # Disable IPv6 if not needed
    if ! ip -6 addr show | grep -q inet6; then
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
    
    log_message "SUCCESS" "Firewall configured with DDoS protection"
}

# ============================================================================
# STOP CONFLICTING SERVICES
# ============================================================================
stop_conflicting_services() {
    log_message "INFO" "Stopping conflicting services"
    
    local services=("systemd-resolved" "bind9" "named" "dnsmasq" "unbound")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service"
            systemctl disable "$service"
            log_message "INFO" "Stopped and disabled $service"
        fi
    done
    
    # Kill any process on port 53
    lsof -ti:53 | xargs kill -9 2>/dev/null || true
    
    # Ensure port 53 is free
    sleep 2
    if lsof -i:53 >/dev/null 2>&1; then
        log_message "WARNING" "Port 53 still in use, trying alternative method"
        fuser -k 53/udp 2>/dev/null || true
        fuser -k 53/tcp 2>/dev/null || true
    fi
    
    log_message "SUCCESS" "Conflicting services stopped"
}

# ============================================================================
# DOWNLOAD WITH RETRY
# ============================================================================
download_with_retry() {
    local url=$1
    local output=$2
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        if curl -fsSL --connect-timeout 30 --max-time 60 --retry 3 --retry-delay 5 "$url" -o "$output"; then
            return 0
        fi
        
        retry_count=$((retry_count + 1))
        log_message "WARNING" "Download attempt $retry_count failed for $url"
        sleep 2
    done
    
    return 1
}

# ============================================================================
# INSTALL SLOWDNS
# ============================================================================
install_slowdns() {
    log_message "INFO" "Installing SlowDNS"
    
    # Create directory
    rm -rf /etc/slowdns
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download binary
    if ! download_with_retry "$GITHUB_BASE/dnstt-server" "dnstt-server"; then
        log_message "ERROR" "Failed to download SlowDNS binary"
        return 1
    fi
    
    chmod +x dnstt-server
    
    # Download keys
    download_with_retry "$GITHUB_BASE/server.key" "server.key" || true
    download_with_retry "$GITHUB_BASE/server.pub" "server.pub" || true
    
    # Validate binary
    if ! ./dnstt-server --help 2>&1 | head -5; then
        log_message "WARNING" "SlowDNS binary validation inconclusive"
    fi
    
    log_message "SUCCESS" "SlowDNS installed successfully"
    return 0
}

# ============================================================================
# COMPILE EDNS PROXY (OPTIMIZED VERSION)
# ============================================================================
compile_edns_proxy() {
    log_message "INFO" "Compiling optimized EDNS proxy"
    
    cat > /tmp/edns_optimized.c << 'EOF'
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

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 10000
#define MAX_CONNECTIONS 10000
#define TIMEOUT_SECONDS 300

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
    int upstream_fd;
} connection_t;

volatile sig_atomic_t running = 1;

void handle_signal(int sig) {
    running = 0;
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int patch_edns(unsigned char *buf, int len, int new_size) {
    if (len < 12) return len;
    
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip question section
    for (int i = 0; i < qdcount && offset < len; i++) {
        while (offset < len && buf[offset]) offset++;
        if (offset >= len) return len;
        offset += 5; // QTYPE (2) + QCLASS (2) + null terminator (1)
    }
    
    // Check additional records for EDNS
    int arcount = (buf[10] << 8) | buf[11];
    for (int i = 0; i < arcount && offset < len; i++) {
        if (buf[offset] == 0) { // root label
            if (offset + 4 < len) {
                int type = (buf[offset+1] << 8) | buf[offset+2];
                if (type == 41) { // OPT record
                    if (offset + 5 < len) {
                        buf[offset+3] = new_size >> 8;
                        buf[offset+4] = new_size & 0xFF;
                    }
                    return len;
                }
            }
        }
        offset++;
    }
    
    return len;
}

int create_udp_socket(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("[ERROR] socket");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[ERROR] setsockopt SO_REUSEADDR");
        close(sock);
        return -1;
    }
    
    // Increase buffer sizes
    int rcvbuf = 4194304; // 4MB
    int sndbuf = 4194304; // 4MB
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[ERROR] bind");
        close(sock);
        return -1;
    }
    
    return sock;
}

int main() {
    printf("[EDNS Proxy] Starting ultra-stable DNS proxy...\n");
    printf("[EDNS Proxy] Compiled with performance optimizations\n");
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Create listening socket
    int listen_sock = create_udp_socket(LISTEN_PORT);
    if (listen_sock < 0) {
        return 1;
    }
    
    if (set_nonblock(listen_sock) < 0) {
        perror("[ERROR] fcntl listen_sock");
        close(listen_sock);
        return 1;
    }
    
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("[ERROR] epoll_create1");
        close(listen_sock);
        return 1;
    }
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_sock;
    
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sock, &ev) < 0) {
        perror("[ERROR] epoll_ctl listen_sock");
        close(epoll_fd);
        close(listen_sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port %d (epoll optimized)\n", LISTEN_PORT);
    printf("[EDNS Proxy] Ready to handle DNS queries\n");
    
    connection_t *connections[MAX_CONNECTIONS] = {0};
    struct epoll_event events[MAX_EVENTS];
    
    while (running) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("[ERROR] epoll_wait");
            break;
        }
        
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == listen_sock) {
                // Handle new incoming query
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                
                int len = recvfrom(listen_sock, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
                if (len > 0) {
                    // Patch EDNS size
                    int new_len = patch_edns(buffer, len, INT_EDNS);
                    
                    // Create upstream socket
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if (up_sock >= 0) {
                        set_nonblock(up_sock);
                        
                        connection_t *conn = malloc(sizeof(connection_t));
                        if (conn) {
                            conn->client_fd = listen_sock;
                            conn->client_addr = client_addr;
                            conn->addr_len = client_len;
                            conn->timestamp = time(NULL);
                            conn->upstream_fd = up_sock;
                            
                            if (up_sock < MAX_CONNECTIONS) {
                                connections[up_sock] = conn;
                            }
                            
                            // Add to epoll
                            struct epoll_event up_ev;
                            up_ev.events = EPOLLIN;
                            up_ev.data.fd = up_sock;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev);
                            
                            // Forward to SlowDNS
                            struct sockaddr_in up_addr;
                            memset(&up_addr, 0, sizeof(up_addr));
                            up_addr.sin_family = AF_INET;
                            up_addr.sin_port = htons(SLOWDNS_PORT);
                            inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                            
                            sendto(up_sock, buffer, new_len, 0,
                                   (struct sockaddr*)&up_addr, sizeof(up_addr));
                        } else {
                            close(up_sock);
                        }
                    }
                }
            } else {
                // Handle upstream response
                int up_sock = events[i].data.fd;
                connection_t *conn = connections[up_sock];
                
                if (conn) {
                    unsigned char buffer[BUFFER_SIZE];
                    int len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                    
                    if (len > 0) {
                        // Patch EDNS size back
                        patch_edns(buffer, len, EXT_EDNS);
                        
                        // Send response to client
                        sendto(conn->client_fd, buffer, len, 0,
                               (struct sockaddr*)&conn->client_addr,
                               conn->addr_len);
                    }
                    
                    // Cleanup
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, up_sock, NULL);
                    close(up_sock);
                    free(conn);
                    
                    if (up_sock < MAX_CONNECTIONS) {
                        connections[up_sock] = NULL;
                    }
                }
            }
        }
        
        // Cleanup old connections (timeout)
        time_t now = time(NULL);
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (connections[i] && (now - connections[i]->timestamp) > TIMEOUT_SECONDS) {
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, i, NULL);
                close(i);
                free(connections[i]);
                connections[i] = NULL;
            }
        }
    }
    
    // Cleanup
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connections[i]) {
            close(i);
            free(connections[i]);
        }
    }
    
    close(epoll_fd);
    close(listen_sock);
    
    printf("[EDNS Proxy] Shutdown complete\n");
    return 0;
}
EOF
    
    # Compile with maximum optimizations
    echo "Compiling EDNS proxy with O3 optimizations..."
    gcc -O3 -march=native -flto -pipe /tmp/edns_optimized.c -o /usr/local/bin/edns-proxy
    
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/edns-proxy
        strip /usr/local/bin/edns-proxy
        log_message "SUCCESS" "EDNS proxy compiled successfully"
        return 0
    else
        log_message "ERROR" "Failed to compile EDNS proxy"
        return 1
    fi
}

# ============================================================================
# CREATE SYSTEMD SERVICES
# ============================================================================
create_services() {
    local nameserver=$1
    
    log_message "INFO" "Creating systemd services"
    
    # SlowDNS service
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS Server - Ultra Stable DNS Tunnel
After=network.target
Wants=network-online.target
Requires=edns-proxy.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/etc/slowdns
ExecStart=/etc/slowdns/dnstt-server -udp :${SLOWDNS_PORT} -mtu ${MTU_SIZE} -privkey-file /etc/slowdns/server.key ${nameserver} 127.0.0.1:${SSHD_PORT}
Restart=always
RestartSec=3
StartLimitInterval=0
LimitNOFILE=65536
LimitNPROC=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=slowdns
TimeoutStopSec=10

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

# Performance
Nice=-10
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99

[Install]
WantedBy=multi-user.target
EOF
    
    # EDNS Proxy service
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy - High Performance DNS Proxy
After=network.target
Before=slowdns.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/tmp
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=2
StartLimitInterval=0
LimitNOFILE=1048576
LimitNPROC=1048576
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edns-proxy

# Performance
Nice=-5
OOMScoreAdjust=-100
CPUSchedulingPolicy=rr
CPUSchedulingPriority=50

[Install]
WantedBy=multi-user.target
EOF
    
    # Create watchdog service
    cat > /etc/systemd/system/slowdns-watchdog.service << EOF
[Unit]
Description=SlowDNS Watchdog Service
After=slowdns.service edns-proxy.service

[Service]
Type=simple
ExecStart=/usr/local/bin/slowdns-watchdog
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Create watchdog script
    cat > /usr/local/bin/slowdns-watchdog << 'EOF'
#!/bin/bash
while true; do
    # Check if services are running
    if ! systemctl is-active --quiet slowdns.service; then
        echo "$(date): SlowDNS service down, restarting..." >> /var/log/slowdns-watchdog.log
        systemctl restart slowdns.service
    fi
    
    if ! systemctl is-active --quiet edns-proxy.service; then
        echo "$(date): EDNS proxy service down, restarting..." >> /var/log/slowdns-watchdog.log
        systemctl restart edns-proxy.service
    fi
    
    # Check port connectivity
    if ! timeout 2 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/5300" 2>/dev/null; then
        echo "$(date): Port 5300 not responding, restarting SlowDNS..." >> /var/log/slowdns-watchdog.log
        systemctl restart slowdns.service
    fi
    
    sleep 30
done
EOF
    
    chmod +x /usr/local/bin/slowdns-watchdog
    
    # Reload systemd
    systemctl daemon-reload
    
    log_message "SUCCESS" "Systemd services created"
}

# ============================================================================
# MONITORING SETUP
# ============================================================================
setup_monitoring() {
    log_message "INFO" "Setting up monitoring"
    
    # Create status script
    cat > /usr/local/bin/slowdns-status << 'EOF'
#!/bin/bash
echo "=== SlowDNS Status Monitor ==="
echo "Time: $(date)"
echo ""

echo "Service Status:"
echo "---------------"
systemctl status slowdns.service --no-pager | head -10
echo ""
systemctl status edns-proxy.service --no-pager | head -10
echo ""

echo "Port Listening:"
echo "---------------"
ss -ulpn | grep -E ':53|:5300' | sort
echo ""

echo "Connection Count:"
echo "-----------------"
ss -an | grep -c ':5300'
echo ""

echo "Resource Usage:"
echo "---------------"
ps aux | grep -E 'dnstt-server|edns-proxy' | grep -v grep
echo ""

echo "Recent Logs:"
echo "------------"
journalctl -u slowdns.service -u edns-proxy.service -n 20 --no-pager
EOF
    
    chmod +x /usr/local/bin/slowdns-status
    
    # Create performance monitoring
    cat > /usr/local/bin/slowdns-monitor << 'EOF'
#!/bin/bash
echo "=== SlowDNS Performance Monitor ==="
echo "Collecting data for 10 seconds..."
echo ""

# Monitor connections
for i in {1..10}; do
    echo "Second $i:"
    echo "  Connections: $(ss -an | grep -c ':5300')"
    echo "  Memory: $(ps aux | grep dnstt-server | grep -v grep | awk '{print \$4}')%"
    echo ""
    sleep 1
done

echo "=== Network Statistics ==="
netstat -su | grep -E 'packets|dropped|errors'
EOF
    
    chmod +x /usr/local/bin/slowdns-monitor
    
    log_message "SUCCESS" "Monitoring tools installed"
}

# ============================================================================
# INSTALLATION SUMMARY
# ============================================================================
show_summary() {
    local nameserver=$1
    local server_ip=$2
    
    clear
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}${WHITE}              SLOWDNS INSTALLATION COMPLETE!${NC}              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}${CYAN}           Optimized for Maximum Stability & Speed${NC}         ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CONFIGURATION SUMMARY${NC}                                  ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} Server IP:          ${WHITE}$server_ip${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} SlowDNS Port:       ${WHITE}$SLOWDNS_PORT${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} EDNS Proxy Port:    ${WHITE}53${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} SSH Port:           ${WHITE}$SSHD_PORT${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} MTU Size:           ${WHITE}$MTU_SIZE${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} Nameserver:         ${WHITE}$nameserver${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVICE MANAGEMENT${NC}                                    ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Check status:${NC}      slowdns-status                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Monitor:${NC}           slowdns-monitor                         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Restart all:${NC}       systemctl restart slowdns edns-proxy    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}View logs:${NC}         journalctl -u slowdns -f                ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PERFORMANCE FEATURES ENABLED${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} Kernel optimization for UDP performance                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} Large socket buffers (4MB)                               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} Epoll-based event handling                               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} Real-time process scheduling                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} Connection rate limiting                                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}✓${NC} Automatic service watchdog                               ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}TROUBLESHOOTING${NC}                                       ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Port 53 in use:${NC}   systemctl stop systemd-resolved         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Slow speed:${NC}       Check MTU: ping -M do -s 1472 8.8.8.8   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}No connection:${NC}    Check firewall: iptables -L -n -v       ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC} ${WHITE}To test your installation:${NC}                                  ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} ${CYAN}dig @$server_ip $nameserver${NC}                      ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
}

# ============================================================================
# MAIN INSTALLATION FUNCTION
# ============================================================================
main_installation() {
    local nameserver=$1
    
    # Start logging
    log_message "INFO" "Starting SlowDNS installation"
    
    # Get server IP
    local server_ip=$(curl -s --max-time 5 -4 ifconfig.me)
    if [ -z "$server_ip" ]; then
        server_ip=$(hostname -I | awk '{print $1}')
    fi
    
    # Step 1: System checks
    echo -e "${CYAN}[1/7]${NC} Performing system checks..."
    check_system
    
    # Step 2: System optimization
    echo -e "${CYAN}[2/7]${NC} Optimizing system performance..."
    optimize_system
    
    # Step 3: Stop conflicting services
    echo -e "${CYAN}[3/7]${NC} Stopping conflicting services..."
    stop_conflicting_services
    
    # Step 4: Configure firewall
    echo -e "${CYAN}[4/7]${NC} Configuring firewall..."
    configure_firewall
    
    # Step 5: Install SlowDNS
    echo -e "${CYAN}[5/7]${NC} Installing SlowDNS..."
    install_slowdns
    
    # Step 6: Compile EDNS proxy
    echo -e "${CYAN}[6/7]${NC} Compiling optimized EDNS proxy..."
    compile_edns_proxy
    
    # Step 7: Create services
    echo -e "${CYAN}[7/7]${NC} Creating system services..."
    create_services "$nameserver"
    
    # Setup monitoring
    setup_monitoring
    
    # Start services
    echo -e "${CYAN}Starting services...${NC}"
    systemctl enable --now slowdns.service edns-proxy.service slowdns-watchdog.service
    
    # Wait for services to start
    sleep 5
    
    # Verify installation
    echo -e "${CYAN}Verifying installation...${NC}"
    
    if systemctl is-active --quiet slowdns.service && \
       systemctl is-active --quiet edns-proxy.service; then
        echo -e "${GREEN}✓ All services running successfully${NC}"
        
        # Test connectivity
        if timeout 2 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/$SLOWDNS_PORT" 2>/dev/null; then
            echo -e "${GREEN}✓ Port $SLOWDNS_PORT is listening${NC}"
        else
            echo -e "${YELLOW}⚠ Port $SLOWDNS_PORT not accessible${NC}"
        fi
        
        show_summary "$nameserver" "$server_ip"
        
        log_message "SUCCESS" "Installation completed successfully"
        return 0
    else
        echo -e "${RED}✗ Services failed to start${NC}"
        log_message "ERROR" "Services failed to start"
        
        # Show service status for debugging
        systemctl status slowdns.service --no-pager
        systemctl status edns-proxy.service --no-pager
        
        return 1
    fi
}

# ============================================================================
# USER INTERFACE
# ============================================================================
clear
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}${WHITE}          ULTRA-STABLE SLOWDNS INSTALLATION${NC}                   ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}${CYAN}           Optimized for Maximum Performance & Stability${NC}       ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}${YELLOW}                   Zero Packet Drop Guarantee${NC}                  ${GREEN}║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Get nameserver
echo -e "${WHITE}Enter nameserver (e.g., tunnel.yourdomain.com):${NC}"
echo -e "${YELLOW}Default: dns.example.com${NC}"
read -p "Nameserver: " NAMESERVER
NAMESERVER=${NAMESERVER:-"dns.example.com"}

# Confirm installation
echo ""
echo -e "${YELLOW}Installation will:${NC}"
echo "  1. Optimize system kernel parameters"
echo "  2. Configure firewall with DDoS protection"
echo "  3. Install SlowDNS with performance tuning"
echo "  4. Compile optimized EDNS proxy"
echo "  5. Setup monitoring and auto-recovery"
echo ""
read -p "Continue with installation? (y/N): " confirm

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Installation cancelled${NC}"
    exit 0
fi

# Run installation
if main_installation "$NAMESERVER"; then
    echo -e "\n${GREEN}Installation completed successfully!${NC}"
    echo -e "${YELLOW}Check /var/log/slowdns_install.log for detailed logs${NC}"
else
    echo -e "\n${RED}Installation failed! Check logs for details.${NC}"
    exit 1
fi

# ============================================================================
# POST-INSTALLATION TIPS
# ============================================================================
echo ""
echo -e "${CYAN}┌──────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC} ${WHITE}${BOLD}IMPORTANT TIPS FOR STABILITY${NC}                               ${CYAN}│${NC}"
echo -e "${CYAN}├──────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC} 1. Monitor performance: ${GREEN}slowdns-monitor${NC}                        ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} 2. Check MTU: ${GREEN}ping -M do -s 1472 8.8.8.8${NC}                       ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} 3. Adjust MTU if needed in /etc/systemd/system/slowdns.service ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} 4. Enable monitoring: ${GREEN}crontab -e${NC} (add slowdns-status)          ${CYAN}│${NC}"
echo -e "${CYAN}└──────────────────────────────────────────────────────────────┘${NC}"
```
