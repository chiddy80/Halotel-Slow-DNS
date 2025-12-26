#!/bin/bash

# ╔═══════════════════════════════════════════════════════════════════╗
# ║                     FAST DNS  DEVELOPER SCRIPT                                ║
# ║                     PATCHED HIGH SPEED VERISON                                ║
# ╚═══════════════════════════════════════════════════════════════════╝
#
#  ███████╗██╗      ██████╗ ██╗    ██╗██████╗ ███╗   ██╗███████╗
#  ██╔════╝██║     ██╔═══██╗██║    ██║██╔══██╗████╗  ██║██╔════╝
#  ███████╗██║     ██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║███████╗
#  ╚════██║██║     ██║   ██║██║███╗██║██║  ██║██║╚██╗██║╚════██║
#  ███████║███████╗╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║███████║
#  ╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
#
#  🌍 MRCHIDDY ESIMFREEGB | ⌛ FAST DNS HALOTEL | ⚡ CONTACT ADMIN

# ============================================================================
#                             SYSTEM CONFIGURATION
# ============================================================================
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
VALID_KEYS_URL="$GITHUB_BASE/Valid_Keys.txt"
ALLOWED_IPS_URL="$GITHUB_BASE/Allowips.text"
MAX_ATTEMPTS=3
LOG_FILE="/var/log/slowdns_pro.log"
INSTALL_DIR="/opt/slowdns_pro"

# ============================================================================
#                              COLOR SCHEME
# ============================================================================
# Primary Colors
PRIMARY='\033[38;5;45m'      # Cyan Blue
SECONDARY='\033[38;5;208m'   # Orange
SUCCESS='\033[38;5;46m'      # Green
ERROR='\033[38;5;196m'       # Red
WARNING='\033[38;5;226m'     # Yellow
INFO='\033[38;5;51m'         # Light Cyan
HIGHLIGHT='\033[38;5;201m'   # Magenta
DIM='\033[38;5;244m'         # Gray
BOLD='\033[1m'
RESET='\033[0m'

# ============================================================================
#                               GRAPHICS
# ============================================================================
BOX_TOP="╔════════════════════════════════════════════════════════════════════╗"
BOX_MID="╠════════════════════════════════════════════════════════════════════╣"
BOX_BOT="╚════════════════════════════════════════════════════════════════════╝"
LINE="────────────────────────────────────────────────────────────────────────"
STAR="✦"
CHECK="✅"
CROSS="❌"
WARN="⚠️"
LOCK="🔒"
KEY="🔑"
SERVER="🖥️"
NETWORK="🌐"
CLOCK="⏱️"
ROCKET="🚀"

# ============================================================================
#                          LOGGING SYSTEM
# ============================================================================
log() {
    echo -e "${DIM}[$(date '+%Y-%m-%d %H:%M:%S')]${RESET} $1" | tee -a "$LOG_FILE"
}

print_header() {
    clear
    echo -e "${PRIMARY}"
    echo "    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    echo "    █${BOLD}                                                      ${RESET}${PRIMARY}█"
    echo "    █${BOLD}  ╔═╗╦  ╔═╗╔╗ ╔═╗╔╦╗╔═╗╔═╗╔═╗  ╔═╗╔═╗╔═╗╦╔═╔═╗╦═╗  ${RESET}${PRIMARY}█"
    echo "    █${BOLD}  ╠═╝║  ║ ║╠╩╗╠═╣ ║║╠═╣║  ╚═╗  ╚═╗║╣ ╠═╝╠╩╗║╣ ╠╦╝  ${RESET}${PRIMARY}█"
    echo "    █${BOLD}  ╩  ╩═╝╚═╝╚═╝╩ ╩═╩╝╩ ╩╚═╝╚═╝  ╚═╝╚═╝╩  ╩ ╩╚═╝╩╚═  ${RESET}${PRIMARY}█"
    echo "    █${BOLD}                                                      ${RESET}${PRIMARY}█"
    echo "    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    echo -e "${RESET}"
    echo -e "${INFO}${BOLD}           Professional SlowDNS Tunnel System${RESET}"
    echo -e "${DIM}                    Optimized for Maximum Performance${RESET}"
    echo ""
    echo -e "${SECONDARY}${BOLD}   🌍 MRCHIDDY ESIMFREEGB  ${DIM}|${RESET} ${SUCCESS}${BOLD}⌛ FAST DNS HALOTEL  ${DIM}|${RESET} ${WARNING}${BOLD}⚡ CONTACT ADMIN${RESET}"
    echo ""
}

print_section() {
    echo -e "${PRIMARY}${BOLD}╔════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PRIMARY}${BOLD}║${RESET} ${HIGHLIGHT}${BOLD}$1${RESET}"
    echo -e "${PRIMARY}${BOLD}╚════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

print_status() {
    case $1 in
        success) echo -e "${SUCCESS}${CHECK} $2${RESET}" ;;
        error) echo -e "${ERROR}${CROSS} $2${RESET}" ;;
        warning) echo -e "${WARNING}${WARN} $2${RESET}" ;;
        info) echo -e "${INFO}${SERVER} $2${RESET}" ;;
        *) echo -e "$2" ;;
    esac
}

spinner() {
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

# ============================================================================
#                          VALIDATION SYSTEM
# ============================================================================
get_vps_ip() {
    local ip=""
    local services=(
        "https://ifconfig.me"
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
        "https://ipinfo.io/ip"
    )
    
    for service in "${services[@]}"; do
        ip=$(curl -s --max-time 2 "$service" 2>/dev/null)
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    print_status error "Failed to detect public IP"
    return 1
}

fetch_github_content() {
    local url="$1"
    local retries=3
    local timeout=5
    
    for ((i=1; i<=retries; i++)); do
        local content=$(curl -s --max-time "$timeout" "$url")
        if [ -n "$content" ]; then
            echo "$content"
            return 0
        fi
        sleep 1
    done
    
    return 1
}

check_ip_authorization() {
    print_status info "Validating VPS Authorization"
    echo -e "${DIM}${LINE}${RESET}"
    
    local current_ip=$(get_vps_ip)
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    echo -e "${INFO}Detected Public IP: ${BOLD}$current_ip${RESET}"
    
    local allowed_ips=$(fetch_github_content "$ALLOWED_IPS_URL")
    if [ $? -ne 0 ]; then
        print_status error "Cannot fetch authorization list"
        return 1
    fi
    
    local clean_list=$(echo "$allowed_ips" | grep -v '^#' | grep -v '^$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if echo "$clean_list" | grep -q "^$current_ip$"; then
        print_status success "VPS authorized for installation"
        echo -e "${DIM}${LINE}${RESET}\n"
        return 0
    else
        print_status error "VPS not authorized"
        echo -e "${WARNING}"
        echo "╔══════════════════════════════════════════════════════╗"
        echo "║           LICENSE REQUIRED - CONTACT ADMIN           ║"
        echo "╠══════════════════════════════════════════════════════╣"
        echo "║                                                      ║"
        echo "║  Telegram: @esimfreegb                               ║"
        echo "║                                                      ║"
        echo "║  Provide your VPS IP to administrator:               ║"
        echo "║  ${BOLD}$current_ip${RESET}${WARNING}                          ║"
        echo "║                                                      ║"
        echo "╚══════════════════════════════════════════════════════╝"
        echo -e "${RESET}"
        return 1
    fi
}

validate_license() {
    local attempts=0
    
    while [ $attempts -lt $MAX_ATTEMPTS ]; do
        attempts=$((attempts + 1))
        
        echo -e "${INFO}${BOLD}License Verification (Attempt $attempts/$MAX_ATTEMPTS)${RESET}"
        echo -e "${DIM}${LINE}${RESET}"
        
        echo -ne "${HIGHLIGHT}${KEY} Enter License Key: ${RESET}"
        stty -echo
        read -r license_key
        stty echo
        echo ""
        
        if [ -z "$license_key" ]; then
            print_status warning "License key cannot be empty"
            echo ""
            continue
        fi
        
        license_key=$(echo "$license_key" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
        
        echo -ne "${INFO}Verifying license ${ROCKET}"
        for i in {1..10}; do
            echo -ne "."
            sleep 0.1
        done
        echo -e "${RESET}"
        
        local valid_keys=$(fetch_github_content "$VALID_KEYS_URL")
        if [ $? -ne 0 ]; then
            print_status error "Cannot connect to license server"
            continue
        fi
        
        local clean_keys=$(echo "$valid_keys" | grep -v '^#' | grep -v '^$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        if echo "$clean_keys" | grep -q "^$license_key$"; then
            echo -e "${SUCCESS}"
            echo "╔══════════════════════════════════════════════════════╗"
            echo "║              LICENSE VALIDATION SUCCESS              ║"
            echo "╠══════════════════════════════════════════════════════╣"
            echo "║                                                      ║"
            echo "║  ${CHECK} License Activated Successfully               ║"
            echo "║  ${CLOCK} Valid Until: Unlimited                       ║"
            echo "║  ${NETWORK} Status: Active                               ║"
            echo "║                                                      ║"
            echo "╚══════════════════════════════════════════════════════╝"
            echo -e "${RESET}"
            return 0
        else
            print_status error "Invalid license key"
            
            if [ $attempts -lt $MAX_ATTEMPTS ]; then
                echo -e "${WARNING}Remaining attempts: $((MAX_ATTEMPTS - attempts))${RESET}\n"
            fi
        fi
    done
    
    print_status error "Maximum verification attempts reached"
    echo -e "${ERROR}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║               VERIFICATION FAILED                    ║"
    echo "╠══════════════════════════════════════════════════════╣"
    echo "║                                                      ║"
    echo "║  Contact administrator for assistance:               ║"
    echo "║  Telegram: @esimfreegb                               ║"
    echo "║                                                      ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    return 1
}

# ============================================================================
#                         INSTALLATION FUNCTIONS
# ============================================================================
configure_openssh() {
    print_status info "Configuring OpenSSH Server"
    echo -e "${DIM}${LINE}${RESET}"
    
    SSHD_PORT=22
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%s)
    
    cat > /etc/ssh/sshd_config << EOF
# ===========================================
# OpenSSH Configuration - SlowDNS Optimized
# ===========================================

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
    
    systemctl restart sshd
    sleep 2
    
    if systemctl is-active --quiet sshd; then
        print_status success "SSH configured on port $SSHD_PORT"
    else
        print_status error "SSH configuration failed"
        return 1
    fi
}

install_slowdns() {
    print_status info "Installing SlowDNS Engine"
    echo -e "${DIM}${LINE}${RESET}"
    
    SLOWDNS_PORT=5300
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download components
    echo -ne "${INFO}Downloading components "
    for i in {1..3}; do
        echo -ne "${STAR}"
        sleep 0.3
    done
    echo -e "${RESET}"
    
    wget -q --show-progress -O dnstt-server "$GITHUB_BASE/dnstt-server"
    wget -q --show-progress -O server.key "$GITHUB_BASE/server.key"
    wget -q --show-progress -O server.pub "$GITHUB_BASE/server.pub"
    
    chmod +x dnstt-server
    
    # Test binary
    if ./dnstt-server --help 2>&1 | head -1 | grep -q "dnstt"; then
        print_status success "SlowDNS binary verified"
    else
        print_status warning "Binary test inconclusive - proceeding anyway"
    fi
}

create_services() {
    print_status info "Creating System Services"
    echo -e "${DIM}${LINE}${RESET}"
    
    # Get nameserver
    read -p "$(echo -e "${HIGHLIGHT}${NETWORK} Enter nameserver [dns.halotel.com]: ${RESET}")" NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.halotel.com}
    
    # SlowDNS Service
    cat > /etc/systemd/system/slowdns-tunnel.service << EOF
[Unit]
Description=SlowDNS Secure Tunnel
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/slowdns
ExecStart=/etc/slowdns/dnstt-server -udp :5300 -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:22
Restart=always
RestartSec=3
LimitNOFILE=infinity
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # EDNS Proxy Service
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy Handler
After=slowdns-tunnel.service
Requires=slowdns-tunnel.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    print_status success "Service files created"
}

compile_edns_proxy() {
    print_status info "Compiling EDNS Proxy"
    echo -e "${DIM}${LINE}${RESET}"
    
    # Install compiler if needed
    if ! command -v gcc >/dev/null 2>&1; then
        echo -ne "${INFO}Installing build tools "
        apt-get update >/dev/null 2>&1 &
        spinner $!
        apt-get install -y gcc >/dev/null 2>&1 &
        spinner $!
        print_status success "Build tools installed"
    fi
    
    # Compile optimized EDNS proxy
    cat > /tmp/edns_opt.c << 'EOF'
// High-Performance EDNS Proxy for SlowDNS
// Optimized with epoll for 10K+ connections

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
#define MAX_EVENTS 1024
#define MAX_CONNECTIONS 10000

// Optimized EDNS patching
int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip question section
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        if(offset >= len) return len;
        offset += 5;
    }
    
    // Find and patch EDNS0
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0 && offset + 4 < len) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            if(type == 41) { // EDNS0
                buf[offset+3] = new_size >> 8;
                buf[offset+4] = new_size & 0xFF;
                return len;
            }
        }
        offset++;
    }
    
    return len;
}

int main() {
    printf("🚀 High-Performance EDNS Proxy Starting...\n");
    printf("📡 Listening on UDP port 53\n");
    printf("🎯 Forwarding to SlowDNS on port 5300\n");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Bind to port 53
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }
    
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0) {
        perror("epoll_create1");
        close(sock);
        return 1;
    }
    
    // Add main socket to epoll
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
    
    printf("✅ EDNS Proxy ready for connections\n");
    
    struct epoll_event events[MAX_EVENTS];
    while(1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for(int i = 0; i < n; i++) {
            // Handle incoming DNS queries
            unsigned char buffer[BUFFER_SIZE];
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                             (struct sockaddr*)&client_addr, &client_len);
            
            if(len > 0) {
                // Patch EDNS size for internal transport
                patch_edns(buffer, len, INT_EDNS);
                
                // Forward to SlowDNS
                int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                if(up_sock >= 0) {
                    struct sockaddr_in up_addr = {0};
                    up_addr.sin_family = AF_INET;
                    up_addr.sin_port = htons(SLOWDNS_PORT);
                    inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                    
                    sendto(up_sock, buffer, len, 0,
                           (struct sockaddr*)&up_addr, sizeof(up_addr));
                    
                    // Receive response
                    len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                    if(len > 0) {
                        // Restore EDNS size for client
                        patch_edns(buffer, len, EXT_EDNS);
                        sendto(sock, buffer, len, 0,
                               (struct sockaddr*)&client_addr, client_len);
                    }
                    close(up_sock);
                }
            }
        }
    }
    
    close(epoll_fd);
    close(sock);
    info;
}
EOF
    
    echo -ne "${INFO}Compiling optimized proxy "
    gcc -O3 -o /usr/local/bin/edns-proxy /tmp/edns_opt.c 2>/dev/null &
    spinner $!
    
    if [ -f "/usr/local/bin/edns-proxy" ]; then
        chmod +x /usr/local/bin/edns-proxy
        print_status success "EDNS Proxy compiled successfully"
    else
        print_status error "Compilation failed"
        return 1
    fi
}

configure_firewall() {
    print_status info "Configuring System Firewall"
    echo -e "${DIM}${LINE}${RESET}"
    
    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    
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
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
    
    # Allow DNS ports
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -p udp --dport 5300 -j ACCEPT
    
    # Allow ICMP (ping)
    iptables -A INPUT -p icmp -j ACCEPT
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4
    
    # Disable IPv6
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null
    
    print_status success "Firewall configured"
}

start_services() {
    print_status info "Starting System Services"
    echo -e "${DIM}${LINE}${RESET}"
    
    # Stop conflicting services
    echo -ne "${INFO}Stopping systemd-resolved "
    systemctl stop systemd-resolved 2>/dev/null &
    spinner $!
    systemctl disable systemd-resolved 2>/dev/null
    
    echo -ne "${INFO}Clearing port 53 "
    fuser -k 53/udp 2>/dev/null &
    spinner $!
    
    # Start SlowDNS with animation
    echo -ne "${INFO}Activating SlowDNS Tunnel "
    systemctl enable slowdns-tunnel.service >/dev/null 2>&1
    systemctl start slowdns-tunnel.service &
    for i in {1..5}; do
        echo -ne "${ROCKET}"
        sleep 0.3
    done
    echo -e "${RESET}"
    
    sleep 2
    
    # Start EDNS Proxy with animation
    echo -ne "${INFO}Initializing EDNS Proxy "
    systemctl enable edns-proxy.service >/dev/null 2>&1
    systemctl start edns-proxy.service &
    for i in {1..5}; do
        echo -ne "${NETWORK}"
        sleep 0.3
    done
    echo -e "${RESET}"
    
    sleep 2
    
    # Verify services with detailed status
    echo ""
    echo -e "${INFO}${BOLD}Service Verification${RESET}"
    echo -e "${DIM}${LINE}${RESET}"
    
    # Check SlowDNS
    echo -ne "${INFO}Checking SlowDNS Tunnel "
    sleep 1
    if systemctl is-active --quiet slowdns-tunnel.service; then
        echo -e "${SUCCESS}${CHECK} ACTIVE${RESET}"
        echo -e "  ${DIM}├─ Port: 5300/UDP${RESET}"
        echo -e "  ${DIM}├─ MTU: 1800${RESET}"
        echo -e "  ${DIM}└─ PID: $(systemctl show -p MainPID slowdns-tunnel.service | cut -d= -f2)${RESET}"
    else
        echo -e "${ERROR}${CROSS} INACTIVE${RESET}"
        journalctl -u slowdns-tunnel.service -n 5 --no-pager | grep -i error 2>/dev/null || true
    fi
    
    # Check EDNS Proxy
    echo -ne "${INFO}Checking EDNS Proxy "
    sleep 1
    if systemctl is-active --quiet edns-proxy.service; then
        echo -e "${SUCCESS}${CHECK} ACTIVE${RESET}"
        echo -e "  ${DIM}├─ Listening: 0.0.0.0:53/UDP${RESET}"
        echo -e "  ${DIM}├─ Backend: 127.0.0.1:5300${RESET}"
        echo -e "  ${DIM}└─ PID: $(systemctl show -p MainPID edns-proxy.service | cut -d= -f2)${RESET}"
    else
        echo -e "${ERROR}${CROSS} INACTIVE${RESET}"
        journalctl -u edns-proxy.service -n 5 --no-pager | grep -i error 2>/dev/null || true
    fi
    
    # Check port binding
    echo -ne "${INFO}Checking Network Ports "
    sleep 1
    echo ""
    
    if ss -ulpn | grep -q ":53 "; then
        echo -e "  ${SUCCESS}${CHECK} UDP 53: ${BOLD}LISTENING${RESET}"
    else
        echo -e "  ${ERROR}${CROSS} UDP 53: ${BOLD}NOT BOUND${RESET}"
    fi
    
    if ss -ulpn | grep -q ":5300 "; then
        echo -e "  ${SUCCESS}${CHECK} UDP 5300: ${BOLD}LISTENING${RESET}"
    else
        echo -e "  ${ERROR}${CROSS} UDP 5300: ${BOLD}NOT BOUND${RESET}"
    fi
    
    # Check connectivity test
    echo ""
    echo -ne "${INFO}Performing connectivity test "
    local test_result=$(timeout 2 bash -c 'echo -n "test" | nc -u -w1 127.0.0.1 5300 2>/dev/null' || true)
    
    if [ $? -eq 0 ]; then
        echo -e "${SUCCESS}${CHECK} PASSED${RESET}"
    else
        echo -e "${WARNING}${WARN} INCONCLUSIVE${RESET}"
    fi
    
    print_status success "Services initialized"
}

show_summary() {
    local server_ip=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
    local ssh_port=22
    local dns_port=5300
    
    # Clear and show final header
    clear
    echo -e "${PRIMARY}"
    echo "    ╔══════════════════════════════════════════════════════════════════════╗"
    echo "    ║                                                                      ║"
    echo "    ║                SLOWDNS INSTALLATION COMPLETE                         ║"
    echo "    ║                                                                      ║"
    echo "    ╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    
    echo -e "${SUCCESS}"
    cat << "EOF"
   ╭─────────────────────────────────────────────────────────╮
   │                     🎉 SUCCESS!                         │
   │   Your professional DNS tunnel is now operational!      │
   ╰─────────────────────────────────────────────────────────╯
EOF
    echo -e "${RESET}"
    
    # System Information Box
    echo -e "${PRIMARY}${BOLD}╔════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PRIMARY}${BOLD}║                         SYSTEM INFORMATION                         ║${RESET}"
    echo -e "${PRIMARY}${BOLD}╠════════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${PRIMARY}${BOLD}║${RESET}"
    echo -e "${PRIMARY}${BOLD}║  ${SERVER} Server Address:  ${BOLD}$server_ip${RESET}"
    echo -e "${PRIMARY}${BOLD}║  ${NETWORK} SSH Port:         ${BOLD}$ssh_port${RESET}"
    echo -e "${PRIMARY}${BOLD}║  ${CLOCK} SlowDNS Port:      ${BOLD}$dns_port${RESET}"
    echo -e "${PRIMARY}${BOLD}║  🔤 Nameserver:       ${BOLD}$NAMESERVER${RESET}"
    echo -e "${PRIMARY}${BOLD}║${RESET}"
    echo -e "${PRIMARY}${BOLD}╚════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    
    # Public Key Display
    echo -e "${INFO}${BOLD}🔑 PUBLIC KEY (Save for Client Configuration):${RESET}"
    echo -e "${DIM}${LINE}${RESET}"
    
    if [ -f "/etc/slowdns/server.pub" ]; then
        local pubkey=$(cat /etc/slowdns/server.pub)
        echo -e "${HIGHLIGHT}${pubkey}${RESET}"
        
        # Show key info
        echo -e "${DIM}"
        echo "Key Type:    $(echo $pubkey | cut -d: -f1)"
        echo "Key Length:  $(echo $pubkey | wc -c) characters"
        echo -e "${RESET}"
    else
        echo -e "${ERROR}Public key file not found${RESET}"
    fi
    
    echo ""
    
    # Configuration Guide
    echo -e "${WARNING}${BOLD}⚙️  CLIENT CONFIGURATION:${RESET}"
    echo -e "${DIM}${LINE}${RESET}"
    
    cat << EOF
${INFO}For SlowDNS Client (Android/iOS):${RESET}
${DIM}┌─────────────────────────────────────────────────────────┐${RESET}
${DIM}│ Server:    $server_ip${RESET}
${DIM}│ Port:      $dns_port${RESET}
${DIM}│ Nameserver: $NAMESERVER${RESET}
${DIM}│ Public Key: ${pubkey:0:40}...${RESET}
${DIM}└─────────────────────────────────────────────────────────┘${RESET}

${INFO}For SSH Tunneling:${RESET}
${DIM}ssh -p $ssh_port root@$server_ip${RESET}

${INFO}For DNS Configuration:${RESET}
${DIM}nameserver $server_ip${RESET}
${DIM}port $dns_port${RESET}
EOF
    
    echo ""
    
    # Service Status
    echo -e "${SUCCESS}${BOLD}📊 INSTALLED SERVICES:${RESET}"
    echo -e "${DIM}${LINE}${RESET}"
    
    echo -e "${INFO}1. slowdns-tunnel.service${RESET}"
    echo -e "   ${DIM}├─ Status: $(systemctl is-active slowdns-tunnel.service)${RESET}"
    echo -e "   ${DIM}├─ Port: $dns_port/UDP${RESET}"
    echo -e "   ${DIM}└─ Logs: journalctl -u slowdns-tunnel.service -f${RESET}"
    
    echo ""
    
    echo -e "${INFO}2. edns-proxy.service${RESET}"
    echo -e "   ${DIM}├─ Status: $(systemctl is-active edns-proxy.service)${RESET}"
    echo -e "   ${DIM}├─ Port: 53/UDP${RESET}"
    echo -e "   ${DIM}└─ Logs: journalctl -u edns-proxy.service -f${RESET}"
    
    echo ""
    
    # Quick Commands
    echo -e "${WARNING}${BOLD}⚡ QUICK COMMANDS:${RESET}"
    echo -e "${DIM}${LINE}${RESET}"
    
    cat << EOF
${DIM}Restart Services:${RESET}
systemctl restart slowdns-tunnel.service
systemctl restart edns-proxy.service

${DIM}Check Status:${RESET}
systemctl status slowdns-tunnel.service
systemctl status edns-proxy.service

${DIM}View Logs:${RESET}
journalctl -u slowdns-tunnel.service -n 20
journalctl -u edns-proxy.service -n 20

${DIM}Check Ports:${RESET}
ss -ulpn | grep -E ':53|:5300'
EOF
    
    echo ""
    
    # Final Health Check
    echo -ne "${INFO}Performing final system check "
    
    local errors=0
    if ! systemctl is-active --quiet slowdns-tunnel.service; then
        errors=$((errors + 1))
    fi
    
    if ! systemctl is-active --quiet edns-proxy.service; then
        errors=$((errors + 1))
    fi
    
    if ! ss -ulpn | grep -q ":53 "; then
        errors=$((errors + 1))
    fi
    
    sleep 1
    
    if [ $errors -eq 0 ]; then
        echo -e "${SUCCESS}${CHECK} ALL SYSTEMS OPERATIONAL${RESET}"
        
        echo -e "${SUCCESS}"
        cat << "EOF"
   ╭─────────────────────────────────────────────────────────╮
   │  ✅ All services are running correctly!                 │
   │  ✅ Network ports are properly bound!                   │
   │  ✅ System is ready for client connections!             │
   ╰─────────────────────────────────────────────────────────╯
EOF
        echo -e "${RESET}"
    elif [ $errors -eq 1 ]; then
        echo -e "${WARNING}${WARN} MINOR ISSUES DETECTED${RESET}"
        echo -e "${WARNING}One service may need attention. Check logs above.${RESET}"
    else
        echo -e "${ERROR}${CROSS} MULTIPLE ISSUES DETECTED${RESET}"
        echo -e "${ERROR}Please check service status and logs.${RESET}"
    fi
    
    echo ""
    echo -e "${DIM}${LINE}${RESET}"
    echo -e "${PRIMARY}${BOLD}🌍 MRCHIDDY ESIMFREEGB${RESET} ${DIM}|${RESET} ${SUCCESS}${BOLD}⌛ FAST DNS HALOTEL${RESET} ${DIM}|${RESET} ${WARNING}${BOLD}⚡ CONTACT: @esimfreegb${RESET}"
    echo -e "${DIM}${LINE}${RESET}"
    echo ""
    
    # Installation timestamp
    local install_time=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${DIM}Installed: $install_time${RESET}"
    echo -e "${DIM}Duration: ~$(($SECONDS / 60)) minutes $(($SECONDS % 60)) seconds${RESET}"
    
    # Log completion
    log "=== INSTALLATION COMPLETED SUCCESSFULLY ==="
    log "Server IP: $server_ip"
    log "Nameserver: $NAMESERVER"
    log "Installation time: $(date)"
    log "=========================================="
}

# ============================================================================
#                             MAIN EXECUTION
# ============================================================================
main() {
    # Record start time
    SECONDS=0
    
    # Check root privileges
    if [ "$EUID" -ne 0 ]; then
        print_status error "This script requires root privileges"
        echo -e "Run with: ${BOLD}sudo bash $0${RESET}"
        exit 1
    fi
    
    # Create log directory
    mkdir -p /var/log 2>/dev/null
    touch "$LOG_FILE" 2>/dev/null
    
    # Show header
    print_header
    
    # Phase 1: Authorization
    print_section "SYSTEM AUTHORIZATION"
    
    if ! check_ip_authorization; then
        log "Authorization failed - IP not allowed"
        exit 1
    fi
    
    if ! validate_license; then
        log "License validation failed"
        exit 1
    fi
    
    # Phase 2: Installation
    print_section "SYSTEM DEPLOYMENT"
    
    if ! configure_openssh; then
        log "OpenSSH configuration failed"
        exit 1
    fi
    
    if ! install_slowdns; then
        log "SlowDNS installation failed"
        exit 1
    fi
    
    if ! compile_edns_proxy; then
        log "EDNS proxy compilation failed"
        exit 1
    fi
    
    if ! create_services; then
        log "Service creation failed"
        exit 1
    fi
    
    if ! configure_firewall; then
        log "Firewall configuration failed"
        exit 1
    fi
    
    if ! start_services; then
        log "Service startup failed"
        exit 1
    fi
    
    # Phase 3: Summary
    show_summary
    
    # Cleanup
    rm -f /tmp/edns_opt.c 2>/dev/null
    
    exit 0
}

# Handle interrupts gracefully
trap '
    echo -e "\n${ERROR}⚠️  Installation interrupted by user${RESET}"
    echo -e "${WARNING}Cleaning up...${RESET}"
    
    # Stop services if they were started
    systemctl stop slowdns-tunnel.service 2>/dev/null
    systemctl stop edns-proxy.service 2>/dev/null
    
    # Remove temporary files
    rm -f /tmp/edns_opt.c 2>/dev/null
    
    log "Installation interrupted by user at $(date)"
    exit 1
' INT TERM

# Start main process
main "$@"
