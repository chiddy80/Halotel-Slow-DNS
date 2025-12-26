#!/bin/bash

# ============================================================================
#                     SLOWDNS PROFESSIONAL INSTALLER
# ============================================================================

# =================== HARD LICENSE GATE ===================

KEY_FILE="/etc/halotel/keys.txt"
IP_FILE="/etc/halotel/ips.txt"

# Lock permissions
[ -f "$KEY_FILE" ] && chmod 600 "$KEY_FILE"
[ -f "$IP_FILE" ] && chmod 600 "$IP_FILE"

# Must exist
if [ ! -f "$KEY_FILE" ] || [ ! -f "$IP_FILE" ]; then
    echo "License system missing"
    exit 1
fi

# Get VPS IP
MYIP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)

echo "[i] Checking VPS IP..."
echo "VPS IP: $MYIP"
echo "──────────────────────────────────────────"

# Check IP
if ! grep -Fxq "$MYIP" "$IP_FILE"; then
    echo "[✗] VPS IP not authorized"
    echo "[!] Contact admin to whitelist your IP"
    echo "[!] Telegram: @esimfreegb"
    exit 1
fi

# Ask key
read -p "Enter license key: " USERKEY

# Check key
if ! grep -Fxq "$USERKEY" "$KEY_FILE"; then
    echo "[✗] Invalid license key"
    exit 1
fi

echo "[✓] License accepted"
echo "──────────────────────────────────────────"

# ================= END LICENSE GATE ======================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m'

# ============================================================================
# Display Functions
# ============================================================================
print_header() {
    clear
    echo -e "${CYAN}"
    echo "   ███████╗██╗      ██████╗ ██╗    ██╗██████╗ ███╗   ██╗███████╗"
    echo "   ██╔════╝██║     ██╔═══██╗██║    ██║██╔══██╗████╗  ██║██╔════╝"
    echo "   ███████╗██║     ██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║███████╗"
    echo "   ╚════██║██║     ██║   ██║██║███╗██║██║  ██║██║╚██╗██║╚════██║"
    echo "   ███████║███████╗╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║███████║"
    echo "   ╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝"
    echo -e "${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}       Professional SlowDNS Tunnel System${NC}"
    echo -e "${YELLOW}     🌍 MRCHIDDY ESIMFREEGB | ⌛ FAST DNS HALOTEL${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_line() {
    echo -e "${BLUE}──────────────────────────────────────────────────────────${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

print_info() {
    echo -e "${CYAN}[i] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# ============================================================================
# System Functions
# ============================================================================
get_vps_ip() {
    local ip=""
    ip=$(curl -s --max-time 3 https://ifconfig.me 2>/dev/null)
    [ -z "$ip" ] && ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null)
    [ -z "$ip" ] && ip=$(curl -s --max-time 3 https://checkip.amazonaws.com 2>/dev/null)
    echo "$ip"
}

fetch_from_github() {
    curl -s --max-time 5 "$1" 2>/dev/null
}

check_ip_allowed() {
    local current_ip="$1"
    local allowed_ips=$(fetch_from_github "$ALLOWED_IPS_URL")
    
    if [ $? -ne 0 ]; then
        print_error "Cannot fetch allowed IPs list"
        return 2
    fi
    
    local clean_list=$(echo "$allowed_ips" | grep -v '^#' | grep -v '^$' | tr -d '[]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if echo "$clean_list" | grep -q "^$current_ip$"; then
        return 0
    else
        return 1
    fi
}

validate_license_key() {
    local license_key="$1"
    local valid_keys=$(fetch_from_github "$VALID_KEYS_URL")
    
    if [ $? -ne 0 ]; then
        print_error "Cannot fetch license keys"
        return 2
    fi
    
    local clean_keys=$(echo "$valid_keys" | grep -v '^#' | grep -v '^$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if echo "$clean_keys" | grep -q "^$license_key$"; then
        return 0
    else
        return 1
    fi
}

read_hidden() {
    stty -echo
    read value
    stty echo
    echo
    echo "$value"
}

# ============================================================================
# License Check Function
# ============================================================================
check_license() {
    print_header
    
    echo -e "${WHITE}═════════════ LICENSE VERIFICATION ═════════════${NC}"
    echo ""
    
    # Get VPS IP
    print_info "Checking VPS IP..."
    CURRENT_IP=$(get_vps_ip)
    
    if [ -z "$CURRENT_IP" ] || [[ ! $CURRENT_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_error "Cannot get VPS IP"
        exit 1
    fi
    
    echo -e "${CYAN}VPS IP: ${WHITE}$CURRENT_IP${NC}"
    print_line
    
    # Check IP authorization
    print_info "Checking IP authorization..."
    if ! check_ip_allowed "$CURRENT_IP"; then
        print_error "VPS IP not authorized"
        echo ""
        print_warning "Contact admin to whitelist your IP"
        print_warning "Telegram: @esimfreegb"
        exit 1
    fi
    
    print_success "IP authorized"
    echo ""
    
    # License verification
    echo -e "${WHITE}════════════ LICENSE KEY REQUIRED ═════════════${NC}"
    echo ""
    print_info "Get license key from: @esimfreegb"
    echo ""
    
    local attempts=0
    while [ $attempts -lt $MAX_ATTEMPTS ]; do
        attempts=$((attempts + 1))
        
        echo -e "${CYAN}Attempt ${WHITE}$attempts${CYAN} of ${WHITE}$MAX_ATTEMPTS${NC}"
        echo -ne "${YELLOW}Enter license key: ${NC}"
        LICENSE_KEY=$(read_hidden)
        
        if [ -z "$LICENSE_KEY" ]; then
            print_error "License key cannot be empty"
            echo ""
            continue
        fi
        
        LICENSE_KEY=$(echo "$LICENSE_KEY" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
        
        print_info "Verifying license..."
        
        if validate_license_key "$LICENSE_KEY"; then
            echo ""
            print_success "✓ License verified successfully"
            print_success "✓ Starting installation..."
            sleep 1
            return 0
        else
            print_error "Invalid license key"
            
            if [ $attempts -lt $MAX_ATTEMPTS ]; then
                echo ""
                print_warning "Try again"
                print_line
                echo ""
            else
                echo ""
                print_error "Maximum attempts reached"
                print_warning "Contact: @esimfreegb"
                exit 1
            fi
        fi
    done
    
    exit 1
}

# ============================================================================
# Installation Functions
# ============================================================================
configure_openssh() {
    print_info "Configuring OpenSSH..."
    SSHD_PORT=22
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
    
    cat > /etc/ssh/sshd_config << EOF
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
    print_success "SSH configured on port $SSHD_PORT"
}

install_slowdns() {
    print_info "Setting up SlowDNS..."
    
    rm -rf /etc/slowdns
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download binary
    wget -q -O dnstt-server "$GITHUB_BASE/dnstt-server"
    chmod +x dnstt-server
    
    # Download keys
    wget -q -O server.key "$GITHUB_BASE/server.key"
    wget -q -O server.pub "$GITHUB_BASE/server.pub"
    
    print_success "SlowDNS components downloaded"
}

create_services() {
    print_info "Creating services..."
    
    # Get nameserver
    echo ""
    echo -ne "${YELLOW}Enter nameserver [dns.halotel.com]: ${NC}"
    read NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.halotel.com}
    
    # SlowDNS service
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :5300 -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:22
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # EDNS Proxy service
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy for SlowDNS
After=slowdns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Service files created"
}

compile_edns_proxy() {
    print_info "Compiling EDNS Proxy..."
    
    # Install gcc if needed
    if ! command -v gcc &>/dev/null; then
        apt update > /dev/null 2>&1
        apt install -y gcc > /dev/null 2>&1
    fi
    
    # Create C source
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

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 100

int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        offset += 5;
    }
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0 && offset + 4 < len) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            if(type == 41) {
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
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        return 1;
    }
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }
    
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0) {
        perror("epoll_create1");
        close(sock);
        return 1;
    }
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
    
    struct epoll_event events[MAX_EVENTS];
    while(1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        for(int i = 0; i < n; i++) {
            if(events[i].data.fd == sock) {
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
                if(len > 0) {
                    patch_edns(buffer, len, INT_EDNS);
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if(up_sock >= 0) {
                        struct sockaddr_in up_addr;
                        memset(&up_addr, 0, sizeof(up_addr));
                        up_addr.sin_family = AF_INET;
                        up_addr.sin_port = htons(SLOWDNS_PORT);
                        inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                        sendto(up_sock, buffer, len, 0,
                               (struct sockaddr*)&up_addr, sizeof(up_addr));
                        len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                        if(len > 0) {
                            patch_edns(buffer, len, EXT_EDNS);
                            sendto(sock, buffer, len, 0,
                                   (struct sockaddr*)&client_addr, client_len);
                        }
                        close(up_sock);
                    }
                }
            }
        }
    }
}
EOF
    
    # Compile
    gcc -O3 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/dev/null
    chmod +x /usr/local/bin/edns-proxy
    
    print_success "EDNS Proxy compiled"
}

configure_firewall() {
    print_info "Configuring firewall..."
    
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p udp --dport 5300 -j ACCEPT
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
    iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A INPUT -m state --state INVALID -j DROP
    
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
    
    print_success "Firewall configured"
}

start_services() {
    print_info "Starting services..."
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    
    # Start SlowDNS
    systemctl daemon-reload
    systemctl enable slowdns.service >/dev/null 2>&1
    systemctl start slowdns.service
    
    # Start EDNS proxy
    systemctl enable edns-proxy.service >/dev/null 2>&1
    systemctl start edns-proxy.service
    
    sleep 2
    
    # Check status
    if systemctl is-active --quiet slowdns.service; then
        print_success "SlowDNS service started"
    else
        print_warning "SlowDNS service may need attention"
    fi
    
    if systemctl is-active --quiet edns-proxy.service; then
        print_success "EDNS Proxy service started"
    else
        print_warning "EDNS Proxy service may need attention"
    fi
}

show_summary() {
    local server_ip=$(curl -s ifconfig.me)
    local ssh_port=22
    local dns_port=5300
    
    print_header
    echo -e "${WHITE}════════════════ INSTALLATION COMPLETE ═══════════════${NC}"
    echo ""
    
    echo -e "${CYAN}Server Information:${NC}"
    print_line
    echo -e "Server IP:    ${WHITE}$server_ip${NC}"
    echo -e "SSH Port:     ${WHITE}$ssh_port${NC}"
    echo -e "SlowDNS Port: ${WHITE}$dns_port${NC}"
    echo -e "Nameserver:   ${WHITE}$NAMESERVER${NC}"
    echo ""
    
    echo -e "${CYAN}Public Key:${NC}"
    print_line
    cat /etc/slowdns/server.pub 2>/dev/null || echo "Not available"
    echo ""
    
    echo -e "${CYAN}Services:${NC}"
    print_line
    echo -e "slowdns.service"
    echo -e "edns-proxy.service"
    echo ""
    
    echo -e "${GREEN}✓ Installation completed successfully${NC}"
    echo ""
    
    # Final check
    if systemctl is-active --quiet slowdns.service && ss -ulpn | grep -q ":53 "; then
        echo -e "${GREEN}✓ All services are running correctly${NC}"
    else
        echo -e "${YELLOW}! Some services may need manual checking${NC}"
    fi
    
    echo ""
    print_line
    echo -e "${YELLOW}Support: @esimfreegb${NC}"
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    # Check root
    if [ "$EUID" -ne 0 ]; then
        print_error "Run as root: sudo bash $0"
        exit 1
    fi
    
    # Create log file
    mkdir -p /var/log 2>/dev/null
    touch "$LOG_FILE" 2>/dev/null
    
    # Run license check
    check_license
    
    # Installation
    configure_openssh
    install_slowdns
    compile_edns_proxy
    create_services
    configure_firewall
    start_services
    
    # Show summary
    show_summary
    
    # Cleanup
    rm -f /tmp/edns.c 2>/dev/null
}

# Start
main "$@"
