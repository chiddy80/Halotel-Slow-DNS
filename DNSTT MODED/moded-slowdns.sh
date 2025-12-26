#!/bin/bash

# ============================================================================
#                     SLOWDNS PROFESSIONAL INSTALLER
# ============================================================================

# =================== LICENSE SYSTEM ===================
KEY_FILE="/etc/halotel/keys.txt"
IP_FILE="/etc/halotel/ips.txt"

# Secure files
[ -f "$KEY_FILE" ] && chmod 600 "$KEY_FILE"
[ -f "$IP_FILE" ] && chmod 600 "$IP_FILE"

# Check if files exist
if [ ! -f "$KEY_FILE" ] || [ ! -f "$IP_FILE" ]; then
    echo -e "\033[1;31m[✗] License system missing\033[0m"
    exit 1
fi

# Get VPS IP
MYIP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || echo "0.0.0.0")

# License check
echo ""
echo -e "\033[1;36m[i] License Verification\033[0m"
echo "────────────────────────────────────────"
echo "VPS IP: $MYIP"

# Check IP in whitelist
if ! grep -Fxq "$MYIP" "$IP_FILE" 2>/dev/null; then
    echo -e "\033[1;31m[✗] IP not authorized\033[0m"
    echo -e "\033[1;33m[!] Contact: @esimfreegb\033[0m"
    exit 1
fi

echo -e "\033[1;32m[✓] IP authorized\033[0m"
echo "────────────────────────────────────────"

# Ask for license key
read -p "Enter license key: " USERKEY

# Check license key
if ! grep -Fxq "$USERKEY" "$KEY_FILE" 2>/dev/null; then
    echo -e "\033[1;31m[✗] Invalid license key\033[0m"
    exit 1
fi

echo -e "\033[1;32m[✓] License accepted\033[0m"
echo "────────────────────────────────────────"
sleep 1

# ================= MAIN INSTALLATION ==================
clear

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m'

# Display functions
print_header() {
    echo -e "${CYAN}"
    echo "   ███████╗██╗      ██████╗ ██╗    ██╗██████╗ ███╗   ██╗███████╗"
    echo "   ██╔════╝██║     ██╔═══██╗██║    ██║██╔══██╗████╗  ██║██╔════╝"
    echo "   ███████╗██║     ██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║███████╗"
    echo "   ╚════██║██║     ██║   ██║██║███╗██║██║  ██║██║╚██╗██║╚════██║"
    echo "   ███████║███████╗╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║███████║"
    echo "   ╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝"
    echo -e "${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}      Professional SlowDNS Tunnel System${NC}"
    echo -e "${YELLOW}    🌍 MRCHIDDY ESIMFREEGB | ⌛ FAST DNS HALOTEL${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
    echo ""
}

print_success() { echo -e "${GREEN}[✓] $1${NC}"; }
print_error() { echo -e "${RED}[✗] $1${NC}"; }
print_info() { echo -e "${CYAN}[i] $1${NC}"; }
print_line() { echo -e "${BLUE}──────────────────────────────────────────${NC}"; }

# Installation functions
configure_openssh() {
    print_info "Configuring OpenSSH..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
    
    cat > /etc/ssh/sshd_config << EOF
Port 22
Protocol 2
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 60
AllowTcpForwarding yes
GatewayPorts yes
UseDNS no
EOF
    
    systemctl restart sshd
    sleep 2
    print_success "SSH configured"
}

install_slowdns() {
    print_info "Installing SlowDNS..."
    
    rm -rf /etc/slowdns
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download components
    wget -q -O dnstt-server "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"
    wget -q -O server.key "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
    wget -q -O server.pub "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
    
    chmod +x dnstt-server
    print_success "SlowDNS downloaded"
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
    
    print_success "Services created"
}

compile_edns_proxy() {
    print_info "Compiling EDNS proxy..."
    
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096

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
    struct sockaddr_in addr;
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    while(1) {
        unsigned char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                         (struct sockaddr*)&client_addr, &client_len);
        
        if(len > 0) {
            patch_edns(buffer, len, INT_EDNS);
            
            int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
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
    return 0;
}
EOF
    
    # Compile
    gcc -O2 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/dev/null
    chmod +x /usr/local/bin/edns-proxy
    print_success "EDNS proxy compiled"
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
    iptables -A INPUT -p icmp -j ACCEPT
    
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
    print_success "Firewall configured"
}

start_services() {
    print_info "Starting services..."
    
    systemctl stop systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    
    systemctl daemon-reload
    systemctl enable slowdns.service >/dev/null 2>&1
    systemctl start slowdns.service
    
    systemctl enable edns-proxy.service >/dev/null 2>&1
    systemctl start edns-proxy.service
    
    sleep 2
    
    if systemctl is-active --quiet slowdns.service; then
        print_success "SlowDNS started"
    else
        print_error "SlowDNS failed"
    fi
    
    if systemctl is-active --quiet edns-proxy.service; then
        print_success "EDNS proxy started"
    else
        print_error "EDNS proxy failed"
    fi
}

show_summary() {
    local server_ip=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
    
    echo ""
    print_line
    echo -e "${WHITE}═════════ INSTALLATION COMPLETE ═════════${NC}"
    print_line
    echo ""
    
    echo -e "${CYAN}Server Details:${NC}"
    echo "IP Address:  $server_ip"
    echo "SSH Port:    22"
    echo "DNS Port:    5300"
    echo "Nameserver:  $NAMESERVER"
    echo ""
    
    echo -e "${CYAN}Public Key:${NC}"
    if [ -f "/etc/slowdns/server.pub" ]; then
        cat /etc/slowdns/server.pub
    else
        echo "Not found"
    fi
    echo ""
    
    echo -e "${CYAN}Services:${NC}"
    echo "• slowdns.service"
    echo "• edns-proxy.service"
    echo ""
    
    print_line
    echo -e "${YELLOW}Support: @esimfreegb${NC}"
    print_line
    echo ""
}

# Main execution
main() {
    # Check root
    if [ "$EUID" -ne 0 ]; then
        print_error "Run as root: sudo bash $0"
        exit 1
    fi
    
    # Show header
    print_header
    
    # Installation steps
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
