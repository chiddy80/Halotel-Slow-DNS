#!/bin/bash

# ============================================================================
#                       SLOWDNS INSTALLER
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# License files
KEY_FILE="/etc/halotel/keys.txt"
IP_FILE="/etc/halotel/ips.txt"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
error() { echo -e "${RED}[✗] $1${NC}"; exit 1; }
success() { echo -e "${GREEN}[✓] $1${NC}"; }
info() { echo -e "${CYAN}[i] $1${NC}"; }
line() { echo "────────────────────────────────────────────"; }

# ============================================================================
# LICENSE CHECK
# ============================================================================
clear
echo -e "${CYAN}"
echo "███████╗██╗      ██████╗ ██╗    ██╗███╗   ██╗███████╗"
echo "██╔════╝██║     ██╔═══██╗██║    ██║████╗  ██║██╔════╝"
echo "███████╗██║     ██║   ██║██║ █╗ ██║██╔██╗ ██║███████╗"
echo "╚════██║██║     ██║   ██║██║███╗██║██║╚██╗██║╚════██║"
echo "███████║███████╗╚██████╔╝╚███╔███╔╝██║ ╚████║███████║"
echo "╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝"
echo -e "${NC}"
line
echo -e "${BLUE}       SlowDNS Tunnel System${NC}"
echo -e "${YELLOW}        @esimfreegb${NC}"
line
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    error "Run as root: sudo bash $0"
fi

# Check license files
[ ! -f "$KEY_FILE" ] && error "License system missing"
[ ! -f "$IP_FILE" ] && error "IP whitelist missing"

# Get IP
IP=$(curl -s ifconfig.me || echo "0.0.0.0")
info "VPS IP: $IP"
line

# Check IP
grep -Fxq "$IP" "$IP_FILE" || error "IP not authorized"
success "IP authorized"

# Ask key
read -p "Enter license key: " LIC_KEY
grep -Fxq "$LIC_KEY" "$KEY_FILE" || error "Invalid license key"
success "License accepted"
line

# ============================================================================
# INSTALLATION
# ============================================================================
clear
echo -e "${CYAN}"
echo "███████╗██╗      ██████╗ ██╗    ██╗███╗   ██╗███████╗"
echo "██╔════╝██║     ██╔═══██╗██║    ██║████╗  ██║██╔════╝"
echo "███████╗██║     ██║   ██║██║ █╗ ██║██╔██╗ ██║███████╗"
echo "╚════██║██║     ██║   ██║██║███╗██║██║╚██╗██║╚════██║"
echo "███████║███████╗╚██████╔╝╚███╔███╔╝██║ ╚████║███████║"
echo "╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝"
echo -e "${NC}"
line
echo ""

# 1. SSH CONFIG
info "Configuring SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
cat > /etc/ssh/sshd_config << 'EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
AllowTcpForwarding yes
GatewayPorts yes
UseDNS no
EOF
systemctl restart sshd
sleep 1
success "SSH configured"

# 2. SLOWDNS SETUP
info "Installing SlowDNS..."
rm -rf /etc/slowdns
mkdir -p /etc/slowdns && cd /etc/slowdns
wget -q https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server
wget -q https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key
wget -q https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub
chmod +x dnstt-server
success "SlowDNS downloaded"

# 3. NAMESERVER
echo ""
read -p "Enter nameserver [dns.halotel.com]: " NS
NS=${NS:-dns.halotel.com}

# 4. SERVICES
info "Creating services..."

# SlowDNS service
cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :5300 -mtu 1800 -privkey-file /etc/slowdns/server.key $NS 127.0.0.1:22
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# EDNS Proxy
cat > /tmp/edns.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
    struct sockaddr_in addr = {0};
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
            struct sockaddr_in up_addr = {0};
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

# Compile EDNS
gcc -O2 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/dev/null
chmod +x /usr/local/bin/edns-proxy

# EDNS service
cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy
After=slowdns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

success "Services created"

# 5. FIREWALL
info "Configuring firewall..."
iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p udp --dport 5300 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
success "Firewall configured"

# 6. START SERVICES
info "Starting services..."
systemctl stop systemd-resolved 2>/dev/null
fuser -k 53/udp 2>/dev/null
systemctl daemon-reload
systemctl enable slowdns.service >/dev/null 2>&1
systemctl start slowdns.service
systemctl enable edns-proxy.service >/dev/null 2>&1
systemctl start edns-proxy.service
sleep 2

if systemctl is-active --quiet slowdns.service; then
    success "SlowDNS running"
else
    error "SlowDNS failed"
fi

if systemctl is-active --quiet edns-proxy.service; then
    success "EDNS proxy running"
else
    error "EDNS proxy failed"
fi

# ============================================================================
# SUMMARY
# ============================================================================
clear
echo -e "${CYAN}"
echo "███████╗██╗      ██████╗ ██╗    ██╗███╗   ██╗███████╗"
echo "██╔════╝██║     ██╔═══██╗██║    ██║████╗  ██║██╔════╝"
echo "███████╗██║     ██║   ██║██║ █╗ ██║██╔██╗ ██║███████╗"
echo "╚════██║██║     ██║   ██║██║███╗██║██║╚██╗██║╚════██║"
echo "███████║███████╗╚██████╔╝╚███╔███╔╝██║ ╚████║███████║"
echo "╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝"
echo -e "${NC}"
line
echo -e "${GREEN}          INSTALLATION COMPLETE${NC}"
line
echo ""

# Get server IP
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

echo -e "${CYAN}SERVER DETAILS${NC}"
line
echo "IP Address:  $SERVER_IP"
echo "SSH Port:    22"
echo "DNS Port:    5300"
echo "Nameserver:  $NS"
echo ""

echo -e "${CYAN}PUBLIC KEY${NC}"
line
[ -f "/etc/slowdns/server.pub" ] && cat /etc/slowdns/server.pub || echo "Not found"
echo ""

echo -e "${CYAN}SERVICES${NC}"
line
echo "slowdns.service"
echo "edns-proxy.service"
echo ""

echo -e "${CYAN}STATUS${NC}"
line
systemctl is-active slowdns.service && echo "SlowDNS:  Active" || echo "SlowDNS:  Inactive"
systemctl is-active edns-proxy.service && echo "EDNS:     Active" || echo "EDNS:     Inactive"
echo ""

line
echo -e "${YELLOW}Support: @esimfreegb${NC}"
line
echo ""

# Cleanup
rm -f /tmp/edns.c 2>/dev/null
