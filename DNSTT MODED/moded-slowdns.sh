#!/bin/bash

# ============================================================================
#                     SLOWDNS PROFESSIONAL INSTALLER
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# ============================================================================
# CLEAN HEADER DESIGN
# ============================================================================
clear
echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║                                                      ║"
echo "║  ███████╗██╗      ██████╗ ██╗    ██╗██████╗ ███╗   ██╗  ║"
echo "║  ██╔════╝██║     ██╔═══██╗██║    ██║██╔══██╗████╗  ██║  ║"
echo "║  ███████╗██║     ██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║  ║"
echo "║  ╚════██║██║     ██║   ██║██║███╗██║██║  ██║██║╚██╗██║  ║"
echo "║  ███████║███████╗╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║  ║"
echo "║  ╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝  ║"
echo "║                                                      ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  ${CYAN}🚀 Professional DNS Tunneling System${PURPLE}             ║"
echo "║  ${YELLOW}🌍 MRCHIDDY ESIMFREEGB | ⚡ @esimfreegb${PURPLE}          ║"
echo "║                                                      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# ============================================================================
# LICENSE CHECK
# ============================================================================
KEY_FILE="/etc/halotel/keys.txt"
IP_FILE="/etc/halotel/ips.txt"

# Check files
[ ! -f "$KEY_FILE" ] && echo -e "${RED}✗ License system missing${NC}" && exit 1
[ ! -f "$IP_FILE" ] && echo -e "${RED}✗ IP whitelist missing${NC}" && exit 1

# Get IP
IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || hostname -I | awk '{print $1}')
echo -e "${CYAN}🔍 Detected IP:${NC} $IP"
echo ""

# Check IP
if ! grep -Fxq "$IP" "$IP_FILE" 2>/dev/null; then
    echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║             ACCESS DENIED                        ║${NC}"
    echo -e "${RED}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║                                                  ║${NC}"
    echo -e "${RED}║  ✗ IP not authorized                            ║${NC}"
    echo -e "${RED}║  Contact: @esimfreegb                           ║${NC}"
    echo -e "${RED}║                                                  ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
    exit 1
fi

# License key
read -p "$(echo -e "${YELLOW}🔑 Enter license key: ${NC}")" LIC_KEY
if ! grep -Fxq "$LIC_KEY" "$KEY_FILE" 2>/dev/null; then
    echo -e "${RED}✗ Invalid license key${NC}"
    exit 1
fi

echo -e "${GREEN}✓ License accepted${NC}"
echo ""

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================
install_ssh() {
    echo -e "${CYAN}[1/6] Configuring SSH...${NC}"
    cat > /etc/ssh/sshd_config << 'EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
AllowTcpForwarding yes
GatewayPorts yes
UseDNS no
EOF
    systemctl restart sshd
    echo -e "${GREEN}✓ SSH configured${NC}"
}

install_slowdns() {
    echo -e "${CYAN}[2/6] Installing SlowDNS...${NC}"
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    wget -q https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server
    wget -q https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key
    wget -q https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub
    chmod +x dnstt-server
    echo -e "${GREEN}✓ SlowDNS installed${NC}"
}

setup_services() {
    echo -e "${CYAN}[3/6] Setting up services...${NC}"
    
    # Get nameserver
    echo ""
    read -p "$(echo -e "${YELLOW}🌐 Enter nameserver [dns.halotel.com]: ${NC}")" NS
    NS=${NS:-dns.halotel.com}
    
    # Create SlowDNS service
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :5300 -mtu 1800 -privkey-file /etc/slowdns/server.key $NS 127.0.0.1:22
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Compile EDNS proxy
    cat > /tmp/edns.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define EDNS_SIZE 1800
#define PORT 53
#define BUFFER_SIZE 4096

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    while(1) {
        unsigned char buffer[BUFFER_SIZE];
        struct sockaddr_in client;
        socklen_t len = sizeof(client);
        
        int recv_len = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client, &len);
        if(recv_len > 0) {
            // Forward to SlowDNS
            int slow_sock = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in slow_addr = {0};
            slow_addr.sin_family = AF_INET;
            slow_addr.sin_port = htons(5300);
            inet_pton(AF_INET, "127.0.0.1", &slow_addr.sin_addr);
            sendto(slow_sock, buffer, recv_len, 0, (struct sockaddr*)&slow_addr, sizeof(slow_addr));
            
            int resp_len = recv(slow_sock, buffer, BUFFER_SIZE, 0);
            if(resp_len > 0) {
                sendto(sock, buffer, resp_len, 0, (struct sockaddr*)&client, len);
            }
            close(slow_sock);
        }
    }
    return 0;
}
EOF

    gcc -O2 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/dev/null
    chmod +x /usr/local/bin/edns-proxy
    
    # Create EDNS service
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

    echo -e "${GREEN}✓ Services configured${NC}"
}

configure_firewall() {
    echo -e "${CYAN}[4/6] Configuring firewall...${NC}"
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p udp --dport 5300 -j ACCEPT
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
    echo -e "${GREEN}✓ Firewall configured${NC}"
}

start_services() {
    echo -e "${CYAN}[5/6] Starting services...${NC}"
    systemctl stop systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    systemctl daemon-reload
    systemctl enable slowdns.service >/dev/null 2>&1
    systemctl start slowdns.service
    systemctl enable edns-proxy.service >/dev/null 2>&1
    systemctl start edns-proxy.service
    sleep 2
    
    if systemctl is-active --quiet slowdns.service; then
        echo -e "${GREEN}✓ SlowDNS service active${NC}"
    else
        echo -e "${RED}✗ SlowDNS service failed${NC}"
    fi
    
    if systemctl is-active --quiet edns-proxy.service; then
        echo -e "${GREEN}✓ EDNS proxy active${NC}"
    else
        echo -e "${RED}✗ EDNS proxy failed${NC}"
    fi
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
echo -e "${BLUE}════════════════ INSTALLATION STARTED ════════════════${NC}"
echo ""

install_ssh
install_slowdns
setup_services
configure_firewall
start_services

echo ""
echo -e "${BLUE}════════════════ INSTALLATION COMPLETE ═══════════════${NC}"
echo ""

# ============================================================================
# FINAL SUMMARY
# ============================================================================
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║               INSTALLATION COMPLETE                  ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  ${CYAN}📡 Server IP:${NC}   $SERVER_IP                    ${PURPLE}║"
echo "║  ${CYAN}🔒 SSH Port:${NC}    22                              ${PURPLE}║"
echo "║  ${CYAN}🌐 DNS Port:${NC}    5300                            ${PURPLE}║"
echo "║  ${CYAN}🔤 Nameserver:${NC}  $NS                            ${PURPLE}║"
echo "║                                                      ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  ${YELLOW}Public Key:${NC}                                    ${PURPLE}║"
echo "║                                                      ║"
[ -f "/etc/slowdns/server.pub" ] && echo "║  $(cat /etc/slowdns/server.pub)  ║"
echo "║                                                      ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  ${GREEN}Services:${NC}                                       ${PURPLE}║"
echo "║  • slowdns.service                                   ║"
echo "║  • edns-proxy.service                                ║"
echo "║                                                      ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  ${YELLOW}Support: @esimfreegb${NC}                             ${PURPLE}║"
echo "║                                                      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Cleanup
rm -f /tmp/edns.c 2>/dev/null
