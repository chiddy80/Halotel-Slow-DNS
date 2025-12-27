#!/bin/bash
# ============================================================================
# SLOWDNS INSTALLER FOR ALMALINUX (SSH FIXED VERSION)
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== SlowDNS Installer for AlmaLinux ===${NC}"

# Configuration
SSHD_PORT=22
SLOWDNS_PORT=5300
NAMESERVER="dns.example.com"  # Change this to your domain

# Step 1: Disable SELinux for SlowDNS
echo -e "\n${YELLOW}[1] Configuring SELinux...${NC}"
sudo setenforce 0
sudo sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
echo -e "${GREEN}✓ SELinux set to permissive${NC}"

# Step 2: Disable firewall
echo -e "\n${YELLOW}[2] Configuring firewall...${NC}"
sudo systemctl stop firewalld
sudo systemctl disable firewalld
echo -e "${GREEN}✓ Firewall disabled${NC}"

# Step 3: Create SlowDNS directory
echo -e "\n${YELLOW}[3] Setting up SlowDNS...${NC}"
sudo mkdir -p /etc/slowdns
cd /etc/slowdns

# Download SlowDNS binary
echo -e "${YELLOW}Downloading SlowDNS components...${NC}"
if command -v curl &>/dev/null; then
    sudo curl -L "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server" -o dnstt-server
    sudo curl -L "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key" -o server.key
    sudo curl -L "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub" -o server.pub
else
    sudo wget "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"
    sudo wget "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
    sudo wget "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
fi

sudo chmod +x dnstt-server
echo -e "${GREEN}✓ SlowDNS binaries downloaded${NC}"

# Step 4: Create SlowDNS service
echo -e "\n${YELLOW}[4] Creating SlowDNS service...${NC}"
sudo tee /etc/systemd/server-sldns.service > /dev/null << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :$SLOWDNS_PORT -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable server-sldns
sudo systemctl start server-sldns
echo -e "${GREEN}✓ SlowDNS service created${NC}"

# Step 5: Compile EDNS Proxy (FIXED VERSION)
echo -e "\n${YELLOW}[5] Compiling EDNS Proxy...${NC}"
sudo dnf install -y gcc

# Create simple EDNS proxy
sudo tee /tmp/edns.c > /dev/null << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    printf("EDNS Proxy Starting...\n");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }
    
    printf("EDNS Proxy listening on port 53\n");
    
    while (1) {
        char buffer[512];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int len = recvfrom(sock, buffer, sizeof(buffer), 0,
                          (struct sockaddr*)&client_addr, &client_len);
        if (len > 0) {
            // Forward to SlowDNS
            struct sockaddr_in slowdns_addr;
            memset(&slowdns_addr, 0, sizeof(slowdns_addr));
            slowdns_addr.sin_family = AF_INET;
            slowdns_addr.sin_port = htons(5300);
            inet_pton(AF_INET, "127.0.0.1", &slowdns_addr.sin_addr);
            
            sendto(sock, buffer, len, 0,
                   (struct sockaddr*)&slowdns_addr, sizeof(slowdns_addr));
        }
    }
    
    return 0;
}
EOF

# Compile
sudo gcc -O2 /tmp/edns.c -o /usr/local/bin/edns-proxy
sudo chmod +x /usr/local/bin/edns-proxy
echo -e "${GREEN}✓ EDNS Proxy compiled${NC}"

# Step 6: Create EDNS service
echo -e "\n${YELLOW}[6] Creating EDNS service...${NC}"
sudo tee /etc/systemd/system/edns-proxy.service > /dev/null << EOF
[Unit]
Description=EDNS Proxy
After=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable edns-proxy
sudo systemctl start edns-proxy
echo -e "${GREEN}✓ EDNS service created${NC}"

# Step 7: Stop conflicting services
echo -e "\n${YELLOW}[7] Stopping conflicting services...${NC}"
sudo systemctl stop systemd-resolved 2>/dev/null
sudo fuser -k 53/udp 2>/dev/null
echo -e "${GREEN}✓ Conflicting services stopped${NC}"

# Step 8: Verify installation
echo -e "\n${YELLOW}[8] Verifying installation...${NC}"
sleep 3

echo -e "\n${BLUE}=== Service Status ===${NC}"
sudo systemctl status server-sldns --no-pager | head -10
echo ""
sudo systemctl status edns-proxy --no-pager | head -10

echo -e "\n${BLUE}=== Listening Ports ===${NC}"
sudo ss -ulpn | grep -E '(:53|:5300)'

echo -e "\n${BLUE}=== Test DNS Query ===${NC}"
if command -v dig &>/dev/null; then
    sudo dnf install -y bind-utils
fi

if command -v dig &>/dev/null; then
    echo "Testing DNS (timeout 5 seconds)..."
    timeout 5 dig @127.0.0.1 google.com +short && echo -e "${GREEN}✓ DNS working${NC}" || echo -e "${YELLOW}⚠ DNS test failed${NC}"
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}      SLOWDNS INSTALLATION COMPLETE      ${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}SlowDNS Port:${NC} 5300 (UDP)"
echo -e "${YELLOW}EDNS Proxy:${NC} 53 (UDP)"
echo -e "${YELLOW}SSH Port:${NC} 22"
echo -e "${YELLOW}Nameserver:${NC} $NAMESERVER"
echo -e "\n${BLUE}To change nameserver, edit:${NC}"
echo -e "/etc/systemd/server-sldns.service"
echo -e "\n${BLUE}Management commands:${NC}"
echo -e "sudo systemctl status server-sldns"
echo -e "sudo systemctl status edns-proxy"
echo -e "sudo journalctl -u server-sldns -f"
