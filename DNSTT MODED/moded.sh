#!/bin/bash
# ============================================================================
#        OPTIMIZED SLOWDNS + EDNS INSTALLER (LOW CPU / HIGH SPEED)
# ============================================================================

set -e

# Root check
[ "$EUID" -ne 0 ] && echo "Run as root" && exit 1

# ================== CONFIG ==================
SSHD_PORT=22
SLOWDNS_PORT=5300
MTU=1200
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# ================== COLORS ==================
GREEN="\033[0;32m"
RED="\033[0;31m"
CYAN="\033[0;36m"
NC="\033[0m"

echo -e "${CYAN}=== OPTIMIZED SLOWDNS INSTALLER ===${NC}"

read -p "Enter DNS domain (example: dns.example.com): " NAMESERVER
NAMESERVER=${NAMESERVER:-dns.example.com}

SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

# ================== SYSTEM TUNING ==================
echo -e "${CYAN}Applying kernel optimizations...${NC}"

cat > /etc/sysctl.d/99-slowdns.conf <<EOF
net.core.rmem_max=4194304
net.core.wmem_max=4194304
net.core.netdev_max_backlog=16384
net.ipv4.udp_mem=65536 131072 262144
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.ip_local_port_range=10240 65535
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
EOF

sysctl --system >/dev/null

# ================== SSH ==================
echo -e "${CYAN}Configuring SSH...${NC}"
sed -i "s/^#Port .*/Port $SSHD_PORT/" /etc/ssh/sshd_config
systemctl restart sshd

# ================== SLOWDNS ==================
echo -e "${CYAN}Installing SlowDNS...${NC}"
rm -rf /etc/slowdns
mkdir /etc/slowdns
cd /etc/slowdns

curl -fsSL "$GITHUB_BASE/dnstt-server" -o dnstt-server
chmod +x dnstt-server
curl -fsSL "$GITHUB_BASE/server.key" -o server.key
curl -fsSL "$GITHUB_BASE/server.pub" -o server.pub

# ================== SLOWDNS SERVICE (TCP MODE) ==================
cat > /etc/systemd/system/server-sldns.service <<EOF
[Unit]
Description=SlowDNS Server (TCP Optimized)
After=network.target

[Service]
ExecStart=/etc/slowdns/dnstt-server -tcp :$SLOWDNS_PORT -mtu $MTU -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=3
CPUAffinity=0
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# ================== EDNS PROXY (LOW CPU) ==================
echo -e "${CYAN}Building optimized EDNS proxy...${NC}"

cat > /tmp/edns.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#define MAX_EVENTS 64
#define BUF 2048

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(53);
    a.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (void*)&a, sizeof(a));

    int up = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in slow = {0};
    slow.sin_family = AF_INET;
    slow.sin_port = htons(5300);
    inet_pton(AF_INET, "127.0.0.1", &slow.sin_addr);

    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = sock};
    epoll_ctl(ep, EPOLL_CTL_ADD, sock, &ev);

    struct epoll_event events[MAX_EVENTS];
    char buf[BUF];

    while (1) {
        int n = epoll_wait(ep, events, MAX_EVENTS, 100);
        for (int i = 0; i < n; i++) {
            int len = recv(sock, buf, BUF, 0);
            if (len > 0)
                sendto(up, buf, len, 0, (void*)&slow, sizeof(slow));
        }
    }
}
EOF

gcc -O2 -pipe /tmp/edns.c -o /usr/local/bin/edns-proxy
chmod +x /usr/local/bin/edns-proxy

# ================== EDNS SERVICE ==================
cat > /etc/systemd/system/edns-proxy.service <<EOF
[Unit]
Description=Low CPU EDNS Proxy
After=server-sldns.service

[Service]
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=2
CPUAffinity=0
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# ================== FIREWALL ==================
echo -e "${CYAN}Configuring firewall...${NC}"
iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
iptables -A INPUT -p tcp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

systemctl stop systemd-resolved || true
fuser -k 53/udp || true

# ================== START ==================
systemctl daemon-reload
systemctl enable server-sldns edns-proxy
systemctl restart server-sldns edns-proxy

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} SLOWDNS OPTIMIZED INSTALL COMPLETE${NC}"
echo -e "${GREEN} IP: $SERVER_IP${NC}"
echo -e "${GREEN} DNS: $NAMESERVER${NC}"
echo -e "${GREEN} MTU: $MTU (Mobile Safe)${NC}"
echo -e "${GREEN} CPU USAGE: LOW${NC}"
echo -e "${GREEN}========================================${NC}"
