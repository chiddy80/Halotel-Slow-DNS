#!/bin/bash

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "[✗] Please run this script as root"
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Port Configuration
SSHD_PORT=22
SLOWDNS_PORT=5300

read -p "Enter nameserver (default: dns.example.com): " NAMESERVER
NAMESERVER=${NAMESERVER:-dns.example.com}

print_success(){ echo -e "${GREEN}[✓]${NC} $1"; }
print_error(){ echo -e "${RED}[✗]${NC} $1"; }

echo "Starting OpenSSH SlowDNS Installation..."

SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

# SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
cat > /etc/ssh/sshd_config << EOF
Port $SSHD_PORT
Protocol 2
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
UseDNS no
Subsystem sftp /usr/lib/openssh/sftp-server
MaxSessions 100
MaxStartups 100:30:200
EOF
systemctl restart sshd

# SlowDNS
rm -rf /etc/slowdns
mkdir -p /etc/slowdns
cd /etc/slowdns

curl -fsSL "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server" -o dnstt-server
chmod +x dnstt-server

wget -q -O server.key "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
wget -q -O server.pub "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"

cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target sshd.service

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :$SLOWDNS_PORT -mtu 1200 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# dnsdist (EDNS proxy)
apt update > /dev/null 2>&1
apt install -y dnsdist > /dev/null 2>&1
systemctl stop dnsdist

cat > /etc/dnsdist/dnsdist.conf << 'EOF'
setLocal("0.0.0.0:53")
newServer({address="127.0.0.1:5300", name="slowdns"})
setMaxUDPOutstanding(4096)
setUDPSocketBuffer(8*1024*1024)
addAction(AllRule(), SetEDNSOptionAction(4096))
addAction(AllRule(), SetEDNSOptionAction(1232))
addAction(NotRule(DNSHeaderRule()), DropAction())
addAction(MaxQPSIPRule(50), DropAction())
setStaleCacheEntriesTTL(20)
EOF

systemctl enable dnsdist
systemctl start dnsdist

# Firewall
iptables -F
iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

systemctl daemon-reload
systemctl enable server-sldns
systemctl restart server-sldns

echo ""
print_success "SlowDNS + dnsdist installed"
echo "Server IP: $SERVER_IP"
echo "DNS Port: 53"
echo "SlowDNS Port: $SLOWDNS_PORT"
echo "MTU: 1200"
echo "Test: dig @$SERVER_IP google.com"
