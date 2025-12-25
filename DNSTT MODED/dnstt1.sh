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

# SSH Port Configuration
SSHD_PORT=22
SLOWDNS_PORT=5300

# Prompt user for nameserver
read -p "Enter nameserver (default: dns.example.com): " NAMESERVER
NAMESERVER=${NAMESERVER:-dns.example.com}

# Functions
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

echo "Starting OpenSSH SlowDNS Installation..."

# Get Server IP
SERVER_IP=$(curl -s ifconfig.me)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
fi

# Configure OpenSSH
echo "Configuring OpenSSH on port $SSHD_PORT..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null

cat > /etc/ssh/sshd_config << EOF
# OpenSSH Configuration
Port $SSHD_PORT
Protocol 2
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
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
print_success "OpenSSH configured on port $SSHD_PORT with key-based authentication only"

# Setup SlowDNS
echo "Setting up SlowDNS..."
rm -rf /etc/slowdns
mkdir -p /etc/slowdns
print_success "SlowDNS directory created"

# Download files
echo "Downloading SlowDNS files..."
wget -q -O /etc/slowdns/server.key "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key" && print_success "server.key downloaded"
wget -q -O /etc/slowdns/server.pub "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub" && print_success "server.pub downloaded"
wget -q -O /etc/slowdns/sldns-server "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server" && print_success "dnstt-server downloaded"

chmod +x /etc/slowdns/sldns-server
print_success "File permissions set"

# Create SlowDNS service with MTU 1800
echo "Creating SlowDNS service..."
cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target sshd.service

[Service]
Type=simple
ExecStart=/etc/slowdns/sldns-server -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

print_success "Service file created"

# Startup config with ALL iptables
echo "Setting up startup configuration..."
cat > /etc/rc.local <<-END
#!/bin/sh -e
systemctl start sshd
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
iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -p tcp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A OUTPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -p tcp --dport $SSHD_PORT -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport $SSHD_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.core.rmem_max=134217728 > /dev/null 2>&1
sysctl -w net.core.wmem_max=134217728 > /dev/null 2>&1
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local > /dev/null 2>&1
systemctl start rc-local.service > /dev/null 2>&1
print_success "Startup configuration set"

# Disable IPv6
echo "Disabling IPv6..."
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1
print_success "IPv6 disabled"

# Start SlowDNS service
echo "Starting SlowDNS service..."
pkill sldns-server 2>/dev/null
systemctl daemon-reload
systemctl enable server-sldns > /dev/null 2>&1
systemctl start server-sldns
sleep 3

if systemctl is-active --quiet server-sldns; then
    print_success "SlowDNS service started"
    
    echo "Testing DNS functionality..."
    sleep 2
    
    if timeout 3 bash -c "echo > /dev/udp/127.0.0.1/$SLOWDNS_PORT" 2>/dev/null; then
        print_success "SlowDNS is listening on port $SLOWDNS_PORT"
    else
        print_warning "SlowDNS not responding on port $SLOWDNS_PORT"
    fi
else
    print_error "SlowDNS service failed to start"
    
    # Try direct start with MTU 1800
    pkill sldns-server 2>/dev/null
    /etc/slowdns/sldns-server -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT &
    sleep 2
    
    if pgrep -x "sldns-server" > /dev/null; then
        print_success "SlowDNS started directly"
    else
        print_error "Failed to start SlowDNS"
    fi
fi

# Clean up packages (no sudo)
apt-get remove -y libpam-pwquality 2>/dev/null || true
print_success "Packages cleaned"

# Test connection
echo "Testing SSH connection..."
if timeout 5 bash -c "echo > /dev/tcp/127.0.0.1/$SSHD_PORT" 2>/dev/null; then
    print_success "SSH port $SSHD_PORT is accessible"
else
    print_error "SSH port $SSHD_PORT is not accessible"
fi

echo ""
print_success "OpenSSH SlowDNS Installation Completed!"
echo ""
echo "Server IP: $SERVER_IP"
echo "SSH Port: $SSHD_PORT"
echo "SlowDNS Port: $SLOWDNS_PORT"
echo "MTU: 1800"
echo ""
echo "Note: SlowDNS is running on port $SLOWDNS_PORT"
