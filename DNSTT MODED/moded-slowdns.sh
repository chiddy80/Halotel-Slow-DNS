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
DNSDIST_PORT=53

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

echo "Starting OpenSSH SlowDNS with dnsdist Installation..."

# Get Server IP
SERVER_IP=$(curl -s ifconfig.me)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
fi

# Update system and install dependencies
echo "Updating system and installing dependencies..."
apt update > /dev/null 2>&1
apt install -y openssh-server curl wget dnsdist iptables-persistent net-tools > /dev/null 2>&1
print_success "Dependencies installed"

# Configure OpenSSH
echo "Configuring OpenSSH on port $SSHD_PORT..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null

cat > /etc/ssh/sshd_config << EOF

# OpenSSH Configuration

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
print_success "OpenSSH configured on port $SSHD_PORT"

# Setup SlowDNS
echo "Setting up SlowDNS..."
rm -rf /etc/slowdns
mkdir -p /etc/slowdns
cd /etc/slowdns
print_success "SlowDNS directory created"

# Download pre-compiled binary directly
echo "Downloading SlowDNS binary..."
curl -fsSL "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server" -o dnstt-server

if [ $? -eq 0 ] && [ -f "dnstt-server" ]; then
    chmod +x dnstt-server
    SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
    print_success "SlowDNS binary downloaded"
else
    print_warning "Trying alternative download method..."
    wget -q -O dnstt-server "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/dnstt-server"
    if [ $? -eq 0 ]; then
        chmod +x dnstt-server
        SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
        print_success "SlowDNS binary downloaded via wget"
    else
        print_error "Failed to download SlowDNS binary!"
        exit 1
    fi
fi

# Download key files
echo "Downloading key files..."
wget -q -O /etc/slowdns/server.key "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key" && print_success "server.key downloaded"
wget -q -O /etc/slowdns/server.pub "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub" && print_success "server.pub downloaded"

# Create SlowDNS service
echo "Creating SlowDNS service..."
cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=slowdns

[Install]
WantedBy=multi-user.target
EOF

print_success "SlowDNS service file created"

# Configure dnsdist
echo "Configuring dnsdist..."
# Stop any DNS services that might conflict
systemctl stop systemd-resolved 2>/dev/null
systemctl disable systemd-resolved 2>/dev/null

# Backup existing dnsdist config
if [ -f "/etc/dnsdist/dnsdist.conf" ]; then
    cp /etc/dnsdist/dnsdist.conf /etc/dnsdist/dnsdist.conf.backup
fi

# Create optimized dnsdist configuration
cat > /etc/dnsdist/dnsdist.conf << EOF
-- ============================================
-- dnsdist configuration for SlowDNS
-- ============================================

-- Bind to all interfaces on port 53
setLocal("0.0.0.0:${DNSDIST_PORT}")
setLocal("[::]:${DNSDIST_PORT}")

-- Define backend server (SlowDNS)
newServer({address="127.0.0.1:${SLOWDNS_PORT}", name="slowdns", maxInFlight=10000, useClientSubnet=true})

-- Performance tuning
setMaxTCPClientThreads(50)
setMaxTCPQueriesPerConnection(100)
setMaxTCPConnectionsPerClient(100)
setMaxUDPOutstanding(65535)
setUDPSocketBuffer(16777216)
setTCPSocketBuffer(16777216)
setStaleCacheEntriesTTL(5)

-- Timeout settings (adjust for SlowDNS)
setTCPRecvTimeout(10)
setTCPSendTimeout(10)
setUDPTimeout(5)

-- Cache settings (optional, for performance)
-- pc = newPacketCache(10000, {maxTTL=86400, minTTL=0})
-- getPool(""):setCache(pc)

-- Rate limiting (adjust as needed)
-- Max 100 queries per second per IP
addAction(MaxQPSIPRule(100, 32, 100), DropAction())

-- Allow 1000 queries per second globally
-- addAction(MaxQPSRule(1000), DropAction())

-- Block known malicious queries
addAction(AndRule({QTypeRule("ANY"), NotRule(OrRule({QTypeRule("A"), QTypeRule("AAAA"), QTypeRule("TXT")}))}), DropAction())

-- Drop non-DNS packets
addAction(NotRule(QClassRule(1)), DropAction())

-- Response manipulation for SlowDNS
addResponseAction(AllRule(), SetEDNSOptionAction(8, "\\000\\000"))

-- Logging (optional)
-- setVerbose(true)
-- setSyslog(true)

-- Health checks
addAction(makeRule("healthcheck.local."), PoolAction("slowdns"))
EOF

print_success "dnsdist configuration created"

# Create dnsdist systemd service override for better performance
mkdir -p /etc/systemd/system/dnsdist.service.d/
cat > /etc/systemd/system/dnsdist.service.d/override.conf << EOF
[Service]
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity
TasksMax=infinity
Restart=always
RestartSec=3
EOF

# Firewall configuration
echo "Configuring firewall..."
# Save current iptables
iptables-save > /etc/iptables/rules.v4.backup

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
iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT

# Allow DNS (TCP & UDP)
iptables -A INPUT -p udp --dport $DNSDIST_PORT -j ACCEPT
iptables -A INPUT -p tcp --dport $DNSDIST_PORT -j ACCEPT

# Allow SlowDNS port
iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT

# Allow ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT

# Rate limiting for SSH
iptables -A INPUT -p tcp --dport $SSHD_PORT -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport $SSHD_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Rate limiting for DNS (optional)
iptables -A INPUT -p udp --dport $DNSDIST_PORT -m limit --limit 100/sec -j ACCEPT
iptables -A INPUT -p tcp --dport $DNSDIST_PORT -m limit --limit 50/sec -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# Save iptables rules
netfilter-persistent save 2>/dev/null || true

print_success "Firewall configured"

# Disable IPv6 (optional)
echo "Disabling IPv6..."
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1 > /dev/null 2>&1
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf

# Start services
echo "Starting services..."
systemctl daemon-reload

# Start SlowDNS
echo "Starting SlowDNS service..."
systemctl enable server-sldns > /dev/null 2>&1
systemctl start server-sldns
sleep 3

if systemctl is-active --quiet server-sldns; then
    print_success "SlowDNS service started"
else
    print_error "Failed to start SlowDNS service"
    journalctl -u server-sldns -n 10 --no-pager
    exit 1
fi

# Start dnsdist
echo "Starting dnsdist..."
systemctl enable dnsdist > /dev/null 2>&1
systemctl stop dnsdist 2>/dev/null
sleep 1
systemctl start dnsdist
sleep 3

if systemctl is-active --quiet dnsdist; then
    print_success "dnsdist started"
else
    print_error "Failed to start dnsdist"
    journalctl -u dnsdist -n 10 --no-pager
    exit 1
fi

# Verify services are running
echo "Verifying services..."
SERVICES_RUNNING=true

# Check SlowDNS
if ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
    print_success "SlowDNS listening on port $SLOWDNS_PORT"
else
    print_error "SlowDNS NOT listening on port $SLOWDNS_PORT"
    SERVICES_RUNNING=false
fi

# Check dnsdist
if ss -tulpn 2>/dev/null | grep -q ":$DNSDIST_PORT "; then
    print_success "dnsdist listening on port $DNSDIST_PORT"
else
    print_error "dnsdist NOT listening on port $DNSDIST_PORT"
    SERVICES_RUNNING=false
fi

# Check SSH
if systemctl is-active --quiet sshd; then
    print_success "SSH service is running"
else
    print_error "SSH service is NOT running"
    SERVICES_RUNNING=false
fi

# Health check
echo "Performing health check..."
if dig @127.0.0.1 google.com +short +time=2 +tries=1 2>/dev/null | grep -q -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    print_success "DNS resolution is working"
else
    print_warning "DNS resolution test failed - checking service status..."
    # Show service status
    systemctl status server-sldns --no-pager | head -20
    systemctl status dnsdist --no-pager | head -20
fi

# Final output
echo ""
echo "================================================"
echo " Installation Summary"
echo "================================================"
print_success "Installation Completed!"
echo ""
echo "Server Information:"
echo "  Server IP:      $SERVER_IP"
echo "  SSH Port:       $SSHD_PORT"
echo "  SlowDNS Port:   $SLOWDNS_PORT"
echo "  DNS Port:       $DNSDIST_PORT (dnsdist)"
echo "  MTU:            1800"
echo "  Backend:        $NAMESERVER"
echo ""
echo "Firewall Status:"
iptables -L INPUT -n --line-numbers | head -20
echo ""
echo "Service Status:"
systemctl status server-sldns --no-pager | grep -E "(Active|Loaded)" | head -2
systemctl status dnsdist --no-pager | grep -E "(Active|Loaded)" | head -2
echo ""
echo "Test Commands:"
echo "  Test DNS:      dig @$SERVER_IP google.com"
echo "  Test SSH:      ssh root@$SERVER_IP -p $SSHD_PORT"
echo "  Check logs:    journalctl -u server-sldns -f"
echo "  Check logs:    journalctl -u dnsdist -f"
echo ""
echo "dnsdist Web Interface (optional):"
echo "  Enable with: echo 'setWebserverConfig({password=\"PASSWORD\", apiKey=\"KEY\", acl=\"0.0.0.0/0\"})' >> /etc/dnsdist/dnsdist.conf"
echo "  Then restart: systemctl restart dnsdist"
echo "  Access at: http://$SERVER_IP:8083/"
echo ""

# Create uninstall script
cat > /usr/local/bin/uninstall-slowdns-dnsdist.sh << 'EOF'
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi
echo "Uninstalling SlowDNS with dnsdist..."
systemctl stop server-sldns dnsdist
systemctl disable server-sldns dnsdist
rm -f /etc/systemd/system/server-sldns.service
rm -rf /etc/slowdns
apt remove -y dnsdist
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
netfilter-persistent save 2>/dev/null || true
echo "Uninstallation complete"
EOF

chmod +x /usr/local/bin/uninstall-slowdns-dnsdist.sh
print_success "Uninstall script created: /usr/local/bin/uninstall-slowdns-dnsdist.sh"

if [ "$SERVICES_RUNNING" = "true" ]; then
    print_success "All services are running correctly!"
else
    print_warning "Some services may not be running properly. Check above for errors."
fi

echo "Done!"
