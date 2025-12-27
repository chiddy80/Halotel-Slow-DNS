#!/bin/bash

# ============================================================================
#             FIXED SLOWDNS INSTALLATION SCRIPT
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# FUNCTIONS
# ============================================================================
print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_install() {
    if [ $? -eq 0 ]; then
        print_success "$1"
        return 0
    else
        print_error "$2"
        return 1
    fi
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}    SLOWDNS INSTALLER${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Get nameserver
    read -p "Enter nameserver (default: dns.example.com): " NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    # Get Server IP
    print_info "Detecting server IP..."
    SERVER_IP=$(curl -s --connect-timeout 3 ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    print_info "Server IP: $SERVER_IP"
    
    # ============================================================================
    # STEP 1: CONFIGURE OPENSSH
    # ============================================================================
    print_info "Configuring OpenSSH on port $SSHD_PORT"
    
    # Backup SSH config
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    fi
    
    # Create simple SSH config
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
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
AllowTcpForwarding yes
GatewayPorts yes
Subsystem sftp /usr/lib/openssh/sftp-server
UseDNS no
EOF
    
    systemctl restart sshd
    check_install "OpenSSH configured" "Failed to configure SSH"
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS
    # ============================================================================
    print_info "Setting up SlowDNS"
    
    # Create directory
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download binary
    print_info "Downloading SlowDNS binary..."
    if command -v wget >/dev/null 2>&1; then
        wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server
    elif command -v curl >/dev/null 2>&1; then
        curl -s "$GITHUB_BASE/dnstt-server" -o dnstt-server
    else
        apt update && apt install -y wget
        wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server
    fi
    
    if [ -f dnstt-server ]; then
        chmod +x dnstt-server
        print_success "SlowDNS binary downloaded"
    else
        print_error "Failed to download SlowDNS binary"
        exit 1
    fi
    
    # Download key files
    print_info "Downloading key files..."
    wget -q "$GITHUB_BASE/server.key" -O server.key
    wget -q "$GITHUB_BASE/server.pub" -O server.pub
    
    if [ -f server.key ] && [ -f server.pub ]; then
        print_success "Key files downloaded"
    else
        print_warning "Key files may not have downloaded correctly"
    fi
    
    # ============================================================================
    # STEP 3: CREATE SLOWDNS SERVICE
    # ============================================================================
    print_info "Creating SlowDNS service"
    
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp 127.0.0.1:$SLOWDNS_PORT -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=3
User=root
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=slowdns

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "SlowDNS service file created"
    
    # ============================================================================
    # STEP 4: CREATE SIMPLE DNS PROXY (NOT EDNS)
    # ============================================================================
    print_info "Creating DNS Proxy"
    
    # Install dnsmasq for simple DNS forwarding
    apt update > /dev/null 2>&1
    apt install -y dnsmasq > /dev/null 2>&1
    
    # Stop systemd-resolved if running
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    
    # Configure dnsmasq
    cat > /etc/dnsmasq.conf << EOF
# DNSMASQ Configuration for SlowDNS
port=53
listen-address=0.0.0.0
bind-interfaces
no-resolv
server=127.0.0.1#$SLOWDNS_PORT
log-queries
log-facility=/var/log/dnsmasq.log
EOF
    
    # Create simple UDP forwarder script
    cat > /usr/local/bin/dns-proxy << 'EOF'
#!/bin/bash
# Simple DNS forwarder to SlowDNS
while true; do
    socat UDP4-RECVFROM:53,reuseaddr,fork UDP4-SENDTO:127.0.0.1:5300
    sleep 1
done
EOF
    
    chmod +x /usr/local/bin/dns-proxy
    
    # Create dns-proxy service
    cat > /etc/systemd/system/dns-proxy.service << EOF
[Unit]
Description=DNS Proxy for SlowDNS
After=slowdns.service
Requires=slowdns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dns-proxy
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "DNS Proxy configured"
    
    # ============================================================================
    # STEP 5: FIREWALL CONFIGURATION
    # ============================================================================
    print_info "Configuring firewall"
    
    # Install iptables if not present
    if ! command -v iptables >/dev/null 2>&1; then
        apt install -y iptables iptables-persistent
    fi
    
    # Clear existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    
    # Default policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
    
    # Allow DNS ports
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
    
    # Drop invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP
    
    print_success "Firewall configured"
    
    # ============================================================================
    # STEP 6: START SERVICES
    # ============================================================================
    print_info "Starting services"
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable and start SlowDNS
    systemctl enable slowdns
    systemctl start slowdns
    
    if systemctl is-active --quiet slowdns; then
        print_success "SlowDNS service started"
    else
        print_error "Failed to start SlowDNS"
        # Try to run manually
        /etc/slowdns/dnstt-server -udp 127.0.0.1:$SLOWDNS_PORT -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT &
        sleep 2
    fi
    
    # Stop dnsmasq if running (we'll use our proxy)
    systemctl stop dnsmasq 2>/dev/null
    systemctl disable dnsmasq 2>/dev/null
    
    # Start DNS proxy
    systemctl enable dns-proxy
    systemctl start dns-proxy
    
    if systemctl is-active --quiet dns-proxy; then
        print_success "DNS Proxy started"
    else
        print_warning "Starting DNS proxy manually"
        /usr/local/bin/dns-proxy &
    fi
    
    # Kill any process on port 53
    lsof -ti:53 | xargs kill -9 2>/dev/null
    
    # ============================================================================
    # STEP 7: VERIFICATION
    # ============================================================================
    print_info "Verifying installation..."
    
    sleep 3
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}    INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    echo -e "\n${BLUE}SERVER CONFIGURATION:${NC}"
    echo "  Server IP:     $SERVER_IP"
    echo "  SSH Port:      $SSHD_PORT"
    echo "  SlowDNS Port:  $SLOWDNS_PORT"
    echo "  DNS Port:      53"
    echo "  Nameserver:    $NAMESERVER"
    
    echo -e "\n${BLUE}SERVICE STATUS:${NC}"
    
    # Check SlowDNS
    if pgrep -f "dnstt-server" > /dev/null; then
        echo "  ✓ SlowDNS: Running"
    else
        echo "  ✗ SlowDNS: Not running"
    fi
    
    # Check DNS proxy
    if pgrep -f "dns-proxy" > /dev/null; then
        echo "  ✓ DNS Proxy: Running"
    else
        echo "  ✗ DNS Proxy: Not running"
    fi
    
    # Check ports
    echo -e "\n${BLUE}PORT STATUS:${NC}"
    if ss -ulpn | grep -q ":53 "; then
        echo "  ✓ Port 53: Listening"
    else
        echo "  ✗ Port 53: Not listening"
    fi
    
    if ss -ulpn | grep -q ":$SLOWDNS_PORT "; then
        echo "  ✓ Port $SLOWDNS_PORT: Listening"
    else
        echo "  ✗ Port $SLOWDNS_PORT: Not listening"
    fi
    
    # Show public key
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${BLUE}PUBLIC KEY (for client):${NC}"
        pubkey=$(cat /etc/slowdns/server.pub)
        echo "  $pubkey"
    fi
    
    # Test connection
    echo -e "\n${BLUE}TESTING CONNECTION:${NC}"
    print_info "Testing DNS query (this may take 5 seconds)..."
    
    timeout 5 dig @127.0.0.1 $NAMESERVER > /tmp/dig_test.txt 2>&1
    if [ $? -eq 0 ]; then
        echo "  ✓ Local DNS test: PASSED"
    else
        echo "  ✗ Local DNS test: FAILED"
    fi
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}SETUP COMPLETE!${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    echo -e "\n${YELLOW}NEXT STEPS:${NC}"
    echo "1. Configure your domain's NS record to point to: $SERVER_IP"
    echo "2. Use this public key in your client configuration"
    echo "3. Test with: dig @$SERVER_IP $NAMESERVER"
    
    echo -e "\n${YELLOW}TROUBLESHOOTING:${NC}"
    echo "If connection fails, check:"
    echo "  - Port 53 is open: sudo ss -ulpn | grep :53"
    echo "  - SlowDNS is running: sudo systemctl status slowdns"
    echo "  - Firewall allows port 53: sudo iptables -L -n"
    
    echo -e "\n${BLUE}MANUAL START (if needed):${NC}"
    echo "  SlowDNS: /etc/slowdns/dnstt-server -udp 127.0.0.1:$SLOWDNS_PORT \\"
    echo "           -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT"
    echo "  DNS Proxy: /usr/local/bin/dns-proxy"
}

# ============================================================================
# EXECUTE WITH ERROR HANDLING
# ============================================================================
trap 'echo -e "\n${RED}Installation interrupted!${NC}"; exit 1' INT

if main; then
    echo -e "\n${GREEN}Installation finished at: $(date)${NC}"
    exit 0
else
    echo -e "\n${RED}Installation failed!${NC}"
    exit 1
fi
