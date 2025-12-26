#!/bin/bash
set -e

# ============ CONFIG ============
SLOWDNS_PORT=5300
SSH_PORT=22
DOMAIN="dns.example.com"   # change after install if needed
NGINX_DNS_PORT=53
# ================================

if [ "$EUID" -ne 0 ]; then
    echo "Run as root"
    exit 1
fi

echo "=== Updating system ==="
apt update -y
apt upgrade -y
apt install -y curl wget gnupg2 ca-certificates lsb-release nginx libnginx-mod-stream net-tools dnsutils

echo "=== Disable local DNS ==="
systemctl stop systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true
systemctl mask systemd-resolved 2>/dev/null || true

# Kill any process using port 53
fuser -k 53/udp 2>/dev/null || true
fuser -k 53/tcp 2>/dev/null || true

echo "=== Setup DNS resolution ==="
cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
options edns0
EOF
chattr +i /etc/resolv.conf 2>/dev/null || true

echo "=== Setup SlowDNS ==="
mkdir -p /etc/slowdns
cd /etc/slowdns

# Download SlowDNS server (using a reliable source)
if [ ! -f dnstt-server ]; then
    wget -q -O dnstt-server https://github.com/bebasid/bebasid/releases/download/v1.0/dnstt-server
    chmod +x dnstt-server
fi

# Generate keys if they don't exist
if [ ! -f server.key ]; then
    echo "Generating new SlowDNS keys..."
    ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
    echo "Public key (save for client):"
    cat server.pub
    echo ""
fi

echo "=== Create SlowDNS Service ==="
cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS Server (DNSTT)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/slowdns
ExecStart=/etc/slowdns/dnstt-server -udp 127.0.0.1:$SLOWDNS_PORT -privkey-file /etc/slowdns/server.key $DOMAIN 127.0.0.1:$SSH_PORT
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns
systemctl start slowdns

echo "=== Configure NGINX for UDP DNS ==="

# Create NGINX config with stream module for UDP
cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}

# TCP/UDP proxy
stream {
    # DNS UDP proxy (SlowDNS)
    upstream slowdns_backend {
        server 127.0.0.1:5300;
    }
    
    server {
        listen 53 udp reuseport;
        listen [::]:53 udp reuseport;
        proxy_pass slowdns_backend;
        proxy_responses 1;
        proxy_timeout 20s;
        proxy_buffer_size 512k;
    }
    
    # Also handle TCP DNS if needed
    server {
        listen 53 tcp reuseport;
        listen [::]:53 tcp reuseport;
        proxy_pass slowdns_backend;
        proxy_timeout 20s;
        proxy_buffer_size 512k;
    }
}

# HTTP (optional, can be removed if not needed)
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Test and restart NGINX
echo "Testing NGINX configuration..."
nginx -t

# Create a systemd override to ensure NGINX starts after networking
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/override.conf <<EOF
[Unit]
After=network-online.target slowdns.service
Wants=network-online.target
EOF

systemctl daemon-reload
systemctl restart nginx
systemctl enable nginx

echo "=== Configure firewall ==="
# Save current iptables
iptables-save > /etc/iptables.backup

# Flush existing rules
iptables -F
iptables -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DNS (UDP and TCP)
iptables -A INPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT

# Allow SlowDNS port
iptables -A INPUT -p udp --dport $SLOWDNS_PORT -m state --state NEW -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -j ACCEPT

# Allow ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT

# Save rules
apt install -y iptables-persistent 2>/dev/null || true
netfilter-persistent save 2>/dev/null || true

echo "=== Optimize network settings ==="
# Optimize for UDP DNS
cat >> /etc/sysctl.conf <<EOF

# Optimize for UDP/DNS
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_mem = 4096 87380 134217728
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.core.netdev_max_backlog = 50000
net.core.somaxconn = 4096
EOF

sysctl -p

echo "=== Testing setup ==="
sleep 3

echo "1. Checking services..."
systemctl status slowdns --no-pager | head -10
echo ""
systemctl status nginx --no-pager | head -10
echo ""

echo "2. Checking ports..."
ss -tulpn | grep -E ':53|:'$SLOWDNS_PORT
echo ""

echo "3. Testing SlowDNS locally..."
timeout 2 nc -z -u 127.0.0.1 $SLOWDNS_PORT && echo "SlowDNS UDP port is open" || echo "SlowDNS UDP port not responding"
echo ""

echo "4. Testing NGINX UDP proxy..."
timeout 2 nc -z -u 127.0.0.1 53 && echo "NGINX DNS UDP port is open" || echo "NGINX DNS port not responding"

echo ""
echo "=================================================="
echo "           SLOWDNS + NGINX UDP INSTALLED         "
echo "=================================================="
echo "Server IP:          $(curl -s ifconfig.me 2>/dev/null || hostname -I | cut -d' ' -f1)"
echo "NGINX DNS Port:     53 (UDP/TCP)"
echo "SlowDNS Port:       $SLOWDNS_PORT"
echo "SSH Port:           $SSH_PORT"
echo "Domain:             $DOMAIN"
echo ""
echo "=== IMPORTANT ==="
echo "1. Save your public key for clients:"
echo "   cat /etc/slowdns/server.pub"
echo ""
echo "2. Test from client:"
echo "   dig +tcp @YOUR_SERVER_IP $DOMAIN"
echo "   dig +udp @YOUR_SERVER_IP $DOMAIN"
echo ""
echo "3. Check logs:"
echo "   journalctl -u slowdns -f"
echo "   tail -f /var/log/nginx/error.log"
echo ""
echo "4. Client configuration needed:"
echo "   Use dnstt-client with the server.pub key"
echo "=================================================="
