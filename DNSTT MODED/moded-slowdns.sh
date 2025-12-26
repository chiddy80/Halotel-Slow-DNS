#!/bin/bash
set -e

# =============================
# CONFIG
# =============================
SSHD_PORT=22
SLOWDNS_PORT=5300
DNS_PORT=53

read -p "Enter DNS name (example: dns.example.com): " DNS_NAME
DNS_NAME=${DNS_NAME:-dns.example.com}

echo "Installing nginx + SlowDNS..."

# =============================
# PACKAGES
# =============================
apt update -y
apt install -y nginx curl wget iptables openssh-server

systemctl stop systemd-resolved || true
fuser -k 53/udp || true

# =============================
# OPENSSH
# =============================
cat > /etc/ssh/sshd_config <<EOF
Port $SSHD_PORT
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
UsePAM yes
AllowTcpForwarding yes
GatewayPorts yes
ClientAliveInterval 30
ClientAliveCountMax 3
UseDNS no
EOF

systemctl restart ssh

# =============================
# SLOWDNS
# =============================
mkdir -p /etc/slowdns
cd /etc/slowdns

wget -O dnstt-server https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/dnstt-server
chmod +x dnstt-server

wget -O server.key https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/server.key
wget -O server.pub https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/server.pub

cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=DNSTT Server
After=network.target

[Service]
ExecStart=/etc/slowdns/dnstt-server -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $DNS_NAME 127.0.0.1:$SSHD_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns
systemctl start slowdns

# =============================
# NGINX UDP (EDNS SAFE)
# =============================
cat > /etc/nginx/nginx.conf <<EOF
worker_processes auto;
events { worker_connections 10240; }

stream {
    upstream slowdns_backend {
        server 127.0.0.1:$SLOWDNS_PORT;
    }

    server {
        listen 53 udp reuseport;
        proxy_pass slowdns_backend;
        proxy_timeout 10s;
        proxy_responses 1;
    }
}
EOF

systemctl restart nginx
systemctl enable nginx

# =============================
# FIREWALL
# =============================
iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT

# =============================
# SHOW STATUS
# =============================
echo ""
echo "=============================="
echo "SlowDNS + nginx UDP installed"
echo "=============================="
echo "DNS name: $DNS_NAME"
echo "DNS Port: 53 (nginx UDP)"
echo "SlowDNS: 127.0.0.1:$SLOWDNS_PORT"
echo "SSH: $SSHD_PORT"
echo "MTU: 1800"
echo ""
echo "Test with:"
echo "dig @$DNS_NAME google.com"
echo "=============================="
