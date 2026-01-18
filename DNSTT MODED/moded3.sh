#!/bin/bash
# ============================================================================
#               STABLE SLOWDNS INSTALLATION SCRIPT (FIXED)
# ============================================================================

set -e

# Root check
if [ "$EUID" -ne 0 ]; then
    echo "[✗] Run as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
MTU_SIZE=1350
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# ============================================================================
# COLORS
# ============================================================================
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${CYAN}[i]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

# ============================================================================
# INPUT
# ============================================================================
read -rp "Enter DNS hostname (example: tunnel.domain.com): " NAMESERVER
NAMESERVER=${NAMESERVER:-dns.example.com}

SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

# ============================================================================
# STEP 1: SSH OPTIMIZATION
# ============================================================================
info "Configuring SSH"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

cat > /etc/ssh/sshd_config <<EOF
Port $SSHD_PORT
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
UsePAM yes
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
Compression no
UseDNS no
MaxSessions 100
MaxStartups 100:30:200
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

systemctl restart sshd
ok "SSH configured"

# ============================================================================
# STEP 2: INSTALL DEPENDENCIES
# ============================================================================
info "Installing dependencies"
apt update -y
apt install -y curl wget dnsmasq iptables iproute2
ok "Dependencies installed"

# ============================================================================
# STEP 3: KERNEL OPTIMIZATION (CRITICAL)
# ============================================================================
info "Applying kernel network optimizations"

cat >> /etc/sysctl.conf << 'EOF'
# === SlowDNS Stable Tuning ===
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=250000
net.core.somaxconn=65535

net.ipv4.udp_mem=8388608 12582912 16777216
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384

net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=10240 65535
EOF

sysctl -p
ok "Kernel tuned"

# ============================================================================
# STEP 4: INSTALL SLOWDNS
# ============================================================================
info "Installing SlowDNS"
rm -rf /etc/slowdns
mkdir -p /etc/slowdns
cd /etc/slowdns

wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server
wget -q "$GITHUB_BASE/server.key"
wget -q "$GITHUB_BASE/server.pub"

chmod +x dnstt-server
ok "SlowDNS installed"

# ============================================================================
# STEP 5: SLOWDNS SYSTEMD SERVICE
# ============================================================================
info "Creating SlowDNS service"

cat > /etc/systemd/system/server-sldns.service <<EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
ExecStart=/etc/slowdns/dnstt-server \
-udp :$SLOWDNS_PORT \
-mtu $MTU_SIZE \
-max-conns 4096 \
-privkey-file /etc/slowdns/server.key \
$NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# ============================================================================
# STEP 6: DNSMASQ (REPLACES UNSTABLE EDNS PROXY)
# ============================================================================
info "Configuring dnsmasq (stable EDNS)"

systemctl stop systemd-resolved || true
systemctl disable systemd-resolved || true
systemctl mask systemd-resolved || true

rm -f /etc/resolv.conf
echo "nameserver 127.0.0.1" > /etc/resolv.conf

cat > /etc/dnsmasq.conf <<EOF
port=53
bind-interfaces
listen-address=0.0.0.0
no-resolv
cache-size=10000
dns-forward-max=5000
edns-packet-max=1232
server=127.0.0.1#$SLOWDNS_PORT
EOF

systemctl restart dnsmasq
systemctl enable dnsmasq
ok "dnsmasq configured"

# ============================================================================
# STEP 7: SAFE FIREWALL
# ============================================================================
info "Applying firewall rules"

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -j DROP

ok "Firewall applied"

# ============================================================================
# STEP 8: START SERVICES
# ============================================================================
systemctl daemon-reload
systemctl enable server-sldns
systemctl restart server-sldns

ok "Services started"

# ============================================================================
# FINAL OUTPUT
# ============================================================================
echo ""
echo "=============================================="
echo " SLOWDNS STABLE INSTALL COMPLETED"
echo "=============================================="
echo " Server IP      : $SERVER_IP"
echo " DNS Hostname   : $NAMESERVER"
echo " SSH Port       : $SSHD_PORT"
echo " SlowDNS Port   : $SLOWDNS_PORT"
echo " MTU            : $MTU_SIZE"
echo "=============================================="
echo ""
echo "Client example:"
echo "./dnstt-client -udp $SERVER_IP:$SLOWDNS_PORT \\"
echo " -pubkey-file server.pub \\"
echo " $NAMESERVER 127.0.0.1:1080"
echo ""
echo "DONE."
