#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Run as root"
  exit 1
fi

SSHD_PORT=22
SLOWDNS_PORT=5300

read -p "Enter nameserver (example: ns.example.com): " NAMESERVER
NAMESERVER=${NAMESERVER:-dns.example.com}

echo "Installing SlowDNS + dnsdist (Debian 12 compatible)"

SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

###################################
# Packages
###################################
apt update
apt install -y openssh-server curl wget dnsdist iptables

###################################
# SSH
###################################
cat > /etc/ssh/sshd_config << EOF
Port $SSHD_PORT
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
UseDNS no
Subsystem sftp /usr/lib/openssh/sftp-server
MaxSessions 100
MaxStartups 100:30:200
EOF
systemctl restart ssh

###################################
# SlowDNS (dnstt)
###################################
rm -rf /etc/slowdns
mkdir -p /etc/slowdns
cd /etc/slowdns

curl -fsSL https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server -o dnstt-server
chmod +x dnstt-server

wget -q -O server.key https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key
wget -q -O server.pub https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub

cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
ExecStart=/etc/slowdns/dnstt-server -udp :$SLOWDNS_PORT -mtu 1200 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

###################################
# Disable systemd-resolved
###################################
systemctl stop systemd-resolved || true
systemctl disable systemd-resolved || true
rm -f /etc/resolv.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf

###################################
# dnsdist (Debian 12 safe config)
###################################
cat > /etc/dnsdist/dnsdist.conf << 'EOF'
setLocal("0.0.0.0:53")

newServer({
  address="127.0.0.1:5300",
  name="slowdns",
  maxInFlight=2048
})

setMaxUDPOutstanding(8192)

setUDPTimeout(2)
setTCPRecvTimeout(2)
setTCPSendTimeout(2)

addAction(MaxQPSIPRule(60), DropAction())
addAction(NotRule(QClassRule(1)), DropAction())
EOF

###################################
# Firewall
###################################
iptables -F
iptables -P INPUT DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

###################################
# Start everything
###################################
systemctl daemon-reload
systemctl enable server-sldns
systemctl enable dnsdist

systemctl restart server-sldns
sleep 2
systemctl restart dnsdist

###################################
# Output
###################################
echo ""
echo "=============================="
echo " SlowDNS + dnsdist READY"
echo "=============================="
echo "Server IP : $SERVER_IP"
echo "DNS Port  : 53"
echo "SlowDNS   : $SLOWDNS_PORT"
echo "MTU       : 1200"
echo ""
echo "Test:"
echo "dig @$SERVER_IP google.com"
echo ""
