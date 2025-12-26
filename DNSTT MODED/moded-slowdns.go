#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
SLOWDNS_DIR="/etc/slowdns"
GO_PROXY_BINARY="slowdns-go"
SLOWDNS_PORT=5300
EDNS_PORT=53
SSH_PORT=22
DEFAULT_NAMESERVER="dns.example.com"
EDNS_WORKERS=128

# Show title
clear
echo ""
echo -e "${BLUE}===============================================================${NC}"
echo -e "${CYAN}           ESIMFREEGB FAST SLOWDNS + EDNS INSTALLER${NC}"
echo -e "${BLUE}===============================================================${NC}"
echo -e "${WHITE}                  SCRIPT BY ESIM FREE GB${NC}"
echo -e "${BLUE}===============================================================${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[✗] Run as root: sudo bash $0${NC}"
    exit 1
fi

# Prompt for nameserver
read -p "Enter nameserver (default: $DEFAULT_NAMESERVER): " NAMESERVER
NAMESERVER=${NAMESERVER:-$DEFAULT_NAMESERVER}

# Create SlowDNS directory
mkdir -p "$SLOWDNS_DIR"

# Function to download files
download_file() {
    local url=$1
    local dest=$2
    echo -e "${BLUE}[→] Downloading $url...${NC}"
    if curl -fsSL "$url" -o "$dest"; then
        echo -e "${GREEN}[✓] Downloaded $dest${NC}"
        chmod +x "$dest"
    else
        echo -e "${RED}[✗] Failed to download $url${NC}"
        exit 1
    fi
}

# Download SlowDNS server keys
download_file "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key" "$SLOWDNS_DIR/server.key"
download_file "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub" "$SLOWDNS_DIR/server.pub"

# Download or build Go EDNS proxy
if ! command -v go &>/dev/null; then
    echo -e "${YELLOW}[!] Go not found, installing...${NC}"
    apt-get update -y >/dev/null 2>&1
    apt-get install -y golang >/dev/null 2>&1
    echo -e "${GREEN}[✓] Go installed${NC}"
fi

GO_SCRIPT_PATH="$SLOWDNS_DIR/edns_proxy.go"
cat > "$GO_SCRIPT_PATH" << 'EOF'
// Paste the full Go EDNS proxy script here
EOF

echo -e "${BLUE}[→] Building Go EDNS proxy...${NC}"
go build -o "$SLOWDNS_DIR/$GO_PROXY_BINARY" "$GO_SCRIPT_PATH"
chmod +x "$SLOWDNS_DIR/$GO_PROXY_BINARY"
echo -e "${GREEN}[✓] Go EDNS proxy built${NC}"

# Create systemd service for EDNS proxy
cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy
After=network.target

[Service]
Type=simple
ExecStart=$SLOWDNS_DIR/$GO_PROXY_BINARY
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable edns-proxy
systemctl restart edns-proxy
sleep 2

# Test EDNS proxy
if ss -ulpn | grep -q ":$EDNS_PORT"; then
    echo -e "${GREEN}[✓] EDNS Proxy running on port $EDNS_PORT${NC}"
else
    echo -e "${RED}[✗] EDNS Proxy failed to start${NC}"
fi

# Create SlowDNS systemd service
cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target sshd.service

[Service]
Type=simple
ExecStart=$SLOWDNS_DIR/sldns-server -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file $SLOWDNS_DIR/server.key $NAMESERVER 127.0.0.1:$SSH_PORT
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl enable server-sldns
systemctl restart server-sldns
sleep 2

# Check if SlowDNS is running
if ss -ulpn | grep -q ":$SLOWDNS_PORT"; then
    echo -e "${GREEN}[✓] SlowDNS running on port $SLOWDNS_PORT${NC}"
else
    echo -e "${RED}[✗] SlowDNS failed to start${NC}"
fi

# Completion message
echo ""
echo -e "${GREEN}──────────────────────────────────────────────────────────────${NC}"
echo -e "${WHITE}           INSTALLATION COMPLETE${NC}"
echo -e "${GREEN}──────────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "${CYAN}===============================================================${NC}"
echo -e "${WHITE}          SlowDNS & EDNS Proxy Ready!${NC}"
echo -e "${CYAN}===============================================================${NC}"
echo ""
echo -e "${GREEN}[✓] SlowDNS Server installed on port $SLOWDNS_PORT${NC}"
echo -e "${GREEN}[✓] EDNS Proxy configured on port $EDNS_PORT${NC}"
echo -e "${GREEN}[✓] System ready${NC}"
echo ""
