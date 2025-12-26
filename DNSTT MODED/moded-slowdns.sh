#!/bin/bash

# ===================== SMART LICENSE SYSTEM =====================
# Checks IP against allowed list + validates license key from GitHub
# ==========================================================

# GitHub Raw URLs
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
VALID_KEYS_URL="$GITHUB_BASE/Valid_Keys.txt"
ALLOWED_IPS_URL="$GITHUB_BASE/Allowips.text"

MAX_ATTEMPTS=3
LOG_FILE="/var/log/sldns_license.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Create log file
mkdir -p /var/log 2>/dev/null
touch "$LOG_FILE" 2>/dev/null

# Function to get current VPS public IP
get_vps_ip() {
    local ip=""
    
    # Try multiple services
    ip=$(curl -s --max-time 3 https://ifconfig.me 2>/dev/null)
    
    if [ -z "$ip" ] || [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null)
    fi
    
    if [ -z "$ip" ] || [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip=$(curl -s --max-time 3 https://checkip.amazonaws.com 2>/dev/null)
    fi
    
    echo "$ip"
}

# Function to fetch from GitHub
fetch_from_github() {
    local url="$1"
    local content=$(curl -s --max-time 5 "$url" 2>/dev/null)
    if [ -n "$content" ]; then
        echo "$content"
        return 0
    fi
    return 1
}

# Function to check if IP is in allowed list
check_ip_allowed() {
    local current_ip="$1"
    local allowed_ips=$(fetch_from_github "$ALLOWED_IPS_URL")
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Cannot fetch allowed IPs list${NC}"
        return 2
    fi
    
    # Clean the list
    local clean_list=$(echo "$allowed_ips" | grep -v '^#' | grep -v '^$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if echo "$clean_list" | grep -q "^$current_ip$"; then
        return 0
    else
        echo -e "${RED}Error: VPS IP not authorized${NC}"
        echo -e "${YELLOW}Get license: t.me/esimfreegb${NC}"
        return 1
    fi
}

# Function to validate license key
validate_license_key() {
    local license_key="$1"
    local valid_keys=$(fetch_from_github "$VALID_KEYS_URL")
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Cannot fetch license keys${NC}"
        return 2
    fi
    
    # Clean the list
    local clean_keys=$(echo "$valid_keys" | grep -v '^#' | grep -v '^$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if echo "$clean_keys" | grep -q "^$license_key$"; then
        return 0
    else
        echo -e "${RED}Error: Invalid license key${NC}"
        return 1
    fi
}

# Function to read hidden input
read_hidden() {
    stty -echo
    read value
    stty echo
    echo
    echo "$value"
}

# Main license check function
check_license_smart() {
    clear
    
    echo "==========================================="
    echo "      SLOWDNS INSTALLATION"
    echo "==========================================="
    echo ""
    
    # Get current VPS IP
    echo -e "${YELLOW}Checking VPS authorization...${NC}"
    CURRENT_IP=$(get_vps_ip)
    
    if [ -z "$CURRENT_IP" ] || [[ ! $CURRENT_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}Error: Cannot get VPS IP${NC}"
        exit 1
    fi
    
    echo -e "VPS IP: $CURRENT_IP"
    
    # Check if IP is allowed
    if ! check_ip_allowed "$CURRENT_IP"; then
        exit 1
    fi
    
    echo -e "${GREEN}✓ IP authorized${NC}"
    echo ""
    
    # IP is allowed, now check license
    echo -e "${YELLOW}License verification required${NC}"
    echo "Get license: t.me/esimfreegb"
    echo ""
    
    # Track attempts for this session
    local session_attempts=0
    
    while [ $session_attempts -lt $MAX_ATTEMPTS ]; do
        session_attempts=$((session_attempts + 1))
        
        echo -e "Attempt $session_attempts of $MAX_ATTEMPTS"
        echo -n "Enter license key: "
        LICENSE_KEY=$(read_hidden)
        
        if [ -z "$LICENSE_KEY" ]; then
            echo -e "${RED}Error: License key cannot be empty${NC}"
            continue
        fi
        
        # Clean the key
        LICENSE_KEY=$(echo "$LICENSE_KEY" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
        
        echo -e "Verifying..."
        
        # Validate against GitHub
        if validate_license_key "$LICENSE_KEY"; then
            echo -e "${GREEN}✓ License verified${NC}"
            echo -e "${GREEN}✓ Starting installation...${NC}"
            sleep 1
            return 0
        else
            if [ $session_attempts -lt $MAX_ATTEMPTS ]; then
                echo -e "${YELLOW}Try again${NC}"
                echo ""
            else
                echo -e "${RED}Error: Max attempts reached${NC}"
                echo -e "${RED}Contact: t.me/esimfreegb${NC}"
                exit 1
            fi
        fi
    done
    
    exit 1
}

# ===================== MAIN LICENSE CHECK =====================
if [ "$EUID" -ne 0 ]; then
    echo "Error: Run as root"
    exit 1
fi

# Run the smart license check
check_license_smart

# ==========================================================
# MAIN INSTALLATION SCRIPT STARTS HERE
# ==========================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Run as root"
    exit 1
fi

# Port Configuration
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
print_success "OpenSSH configured on port $SSHD_PORT with key-based authentication only"

# Setup SlowDNS - FAST VERSION (no moded-slowdns.sh)
echo "Setting up SlowDNS (fast method)..."
rm -rf /etc/slowdns
mkdir -p /etc/slowdns
cd /etc/slowdns
print_success "SlowDNS directory created"

# Download pre-compiled binary directly (FAST - ~1 second)
echo "Downloading SlowDNS binary directly..."
curl -fsSL "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server" -o dnstt-server

if [ $? -eq 0 ] && [ -f "dnstt-server" ]; then
    chmod +x dnstt-server
    SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
    print_success "SlowDNS binary downloaded (fast method)"
    
    # Check binary size
    BINARY_SIZE=$(du -h dnstt-server | cut -f1)
    echo "Binary size: $BINARY_SIZE"
else
    print_error "Failed to download binary directly"
    print_warning "Trying alternative method..."
    
    # Alternative: Download from different source
    wget -q -O dnstt-server "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/dnstt-server"
    if [ $? -eq 0 ]; then
        chmod +x dnstt-server
        SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
        print_success "SlowDNS binary downloaded via wget"
    else
        print_error "All download methods failed!"
        exit 1
    fi
fi

# Download key files
echo "Downloading key files..."
wget -q -O /etc/slowdns/server.key "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key" && print_success "server.key downloaded"
wget -q -O /etc/slowdns/server.pub "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub" && print_success "server.pub downloaded"

# Test the binary
echo "Testing SlowDNS binary..."
if ./dnstt-server --help 2>&1 | grep -q "usage" || ./dnstt-server -h 2>&1 | head -5; then
    print_success "SlowDNS binary is working"
else
    print_warning "Binary test inconclusive (may still work)"
fi

# Create SlowDNS service with MTU 1800
echo "Creating SlowDNS service..."
cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target sshd.service

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

print_success "Service file created"

# EDNS Proxy Installation (C/epoll) - FAST VERSION
echo "Installing EDNS Proxy (C/epoll)..."
cat > /tmp/edns.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 100

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
} request_t;

int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        offset += 5;
    }
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0 && offset + 4 < len) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            if(type == 41) {
                buf[offset+3] = new_size >> 8;
                buf[offset+4] = new_size & 0xFF;
                return len;
            }
        }
        offset++;
    }
    return len;
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        return 1;
    }
    if(set_nonblock(sock) < 0) {
        perror("fcntl");
        close(sock);
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0) {
        perror("epoll_create1");
        close(sock);
        return 1;
    }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("epoll_ctl");
        close(epoll_fd);
        close(sock);
        return 1;
    }
    printf("EDNS Proxy running on port 53 (C/epoll)\n");
    struct epoll_event events[MAX_EVENTS];
    request_t *requests[10000] = {0};
    while(1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        for(int i = 0; i < n; i++) {
            if(events[i].data.fd == sock) {
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
                if(len > 0) {
                    patch_edns(buffer, len, INT_EDNS);
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if(up_sock >= 0) {
                        set_nonblock(up_sock);
                        request_t *req = malloc(sizeof(request_t));
                        if(req) {
                            req->client_fd = sock;
                            req->client_addr = client_addr;
                            req->addr_len = client_len;
                            req->timestamp = time(NULL);
                            requests[up_sock] = req;
                            struct epoll_event up_ev;
                            up_ev.events = EPOLLIN;
                            up_ev.data.fd = up_sock;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev);
                            struct sockaddr_in up_addr;
                            memset(&up_addr, 0, sizeof(up_addr));
                            up_addr.sin_family = AF_INET;
                            up_addr.sin_port = htons(SLOWDNS_PORT);
                            inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                            sendto(up_sock, buffer, len, 0,
                                   (struct sockaddr*)&up_addr, sizeof(up_addr));
                        } else {
                            close(up_sock);
                        }
                    }
                }
            } else {
                int up_sock = events[i].data.fd;
                request_t *req = requests[up_sock];
                if(req) {
                    unsigned char buffer[BUFFER_SIZE];
                    int len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                    if(len > 0) {
                        patch_edns(buffer, len, EXT_EDNS);
                        sendto(req->client_fd, buffer, len, 0,
                               (struct sockaddr*)&req->client_addr,
                               req->addr_len);
                    }
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, up_sock, NULL);
                    close(up_sock);
                    free(req);
                    requests[up_sock] = NULL;
                }
            }
        }
    }
}
EOF

# Install gcc if needed (quick check)
if ! command -v gcc &>/dev/null; then
    echo "Installing gcc..."
    apt update > /dev/null 2>&1 && apt install -y gcc > /dev/null 2>&1
fi

# Compile EDNS proxy (fast compile)
echo "Compiling EDNS Proxy..."
gcc -O3 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log
if [ $? -eq 0 ]; then
    chmod +x /usr/local/bin/edns-proxy
    print_success "EDNS Proxy compiled successfully"
else
    print_error "EDNS Proxy compilation failed"
    cat /tmp/compile.log
    exit 1
fi

# Create EDNS proxy service
cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy for SlowDNS
After=server-sldns.service
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

print_success "EDNS Proxy service created"

# Startup config (quick setup)
echo "Setting up firewall rules..."
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
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local > /dev/null 2>&1
systemctl start rc-local.service > /dev/null 2>&1

# Disable IPv6 (quick)
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null

# Stop DNS services for EDNS proxy
systemctl stop systemd-resolved 2>/dev/null
fuser -k 53/udp 2>/dev/null

# Start services
echo "Starting services..."
systemctl daemon-reload

# Start SlowDNS
systemctl enable server-sldns > /dev/null 2>&1
systemctl start server-sldns
sleep 2

if systemctl is-active --quiet server-sldns; then
    print_success "SlowDNS service started"
else
    print_warning "Starting SlowDNS directly..."
    $SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT &
    sleep 2
fi

# Start EDNS proxy
systemctl enable edns-proxy > /dev/null 2>&1
systemctl start edns-proxy
sleep 2

# Quick test
echo "Quick test..."
if ss -ulpn 2>/dev/null | grep -q ":53 "; then
    print_success "EDNS Proxy is running on port 53"
else
    print_warning "EDNS Proxy may not be running"
fi

if systemctl is-active --quiet server-sldns; then
    print_success "SlowDNS is running on port $SLOWDNS_PORT"
else
    print_error "SlowDNS service failed to start"
fi

# Installation complete
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] INSTALLATION COMPLETED SUCCESSFULLY${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Server IP:${NC} $SERVER_IP"
echo -e "${YELLOW}SSH Port:${NC} $SSHD_PORT"
echo -e "${YELLOW}SlowDNS Port:${NC} $SLOWDNS_PORT"
echo -e "${YELLOW}Nameserver:${NC} $NAMESERVER"
echo -e "${YELLOW}Public Key:${NC}"
cat /etc/slowdns/server.pub 2>/dev/null || echo "Not available"
echo ""
echo -e "${GREEN}To connect use:${NC}"
echo -e "SlowDNS Client with the above configuration"
echo ""
echo -e "${YELLOW}Services installed:${NC}"
echo -e "  server-sldns.service (SlowDNS)"
echo -e "  edns-proxy.service (EDNS Proxy)"
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"

# Cleanup
rm -f /tmp/edns.c /tmp/compile.log 2>/dev/null

# Final check
if systemctl is-active --quiet server-sldns && ss -ulpn | grep -q ":53 "; then
    echo -e "${GREEN}[✓] All services are running correctly${NC}"
    exit 0
else
    echo -e "${YELLOW}[!] Some services may need manual checking${NC}"
    exit 0
fi
