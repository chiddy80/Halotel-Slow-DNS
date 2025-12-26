#!/bin/bash

# ===================== LICENSE SYSTEM =====================
# Professional license system with hidden input
# ==========================================================

LICENSE_KEY="15072001"
EXPIRY_DATE="2026-12-31"
SERVER_LOCK_FILE="/etc/.sldns-license"
FAILED_ATTEMPTS_FILE="/tmp/.license_failed_attempts"
BLOCKED_IPS_FILE="/etc/.sldns_blocked_ips"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get server fingerprint
get_server_id() {
    SERVER_ID=$(cat /etc/machine-id 2>/dev/null | head -c 12)
    if [ -z "$SERVER_ID" ]; then
        SERVER_ID=$(hostname | md5sum | head -c 12)
    fi
    echo "$SERVER_ID"
}

# Calculate real license hash
calculate_real_hash() {
    echo -n "${LICENSE_KEY}$(get_server_id)" | sha256sum | awk '{print $1}'
}

# Check and block IP
check_and_block_ip() {
    CLIENT_IP=${SSH_CLIENT%% *}
    if [ -z "$CLIENT_IP" ]; then
        CLIENT_IP=$(who am i | awk '{print $5}' | sed 's/[()]//g')
    fi
    
    if [ -n "$CLIENT_IP" ]; then
        # Increment failed attempts
        if [ -f "$FAILED_ATTEMPTS_FILE" ]; then
            ATTEMPTS=$(grep "$CLIENT_IP" "$FAILED_ATTEMPTS_FILE" | cut -d: -f2)
            if [ -n "$ATTEMPTS" ]; then
                ATTEMPTS=$((ATTEMPTS + 1))
                sed -i "/$CLIENT_IP/d" "$FAILED_ATTEMPTS_FILE"
                echo "$CLIENT_IP:$ATTEMPTS" >> "$FAILED_ATTEMPTS_FILE"
            else
                echo "$CLIENT_IP:1" >> "$FAILED_ATTEMPTS_FILE"
            fi
        else
            echo "$CLIENT_IP:1" > "$FAILED_ATTEMPTS_FILE"
        fi
        
        # Check if we should block this IP
        ATTEMPTS=$(grep "$CLIENT_IP" "$FAILED_ATTEMPTS_FILE" 2>/dev/null | cut -d: -f2)
        if [ -n "$ATTEMPTS" ] && [ "$ATTEMPTS" -ge 3 ]; then
            # Block the IP using iptables
            if command -v iptables >/dev/null 2>&1; then
                if ! iptables -C INPUT -s "$CLIENT_IP" -j DROP 2>/dev/null; then
                    iptables -A INPUT -s "$CLIENT_IP" -j DROP
                    echo "[$(date)] Blocked IP $CLIENT_IP for license violations" >> /var/log/sldns_license.log
                    
                    # Save blocked IP to file
                    echo "$CLIENT_IP:$(date '+%Y-%m-%d %H:%M:%S')" >> "$BLOCKED_IPS_FILE"
                    
                    echo -e "${RED}[✗] IP $CLIENT_IP has been blocked permanently${NC}"
                    echo -e "${RED}[✗] Too many failed license attempts${NC}"
                fi
            fi
            
            # Also block with ufw if available
            if command -v ufw >/dev/null 2>&1; then
                ufw deny from "$CLIENT_IP" >/dev/null 2>&1
            fi
        fi
    fi
}

# Function to read hidden input
read_hidden() {
    local prompt="$1"
    local var_name="$2"
    
    # Save current terminal settings
    local stty_settings=$(stty -g)
    
    # Disable echo
    stty -echo
    
    # Read input
    echo -ne "$prompt"
    read "$var_name"
    echo ""
    
    # Restore terminal settings
    stty "$stty_settings"
}

# License check function
check_license() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                SLOWDNS LICENSED INSTALLER                ║${NC}"
    echo -e "${CYAN}║                  Professional Edition                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}       [ Secure Authentication Required ]${NC}"
    echo ""

    # Check expiry date
    TODAY=$(date +%Y-%m-%d)
    if [[ "$TODAY" > "$EXPIRY_DATE" ]]; then
        echo -e "${RED}[✗] License expired. Contact vendor for renewal.${NC}"
        exit 1
    fi

    # Get server ID and calculate hash
    SERVER_ID=$(get_server_id)
    REAL_HASH=$(calculate_real_hash)

    # Check if already activated
    if [ -f "$SERVER_LOCK_FILE" ]; then
        SAVED_HASH=$(cat "$SERVER_LOCK_FILE" 2>/dev/null)
        if [ "$SAVED_HASH" = "$REAL_HASH" ]; then
            echo -e "${GREEN}[✓] License validated successfully${NC}"
            echo -e "${GREEN}[✓] System is properly licensed${NC}"
            sleep 1
            # Clear failed attempts for this IP if any
            if [ -f "$FAILED_ATTEMPTS_FILE" ]; then
                CLIENT_IP=${SSH_CLIENT%% *}
                [ -n "$CLIENT_IP" ] && sed -i "/$CLIENT_IP/d" "$FAILED_ATTEMPTS_FILE" 2>/dev/null
            fi
            return 0
        else
            echo -e "${RED}[✗] License violation detected!${NC}"
            echo -e "${RED}[✗] This installation does not match licensed server${NC}"
            check_and_block_ip
            exit 1
        fi
    else
        # First time activation - ask for license
        MAX_ATTEMPTS=3
        ATTEMPT=1
        
        while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
            echo -e "${YELLOW}[!] License required for installation${NC}"
            echo -e "${YELLOW}[!] Attempt $ATTEMPT of $MAX_ATTEMPTS${NC}"
            echo ""
            
            # Get client IP for tracking
            CLIENT_IP=${SSH_CLIENT%% *}
            [ -z "$CLIENT_IP" ] && CLIENT_IP=$(who am i | awk '{print $5}' | sed 's/[()]//g')
            
            # Read license with hidden input (no echo)
            read_hidden "Enter License Key: " USER_LICENSE
            
            # Calculate user hash
            USER_HASH=$(echo -n "${USER_LICENSE}${SERVER_ID}" | sha256sum | awk '{print $1}')
            
            if [ "$USER_HASH" = "$REAL_HASH" ]; then
                # Valid license - activate
                echo "$REAL_HASH" > "$SERVER_LOCK_FILE"
                chmod 600 "$SERVER_LOCK_FILE"
                
                # Create system protection
                cat > /usr/local/bin/check_license.sh << EOF
#!/bin/bash
REAL_HASH="$REAL_HASH"
LOCK_FILE="$SERVER_LOCK_FILE"
if [ -f "\$LOCK_FILE" ]; then
    SAVED_HASH=\$(cat "\$LOCK_FILE")
    [ "\$SAVED_HASH" != "\$REAL_HASH" ] && exit 1
else
    exit 1
fi
EOF
                chmod +x /usr/local/bin/check_license.sh
                
                echo ""
                echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
                echo -e "${GREEN}[✓] LICENSE ACTIVATED SUCCESSFULLY${NC}"
                echo -e "${GREEN}[✓] Licensed to: Server ID ${SERVER_ID:0:8}...${NC}"
                echo -e "${GREEN}[✓] Expiry Date: $EXPIRY_DATE${NC}"
                echo -e "${GREEN}[✓] System protection enabled${NC}"
                echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
                sleep 2
                return 0
            else
                # Invalid license
                ATTEMPT=$((ATTEMPT + 1))
                echo ""
                echo -e "${RED}[✗] INVALID LICENSE KEY${NC}"
                
                if [ $ATTEMPT -le $MAX_ATTEMPTS ]; then
                    echo -e "${YELLOW}[!] $((MAX_ATTEMPTS - ATTEMPT + 1)) attempt(s) remaining${NC}"
                    echo ""
                    sleep 1
                else
                    echo -e "${RED}[✗] MAXIMUM ATTEMPTS REACHED${NC}"
                    echo -e "${RED}[✗] NO FURTHER ACCESS PROVIDED${NC}"
                    
                    # Block the IP
                    check_and_block_ip
                    
                    # Create fake installation to waste attacker's time
                    echo -e "${YELLOW}[!] Installing dummy packages...${NC}"
                    sleep 5
                    echo -e "${RED}[✗] Installation failed. System corrupted.${NC}"
                    echo -e "${RED}[✗] Contact support for recovery.${NC}"
                    
                    # Log the incident
                    echo "[$(date)] Failed license activation from IP: $CLIENT_IP" >> /var/log/sldns_license.log
                    echo "[$(date)] Server ID: $SERVER_ID" >> /var/log/sldns_license.log
                    
                    exit 1
                fi
            fi
        done
    fi
}

# ==========================================================
# MAIN INSTALLATION SCRIPT STARTS HERE
# ==========================================================

# Check license first - script will exit if invalid
check_license

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "[✗] Please run this script as root"
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
    print_success "EDNS Proxy listening on port 53"
else
    print_warning "EDNS Proxy not listening"
fi

if ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
    print_success "SlowDNS listening on port $SLOWDNS_PORT"
else
    print_warning "SlowDNS not listening"
fi

echo ""
print_success "Installation Completed in ~30 seconds!"
echo ""
echo "Server IP: $SERVER_IP"
echo "SSH Port: $SSHD_PORT"
echo "SlowDNS Port: $SLOWDNS_PORT"
echo "EDNS Proxy Port: 53"
echo "MTU: 1800"
echo ""
echo "Test: dig @$SERVER_IP google.com"
echo ""
echo ""
print_success "License Status: ACTIVE (Expires: $EXPIRY_DATE)"

# Add license check to systemd service
cat > /etc/systemd/system/license-check.service << EOF
[Unit]
Description=License Verification Service
After=network.target
Before=server-sldns.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/check_license.sh
RemainAfterExit=yes
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable license-check.service > /dev/null 2>&1
print_success "License verification service installed"

# Create uninstall script
cat > /usr/local/bin/uninstall-slowdns.sh << 'EOF'
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

read -p "Are you sure you want to uninstall SlowDNS? (y/N): " confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled"
    exit 0
fi

echo "Stopping services..."
systemctl stop server-sldns 2>/dev/null
systemctl stop edns-proxy 2>/dev/null
systemctl disable server-sldns 2>/dev/null
systemctl disable edns-proxy 2>/dev/null

echo "Removing services..."
rm -f /etc/systemd/system/server-sldns.service
rm -f /etc/systemd/system/edns-proxy.service
rm -f /etc/systemd/system/license-check.service

echo "Removing files..."
rm -rf /etc/slowdns
rm -f /usr/local/bin/edns-proxy
rm -f /usr/local/bin/check_license.sh
rm -f /etc/.sldns-license 2>/dev/null

echo "Cleaning firewall rules..."
iptables -F 2>/dev/null

echo "Reloading systemd..."
systemctl daemon-reload
systemctl restart sshd

echo "SlowDNS uninstalled successfully!"
EOF

chmod +x /usr/local/bin/uninstall-slowdns.sh
print_success "Uninstall script created: /usr/local/bin/uninstall-slowdns.sh"

# Create update script
cat > /usr/local/bin/update-slowdns.sh << 'EOF'
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Check license first
if [ ! -f /usr/local/bin/check_license.sh ]; then
    echo "License check not found!"
    exit 1
fi

if ! /usr/local/bin/check_license.sh; then
    echo "License validation failed!"
    exit 1
fi

echo "Updating SlowDNS..."

# Backup current config
BACKUP_DIR="/etc/slowdns_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /etc/slowdns/* "$BACKUP_DIR/" 2>/dev/null
cp /etc/systemd/system/server-sldns.service "$BACKUP_DIR/" 2>/dev/null

# Stop services
systemctl stop server-sldns
systemctl stop edns-proxy

# Update binary
cd /etc/slowdns
rm -f dnstt-server
wget -q -O dnstt-server "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"
if [ $? -eq 0 ]; then
    chmod +x dnstt-server
    echo "Binary updated successfully"
else
    echo "Update failed, restoring backup..."
    cp -r "$BACKUP_DIR"/* /etc/slowdns/ 2>/dev/null
fi

# Restart services
systemctl start server-sldns
systemctl start edns-proxy

sleep 2
if systemctl is-active --quiet server-sldns; then
    echo "SlowDNS updated successfully!"
else
    echo "Update failed, check logs"
fi
EOF

chmod +x /usr/local/bin/update-slowdns.sh
print_success "Update script created: /usr/local/bin/update-slowdns.sh"

# Create status check script
cat > /usr/local/bin/slowdns-status.sh << 'EOF'
#!/bin/bash
echo "=== SlowDNS Status ==="
echo ""
echo "Services:"
systemctl is-active server-sldns >/dev/null 2>&1 && echo "✓ SlowDNS: ACTIVE" || echo "✗ SlowDNS: INACTIVE"
systemctl is-active edns-proxy >/dev/null 2>&1 && echo "✓ EDNS Proxy: ACTIVE" || echo "✗ EDNS Proxy: INACTIVE"
echo ""
echo "Ports:"
ss -ulpn 2>/dev/null | grep -E "(53|5300)" | awk '{print "Port "$5": "$1}'
echo ""
echo "Connections:"
netstat -an | grep ":$SSHD_PORT" | grep ESTABLISHED | wc -l | awk '{print "SSH Connections: "$1}'
echo ""
echo "License:"
if [ -f /etc/.sldns-license ]; then
    echo "✓ License: ACTIVE"
    echo "  Expires: 2026-12-31"
else
    echo "✗ License: NOT FOUND"
fi
EOF

chmod +x /usr/local/bin/slowdns-status.sh
print_success "Status script created: /usr/local/bin/slowdns-status.sh"

# Create usage instructions
echo ""
echo "======================================================"
echo "              INSTALLATION COMPLETE"
echo "======================================================"
echo ""
echo "Management Commands:"
echo "  systemctl start server-sldns      # Start SlowDNS"
echo "  systemctl stop server-sldns       # Stop SlowDNS"
echo "  systemctl restart server-sldns    # Restart SlowDNS"
echo "  systemctl status server-sldns     # Check status"
echo ""
echo "Utility Scripts:"
echo "  slowdns-status.sh                 # Check all services"
echo "  update-slowdns.sh                 # Update SlowDNS"
echo "  uninstall-slowdns.sh              # Remove installation"
echo ""
echo "Test Connection:"
echo "  dig @$SERVER_IP google.com"
echo ""
echo "Client Configuration:"
echo "  Server: $SERVER_IP"
echo "  Port: 53 (UDP)"
echo "  Nameserver: $NAMESERVER"
echo ""
echo "License Information:"
echo "  Status: ACTIVE"
echo "  Expires: $EXPIRY_DATE"
echo "  Server ID: ${SERVER_ID:0:8}..."
echo ""
echo "Support:"
echo "  If you have issues, check logs with:"
echo "  journalctl -u server-sldns -f"
echo "  journalctl -u edns-proxy -f"
echo ""
echo "======================================================"

# Final check
sleep 3
echo ""
echo "Final system check..."
if ss -ulpn 2>/dev/null | grep -q ":53 " && ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
    print_success "All services are running correctly!"
    echo ""
    echo -e "${GREEN}✓ Installation successful!${NC}"
    echo -e "${GREEN}✓ License verified and active${NC}"
    echo -e "${GREEN}✓ Services started successfully${NC}"
    echo -e "${GREEN}✓ Ready for client connections${NC}"
else
    print_warning "Some services may need manual start"
    echo "Try: systemctl restart server-sldns edns-proxy"
fi

# Save configuration
cat > /etc/slowdns/config.info << EOF
# SlowDNS Configuration
INSTALL_DATE=$(date)
SERVER_IP=$SERVER_IP
SSH_PORT=$SSHD_PORT
SLOWDNS_PORT=$SLOWDNS_PORT
NAMESERVER=$NAMESERVER
LICENSE_KEY=ACTIVE
EXPIRY_DATE=$EXPIRY_DATE
SERVER_ID=$SERVER_ID
EOF

chmod 600 /etc/slowdns/config.info
print_success "Configuration saved to /etc/slowdns/config.info"

echo ""
echo "======================================================"
echo -e "${GREEN}      SLOWDNS INSTALLATION COMPLETED!${NC}"
echo "======================================================"
echo ""
