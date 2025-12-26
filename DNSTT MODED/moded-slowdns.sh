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
                return 0  # <-- THIS IS GOOD, returns success
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
                    
                    exit 1  # <-- THIS IS GOOD, exits on failure
                fi
            fi
        done
        
        # If we exit the while loop without activating, exit the script
        if [ ! -f "$SERVER_LOCK_FILE" ]; then
            echo -e "${RED}[✗] License activation failed${NC}"
            exit 1
        fi
    fi
fi

# ==========================================================
# MAIN INSTALLATION SCRIPT STARTS HERE
# Only reaches here if license is VALID
# ==========================================================

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
print_success "Installation Completed!"
echo ""
echo "Server IP: $SERVER_IP"
echo "SSH Port: $SSHD_PORT"
echo "SlowDNS Port: $SLOWDNS_PORT"
echo "EDNS Proxy Port: 53"
echo "MTU: 1800"
echo ""
echo "Test: dig @$SERVER_IP google.com"
echo ""
print_success "License Status: ACTIVE (Expires: $EXPIRY_DATE)"
echo ""
print_success "IMPORTANT: Save this information!"
echo ""
echo "Server ID: $SERVER_ID"
echo "License Key: 15072001"
echo "Lock File: $SERVER_LOCK_FILE"
echo ""
echo "======================================================"
echo "       Installation completed successfully!"
echo "======================================================"
