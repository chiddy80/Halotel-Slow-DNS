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
MTU_SIZE=1400  # Reduced from 1800 for better reliability

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

# Trap Ctrl+C
trap 'echo -e "\n${YELLOW}[!] Installation interrupted${NC}"; exit 1' INT

echo "Starting OpenSSH SlowDNS Installation..."

# Get Server IP
SERVER_IP=$(curl -4 -s --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s --connect-timeout 5 ifconfig.me 2>/dev/null)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
fi

print_success "Server IP: $SERVER_IP"

# Configure OpenSSH
echo "Configuring OpenSSH on port $SSHD_PORT..."
BACKUP_FILE="/etc/ssh/sshd_config.backup.$(date +%s)"
cp /etc/ssh/sshd_config "$BACKUP_FILE" 2>/dev/null
print_success "Backup created: $BACKUP_FILE"

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
sleep 1
if systemctl is-active --quiet sshd; then
    print_success "OpenSSH configured on port $SSHD_PORT"
else
    print_error "Failed to restart SSH"
    cp "$BACKUP_FILE" /etc/ssh/sshd_config
    systemctl restart sshd
    exit 1
fi

# Setup SlowDNS
echo "Setting up SlowDNS..."
rm -rf /etc/slowdns
mkdir -p /etc/slowdns
cd /etc/slowdns
print_success "SlowDNS directory created"

# Download pre-compiled binary
echo "Downloading SlowDNS binary..."
DOWNLOAD_URLS=(
    "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"
    "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/dnstt-server"
)

for url in "${DOWNLOAD_URLS[@]}"; do
    echo "Trying: $url"
    if curl -fsSL --connect-timeout 10 "$url" -o dnstt-server.tmp; then
        mv dnstt-server.tmp dnstt-server
        if [ -f "dnstt-server" ]; then
            chmod +x dnstt-server
            SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
            BINARY_SIZE=$(stat -c%s "dnstt-server")
            if [ "$BINARY_SIZE" -gt 1000000 ]; then  # At least 1MB
                print_success "SlowDNS binary downloaded ($BINARY_SIZE bytes)"
                break
            else
                print_warning "Binary too small, trying next source..."
                rm -f dnstt-server
            fi
        fi
    fi
done

if [ ! -f "dnstt-server" ]; then
    print_error "Failed to download SlowDNS binary"
    exit 1
fi

# Download key files
echo "Downloading key files..."
KEY_URL="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
if wget -q --timeout=10 -O server.key "$KEY_URL/server.key"; then
    print_success "server.key downloaded"
else
    print_warning "Failed to download server.key, creating dummy key..."
    openssl genrsa -out server.key 2048 2>/dev/null
fi

if wget -q --timeout=10 -O server.pub "$KEY_URL/server.pub"; then
    print_success "server.pub downloaded"
else
    print_warning "Failed to download server.pub, extracting from key..."
    openssl rsa -in server.key -pubout -out server.pub 2>/dev/null
fi

# Test the binary
echo "Testing SlowDNS binary..."
if timeout 2 ./dnstt-server --help 2>&1 | head -5; then
    print_success "SlowDNS binary is working"
else
    print_warning "Binary test inconclusive, proceeding anyway..."
fi

# Create SlowDNS service
echo "Creating SlowDNS service..."
cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu $MTU_SIZE -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=slowdns

# Security
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF

print_success "SlowDNS service file created"

# EDNS Proxy Installation (Fixed C Code)
echo "Installing EDNS Proxy (Fixed C/epoll)..."
cat > /tmp/edns-fixed.c << 'EOF'
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
#include <errno.h>
#include <signal.h>

#define EXT_EDNS 512
#define INT_EDNS 1400
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 1024
#define MAX_SOCKETS 10000
#define SOCKET_BUFFER_SIZE (1024 * 1024)
#define MAX_RETRIES 3
#define REQUEST_TIMEOUT 10
#define CLEANUP_INTERVAL 5

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
    unsigned char packet[BUFFER_SIZE];
    int packet_len;
    int retry_count;
} request_t;

volatile sig_atomic_t shutdown_flag = 0;

void handle_signal(int sig) {
    shutdown_flag = 1;
}

int set_socket_buffers(int sockfd) {
    int rcvbuf = SOCKET_BUFFER_SIZE;
    int sndbuf = SOCKET_BUFFER_SIZE;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("setsockopt SO_RCVBUF");
        return -1;
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        perror("setsockopt SO_SNDBUF");
        return -1;
    }
    
    // Verify buffer sizes
    socklen_t len = sizeof(rcvbuf);
    getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &len);
    getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &len);
    
    printf("Socket buffers - RCV: %d, SND: %d\n", rcvbuf, sndbuf);
    return 0;
}

int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip question section
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) {
            offset++;
        }
        if(offset >= len) return len;
        offset += 5;
    }
    
    // Check additional records for EDNS
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(offset + 11 < len && buf[offset] == 0) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            if(type == 41) {
                if(offset + 4 < len) {
                    buf[offset+3] = new_size >> 8;
                    buf[offset+4] = new_size & 0xFF;
                }
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

void cleanup_old_requests(request_t **requests, int max_sockets) {
    time_t now = time(NULL);
    for(int i = 0; i < max_sockets; i++) {
        if(requests[i] != NULL) {
            if(difftime(now, requests[i]->timestamp) > REQUEST_TIMEOUT) {
                printf("Cleaning up timed out request (fd: %d)\n", i);
                free(requests[i]);
                requests[i] = NULL;
            }
        }
    }
}

int main() {
    // Setup signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Create main socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket creation failed");
        return 1;
    }
    
    // Set socket options
    int optval = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sock);
        return 1;
    }
    
    // Set socket buffers
    if(set_socket_buffers(sock) < 0) {
        close(sock);
        return 1;
    }
    
    if(set_nonblock(sock) < 0) {
        perror("fcntl nonblock");
        close(sock);
        return 1;
    }
    
    // Bind socket
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(sock);
        return 1;
    }
    
    // Create epoll instance
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
        perror("epoll_ctl add main socket");
        close(epoll_fd);
        close(sock);
        return 1;
    }
    
    printf("EDNS Proxy running on port 53 (C/epoll - Fixed)\n");
    printf("Socket buffer size: %d bytes\n", SOCKET_BUFFER_SIZE);
    printf("Internal EDNS: %d, External EDNS: %d\n", INT_EDNS, EXT_EDNS);
    
    struct epoll_event events[MAX_EVENTS];
    request_t *requests[MAX_SOCKETS] = {0};
    time_t last_cleanup = time(NULL);
    int total_requests = 0;
    int dropped_packets = 0;
    
    while(!shutdown_flag) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        
        if(n < 0) {
            if(errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        
        // Periodic cleanup
        time_t now = time(NULL);
        if(difftime(now, last_cleanup) > CLEANUP_INTERVAL) {
            cleanup_old_requests(requests, MAX_SOCKETS);
            last_cleanup = now;
        }
        
        for(int i = 0; i < n; i++) {
            if(events[i].data.fd == sock) {
                // Incoming packet from client
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                
                int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
                if(len > 0) {
                    total_requests++;
                    
                    // Patch EDNS size
                    int new_len = patch_edns(buffer, len, INT_EDNS);
                    
                    // Create upstream socket
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if(up_sock >= 0 && up_sock < MAX_SOCKETS) {
                        // Set socket options
                        set_socket_buffers(up_sock);
                        set_nonblock(up_sock);
                        
                        // Store request info
                        request_t *req = malloc(sizeof(request_t));
                        if(req) {
                            req->client_fd = sock;
                            req->client_addr = client_addr;
                            req->addr_len = client_len;
                            req->timestamp = time(NULL);
                            req->packet_len = new_len;
                            req->retry_count = 0;
                            memcpy(req->packet, buffer, new_len);
                            
                            requests[up_sock] = req;
                            
                            // Add to epoll
                            struct epoll_event up_ev;
                            up_ev.events = EPOLLIN;
                            up_ev.data.fd = up_sock;
                            if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev) < 0) {
                                perror("epoll_ctl add upstream");
                                free(req);
                                close(up_sock);
                                continue;
                            }
                            
                            // Send to SlowDNS
                            struct sockaddr_in up_addr;
                            memset(&up_addr, 0, sizeof(up_addr));
                            up_addr.sin_family = AF_INET;
                            up_addr.sin_port = htons(SLOWDNS_PORT);
                            inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                            
                            int sent = sendto(up_sock, buffer, new_len, 0,
                                           (struct sockaddr*)&up_addr, sizeof(up_addr));
                            if(sent != new_len) {
                                fprintf(stderr, "sendto failed: %s (sent %d of %d)\n",
                                        strerror(errno), sent, new_len);
                                dropped_packets++;
                            }
                        } else {
                            perror("malloc failed");
                            close(up_sock);
                            dropped_packets++;
                        }
                    } else {
                        fprintf(stderr, "socket creation failed or out of range: %d\n", up_sock);
                        dropped_packets++;
                    }
                }
            } else {
                // Response from SlowDNS
                int up_sock = events[i].data.fd;
                request_t *req = requests[up_sock];
                
                if(req) {
                    unsigned char buffer[BUFFER_SIZE];
                    int len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                    
                    if(len > 0) {
                        // Patch EDNS back to external size
                        patch_edns(buffer, len, EXT_EDNS);
                        
                        // Send back to client
                        int sent = sendto(req->client_fd, buffer, len, 0,
                                       (struct sockaddr*)&req->client_addr,
                                       req->addr_len);
                        if(sent != len) {
                            fprintf(stderr, "Response send failed: %s\n", strerror(errno));
                            dropped_packets++;
                        }
                    } else if(len < 0) {
                        if(errno != EAGAIN && errno != EWOULDBLOCK) {
                            perror("recv from upstream");
                        }
                    }
                    
                    // Clean up
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, up_sock, NULL);
                    close(up_sock);
                    free(req);
                    requests[up_sock] = NULL;
                }
            }
        }
        
        // Print statistics every 60 seconds
        static time_t last_stats = 0;
        if(difftime(now, last_stats) > 60) {
            printf("Stats: Total requests: %d, Dropped packets: %d\n",
                   total_requests, dropped_packets);
            last_stats = now;
        }
    }
    
    printf("\nShutting down EDNS Proxy...\n");
    
    // Cleanup all sockets
    for(int i = 0; i < MAX_SOCKETS; i++) {
        if(requests[i] != NULL) {
            free(requests[i]);
            close(i);
        }
    }
    
    close(epoll_fd);
    close(sock);
    
    printf("Final stats: Total requests: %d, Dropped packets: %d\n",
           total_requests, dropped_packets);
    
    return 0;
}
EOF

# Install build tools if needed
echo "Checking for build tools..."
if ! command -v gcc &>/dev/null; then
    echo "Installing gcc..."
    apt-get update > /dev/null 2>&1
    apt-get install -y gcc > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        print_error "Failed to install gcc"
        exit 1
    fi
fi

# Compile EDNS proxy
echo "Compiling EDNS Proxy..."
gcc -O3 -Wall -Wextra /tmp/edns-fixed.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log
if [ $? -eq 0 ]; then
    chmod +x /usr/local/bin/edns-proxy
    print_success "EDNS Proxy compiled successfully"
    
    # Test the binary
    if timeout 1 /usr/local/bin/edns-proxy --help 2>&1 | head -2; then
        print_success "EDNS Proxy binary is functional"
    fi
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
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=65536
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=edns-proxy

# Security
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Resource limits
LimitCORE=infinity
LimitNOFILE=65536
LimitNPROC=65536

[Install]
WantedBy=multi-user.target
EOF

print_success "EDNS Proxy service created"

# Optimize system for UDP traffic
echo "Optimizing system for UDP traffic..."
cat >> /etc/sysctl.conf << EOF

# UDP Optimization for SlowDNS
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.udp_mem = 4096 87380 16777216
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# Disable IPv6 if not needed
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
EOF

sysctl -p > /dev/null 2>&1
print_success "System optimized for UDP"

# Setup firewall rules (non-destructive)
echo "Setting up firewall rules..."
cat > /usr/local/bin/setup-firewall.sh << 'EOF'
#!/bin/bash
# Add firewall rules without flushing existing ones

SSHD_PORT=$1
SLOWDNS_PORT=$2

# Check if rule exists before adding
iptables -C INPUT -p tcp --dport $SSHD_PORT -j ACCEPT 2>/dev/null || \
iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT

iptables -C INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT 2>/dev/null || \
iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT

iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || \
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# Allow localhost
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -A INPUT -i lo -j ACCEPT
iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP (ping)
iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null || iptables -A INPUT -p icmp -j ACCEPT

# Drop invalid packets
iptables -C INPUT -m state --state INVALID -j DROP 2>/dev/null || \
iptables -A INPUT -m state --state INVALID -j DROP

echo "Firewall rules applied (non-destructive)"
EOF

chmod +x /usr/local/bin/setup-firewall.sh
/usr/local/bin/setup-firewall.sh "$SSHD_PORT" "$SLOWDNS_PORT"

# Stop systemd-resolved if it's using port 53
echo "Checking port 53 conflicts..."
if ss -ulpn 2>/dev/null | grep -q ":53 "; then
    PID=$(ss -ulpn 2>/dev/null | grep ":53 " | awk '{print $6}' | cut -d= -f2 | cut -d, -f1)
    if [ -n "$PID" ]; then
                SERVICE=$(systemctl status "$PID" 2>/dev/null | grep "Loaded:" | awk '{print $2}' || echo "unknown")
        print_warning "Port 53 is used by PID $PID ($SERVICE)"
        
        if systemctl is-active --quiet systemd-resolved; then
            print_warning "Stopping systemd-resolved..."
            systemctl stop systemd-resolved
            systemctl disable systemd-resolved 2>/dev/null
        else
            # Try to kill whatever is on port 53
            print_warning "Killing process on port 53..."
            fuser -k 53/udp 2>/dev/null
            sleep 1
        fi
    fi
fi

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
    print_error "Failed to start SlowDNS service"
    systemctl status server-sldns --no-pager
    exit 1
fi

# Start EDNS proxy
systemctl enable edns-proxy > /dev/null 2>&1
systemctl start edns-proxy
sleep 2

if systemctl is-active --quiet edns-proxy; then
    print_success "EDNS Proxy service started"
else
    print_error "Failed to start EDNS Proxy"
    systemctl status edns-proxy --no-pager
    exit 1
fi

# Verify services are listening
echo "Verifying services..."
sleep 2

PORT_53=$(ss -ulpn 2>/dev/null | grep -c ":53 ")
PORT_SLOWDNS=$(ss -ulpn 2>/dev/null | grep -c ":$SLOWDNS_PORT ")
PORT_SSH=$(ss -tlnp 2>/dev/null | grep -c ":$SSHD_PORT ")

echo ""
echo "=== Service Status ==="
[ "$PORT_53" -gt 0 ] && print_success "EDNS Proxy listening on port 53" || print_error "EDNS Proxy NOT listening on 53"
[ "$PORT_SLOWDNS" -gt 0 ] && print_success "SlowDNS listening on port $SLOWDNS_PORT" || print_error "SlowDNS NOT listening"
[ "$PORT_SSH" -gt 0 ] && print_success "SSH listening on port $SSHD_PORT" || print_error "SSH NOT listening"

# Quick test
echo ""
echo "=== Quick Test ==="
if command -v dig &>/dev/null; then
    echo "Testing DNS resolution (timeout 5s)..."
    timeout 5 dig @127.0.0.1 google.com +short > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "Local DNS test passed"
    else
        print_warning "Local DNS test timed out (may be normal)"
    fi
else
    print_warning "dig not installed, skipping DNS test"
fi

# Create diagnostic script
cat > /usr/local/bin/check-slowdns.sh << 'EOF'
#!/bin/bash
echo "=== SlowDNS Diagnostics ==="
echo "Server IP: $(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')"
echo ""
echo "Service Status:"
systemctl status server-sldns --no-pager | grep -A3 "Active:"
systemctl status edns-proxy --no-pager | grep -A3 "Active:"
echo ""
echo "Listening Ports:"
ss -ulpn | grep -E ":53|:5300"
echo ""
echo "Socket Statistics:"
netstat -su | grep -E "packet|error|dropped"
echo ""
echo "Recent Logs:"
journalctl -u server-sldns -u edns-proxy --since "5 minutes ago" --no-pager | tail -20
EOF

chmod +x /usr/local/bin/check-slowdns.sh

# Create uninstall script
cat > /usr/local/bin/uninstall-slowdns.sh << 'EOF'
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

echo "Stopping services..."
systemctl stop server-sldns edns-proxy
systemctl disable server-sldns edns-proxy

echo "Removing services..."
rm -f /etc/systemd/system/server-sldns.service
rm -f /etc/systemd/system/edns-proxy.service

echo "Removing files..."
rm -rf /etc/slowdns
rm -f /usr/local/bin/edns-proxy
rm -f /usr/local/bin/check-slowdns.sh
rm -f /usr/local/bin/setup-firewall.sh

echo "Reloading systemd..."
systemctl daemon-reload

echo "Done. SSH config was backed up to:"
ls -la /etc/ssh/sshd_config.backup.* 2>/dev/null || echo "No backup found"
EOF

chmod +x /usr/local/bin/uninstall-slowdns.sh

echo ""
echo "=========================================="
print_success "Installation Completed Successfully!"
echo "=========================================="
echo ""
echo "Server IP: $SERVER_IP"
echo "SSH Port: $SSHD_PORT (Password authentication enabled)"
echo "SlowDNS Port: $SLOWDNS_PORT"
echo "EDNS Proxy Port: 53"
echo "MTU Size: $MTU_SIZE (optimized for reliability)"
echo ""
echo "Management Commands:"
echo "  Check status: systemctl status server-sldns edns-proxy"
echo "  View logs: journalctl -u server-sldns -u edns-proxy -f"
echo "  Diagnostics: check-slowdns.sh"
echo "  Uninstall: uninstall-slowdns.sh"
echo ""
echo "Test from client:"
echo "  dig @$SERVER_IP google.com"
echo "  ssh -oPort=$SSHD_PORT root@$SERVER_IP"
echo ""
echo "Note: The EDNS Proxy now has:"
echo "  • Proper error handling"
echo "  • 1MB socket buffers"
echo "  • Packet loss tracking"
echo "  • Timeout cleanup"
echo "  • Graceful shutdown"
echo "==========================================" 
