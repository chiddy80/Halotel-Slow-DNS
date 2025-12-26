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

# Setup SlowDNS
echo "Setting up SlowDNS..."
rm -rf /etc/slowdns
mkdir -p /etc/slowdns
print_success "SlowDNS directory created"

# Download SlowDNS files using moded-slowdns.sh (NON-INTERACTIVE FIX)
echo "Downloading and installing SlowDNS via moded-slowdns.sh..."
curl -fsSL "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/moded-slowdns.sh" -o /tmp/moded-slowdns.sh && chmod +x /tmp/moded-slowdns.sh

# Run moded-slowdns.sh NON-INTERACTIVELY - this prevents the loop!
cd /etc/slowdns
echo "$NAMESERVER" | /tmp/moded-slowdns.sh 2>&1 > /tmp/slowdns-install.log

# Check if the script ran successfully
if [ $? -eq 0 ]; then
    print_success "SlowDNS installation completed"
else
    print_warning "moded-slowdns.sh returned an error, checking for binary..."
fi

# Find the SlowDNS binary (check common locations)
echo "Locating SlowDNS binary..."
SLOWDNS_BINARY=""

# Check common locations
for binary in dnstt-server dnstt-server-go dnstt-server-linux dnstt-server-amd64; do
    if [ -f "/usr/local/bin/$binary" ]; then
        SLOWDNS_BINARY="/usr/local/bin/$binary"
        break
    elif [ -f "/usr/bin/$binary" ]; then
        SLOWDNS_BINARY="/usr/bin/$binary"
        break
    elif [ -f "/bin/$binary" ]; then
        SLOWDNS_BINARY="/bin/$binary"
        break
    elif [ -f "/etc/slowdns/$binary" ]; then
        SLOWDNS_BINARY="/etc/slowdns/$binary"
        break
    fi
done

# If not found in common locations, search the system
if [ -z "$SLOWDNS_BINARY" ]; then
    SLOWDNS_BINARY=$(find / -type f -name "dnstt-server*" -executable 2>/dev/null | head -1)
fi

if [ -n "$SLOWDNS_BINARY" ] && [ -f "$SLOWDNS_BINARY" ]; then
    print_success "SlowDNS binary found at: $SLOWDNS_BINARY"
    chmod +x "$SLOWDNS_BINARY"
else
    print_warning "SlowDNS binary not found, downloading directly..."
    # Fallback: download the binary directly
    curl -fsSL "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server" -o /etc/slowdns/dnstt-server
    if [ $? -eq 0 ]; then
        chmod +x /etc/slowdns/dnstt-server
        SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
        print_success "SlowDNS binary downloaded directly"
    else
        print_error "Failed to download SlowDNS binary!"
        exit 1
    fi
fi

# Download key files
echo "Downloading key files..."
wget -q -O /etc/slowdns/server.key "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key" && print_success "server.key downloaded"
wget -q -O /etc/slowdns/server.pub "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub" && print_success "server.pub downloaded"

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

# EDNS Proxy Installation (C/epoll) - FIXED VERSION
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

// Simple EDNS patching
int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    
    // Find OPT record (type 41) in additional section
    int offset = 12;
    
    // Skip questions
    int qdcount = (buf[4] << 8) | buf[5];
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        offset += 5; // null byte + qtype + qclass
    }
    
    // Find OPT (EDNS) record
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0) { // root label
            if(offset + 4 < len) {
                int type = (buf[offset+1] << 8) | buf[offset+2];
                if(type == 41) { // OPT record
                    buf[offset+3] = new_size >> 8;
                    buf[offset+4] = new_size & 0xFF;
                    return len;
                }
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
    // Create UDP socket for clients
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Set non-blocking
    if(set_nonblock(sock) < 0) {
        perror("fcntl");
        close(sock);
        return 1;
    }
    
    // Bind to port 53
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
    
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0) {
        perror("epoll_create1");
        close(sock);
        return 1;
    }
    
    // Add listener socket to epoll
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
    
    // Main event loop
    struct epoll_event events[MAX_EVENTS];
    request_t *requests[10000] = {0};
    
    while(1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        
        for(int i = 0; i < n; i++) {
            if(events[i].data.fd == sock) {
                // New client request
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                
                int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
                
                if(len > 0) {
                    // Patch EDNS for upstream
                    patch_edns(buffer, len, INT_EDNS);
                    
                    // Create upstream socket
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if(up_sock >= 0) {
                        set_nonblock(up_sock);
                        
                        // Store request context
                        request_t *req = malloc(sizeof(request_t));
                        if(req) {
                            req->client_fd = sock;
                            req->client_addr = client_addr;
                            req->addr_len = client_len;
                            req->timestamp = time(NULL);
                            requests[up_sock] = req;
                            
                            // Add upstream socket to epoll
                            struct epoll_event up_ev;
                            up_ev.events = EPOLLIN;
                            up_ev.data.fd = up_sock;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev);
                            
                            // Send to SlowDNS
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
                // Upstream response
                int up_sock = events[i].data.fd;
                request_t *req = requests[up_sock];
                
                if(req) {
                    unsigned char buffer[BUFFER_SIZE];
                    int len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                    
                    if(len > 0) {
                        // Patch EDNS for client
                        patch_edns(buffer, len, EXT_EDNS);
                        
                        // Send back to client
                        sendto(req->client_fd, buffer, len, 0,
                               (struct sockaddr*)&req->client_addr,
                               req->addr_len);
                    }
                    
                    // Cleanup
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, up_sock, NULL);
                    close(up_sock);
                    free(req);
                    requests[up_sock] = NULL;
                }
            }
        }
        
        // Cleanup old requests (every 30 seconds)
        static time_t last_cleanup = 0;
        time_t now = time(NULL);
        if(now - last_cleanup > 30) {
            for(int j = 0; j < 10000; j++) {
                if(requests[j] && (now - requests[j]->timestamp > 30)) {
                    close(j);
                    free(requests[j]);
                    requests[j] = NULL;
                }
            }
            last_cleanup = now;
        }
    }
}
EOF

# Install gcc if needed
if ! command -v gcc &>/dev/null; then
    apt update && apt install -y gcc
fi

# Compile EDNS proxy
gcc -O3 -Wall /tmp/edns.c -o /usr/local/bin/edns-proxy
if [ $? -eq 0 ]; then
    chmod +x /usr/local/bin/edns-proxy
    print_success "EDNS Proxy compiled successfully"
else
    print_error "EDNS Proxy compilation failed"
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

# Startup config with ALL iptables (add EDNS port)
echo "Setting up startup configuration..."
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
iptables -A INPUT -p tcp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -p tcp --dport $SSHD_PORT -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport $SSHD_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.core.rmem_max=134217728 > /dev/null 2>&1
sysctl -w net.core.wmem_max=134217728 > /dev/null 2>&1
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local > /dev/null 2>&1
systemctl start rc-local.service > /dev/null 2>&1
print_success "Startup configuration set"

# Disable IPv6
echo "Disabling IPv6..."
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1
print_success "IPv6 disabled"

# Stop DNS services for EDNS proxy
echo "Stopping systemd-resolved for EDNS proxy..."
systemctl stop systemd-resolved 2>/dev/null
pkill -9 systemd-resolved 2>/dev/null
fuser -k 53/udp 2>/dev/null

# Start SlowDNS service
echo "Starting SlowDNS service..."
pkill dnstt-server 2>/dev/null
systemctl daemon-reload
systemctl enable server-sldns > /dev/null 2>&1
systemctl start server-sldns
sleep 3

if systemctl is-active --quiet server-sldns; then
    print_success "SlowDNS service started"
    
    # Start EDNS proxy
    echo "Starting EDNS Proxy..."
    systemctl enable edns-proxy > /dev/null 2>&1
    systemctl start edns-proxy
    sleep 2
    
    if systemctl is-active --quiet edns-proxy; then
        print_success "EDNS Proxy started on port 53"
    else
        print_warning "EDNS Proxy failed to start"
        # Show error
        journalctl -u edns-proxy -n 10 --no-pager
    fi
    
    echo "Testing DNS functionality..." 
    sleep 2 
    if timeout 3 bash -c "echo > /dev/udp/127.0.0.1/$SLOWDNS_PORT" 2>/dev/null; then 
        print_success "SlowDNS is listening on port $SLOWDNS_PORT" 
    else 
        print_warning "SlowDNS not responding on port $SLOWDNS_PORT" 
    fi
else
    print_error "SlowDNS service failed to start"
    
    # Try direct start
    pkill dnstt-server 2>/dev/null 
    $SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT & 
    sleep 2 
    if pgrep -f "dnstt-server" > /dev/null; then 
        print_success "SlowDNS started directly" 
    else 
        print_error "Failed to start SlowDNS" 
    fi 
fi

# Clean up packages
apt-get remove -y libpam-pwquality 2>/dev/null || true
print_success "Packages cleaned"

# Test connections
echo "Testing connections..."
if timeout 5 bash -c "echo > /dev/tcp/127.0.0.1/$SSHD_PORT" 2>/dev/null; then
    print_success "SSH port $SSHD_PORT is accessible"
else
    print_error "SSH port $SSHD_PORT is not accessible"
fi

# Test EDNS proxy
if ss -ulpn 2>/dev/null | grep -q ":53 "; then
    print_success "EDNS Proxy listening on port 53"
else
    print_warning "EDNS Proxy not listening on port 53"
fi

echo ""
print_success "OpenSSH SlowDNS + EDNS Proxy Installation Completed!"
echo ""
echo "Server IP: $SERVER_IP"
echo "SSH Port: $SSHD_PORT"
echo "SlowDNS Port: $SLOWDNS_PORT"
echo "EDNS Proxy Port: 53"
echo "MTU: 1800"
echo "EDNS Sizes: External=512, Internal=1800"
echo ""
echo "Note:"
echo "1. SlowDNS runs on port $SLOWDNS_PORT"
echo "2. EDNS Proxy runs on port 53"
echo "3. Clients connect to port 53 (EDNS Proxy)"
echo "4. EDNS Proxy forwards to SlowDNS on port $SLOWDNS_PORT"
echo ""
echo "To check status:"
echo "  systemctl status server-sldns"
echo "  systemctl status edns-proxy"
echo "  journalctl -u edns-proxy -f"
