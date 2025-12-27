#!/bin/bash

# ============================================================================
#             OPTIMIZED SLOWDNS INSTALLATION SCRIPT
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# SIMPLE FUNCTIONS
# ============================================================================
print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}    OPTIMIZED SLOWDNS INSTALLER${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Get nameserver
    read -p "Enter nameserver (default: dns.example.com): " NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    # Get Server IP
    SERVER_IP=$(curl -s --connect-timeout 3 ifconfig.me || hostname -I | awk '{print $1}')
    print_info "Server IP: $SERVER_IP"
    
    # ============================================================================
    # STEP 1: CONFIGURE OPENSSH
    # ============================================================================
    print_info "Configuring OpenSSH on port $SSHD_PORT"
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
    
    cat > /etc/ssh/sshd_config << EOF
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
    
    systemctl restart sshd 2>/dev/null
    print_success "OpenSSH configured on port $SSHD_PORT"
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS
    # ============================================================================
    print_info "Setting up SlowDNS"
    
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download binary
    if curl -fsSL "$GITHUB_BASE/dnstt-server" -o dnstt-server 2>/dev/null || \
       wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server 2>/dev/null; then
        chmod +x dnstt-server
        SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
        print_success "SlowDNS binary downloaded"
    else
        print_error "Failed to download binary"
        exit 1
    fi
    
    # Download key files
    wget -q "$GITHUB_BASE/server.key" -O server.key 2>/dev/null
    wget -q "$GITHUB_BASE/server.pub" -O server.pub 2>/dev/null
    print_success "Encryption keys downloaded"
    
    # ============================================================================
    # STEP 3: CREATE SLOWDNS SERVICE
    # ============================================================================
    print_info "Creating SlowDNS service"
    
    cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "SlowDNS service configured"
    
    # ============================================================================
    # STEP 4: COMPILE EDNS PROXY
    # ============================================================================
    print_info "Compiling EDNS Proxy"
    
    # Install compiler if needed
    if ! command -v gcc &>/dev/null; then
        apt update > /dev/null 2>&1 && apt install -y gcc > /dev/null 2>&1
    fi
    
    # Create optimized C code
    cat > /tmp/edns.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096

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

int main() {
    printf("[EDNS Proxy] Starting DNS proxy...\n");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("[ERROR] socket");
        return 1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[ERROR] bind");
        close(sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port 53\n");
    
    while(1) {
        unsigned char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                         (struct sockaddr*)&client_addr, &client_len);
        if(len > 0) {
            patch_edns(buffer, len, INT_EDNS);
            
            int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if(up_sock >= 0) {
                struct sockaddr_in up_addr;
                memset(&up_addr, 0, sizeof(up_addr));
                up_addr.sin_family = AF_INET;
                up_addr.sin_port = htons(SLOWDNS_PORT);
                inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                
                sendto(up_sock, buffer, len, 0,
                       (struct sockaddr*)&up_addr, sizeof(up_addr));
                
                int resp_len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                if(resp_len > 0) {
                    patch_edns(buffer, resp_len, 512);
                    sendto(sock, buffer, resp_len, 0,
                           (struct sockaddr*)&client_addr, client_len);
                }
                close(up_sock);
            }
        }
    }
    return 0;
}
EOF
    
    # Compile with optimizations
    gcc -O3 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/dev/null
    
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/edns-proxy
        print_success "EDNS Proxy compiled"
    else
        print_error "EDNS compilation failed"
        exit 1
    fi
    
    # Create EDNS service
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy for SlowDNS
After=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "EDNS Proxy service configured"
    
    # ============================================================================
    # STEP 5: FIREWALL CONFIGURATION
    # ============================================================================
    print_info "Configuring firewall"
    
    # Clear existing rules
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Essential rules only
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    
    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    
    print_success "Firewall configured"
    
    # ============================================================================
    # STEP 6: START SERVICES
    # ============================================================================
    print_info "Starting services"
    
    systemctl daemon-reload 2>/dev/null
    
    # Start SlowDNS
    systemctl enable server-sldns > /dev/null 2>&1
    systemctl start server-sldns 2>/dev/null
    sleep 1
    
    if systemctl is-active --quiet server-sldns; then
        print_success "SlowDNS service started"
    else
        print_warning "Starting SlowDNS in background"
        $SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT &
    fi
    
    # Start EDNS proxy
    systemctl enable edns-proxy > /dev/null 2>&1
    systemctl start edns-proxy 2>/dev/null
    sleep 1
    
    if systemctl is-active --quiet edns-proxy; then
        print_success "EDNS Proxy service started"
    else
        print_warning "Starting EDNS Proxy manually"
        /usr/local/bin/edns-proxy &
    fi
    
    # ============================================================================
    # VERIFICATION
    # ============================================================================
    print_info "Verifying installation"
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}    INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    echo -e "\n${BLUE}SERVER INFORMATION:${NC}"
    echo "  IP Address:  $SERVER_IP"
    echo "  SSH Port:    $SSHD_PORT"
    echo "  SlowDNS Port: $SLOWDNS_PORT"
    echo "  EDNS Port:   53"
    echo "  Nameserver:  $NAMESERVER"
    
    echo -e "\n${BLUE}SERVICE STATUS:${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":53 "; then
        echo "  ✓ EDNS Proxy (port 53): Listening"
    else
        echo "  ✗ EDNS Proxy (port 53): Not listening"
    fi
    
    if ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
        echo "  ✓ SlowDNS (port $SLOWDNS_PORT): Listening"
    else
        echo "  ✗ SlowDNS (port $SLOWDNS_PORT): Not listening"
    fi
    
    echo -e "\n${BLUE}TEST COMMANDS:${NC}"
    echo "  dig @$SERVER_IP $NAMESERVER"
    echo "  systemctl status server-sldns"
    echo "  systemctl status edns-proxy"
    
    # Show public key
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${BLUE}PUBLIC KEY:${NC}"
        cat /etc/slowdns/server.pub | head -1
    fi
    
    echo -e "\n${GREEN}Installation completed!${NC}"
    
    # Cleanup
    rm -f /tmp/edns.c 2>/dev/null
}

# ============================================================================
# EXECUTE
# ============================================================================
if main; then
    exit 0
else
    print_error "Installation failed"
    exit 1
fi
