#!/bin/bash

# ============================================================================
#                     ULTRA-COMPATIBLE SLOWDNS INSTALLATION
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION - MAXIMUM COMPATIBILITY
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
EDNS_PORT=53
MTU_SIZE=1250  # Smaller for maximum compatibility
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
LOG_FILE="/var/log/slowdns-install-$(date +%s).log"

# ============================================================================
# COLORS
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# LOGGING
# ============================================================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# ============================================================================
# FUNCTIONS
# ============================================================================
print_step() {
    echo -e "\n${BLUE}┌─${NC} ${CYAN}${BOLD}STEP $1${NC}"
    echo -e "${BLUE}│${NC}"
}

print_step_end() {
    echo -e "${BLUE}└─${NC} ${GREEN}✓${NC}"
}

print_success() {
    echo -e "  ${GREEN}${BOLD}✓${NC} ${GREEN}$1${NC}"
    log "SUCCESS: $1"
}

print_error() {
    echo -e "  ${RED}${BOLD}✗${NC} ${RED}$1${NC}"
    log "ERROR: $1"
}

print_warning() {
    echo -e "  ${YELLOW}${BOLD}!${NC} ${YELLOW}$1${NC}"
    log "WARNING: $1"
}

print_info() {
    echo -e "  ${CYAN}${BOLD}ℹ${NC} ${CYAN}$1${NC}"
    log "INFO: $1"
}

# ============================================================================
# KERNEL OPTIMIZATION FOR MAX SPEED
# ============================================================================
optimize_kernel() {
    print_info "Optimizing kernel for maximum speed"
    
    cat > /etc/sysctl.d/99-slowdns-optimize.conf << 'EOF'
# ============================================================================
# MAXIMUM SPEED OPTIMIZATIONS
# ============================================================================

# Network buffers
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 16777216
net.core.netdev_max_backlog = 100000

# TCP optimizations
net.ipv4.tcp_rmem = 4096 87380 268435456
net.ipv4.tcp_wmem = 4096 65536 268435456
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# UDP optimizations
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Queue disciplines
net.core.default_qdisc = fq
EOF

    # Try to enable BBR
    if lsmod | grep -q tcp_bbr || modprobe tcp_bbr 2>/dev/null; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.d/99-slowdns-optimize.conf
        print_success "BBR congestion control enabled"
    fi
    
    # Apply optimizations
    sysctl -p /etc/sysctl.d/99-slowdns-optimize.conf 2>/dev/null
    
    # Disable IPv6 to prevent issues
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1
}

# ============================================================================
# ULTRA-COMPATIBLE SSH CONFIGURATION
# ============================================================================
configure_ssh() {
    print_step "1"
    print_info "Configuring SSH for maximum compatibility"
    
    # Backup original
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.slowdns
    
    # ULTRA-COMPATIBLE SSH CONFIG
    # Accepts ALL ciphers including old/weak ones
    cat > /etc/ssh/sshd_config << 'EOF'
# ============================================================================
# ULTRA-COMPATIBLE SSH CONFIGURATION
# Accepts old clients while maintaining stability
# ============================================================================

# Basic settings
Port 22
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
ClientAliveInterval 120
ClientAliveCountMax 2
AllowTcpForwarding yes
GatewayPorts yes
Compression delayed
Subsystem sftp /usr/lib/openssh/sftp-server
MaxSessions 100
MaxStartups 100:30:200
LoginGraceTime 120
UseDNS no
StrictModes yes
MaxAuthTries 6
AcceptEnv LANG LC_*

# ULTRA-COMPATIBLE CIPHER SETTINGS
# Accepts everything including old/weak ciphers
Ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc
MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1
KexAlgorithms diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group1-sha1
HostKeyAlgorithms ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521

# Performance tweaks
GSSAPIAuthentication no
GSSAPICleanupCredentials no
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
EOF

    # Test configuration
    print_info "Testing SSH configuration"
    if sshd -t 2>/dev/null; then
        print_success "SSH config syntax OK"
        
        # Restart SSH (use correct service name for Debian)
        if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
            sleep 2
            if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
                print_success "SSH service restarted successfully"
            else
                print_warning "SSH restart check failed but continuing"
            fi
        else
            print_warning "SSH restart failed, but continuing installation"
        fi
    else
        print_error "SSH config syntax error, restoring backup"
        cp /etc/ssh/sshd_config.backup.slowdns /etc/ssh/sshd_config
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    fi
    
    print_step_end
}

# ============================================================================
# SLOWDNS SETUP
# ============================================================================
setup_slowdns() {
    print_step "2"
    print_info "Setting up SlowDNS"
    
    echo -e "\n${WHITE}Enter nameserver (e.g., dns.yourdomain.com):${NC}"
    read -p "Nameserver: " NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    # Create directory
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns
    cd /etc/slowdns || exit 1
    
    # Download components with multiple fallbacks
    print_info "Downloading SlowDNS components"
    
    # Download binary
    for url in \
        "$GITHUB_BASE/dnstt-server" \
        "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/dnstt-server" \
        "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"
    do
        if curl -fsSL --connect-timeout 20 --retry 3 "$url" -o dnstt-server; then
            print_success "Binary downloaded"
            break
        fi
    done
    
    if [ ! -f dnstt-server ]; then
        print_error "Failed to download binary"
        exit 1
    fi
    
    chmod +x dnstt-server
    
    # Download keys
    for file in server.key server.pub; do
        for url in \
            "$GITHUB_BASE/$file" \
            "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/$file" \
            "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/$file"
        do
            if curl -fsSL --connect-timeout 20 --retry 3 "$url" -o "$file"; then
                print_success "$file downloaded"
                break
            fi
        done
    done
    
    # Test binary
    if timeout 5 ./dnstt-server --help 2>&1 | head -5; then
        print_success "SlowDNS binary is working"
    else
        print_warning "Binary test inconclusive - proceeding anyway"
    fi
    
    print_step_end
}

# ============================================================================
# SLOWDNS SERVICE
# ============================================================================
create_services() {
    print_step "3"
    print_info "Creating system services"
    
    # SlowDNS service
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=Ultra-Compatible SlowDNS Server
After=network.target
Wants=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
User=root
WorkingDirectory=/etc/slowdns
ExecStart=/etc/slowdns/dnstt-server -udp :$SLOWDNS_PORT -mtu $MTU_SIZE -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
LimitNOFILE=1000000
LimitNPROC=1000000
LimitCORE=infinity
Nice=-5
OOMScoreAdjust=-1000
StandardOutput=journal
StandardError=journal
SyslogIdentifier=slowdns
Environment="GODEBUG=netdns=go"

[Install]
WantedBy=multi-user.target
EOF
    
    # Simple EDNS proxy
    cat > /tmp/edns.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 1;
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return 1;
    }
    
    printf("[EDNS] Listening on port 53\n");
    
    while (1) {
        char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                          (struct sockaddr*)&client_addr, &client_len);
        if (len <= 0) continue;
        
        // Forward to SlowDNS
        int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (up_sock >= 0) {
            struct sockaddr_in up_addr = {0};
            up_addr.sin_family = AF_INET;
            up_addr.sin_port = htons(5300);
            up_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            
            sendto(up_sock, buffer, len, 0,
                  (struct sockaddr*)&up_addr, sizeof(up_addr));
            
            // Get response
            fd_set fds;
            struct timeval tv = {1, 0};
            FD_ZERO(&fds);
            FD_SET(up_sock, &fds);
            
            if (select(up_sock + 1, &fds, NULL, NULL, &tv) > 0) {
                int resp_len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                if (resp_len > 0) {
                    sendto(sock, buffer, resp_len, 0,
                          (struct sockaddr*)&client_addr, client_len);
                }
            }
            close(up_sock);
        }
    }
    return 0;
}
EOF
    
    # Compile EDNS proxy
    if gcc -O3 /tmp/edns.c -o /usr/local/bin/edns-proxy; then
        chmod +x /usr/local/bin/edns-proxy
        
        cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy for SlowDNS
After=slowdns.service
Requires=slowdns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=100000
Nice=-5
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
EOF
        
        print_success "EDNS proxy compiled and configured"
    else
        print_warning "EDNS proxy compilation failed, using alternative method"
        # Fallback: use socat if available
        if command -v socat &>/dev/null; then
            cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy (socat)
After=slowdns.service

[Service]
Type=simple
ExecStart=/usr/bin/socat UDP4-LISTEN:53,fork UDP4:127.0.0.1:5300
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
            print_success "Using socat as EDNS proxy"
        fi
    fi
    
    print_step_end
}

# ============================================================================
# FIREWALL & NETWORK
# ============================================================================
configure_firewall() {
    print_step "4"
    print_info "Configuring firewall and network"
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    
    # Kill anything on port 53
    fuser -k 53/udp 2>/dev/null
    fuser -k 53/tcp 2>/dev/null
    
    # Basic iptables rules
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Essential rules only
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport 5300 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    
    print_success "Firewall configured"
    print_step_end
}

# ============================================================================
# START SERVICES
# ============================================================================
start_services() {
    print_step "5"
    print_info "Starting all services"
    
    systemctl daemon-reload
    
    # Start SlowDNS
    systemctl enable slowdns.service 2>/dev/null
    systemctl start slowdns.service
    
    # Start EDNS proxy
    if [ -f /etc/systemd/system/edns-proxy.service ]; then
        systemctl enable edns-proxy.service 2>/dev/null
        systemctl start edns-proxy.service
    fi
    
    # Wait and check
    sleep 3
    
    if systemctl is-active --quiet slowdns.service; then
        print_success "SlowDNS service is running"
    else
        print_warning "SlowDNS service not active, checking manually..."
        # Try to start manually
        cd /etc/slowdns
        nohup ./dnstt-server -udp :$SLOWDNS_PORT -mtu $MTU_SIZE -privkey-file server.key $NAMESERVER 127.0.0.1:$SSHD_PORT &
        sleep 2
        if pgrep -f dnstt-server > /dev/null; then
            print_success "SlowDNS started manually"
        fi
    fi
    
    print_step_end
}

# ============================================================================
# VERIFICATION
# ============================================================================
verify_installation() {
    print_step "6"
    print_info "Verifying installation"
    
    echo -e "\n${WHITE}=== Installation Summary ===${NC}"
    echo -e "${GREEN}Server IP:${NC} ${SERVER_IP}"
    echo -e "${GREEN}SSH Port:${NC} 22"
    echo -e "${GREEN}SlowDNS Port:${NC} 5300"
    echo -e "${GREEN}EDNS Port:${NC} 53"
    echo -e "${GREEN}Nameserver:${NC} $NAMESERVER"
    echo -e "${GREEN}MTU:${NC} $MTU_SIZE"
    
    echo -e "\n${WHITE}=== Service Status ===${NC}"
    systemctl status slowdns.service --no-pager | head -20
    if [ -f /etc/systemd/system/edns-proxy.service ]; then
        echo ""
        systemctl status edns-proxy.service --no-pager | head -20
    fi
    
    echo -e "\n${WHITE}=== Port Check ===${NC}"
    echo "Port 22 (SSH):"
    ss -tlnp | grep ':22 ' || echo "Not listening"
    
    echo -e "\nPort 53 (DNS):"
    ss -ulnp | grep ':53 ' || echo "Not listening"
    
    echo -e "\nPort 5300 (SlowDNS):"
    ss -ulnp | grep ':5300 ' || echo "Not listening"
    
    echo -e "\n${WHITE}=== Quick Test ===${NC}"
    echo "Test SSH: ssh root@$SERVER_IP"
    echo "Test DNS: dig @$SERVER_IP $NAMESERVER"
    
    # Show public key
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${WHITE}=== Public Key ===${NC}"
        cat /etc/slowdns/server.pub
    fi
    
    print_step_end
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}        ULTRA-COMPATIBLE SLOWDNS INSTALLATION${NC}            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}     Maximum Compatibility + Speed Optimization${NC}         ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}        Supports old SSH clients & algorithms${NC}            ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get server IP
    SERVER_IP=$(curl -s --max-time 5 -4 ifconfig.me || ip route get 1 | awk '{print $7; exit}')
    echo -e "${GREEN}Server IP:${NC} ${WHITE}$SERVER_IP${NC}"
    
    # Run all steps
    optimize_kernel
    configure_ssh
    setup_slowdns
    create_services
    configure_firewall
    start_services
    verify_installation
    
    # Final message
    echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   INSTALLATION COMPLETE!${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "\n${YELLOW}Features enabled:${NC}"
    echo -e "  ✓ Ultra-compatible SSH (accepts old ciphers)"
    echo -e "  ✓ Maximum speed optimizations"
    echo -e "  ✓ Stable kernel tuning"
    echo -e "  ✓ Automatic restart on failure"
    echo -e "  ✓ Works with old SSH clients"
    
    echo -e "\n${YELLOW}To test:${NC}"
    echo -e "  SSH: ${WHITE}ssh root@$SERVER_IP${NC}"
    echo -e "  DNS: ${WHITE}dig @$SERVER_IP $NAMESERVER${NC}"
    
    echo -e "\n${YELLOW}Log file:${NC} $LOG_FILE"
}

# ============================================================================
# EXECUTE
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; exit 1' INT

if main; then
    exit 0
else
    exit 1
fi
