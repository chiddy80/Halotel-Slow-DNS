#!/bin/bash

# ============================================================================
#                     OPTIMIZED SLOWDNS INSTALLATION SCRIPT
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION - TUNED FOR PERFORMANCE
# ============================================================================
SSHD_PORT=22  # Using standard SSH port for compatibility
SLOWDNS_PORT=5300
EDNS_PORT=53
MTU_SIZE=1300   # Better for stability than 1800
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
LOG_FILE="/var/log/slowdns-install.log"

# Performance tuning
SYSCTL_TCP_TW_REUSE=1
SYSCTL_TCP_FASTOPEN=3
SYSCTL_TCP_MAX_SYN_BACKLOG=8192
SYSCTL_TCP_SYNACK_RETRIES=2
SYSCTL_NET_CORE_RMEM_MAX=134217728
SYSCTL_NET_CORE_WMEM_MAX=134217728
SYSCTL_NET_IPV4_TCP_RMEM="4096 87380 134217728"
SYSCTL_NET_IPV4_TCP_WMEM="4096 65536 134217728"

# ============================================================================
# MODERN COLORS & DESIGN
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
# LOGGING FUNCTIONS
# ============================================================================
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# ============================================================================
# PERFORMANCE FUNCTIONS
# ============================================================================
optimize_kernel() {
    print_info "Optimizing kernel parameters for better performance"
    
    # TCP optimizations
    cat >> /etc/sysctl.conf << EOF
# ============================================================================
# SLOWDNS PERFORMANCE OPTIMIZATIONS
# ============================================================================
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_slow_start_after_idle = 0
net.core.default_qdisc = fq
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOF
    
    # Apply immediately
    sysctl -p >> "$LOG_FILE" 2>&1
    
    # Enable BBR if available
    if modprobe tcp_bbr 2>/dev/null; then
        sysctl net.ipv4.tcp_congestion_control=bbr
    fi
}

setup_swap() {
    if ! free | grep -i swap | awk '{print $2}' | grep -qv '^0$'; then
        print_info "Setting up swap for better memory management"
        fallocate -l 2G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        sysctl vm.swappiness=10
        sysctl vm.vfs_cache_pressure=50
    fi
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
show_progress() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while ps -p $pid > /dev/null 2>&1; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

print_step() {
    echo -e "\n${BLUE}┌─${NC} ${CYAN}${BOLD}STEP $1${NC}"
    echo -e "${BLUE}│${NC}"
}

print_step_end() {
    echo -e "${BLUE}└─${NC} ${GREEN}✓${NC} Completed"
}

print_success() {
    echo -e "  ${GREEN}${BOLD}✓${NC} ${GREEN}$1${NC}"
    log_message "SUCCESS: $1"
}

print_error() {
    echo -e "  ${RED}${BOLD}✗${NC} ${RED}$1${NC}"
    log_message "ERROR: $1"
}

print_warning() {
    echo -e "  ${YELLOW}${BOLD}!${NC} ${YELLOW}$1${NC}"
    log_message "WARNING: $1"
}

print_info() {
    echo -e "  ${CYAN}${BOLD}ℹ${NC} ${CYAN}$1${NC}"
    log_message "INFO: $1"
}

print_header() {
    echo -e "\n${PURPLE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════════════${NC}"
    log_message "SECTION: $1"
}

check_dependencies() {
    print_info "Checking and installing dependencies"
    
    local deps=("curl" "wget" "gcc" "iptables" "systemctl" "ss")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        print_info "Installing missing dependencies: ${missing[*]}"
        apt-get update > /dev/null 2>&1
        apt-get install -y "${missing[@]}" > /dev/null 2>&1
    fi
}

# ============================================================================
# FIXED SSH CONFIGURATION - PORT 22 ONLY
# ============================================================================
configure_ssh() {
    print_step "1"
    print_info "Configuring OpenSSH on port $SSHD_PORT"
    
    # Backup SSH config
    BACKUP_FILE="/etc/ssh/sshd_config.backup.$(date +%s)"
    cp /etc/ssh/sshd_config "$BACKUP_FILE"
    
    # Create SIMPLE working SSH config for port 22
    cat > /etc/ssh/sshd_config << 'EOF'
# ============================================================================
# SLOWDNS SSH CONFIGURATION - PORT 22 ONLY
# ============================================================================
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
MaxSessions 50
MaxStartups 50:30:100
LoginGraceTime 60
UseDNS no
StrictModes yes
MaxAuthTries 3
AcceptEnv LANG LC_*
GSSAPIAuthentication no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256
EOF
    
    # Test config syntax
    echo -ne "  ${CYAN}Testing SSH configuration...${NC}"
    if sshd -t 2>/dev/null; then
        echo -e "\r  ${GREEN}SSH config syntax OK${NC}"
        
        # Restart SSH service (ssh not sshd on Debian)
        echo -ne "  ${CYAN}Restarting SSH service...${NC}"
        systemctl restart ssh 2>/dev/null
        sleep 2
        
        if systemctl is-active --quiet ssh; then
            echo -e "\r  ${GREEN}SSH service restarted successfully${NC}"
            print_success "OpenSSH configured on port $SSHD_PORT"
        else
            echo -e "\r  ${RED}SSH service failed to start${NC}"
            
            # Try ultra-minimal config
            print_info "Attempting ultra-minimal configuration..."
            cat > /etc/ssh/sshd_config << EOF
Port 22
PermitRootLogin yes
PasswordAuthentication yes
AllowTcpForwarding yes
GatewayPorts yes
EOF
            
            systemctl restart ssh
            if systemctl is-active --quiet ssh; then
                print_success "SSH running with minimal config"
            else
                print_error "SSH completely broken, restoring backup..."
                cp "$BACKUP_FILE" /etc/ssh/sshd_config
                systemctl restart ssh
            fi
        fi
    else
        echo -e "\r  ${RED}SSH config syntax error${NC}"
        print_info "Restoring original config..."
        cp "$BACKUP_FILE" /etc/ssh/sshd_config
        systemctl restart ssh
    fi
    
    print_step_end
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main() {
    # Create log file
    > "$LOG_FILE"
    
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          🚀 OPTIMIZED SLOWDNS INSTALLATION${NC}               ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}          Fast & Stable Configuration v2.0${NC}               ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get nameserver
    echo -e "${WHITE}${BOLD}Enter nameserver configuration:${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Format:${NC} subdomain.yourdomain.com                           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    while true; do
        read -p "$(echo -e "${WHITE}${BOLD}Enter nameserver [e.g., dns.example.com]: ${NC}")" NAMESERVER
        if [[ -n "$NAMESERVER" ]]; then
            break
        else
            echo -e "${RED}Nameserver cannot be empty${NC}"
        fi
    done
    
    print_header "📦 SYSTEM PREPARATION"
    check_dependencies
    setup_swap
    optimize_kernel
    
    # Get Server IP
    print_info "Detecting server IP address"
    SERVER_IP=$(curl -s --max-time 10 -4 ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(ip route get 1 | awk '{print $7; exit}')
    fi
    echo -e "  ${GREEN}Server IP:${NC} ${WHITE}${BOLD}$SERVER_IP${NC}"
    
    # ============================================================================
    # STEP 1: CONFIGURE SSH
    # ============================================================================
    configure_ssh
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS WITH PROPER VALIDATION
    # ============================================================================
    print_step "2"
    print_info "Setting up SlowDNS"
    
    # Create directory
    rm -rf /etc/slowdns
    mkdir -p /etc/slowdns
    cd /etc/slowdns || exit 1
    
    # Download binary with retry
    print_info "Downloading SlowDNS binary"
    for i in {1..3}; do
        if curl -fsSL --connect-timeout 30 "$GITHUB_BASE/dnstt-server" -o dnstt-server; then
            print_success "Binary downloaded successfully"
            break
        elif [ $i -eq 3 ]; then
            print_error "Failed to download binary after 3 attempts"
            exit 1
        else
            print_warning "Download attempt $i failed, retrying..."
            sleep 2
        fi
    done
    
    chmod +x dnstt-server
    
    # Download keys
    for file in server.key server.pub; do
        if ! curl -fsSL --connect-timeout 30 "$GITHUB_BASE/$file" -o "$file"; then
            print_error "Failed to download $file"
            exit 1
        fi
    done
    print_success "All key files downloaded"
    
    # Test binary
    if ./dnstt-server --help 2>&1 | grep -q -i "usage\|help"; then
        print_success "Binary validated"
    else
        print_warning "Binary test inconclusive - continuing anyway"
    fi
    
    print_step_end
    
    # ============================================================================
    # STEP 3: CREATE OPTIMIZED SLOWDNS SERVICE
    # ============================================================================
    print_step "3"
    print_info "Creating SlowDNS system service"
    
    cat > /etc/systemd/system/slowdns-server.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :$SLOWDNS_PORT -mtu $MTU_SIZE -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root
LimitNOFILE=1000000
LimitCORE=infinity
TimeoutStartSec=0
StandardOutput=journal
StandardError=journal
SyslogIdentifier=slowdns-server
Nice=-10
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
EOF
    
    print_step_end
    
    # ============================================================================
    # STEP 4: COMPILE LIGHTWEIGHT EDNS PROXY
    # ============================================================================
    print_step "4"
    print_info "Compiling optimized EDNS Proxy"
    
    # Create simpler, more stable C code
    cat > /tmp/edns-simple.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define BUFFER_SIZE 4096
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53

void patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return;
    
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip questions
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        offset += 5;
    }
    
    // Find and patch EDNS
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(offset + 1 < len && buf[offset] == 0 && buf[offset+1] == 0) {
            if(offset + 4 < len) {
                buf[offset+3] = new_size >> 8;
                buf[offset+4] = new_size & 0xFF;
                return;
            }
        }
        offset++;
    }
}

int main() {
    printf("[EDNS Proxy] Starting simple proxy...\n");
    
    signal(SIGPIPE, SIG_IGN);
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        return 1;
    }
    
    int reuse = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
    }
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port %d\n", LISTEN_PORT);
    
    while(1) {
        unsigned char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                          (struct sockaddr*)&client_addr, &client_len);
        if(len <= 0) continue;
        
        // Patch EDNS to 1300 for upstream
        patch_edns(buffer, len, 1300);
        
        // Forward to SlowDNS
        int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if(up_sock >= 0) {
            struct sockaddr_in up_addr = {0};
            up_addr.sin_family = AF_INET;
            up_addr.sin_port = htons(SLOWDNS_PORT);
            up_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            
            sendto(up_sock, buffer, len, 0,
                   (struct sockaddr*)&up_addr, sizeof(up_addr));
            
            // Wait for response
            fd_set fds;
            struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
            
            FD_ZERO(&fds);
            FD_SET(up_sock, &fds);
            
            if(select(up_sock + 1, &fds, NULL, NULL, &tv) > 0) {
                int resp_len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                if(resp_len > 0) {
                    // Patch EDNS back to 512 for client
                    patch_edns(buffer, resp_len, 512);
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
    
    # Compile with basic optimizations
    if gcc -O2 -static /tmp/edns-simple.c -o /usr/local/bin/edns-proxy; then
        chmod +x /usr/local/bin/edns-proxy
        print_success "EDNS Proxy compiled successfully"
    else
        print_error "Failed to compile EDNS Proxy"
        exit 1
    fi
    
    # Create EDNS service
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy
After=slowdns-server.service
Requires=slowdns-server.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
EOF
    
    print_step_end
    
    # ============================================================================
    # STEP 5: FIREWALL CONFIGURATION
    # ============================================================================
    print_step "5"
    print_info "Configuring firewall"
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    
    # Kill anything on port 53
    fuser -k 53/udp 2>/dev/null
    fuser -k $SLOWDNS_PORT/udp 2>/dev/null
    
    # Configure iptables
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH on port 22
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
    
    # Allow SlowDNS ports
    iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
    iptables -A INPUT -p udp --dport $EDNS_PORT -j ACCEPT
    
    # Allow ICMP (ping)
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    
    print_success "Firewall configured"
    print_step_end
    
    # ============================================================================
    # STEP 6: START AND VERIFY SERVICES
    # ============================================================================
    print_step "6"
    print_info "Starting services"
    
    systemctl daemon-reload
    
    # Start SlowDNS
    systemctl enable slowdns-server
    systemctl start slowdns-server
    
    # Start EDNS proxy
    systemctl enable edns-proxy
    systemctl start edns-proxy
    
    # Wait and verify
    sleep 3
    
    if systemctl is-active --quiet slowdns-server && systemctl is-active --quiet edns-proxy; then
        print_success "All services started successfully"
    else
        print_error "Some services failed to start"
        
        # Show logs
        echo -e "\n${YELLOW}Checking service status:${NC}"
        systemctl status slowdns-server --no-pager -l
        systemctl status edns-proxy --no-pager -l
    fi
    
    print_step_end
    
    # ============================================================================
    # COMPLETION
    # ============================================================================
    print_header "🎉 INSTALLATION COMPLETE"
    
    # Show configuration
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER CONFIGURATION${NC}                                ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:      ${WHITE}$SERVER_IP${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SSH Port:       ${WHITE}$SSHD_PORT${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SlowDNS Port:   ${WHITE}$SLOWDNS_PORT${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} EDNS Port:      ${WHITE}$EDNS_PORT${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU Size:       ${WHITE}$MTU_SIZE${NC}                         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:     ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Test commands
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}TEST COMMANDS${NC}                                       ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}dig +short @$SERVER_IP $NAMESERVER${NC}              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}systemctl status slowdns-server${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}ss -ulpn | grep -E ':53|:5300'${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Monitoring
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}MONITORING COMMANDS${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}journalctl -u slowdns-server -f -n 50${NC}                ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}netstat -su | grep -E 'packets|errors'${NC}                ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}ss -s | grep UDP${NC}                                    ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Show public key
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PUBLIC KEY${NC}                                        ${CYAN}│${NC}"
        echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
        echo -e "${CYAN}│${NC}${WHITE}"
        cat /etc/slowdns/server.pub
        echo -e "${NC}${CYAN}│${NC}"
        echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    fi
    
    # Final status
    echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   SLOWDNS INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}${BOLD}   Stable configuration applied${NC}"
    echo -e "${GREEN}${BOLD}   Log file: $LOG_FILE${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    
    # Cleanup
    rm -f /tmp/edns-simple.c
    
    # Post-install test
    echo -e "\n${WHITE}Running post-installation test...${NC}"
    
    # Test port 53
    if ss -ulpn | grep -q ":53 "; then
        echo -e "  ${GREEN}✓ Port 53 is listening${NC}"
    else
        echo -e "  ${YELLOW}⚠ Port 53 not listening - check edns-proxy service${NC}"
    fi
    
    # Test SlowDNS port
    if ss -ulpn | grep -q ":$SLOWDNS_PORT "; then
        echo -e "  ${GREEN}✓ Port $SLOWDNS_PORT is listening${NC}"
    else
        echo -e "  ${YELLOW}⚠ Port $SLOWDNS_PORT not listening${NC}"
    fi
    
    echo -e "\n${YELLOW}If experiencing issues, check:${NC}"
    echo -e "  1. ${WHITE}systemctl status slowdns-server${NC}"
    echo -e "  2. ${WHITE}journalctl -u slowdns-server -n 20${NC}"
    echo -e "  3. ${WHITE}Verify firewall: iptables -L -n${NC}"
    
    log_message "Installation completed successfully"
}

# ============================================================================
# EXECUTE WITH PROPER ERROR HANDLING
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; exit 1' INT

if main; then
    echo -e "\n${GREEN}Installation completed at $(date)${NC}"
    exit 0
else
    echo -e "\n${RED}Installation failed - check $LOG_FILE for details${NC}"
    exit 1
fi
```
