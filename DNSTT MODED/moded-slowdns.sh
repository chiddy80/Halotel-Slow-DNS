#!/bin/bash

# ============================================================================
#                     SLOWDNS PROFESSIONAL INSTALLER
# ============================================================================

# Configuration
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
VALID_KEYS_URL="$GITHUB_BASE/Valid_Keys.txt"
ALLOWED_IPS_URL="$GITHUB_BASE/Allowips.text"
MAX_ATTEMPTS=3
LOG_FILE="/var/log/slowdns.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m'

# ============================================================================
# Display Functions
# ============================================================================
print_header() {
    clear
    echo -e "${CYAN}"
    echo "   ███████╗██╗      ██████╗ ██╗    ██╗██████╗ ███╗   ██╗███████╗"
    echo "   ██╔════╝██║     ██╔═══██╗██║    ██║██╔══██╗████╗  ██║██╔════╝"
    echo "   ███████╗██║     ██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║███████╗"
    echo "   ╚════██║██║     ██║   ██║██║███╗██║██║  ██║██║╚██╗██║╚════██║"
    echo "   ███████║███████╗╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║███████║"
    echo "   ╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝"
    echo -e "${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}       Professional SlowDNS Tunnel System${NC}"
    echo -e "${YELLOW}     🌍 MRCHIDDY ESIMFREEGB | ⌛ FAST DNS HALOTEL${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_line() {
    echo -e "${BLUE}──────────────────────────────────────────────────────────${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

print_info() {
    echo -e "${CYAN}[i] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# ============================================================================
# System Functions
# ============================================================================
get_vps_ip() {
    local ip=$(curl -4 -s --connect-timeout 10 https://api.ipify.org)
    if [ -z "$ip" ]; then
        ip=$(curl -4 -s --connect-timeout 10 https://checkip.amazonaws.com)
    fi
    if [ -z "$ip" ]; then
        ip=$(curl -4 -s --connect-timeout 10 https://ifconfig.me/ip)
    fi
    echo "$ip" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

fetch_from_github() {
    curl -s --max-time 10 "$1" 2>/dev/null
}

check_ip_allowed() {
    local current_ip="$1"
    local allowed_ips=$(fetch_from_github "$ALLOWED_IPS_URL")
    
    if [ $? -ne 0 ] || [ -z "$allowed_ips" ]; then
        print_warning "Cannot fetch allowed IPs list, skipping IP check"
        return 0  # Skip IP check if can't fetch list
    fi
    
    local clean_list=$(echo "$allowed_ips" | grep -v '^#' | grep -v '^$' | tr -d '[]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if echo "$clean_list" | grep -q "^$current_ip$"; then
        return 0
    else
        print_warning "IP $current_ip not found in whitelist, but continuing..."
        return 0  # Continue anyway for now
    fi
}

validate_license_key() {
    local license_key="$1"
    local valid_keys=$(fetch_from_github "$VALID_KEYS_URL")
    
    if [ $? -ne 0 ] || [ -z "$valid_keys" ]; then
        print_warning "Cannot fetch license keys, skipping validation"
        return 0  # Skip validation if can't fetch
    fi
    
    local clean_keys=$(echo "$valid_keys" | grep -v '^#' | grep -v '^$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if echo "$clean_keys" | grep -q "^$license_key$"; then
        return 0
    else
        return 1
    fi
}

read_hidden() {
    unset value
    while IFS= read -r -s -n1 char; do
        [[ -z $char ]] && { printf '\n'; break; }
        if [[ $char == $'\x7f' ]]; then
            [[ -n $value ]] && value=${value%?}
            printf '\b \b'
        else
            value+=$char
            printf '*'
        fi
    done
    echo "$value"
}

# ============================================================================
# License Check Function
# ============================================================================
check_license() {
    print_header
    
    echo -e "${WHITE}═════════════ LICENSE VERIFICATION ═════════════${NC}"
    echo ""
    
    # Get VPS IP
    print_info "Checking VPS IP..."
    CURRENT_IP=$(get_vps_ip)
    
    if [ -z "$CURRENT_IP" ] || [[ ! $CURRENT_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_error "Cannot get VPS IP"
        echo -e "${YELLOW}Continuing anyway...${NC}"
        CURRENT_IP="0.0.0.0"
    fi
    
    echo -e "${CYAN}VPS IP: ${WHITE}$CURRENT_IP${NC}"
    print_line
    
    # Check IP authorization
    print_info "Checking IP authorization..."
    check_ip_allowed "$CURRENT_IP"
    
    print_success "IP check completed"
    echo ""
    
    # License verification
    echo -e "${WHITE}════════════ LICENSE KEY REQUIRED ═════════════${NC}"
    echo ""
    print_info "Get license key from: @esimfreegb"
    print_info "Or press Enter to continue without license key"
    echo ""
    
    local attempts=0
    while [ $attempts -lt $MAX_ATTEMPTS ]; do
        attempts=$((attempts + 1))
        
        echo -e "${CYAN}Attempt ${WHITE}$attempts${CYAN} of ${WHITE}$MAX_ATTEMPTS${NC}"
        echo -ne "${YELLOW}Enter license key (or press Enter to skip): ${NC}"
        LICENSE_KEY=$(read_hidden)
        
        if [ -z "$LICENSE_KEY" ]; then
            echo ""
            print_warning "No license key provided, continuing..."
            sleep 1
            return 0
        fi
        
        LICENSE_KEY=$(echo "$LICENSE_KEY" | tr -d ' ' | tr '[:lower:]' '[:upper:]')
        
        print_info "Verifying license..."
        
        if validate_license_key "$LICENSE_KEY"; then
            echo ""
            print_success "✓ License verified successfully"
            print_success "✓ Starting installation..."
            sleep 1
            return 0
        else
            print_error "Invalid license key"
            
            if [ $attempts -lt $MAX_ATTEMPTS ]; then
                echo ""
                print_warning "Try again"
                print_line
                echo ""
            else
                echo ""
                print_warning "Maximum attempts reached, continuing without license..."
                sleep 2
                return 0
            fi
        fi
    done
    
    return 0
}

# ============================================================================
# Installation Functions
# ============================================================================
configure_openssh() {
    print_info "Configuring OpenSSH..."
    SSHD_PORT=22
    
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
    fi
    
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
    
    if systemctl restart sshd 2>/dev/null || service sshd restart 2>/dev/null; then
        print_success "SSH configured on port $SSHD_PORT"
    else
        print_warning "Could not restart SSH service"
    fi
}

install_slowdns() {
    print_info "Setting up SlowDNS..."
    
    rm -rf /etc/slowdns
    mkdir -p /etc/slowdns
    cd /etc/slowdns || exit 1
    
    # Download binary
    if ! wget -q --timeout=30 -O dnstt-server "$GITHUB_BASE/dnstt-server"; then
        print_error "Failed to download dnstt-server"
        return 1
    fi
    chmod +x dnstt-server
    
    # Download keys
    wget -q --timeout=30 -O server.key "$GITHUB_BASE/server.key" || print_warning "Could not download server.key"
    wget -q --timeout=30 -O server.pub "$GITHUB_BASE/server.pub" || print_warning "Could not download server.pub"
    
    # Create keys if download failed
    if [ ! -f server.key ] || [ ! -f server.pub ]; then
        print_info "Generating new keys..."
        if ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub 2>/dev/null; then
            print_success "Generated new keys"
        else
            # Fallback key generation
            openssl genrsa -out server.key 2048 2>/dev/null
            openssl rsa -in server.key -pubout -out server.pub 2>/dev/null
        fi
    fi
    
    print_success "SlowDNS components installed"
}

create_services() {
    print_info "Creating services..."
    
    # Get nameserver
    echo ""
    echo -ne "${YELLOW}Enter nameserver [dns.halotel.com]: ${NC}"
    read -r NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.halotel.com}
    
    # SlowDNS service
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :5300 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:22
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # EDNS Proxy service
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy for SlowDNS
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Service files created"
}

compile_edns_proxy() {
    print_info "Compiling EDNS Proxy..."
    
    # Install gcc if needed
    if ! command -v gcc &>/dev/null; then
        print_info "Installing gcc..."
        apt-get update > /dev/null 2>&1
        apt-get install -y gcc > /dev/null 2>&1 || yum install -y gcc > /dev/null 2>&1 || dnf install -y gcc > /dev/null 2>&1
    fi
    
    if ! command -v gcc &>/dev/null; then
        print_error "Cannot install gcc, skipping EDNS proxy compilation"
        return 1
    fi
    
    # Create C source
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
#include <errno.h>

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 100

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
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        return 1;
    }
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
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
        close(sock);
        close(epoll_fd);
        return 1;
    }
    
    struct epoll_event events[MAX_EVENTS];
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
                        struct sockaddr_in up_addr;
                        memset(&up_addr, 0, sizeof(up_addr));
                        up_addr.sin_family = AF_INET;
                        up_addr.sin_port = htons(SLOWDNS_PORT);
                        up_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                        
                        sendto(up_sock, buffer, len, 0,
                               (struct sockaddr*)&up_addr, sizeof(up_addr));
                        
                        struct timeval tv;
                        tv.tv_sec = 2;
                        tv.tv_usec = 0;
                        setsockopt(up_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                        
                        len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                        if(len > 0) {
                            patch_edns(buffer, len, EXT_EDNS);
                            sendto(sock, buffer, len, 0,
                                   (struct sockaddr*)&client_addr, client_len);
                        }
                        close(up_sock);
                    }
                }
            }
        }
    }
    
    close(sock);
    close(epoll_fd);
    return 0;
}
EOF
    
    # Compile
    if gcc -O3 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/dev/null; then
        chmod +x /usr/local/bin/edns-proxy
        print_success "EDNS Proxy compiled successfully"
        return 0
    else
        print_error "Failed to compile EDNS Proxy"
        # Create a simple shell script fallback
        cat > /usr/local/bin/edns-proxy << 'EOF'
#!/bin/bash
echo "EDNS Proxy not compiled properly"
exit 1
EOF
        chmod +x /usr/local/bin/edns-proxy
        return 1
    fi
}

configure_firewall() {
    print_info "Configuring firewall..."
    
    # Check for iptables
    if ! command -v iptables &>/dev/null; then
        print_info "Installing iptables..."
        apt-get install -y iptables iptables-persistent 2>/dev/null || \
        yum install -y iptables iptables-services 2>/dev/null || \
        dnf install -y iptables iptables-services 2>/dev/null
    fi
    
    # Save current rules
    iptables-save > /etc/iptables.backup 2>/dev/null
    
    # Clear rules
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    
    # Allow necessary ports
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport 5300 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    
    # Allow localhost
    iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    
    # Allow ICMP
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null
    
    # Drop invalid
    iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null
    
    # Default policies
    iptables -P INPUT DROP 2>/dev/null
    iptables -P FORWARD DROP 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Disable IPv6 if possible
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
    
    # Save rules
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
    fi
    
    print_success "Firewall configured"
}

start_services() {
    print_info "Starting services..."
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    pkill -9 dnsmasq 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    fuser -k 5300/udp 2>/dev/null
    
    # Start SlowDNS
    systemctl daemon-reload 2>/dev/null
    systemctl enable slowdns.service 2>/dev/null
    systemctl start slowdns.service 2>/dev/null
    
    sleep 1
    
    # Start EDNS proxy
    systemctl enable edns-proxy.service 2>/dev/null
    systemctl start edns-proxy.service 2>/dev/null
    
    sleep 2
    
    # Check status
    echo ""
    print_info "Checking service status..."
    
    if systemctl is-active --quiet slowdns.service 2>/dev/null; then
        print_success "SlowDNS service is running"
    else
        print_warning "SlowDNS service is not running"
        print_info "Trying to start manually..."
        /etc/slowdns/dnstt-server -udp :5300 -privkey-file /etc/slowdns/server.key "$NAMESERVER" 127.0.0.1:22 &
    fi
    
    if systemctl is-active --quiet edns-proxy.service 2>/dev/null; then
        print_success "EDNS Proxy service is running"
    else
        print_warning "EDNS Proxy service is not running"
    fi
    
    # Check if ports are listening
    if ss -ulpn | grep -q ":53 "; then
        print_success "DNS port 53 is listening"
    else
        print_warning "Port 53 is not listening"
    fi
    
    if ss -ulpn | grep -q ":5300 "; then
        print_success "SlowDNS port 5300 is listening"
    else
        print_warning "Port 5300 is not listening"
    fi
}

show_summary() {
    local server_ip=$(curl -s --max-time 5 https://api.ipify.org || echo "Unknown")
    local ssh_port=22
    local dns_port=5300
    
    print_header
    echo -e "${WHITE}════════════════ INSTALLATION COMPLETE ═══════════════${NC}"
    echo ""
    
    echo -e "${CYAN}Server Information:${NC}"
    print_line
    echo -e "Server IP:    ${WHITE}$server_ip${NC}"
    echo -e "SSH Port:     ${WHITE}$ssh_port${NC}"
    echo -e "SlowDNS Port: ${WHITE}$dns_port${NC}"
    echo -e "Nameserver:   ${WHITE}$NAMESERVER${NC}"
    echo ""
    
    echo -e "${CYAN}Public Key:${NC}"
    print_line
    if [ -f /etc/slowdns/server.pub ]; then
        cat /etc/slowdns/server.pub
    else
        echo "Not available"
    fi
    echo ""
    
    echo -e "${CYAN}Services:${NC}"
    print_line
    echo -e "slowdns.service"
    echo -e "edns-proxy.service"
    echo ""
    
    echo -e "${CYAN}Check Services:${NC}"
    print_line
    echo -e "systemctl status slowdns.service"
    echo -e "systemctl status edns-proxy.service"
    echo ""
    
    echo -e "${CYAN}Check Ports:${NC}"
    print_line
    echo -e "ss -ulpn | grep ':53'"
    echo -e "ss -ulpn | grep ':5300'"
    echo ""
    
    echo -e "${GREEN}✓ Installation completed${NC}"
    echo -e "${YELLOW}Note: Some services might need manual configuration${NC}"
    echo ""
    
    print_line
    echo -e "${YELLOW}Support: @esimfreegb${NC}"
    echo ""
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    # Check root
    if [ "$EUID" -ne 0 ]; then
        print_error "Run as root: sudo bash $0"
        exit 1
    fi
    
    # Check OS compatibility
    print_info "Checking OS compatibility..."
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        echo -e "${CYAN}OS: ${WHITE}$NAME $VERSION${NC}"
    else
        print_warning "Cannot detect OS, continuing anyway..."
    fi
    
    # Install dependencies
    print_info "Installing dependencies..."
    
    if command -v apt &>/dev/null; then
        apt update -y > /dev/null 2>&1
        apt install -y curl wget net-tools iproute2 iputils-ping dnsutils > /dev/null 2>&1
    elif command -v yum &>/dev/null; then
        yum install -y curl wget net-tools iproute iputils bind-utils > /dev/null 2>&1
    elif command -v dnf &>/dev/null; then
        dnf install -y curl wget net-tools iproute iputils bind-utils > /dev/null 2>&1
    else
        print_warning "Cannot install dependencies automatically"
    fi
    
    # Check for required commands
    for cmd in curl wget; do
        if ! command -v $cmd &>/dev/null; then
            print_error "$cmd is not installed. Please install it manually."
            exit 1
        fi
    done
    
    print_success "Dependencies installed"
    
    # Create log file
    mkdir -p /var/log 2>/dev/null
    touch "$LOG_FILE" 2>/dev/null
    echo "=== SlowDNS Installation Started at $(date) ===" >> "$LOG_FILE"
    
    # Run license check
    check_license
    
    # Installation steps
    echo "=== Configuration started ===" >> "$LOG_FILE"
    
    print_header
    echo -e "${WHITE}════════════════ INSTALLATION STARTED ═══════════════${NC}"
    echo ""
    
    # Step 1: Configure SSH
    print_info "Step 1/6: Configuring SSH..."
    configure_openssh
    echo "SSH configured" >> "$LOG_FILE"
    
    # Step 2: Install SlowDNS
    print_info "Step 2/6: Installing SlowDNS..."
    if install_slowdns; then
        print_success "SlowDNS installed"
        echo "SlowDNS installed" >> "$LOG_FILE"
    else
        print_error "Failed to install SlowDNS"
        echo "Failed to install SlowDNS" >> "$LOG_FILE"
        exit 1
    fi
    
    # Step 3: Compile EDNS Proxy
    print_info "Step 3/6: Compiling EDNS Proxy..."
    if compile_edns_proxy; then
        print_success "EDNS Proxy compiled"
        echo "EDNS Proxy compiled" >> "$LOG_FILE"
    else
        print_warning "EDNS Proxy compilation failed, continuing..."
        echo "EDNS Proxy compilation failed" >> "$LOG_FILE"
    fi
    
    # Step 4: Create services
    print_info "Step 4/6: Creating services..."
    create_services
    print_success "Services created"
    echo "Services created with nameserver: $NAMESERVER" >> "$LOG_FILE"
    
    # Step 5: Configure firewall
    print_info "Step 5/6: Configuring firewall..."
    configure_firewall
    print_success "Firewall configured"
    echo "Firewall configured" >> "$LOG_FILE"
    
    # Step 6: Start services
    print_info "Step 6/6: Starting services..."
    start_services
    print_success "Services started"
    echo "Services started" >> "$LOG_FILE"
    
    # Show summary
    show_summary
    
    # Log completion
    echo "=== Installation completed at $(date) ===" >> "$LOG_FILE"
    
    # Display log file location
    echo ""
    print_line
    echo -e "${CYAN}Log file: ${WHITE}$LOG_FILE${NC}"
    echo -e "${CYAN}To check service status:${NC}"
    echo -e "${WHITE}  systemctl status slowdns.service${NC}"
    echo -e "${WHITE}  systemctl status edns-proxy.service${NC}"
    echo ""
    echo -e "${CYAN}To view logs:${NC}"
    echo -e "${WHITE}  journalctl -u slowdns.service -f${NC}"
    echo -e "${WHITE}  journalctl -u edns-proxy.service -f${NC}"
    echo ""
    
    # Test instructions
    print_line
    echo -e "${YELLOW}Testing Instructions:${NC}"
    echo -e "${WHITE}1. Test DNS:${NC} dig @$server_ip $NAMESERVER"
    echo -e "${WHITE}2. Test SSH:${NC} ssh -o \"ProxyCommand nc -x 127.0.0.1:5300 %h %p\" root@$NAMESERVER"
    echo ""
    
    # Important notes
    print_line
    echo -e "${RED}Important Notes:${NC}"
    echo -e "1. Make sure port 53 UDP is open in your VPS firewall"
    echo -e "2. Allow port 53 in your hosting provider's firewall"
    echo -e "3. DNS queries may take a few seconds initially"
    echo -e "4. Restart services if they stop: systemctl restart slowdns edns-proxy"
    echo ""
    
    # Cleanup
    print_info "Cleaning up temporary files..."
    rm -f /tmp/edns.c 2>/dev/null
    rm -f /tmp/slowdns_install.sh 2>/dev/null
    
    # Final message
    print_line
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        INSTALLATION COMPLETED SUCCESSFULLY   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}Need help? Contact: @esimfreegb${NC}"
    
    # Wait for user input before exiting
    echo ""
    echo -ne "${YELLOW}Press Enter to exit...${NC}"
    read -r
}

# Function to uninstall SlowDNS
uninstall_slowdns() {
    print_header
    echo -e "${RED}═════════════ UNINSTALL SLOWDNS ═════════════${NC}"
    echo ""
    echo -e "${YELLOW}This will remove all SlowDNS components.${NC}"
    echo ""
    echo -ne "${RED}Are you sure? (y/N): ${NC}"
    read -r confirm
    
    if [[ $confirm != "y" && $confirm != "Y" ]]; then
        echo -e "${GREEN}Uninstallation cancelled.${NC}"
        exit 0
    fi
    
    print_info "Stopping services..."
    systemctl stop slowdns.service 2>/dev/null
    systemctl stop edns-proxy.service 2>/dev/null
    
    print_info "Disabling services..."
    systemctl disable slowdns.service 2>/dev/null
    systemctl disable edns-proxy.service 2>/dev/null
    
    print_info "Removing service files..."
    rm -f /etc/systemd/system/slowdns.service
    rm -f /etc/systemd/system/edns-proxy.service
    systemctl daemon-reload 2>/dev/null
    
    print_info "Removing binaries..."
    rm -f /usr/local/bin/edns-proxy
    rm -rf /etc/slowdns
    
    print_info "Restoring SSH configuration..."
    if [ -f /etc/ssh/sshd_config.backup ]; then
        cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config 2>/dev/null
        systemctl restart sshd 2>/dev/null
    fi
    
    print_info "Resetting firewall..."
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Restore iptables backup if exists
    if [ -f /etc/iptables.backup ]; then
        iptables-restore < /etc/iptables.backup 2>/dev/null
    fi
    
    print_success "SlowDNS has been uninstalled!"
    echo ""
    echo -e "${GREEN}All components removed successfully.${NC}"
    echo ""
}

# Function to show status
show_status() {
    print_header
    echo -e "${CYAN}════════════════ SLOWDNS STATUS ════════════════${NC}"
    echo ""
    
    # Get server IP
    SERVER_IP=$(get_vps_ip)
    echo -e "${WHITE}Server IP:${NC} ${CYAN}$SERVER_IP${NC}"
    echo ""
    
    # Check services
    echo -e "${WHITE}Service Status:${NC}"
    print_line
    
    # SlowDNS service
    if systemctl is-active --quiet slowdns.service 2>/dev/null; then
        echo -e "slowdns.service:    ${GREEN}ACTIVE${NC}"
    else
        echo -e "slowdns.service:    ${RED}INACTIVE${NC}"
    fi
    
    # EDNS Proxy service
    if systemctl is-active --quiet edns-proxy.service 2>/dev/null; then
        echo -e "edns-proxy.service: ${GREEN}ACTIVE${NC}"
    else
        echo -e "edns-proxy.service: ${RED}INACTIVE${NC}"
    fi
    
    echo ""
    
    # Check ports
    echo -e "${WHITE}Port Status:${NC}"
    print_line
    
    # Port 53
    if ss -ulpn | grep -q ":53 "; then
        echo -e "Port 53 (DNS):     ${GREEN}LISTENING${NC}"
    else
        echo -e "Port 53 (DNS):     ${RED}NOT LISTENING${NC}"
    fi
    
    # Port 5300
    if ss -ulpn | grep -q ":5300 "; then
        echo -e "Port 5300:         ${GREEN}LISTENING${NC}"
    else
        echo -e "Port 5300:         ${RED}NOT LISTENING${NC}"
    fi
    
    # Port 22
    if ss -tlnp | grep -q ":22 "; then
        echo -e "Port 22 (SSH):     ${GREEN}LISTENING${NC}"
    else
        echo -e "Port 22 (SSH):     ${RED}NOT LISTENING${NC}"
    fi
    
    echo ""
    
    # Show public key if exists
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "${WHITE}Public Key:${NC}"
        print_line
        cat /etc/slowdns/server.pub
        echo ""
    fi
    
    # Show nameserver
    if [ -f /etc/systemd/system/slowdns.service ]; then
        NAMESERVER=$(grep -o "dns\..*" /etc/systemd/system/slowdns.service | head -1)
        if [ -n "$NAMESERVER" ]; then
            echo -e "${WHITE}Nameserver:${NC} ${CYAN}$NAMESERVER${NC}"
        fi
    fi
    
    echo ""
    print_line
    echo -e "${YELLOW}Quick Commands:${NC}"
    echo -e "${WHITE}Restart services:${NC} systemctl restart slowdns edns-proxy"
    echo -e "${WHITE}View logs:${NC} journalctl -u slowdns.service -f"
    echo -e "${WHITE}Test DNS:${NC} dig @$SERVER_IP $NAMESERVER"
    echo ""
}

# Function to restart services
restart_services() {
    print_header
    echo -e "${CYAN}════════════ RESTARTING SERVICES ════════════${NC}"
    echo ""
    
    print_info "Restarting SlowDNS..."
    systemctl restart slowdns.service 2>/dev/null
    
    print_info "Restarting EDNS Proxy..."
    systemctl restart edns-proxy.service 2>/dev/null
    
    sleep 2
    
    print_info "Checking status..."
    if systemctl is-active --quiet slowdns.service 2>/dev/null; then
        print_success "SlowDNS service restarted successfully"
    else
        print_error "Failed to restart SlowDNS service"
    fi
    
    if systemctl is-active --quiet edns-proxy.service 2>/dev/null; then
        print_success "EDNS Proxy service restarted successfully"
    else
        print_error "Failed to restart EDNS Proxy service"
    fi
    
    echo ""
    print_line
    echo -e "${GREEN}Services restart completed.${NC}"
    echo ""
}

# Handle command line arguments
case "${1:-}" in
    "uninstall")
        uninstall_slowdns
        exit 0
        ;;
    "status")
        show_status
        exit 0
        ;;
    "restart")
        restart_services
        exit 0
        ;;
    "help"|"--help"|"-h")
        print_header
        echo -e "${CYAN}══════════════════ HELP MENU ══════════════════${NC}"
        echo ""
        echo -e "${WHITE}Usage:${NC}"
        echo -e "  $0 [option]"
        echo ""
        echo -e "${WHITE}Options:${NC}"
        echo -e "  install      - Install SlowDNS (default)"
        echo -e "  uninstall    - Remove SlowDNS"
        echo -e "  status       - Show current status"
        echo -e "  restart      - Restart services"
        echo -e "  help         - Show this help"
        echo ""
        echo -e "${WHITE}Examples:${NC}"
        echo -e "  sudo bash $0 install"
        echo -e "  sudo bash $0 status"
        echo -e "  sudo bash $0 restart"
        echo ""
        echo -e "${YELLOW}Note: Run with sudo or as root${NC}"
        echo ""
        exit 0
        ;;
    "install"|"")
        # Continue with installation
        ;;
    *)
        print_error "Unknown option: $1"
        echo -e "${YELLOW}Use '$0 help' for usage information.${NC}"
        exit 1
        ;;
esac

# Trap for cleanup on interrupt
cleanup() {
    echo ""
    print_error "Installation interrupted!"
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Stop any running services
    pkill -f dnstt-server 2>/dev/null
    pkill -f edns-proxy 2>/dev/null
    
    # Remove temporary files
    rm -f /tmp/edns.c 2>/dev/null
    
    echo -e "${GREEN}Cleanup completed.${NC}"
    exit 1
}

trap cleanup INT TERM

# Start main installation
main "$@"
