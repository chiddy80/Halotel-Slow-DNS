#!/bin/bash

# ============================================================================
#           SLOWDNS MODERN INSTALLATION SCRIPT - CENTOS COMPATIBLE
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# DETECT OS AND SET PACKAGE MANAGER
# ============================================================================
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        echo -e "\033[0;31m[✗]\033[0m Cannot detect OS"
        exit 1
    fi
}

setup_package_manager() {
    case $OS in
        ubuntu|debian)
            PKG_MGR="apt"
            INSTALL_CMD="apt install -y"
            UPDATE_CMD="apt update"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            PKG_MGR="yum"
            INSTALL_CMD="yum install -y"
            UPDATE_CMD="yum check-update || true"
            if command -v dnf &>/dev/null; then
                PKG_MGR="dnf"
                INSTALL_CMD="dnf install -y"
                UPDATE_CMD="dnf check-update || true"
            fi
            ;;
        *)
            echo -e "\033[0;31m[✗]\033[0m Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    echo -e "\033[0;32m[✓]\033[0m Detected OS: $OS $VER"
    echo -e "\033[0;32m[✓]\033[0m Using package manager: $PKG_MGR"
}

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
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# INSTALL DEPENDENCIES (OS-SPECIFIC)
# ============================================================================
install_dependencies() {
    echo -e "\n${CYAN}${BOLD}Installing dependencies for $OS...${NC}"
    
    case $OS in
        ubuntu|debian)
            $UPDATE_CMD
            $INSTALL_CMD curl wget gcc make iptables net-tools
            $INSTALL_CMD openssh-server
            ;;
        centos|rhel|rocky|almalinux)
            # Disable firewalld first (conflicts with iptables)
            systemctl stop firewalld 2>/dev/null || true
            systemctl disable firewalld 2>/dev/null || true
            
            $INSTALL_CMD epel-release
            $INSTALL_CMD curl wget gcc make iptables iptables-services net-tools
            $INSTALL_CMD openssh-server openssh-clients
            
            # Enable and start iptables
            systemctl enable iptables
            systemctl start iptables
            ;;
        fedora)
            $INSTALL_CMD curl wget gcc make iptables iptables-services net-tools
            $INSTALL_CMD openssh-server openssh-clients
            ;;
    esac
    
    echo -e "${GREEN}${BOLD}✓ Dependencies installed${NC}"
}

# ============================================================================
# DOWNLOAD UTILITIES (WITH FALLBACK)
# ============================================================================
download_file() {
    local url="$1"
    local output="$2"
    
    echo -ne "  ${CYAN}Downloading $(basename "$output")...${NC}"
    
    # Try curl first
    if curl -fsSL --connect-timeout 30 "$url" -o "$output" 2>/dev/null; then
        echo -e "\r  ${GREEN}Downloaded via curl${NC}"
        return 0
    fi
    
    # Try wget
    if wget -q --timeout=30 "$url" -O "$output" 2>/dev/null; then
        echo -e "\r  ${GREEN}Downloaded via wget${NC}"
        return 0
    fi
    
    echo -e "\r  ${YELLOW}Download failed, trying alternative...${NC}"
    return 1
}

# ============================================================================
# CONFIGURE OPENSSH
# ============================================================================
configure_ssh() {
    echo -e "\n${CYAN}${BOLD}Configuring OpenSSH...${NC}"
    
    # Backup SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
    
    # Configure SSH
    cat > /etc/ssh/sshd_config << EOF
# SlowDNS Optimized SSH Configuration
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
    
    # Restart SSH (different service names on different OS)
    case $OS in
        ubuntu|debian)
            systemctl restart ssh
            ;;
        centos|rhel|fedora|rocky|almalinux)
            systemctl restart sshd
            ;;
    esac
    
    echo -e "${GREEN}${BOLD}✓ SSH configured on port $SSHD_PORT${NC}"
}

# ============================================================================
# SETUP SLOWDNS
# ============================================================================
setup_slowdns() {
    echo -e "\n${CYAN}${BOLD}Setting up SlowDNS...${NC}"
    
    # Create directory
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download binary with multiple attempts
    echo -e "  ${YELLOW}Downloading SlowDNS components...${NC}"
    
    # Try multiple sources
    if ! download_file "$GITHUB_BASE/dnstt-server" "dnstt-server"; then
        echo -e "  ${YELLOW}Trying alternative download methods...${NC}"
        
        # Try direct download from CDN
        download_file "https://cdn.jsdelivr.net/gh/chiddy80/Halotel-Slow-DNS/DNSTT%20MODED/dnstt-server" "dnstt-server" || \
        download_file "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED/dnstt-server" "dnstt-server" || {
            echo -e "  ${RED}Failed to download SlowDNS binary${NC}"
            echo -e "  ${YELLOW}You may need to download it manually and place in /etc/slowdns/${NC}"
            return 1
        }
    fi
    
    # Download keys
    download_file "$GITHUB_BASE/server.key" "server.key" || true
    download_file "$GITHUB_BASE/server.pub" "server.pub" || true
    
    # Make executable
    chmod +x dnstt-server
    
    echo -e "${GREEN}${BOLD}✓ SlowDNS installed${NC}"
}

# ============================================================================
# COMPILE EDNS PROXY (COMPATIBLE WITH CENTOS)
# ============================================================================
compile_edns_proxy() {
    echo -e "\n${CYAN}${BOLD}Compiling EDNS Proxy...${NC}"
    
    # Check for gcc
    if ! command -v gcc &>/dev/null; then
        echo -e "  ${YELLOW}Installing gcc...${NC}"
        $INSTALL_CMD gcc
    fi
    
    # Create simple EDNS proxy C code
    cat > /tmp/edns.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096

int main() {
    printf("[EDNS Proxy] Starting on port 53\n");
    
    // Create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Allow port reuse
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind to port 53
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port %d\n", LISTEN_PORT);
    
    // Main loop
    while (1) {
        unsigned char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Receive from client
        int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                         (struct sockaddr*)&client_addr, &client_len);
        if (len > 0) {
            // Forward to SlowDNS
            int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (up_sock >= 0) {
                struct sockaddr_in up_addr;
                memset(&up_addr, 0, sizeof(up_addr));
                up_addr.sin_family = AF_INET;
                up_addr.sin_port = htons(SLOWDNS_PORT);
                inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                
                sendto(up_sock, buffer, len, 0,
                       (struct sockaddr*)&up_addr, sizeof(up_addr));
                
                // Receive response
                int up_len = recvfrom(up_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
                if (up_len > 0) {
                    // Send back to client
                    sendto(sock, buffer, up_len, 0,
                           (struct sockaddr*)&client_addr, client_len);
                }
                
                close(up_sock);
            }
        }
    }
    
    close(sock);
    return 0;
}
EOF
    
    # Compile
    echo -ne "  ${CYAN}Compiling EDNS Proxy...${NC}"
    if gcc -O2 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/dev/null; then
        chmod +x /usr/local/bin/edns-proxy
        echo -e "\r  ${GREEN}EDNS Proxy compiled${NC}"
    else
        echo -e "\r  ${YELLOW}Compilation failed, using simple script fallback${NC}"
        # Create fallback shell script
        create_edns_fallback
    fi
}

create_edns_fallback() {
    cat > /usr/local/bin/edns-proxy << 'EOF'
#!/bin/bash
# Simple UDP proxy fallback

LISTEN_PORT=53
SLOWDNS_PORT=5300
BUFFER_SIZE=4096

echo "[EDNS Fallback] Starting on port $LISTEN_PORT"

# Use socat if available
if command -v socat &>/dev/null; then
    socat UDP-LISTEN:$LISTEN_PORT,fork,reuseaddr UDP:127.0.0.1:$SLOWDNS_PORT &
    echo "Using socat for proxy"
    wait
    exit 0
fi

# Use netcat if available
if command -v nc &>/dev/null; then
    echo "Using netcat (may not work perfectly)"
    while true; do
        nc -l -u -p $LISTEN_PORT -c "nc -u 127.0.0.1 $SLOWDNS_PORT"
    done
    exit 0
fi

echo "No proxy tools available. Install socat or netcat."
exit 1
EOF
    
    chmod +x /usr/local/bin/edns-proxy
    echo -e "  ${YELLOW}Created shell script fallback${NC}"
}

# ============================================================================
# CONFIGURE FIREWALL (OS-SPECIFIC)
# ============================================================================
configure_firewall() {
    echo -e "\n${CYAN}${BOLD}Configuring firewall...${NC}"
    
    case $OS in
        ubuntu|debian)
            # Ubuntu/Debian iptables
            iptables -F
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A OUTPUT -o lo -j ACCEPT
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
            iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
            iptables -A INPUT -p udp --dport 53 -j ACCEPT
            iptables -A INPUT -p tcp --dport 53 -j ACCEPT
            iptables -P INPUT DROP
            
            # Save rules if iptables-persistent exists
            if command -v netfilter-persistent &>/dev/null; then
                netfilter-persistent save
            fi
            ;;
            
        centos|rhel|fedora|rocky|almalinux)
            # CentOS/RHEL - use iptables-services
            iptables -F
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A OUTPUT -o lo -j ACCEPT
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
            iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
            iptables -A INPUT -p udp --dport 53 -j ACCEPT
            iptables -A INPUT -p tcp --dport 53 -j ACCEPT
            iptables -P INPUT DROP
            
            # Save iptables rules
            iptables-save > /etc/sysconfig/iptables
            
            # Disable firewalld if enabled
            systemctl stop firewalld 2>/dev/null || true
            systemctl disable firewalld 2>/dev/null || true
            ;;
    esac
    
    # Stop conflicting DNS services
    systemctl stop systemd-resolved 2>/dev/null || true
    
    echo -e "${GREEN}${BOLD}✓ Firewall configured${NC}"
}

# ============================================================================
# CREATE SERVICES (SYSTEMD COMPATIBLE)
# ============================================================================
create_services() {
    local nameserver="$1"
    
    echo -e "\n${CYAN}${BOLD}Creating system services...${NC}"
    
    # SlowDNS service
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :$SLOWDNS_PORT -mtu 1350 -privkey-file /etc/slowdns/server.key $nameserver 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # EDNS Proxy service
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy
After=slowdns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}${BOLD}✓ Services created${NC}"
}

# ============================================================================
# START SERVICES
# ============================================================================
start_services() {
    echo -e "\n${CYAN}${BOLD}Starting services...${NC}"
    
    systemctl enable slowdns.service
    systemctl enable edns-proxy.service
    
    systemctl start slowdns.service
    systemctl start edns-proxy.service
    
    sleep 2
    
    # Check if services are running
    if systemctl is-active --quiet slowdns.service && \
       systemctl is-active --quiet edns-proxy.service; then
        echo -e "${GREEN}${BOLD}✓ Services started successfully${NC}"
    else
        echo -e "${YELLOW}⚠ Some services may need manual start${NC}"
        echo -e "  ${WHITE}Try: systemctl status slowdns edns-proxy${NC}"
    fi
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          SLOWDNS INSTALLATION SCRIPT (Multi-OS)${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}        Compatible with Ubuntu/Debian/CentOS/RHEL${NC}        ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    
    # Detect OS
    detect_os
    setup_package_manager
    
    # Get nameserver
    echo -e "\n${WHITE}Enter nameserver (e.g., dns.example.com):${NC}"
    read -p "Nameserver [dns.example.com]: " NAMESERVER
    NAMESERVER=${NAMESERVER:-"dns.example.com"}
    
    # Installation steps
    install_dependencies
    configure_ssh
    setup_slowdns
    compile_edns_proxy
    configure_firewall
    create_services "$NAMESERVER"
    start_services
    
    # Get server IP
    SERVER_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    
    # Show summary
    echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}${WHITE}            INSTALLATION COMPLETE!${NC}                     ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}${CYAN}            Server: $SERVER_IP${NC}                          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}${CYAN}            SlowDNS Port: $SLOWDNS_PORT${NC}                 ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}${CYAN}            EDNS Port: 53${NC}                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}${CYAN}            Nameserver: $NAMESERVER${NC}                     ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}Test your installation:${NC}"
    echo -e "  ${WHITE}dig @$SERVER_IP $NAMESERVER${NC}"
    echo -e "  ${WHITE}systemctl status slowdns${NC}"
    echo -e "  ${WHITE}ss -ulpn | grep ':53\|:5300'${NC}"
    
    echo -e "\n${YELLOW}If port 53 is in use:${NC}"
    echo -e "  ${WHITE}systemctl stop systemd-resolved${NC}"
    echo -e "  ${WHITE}fuser -k 53/udp${NC}"
    echo -e "  ${WHITE}systemctl restart edns-proxy${NC}"
}

# ============================================================================
# RUN WITH ERROR HANDLING
# ============================================================================
trap 'echo -e "\n${RED}Installation interrupted!${NC}"; exit 1' INT

if main; then
    exit 0
else
    echo -e "\n${RED}Installation failed${NC}"
    exit 1
fi
