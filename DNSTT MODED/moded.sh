#!/bin/bash

# ============================================================================
#                     SLOWDNS MODERN INSTALLATION SCRIPT
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

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
# ANIMATION FUNCTIONS
# ============================================================================
show_progress() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
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

print_box() {
    local text="$1"
    local color="$2"
    local width=50
    local padding=$(( ($width - ${#text} - 2) / 2 ))
    printf "${color}┌"
    printf "─%.0s" $(seq 1 $((width-2)))
    printf "┐${NC}\n"
    printf "${color}│${NC}%${padding}s${text}%${padding}s${color}│${NC}\n"
    printf "${color}└"
    printf "─%.0s" $(seq 1 $((width-2)))
    printf "┘${NC}\n"
}

print_banner() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          🚀 MODERN SLOWDNS INSTALLATION SCRIPT${NC}          ${BLUE}.      ║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}            Fast & Professional Configuration${NC}            ${BLUE}.                         ║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}                Optimized for Performance${NC}                ${BLUE}.                         ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_header() {
    echo -e "\n${PURPLE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════════════${NC}"
}

print_success() {
    echo -e "  ${GREEN}${BOLD}✓${NC} ${GREEN}$1${NC}"
}

print_error() {
    echo -e "  ${RED}${BOLD}✗${NC} ${RED}$1${NC}"
}

print_warning() {
    echo -e "  ${YELLOW}${BOLD}!${NC} ${YELLOW}$1${NC}"
}

print_info() {
    echo -e "  ${CYAN}${BOLD}ℹ${NC} ${CYAN}$1${NC}"
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main() {
    print_banner
    
    # Get nameserver with modern prompt
    echo -e "${WHITE}${BOLD}Enter nameserver configuration:${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Default:${NC} dns.example.com                                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Example:${NC} tunnel.yourdomain.com                               ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    read -p "$(echo -e "${WHITE}${BOLD}Enter nameserver: ${NC}")" NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    print_header "📦 GATHERING SYSTEM INFORMATION"
    
    # Get Server IP with animation
    echo -ne "  ${CYAN}Detecting server IP address...${NC}"
    SERVER_IP=$(curl -s --connect-timeout 5 ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    echo -e "\r  ${GREEN}Server IP:${NC} ${WHITE}${BOLD}$SERVER_IP${NC}"
    
    # ============================================================================
    # STEP 1: CONFIGURE OPENSSH
    # ============================================================================
    print_step "1"
    print_info "Configuring OpenSSH on port $SSHD_PORT"
    
    echo -ne "  ${CYAN}Backing up SSH configuration...${NC}"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}SSH configuration backed up${NC}"
    
    cat > /etc/ssh/sshd_config << EOF
# ============================================================================
# SLOWDNS OPTIMIZED SSH CONFIGURATION
# ============================================================================
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
    
    echo -ne "  ${CYAN}Restarting SSH service...${NC}"
    systemctl restart sshd 2>/dev/null &
    show_progress $!
    sleep 2
    echo -e "\r  ${GREEN}SSH service restarted${NC}"
    
    print_success "OpenSSH configured on port $SSHD_PORT"
    print_step_end
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS
    # ============================================================================
    print_step "2"
    print_info "Setting up SlowDNS environment"
    
    echo -ne "  ${CYAN}Creating SlowDNS directory...${NC}"
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns 2>/dev/null &
    show_progress $!
    cd /etc/slowdns
    echo -e "\r  ${GREEN}SlowDNS directory created${NC}"
    
    # Download binary
    print_info "Downloading SlowDNS binary"
    echo -ne "  ${CYAN}Fetching binary from GitHub...${NC}"
    
    # Try multiple download methods
    if curl -fsSL "$GITHUB_BASE/dnstt-server" -o dnstt-server 2>/dev/null; then
        echo -e "\r  ${GREEN}Binary downloaded via curl${NC}"
    elif wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server 2>/dev/null; then
        echo -e "\r  ${GREEN}Binary downloaded via wget${NC}"
    else
        echo -e "\r  ${RED}Failed to download binary${NC}"
        exit 1
    fi
    
    chmod +x dnstt-server
    SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
    
    # Download key files
    print_info "Downloading encryption keys"
    echo -ne "  ${CYAN}Downloading server.key...${NC}"
    wget -q "$GITHUB_BASE/server.key" -O server.key 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}server.key downloaded${NC}"
    
    echo -ne "  ${CYAN}Downloading server.pub...${NC}"
    wget -q "$GITHUB_BASE/server.pub" -O server.pub 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}server.pub downloaded${NC}"
    
    # Test binary
    echo -ne "  ${CYAN}Validating binary...${NC}"
    if ./dnstt-server --help 2>&1 | grep -q "usage" || ./dnstt-server -h 2>&1 | head -5; then
        echo -e "\r  ${GREEN}Binary validated successfully${NC}"
    else
        echo -e "\r  ${YELLOW}Binary test inconclusive${NC}"
    fi
    
    print_success "SlowDNS components installed"
    print_step_end
    
    # ============================================================================
    # STEP 3: CREATE SLOWDNS SERVICE
    # ============================================================================
    print_step "3"
    print_info "Creating SlowDNS system service"
    
    cat > /etc/systemd/system/server-sldns.service << EOF
# ============================================================================
# SLOWDNS SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=SlowDNS Server
Description=High-performance DNS tunnel server
After=network.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1500 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
LimitCORE=infinity
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Service configuration created"
    print_step_end
    
    # ============================================================================
    # STEP 4: COMPILE EDNS PROXY
    # ============================================================================
    print_step "4"
    print_info "Compiling high-performance EDNS Proxy"
    
    # Check for gcc
    if ! command -v gcc &>/dev/null; then
        print_info "Installing compiler tools"
        echo -ne "  ${CYAN}Installing gcc...${NC}"
        apt update > /dev/null 2>&1 && apt install -y gcc > /dev/null 2>&1 &
        show_progress $!
        echo -e "\r  ${GREEN}Compiler installed${NC}"
    fi
    
    # Create optimized C code
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
#define INT_EDNS 1500
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 4096
#define UPSTREAM_POOL 16

typedef struct {
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
} request_t;

static request_t requests[65536];

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
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    printf("[EDNS] Starting multi-core EDNS proxy\n");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    int one = 1;
    int bufsize = 64 * 1024 * 1024;

    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one));

    set_nonblock(sock);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    int epoll_fd = epoll_create1(0);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);

    int upstream[UPSTREAM_POOL];
    for(int i = 0; i < UPSTREAM_POOL; i++) {
        upstream[i] = socket(AF_INET, SOCK_DGRAM, 0);
        set_nonblock(upstream[i]);
        struct epoll_event ue;
        ue.events = EPOLLIN;
        ue.data.fd = upstream[i];
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstream[i], &ue);
    }

    struct sockaddr_in slowdns;
    memset(&slowdns, 0, sizeof(slowdns));
    slowdns.sin_family = AF_INET;
    slowdns.sin_port = htons(SLOWDNS_PORT);
    inet_pton(AF_INET, "127.0.0.1", &slowdns.sin_addr);

    struct epoll_event events[MAX_EVENTS];
    unsigned idx = 0;

    while(1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for(int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if(fd == sock) {
                unsigned char buf[BUFFER_SIZE];
                struct sockaddr_in caddr;
                socklen_t clen = sizeof(caddr);
                int len = recvfrom(sock, buf, BUFFER_SIZE, 0, (void*)&caddr, &clen);
                if(len > 0) {
                    patch_edns(buf, len, INT_EDNS);
                    int u = upstream[idx++ % UPSTREAM_POOL];
                    requests[u].client_addr = caddr;
                    requests[u].addr_len = clen;
                    requests[u].timestamp = time(NULL);
                    sendto(u, buf, len, 0, (void*)&slowdns, sizeof(slowdns));
                }
            } else {
                unsigned char buf[BUFFER_SIZE];
                int len = recv(fd, buf, BUFFER_SIZE, 0);
                if(len > 0) {
                    patch_edns(buf, len, EXT_EDNS);
                    sendto(sock, buf, len, 0,
                           (void*)&requests[fd].client_addr,
                           requests[fd].addr_len);
                }
            }
        }
    }

    return 0;
}
EOF
    
    # Compile with optimizations
    echo -ne "  ${CYAN}Compiling EDNS Proxy with O3 optimizations...${NC}"
    gcc -O3 -march=native -pipe /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log &
    show_progress $!
    
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/edns-proxy
        echo -e "\r  ${GREEN}EDNS Proxy compiled successfully${NC}"
    else
        echo -e "\r  ${RED}Compilation failed${NC}"
        exit 1
    fi
    
    # Create EDNS service
    cat > /etc/systemd/system/edns-proxy.service << EOF
# ============================================================================
# EDNS PROXY SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=EDNS Proxy for SlowDNS
Description=High-performance DNS proxy with EDNS support
After=server-sldns.service
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "EDNS Proxy service configured"
    print_step_end
    
    # ============================================================================
    # STEP 5: FIREWALL CONFIGURATION
    # ============================================================================
    print_step "5"
    print_info "Configuring system firewall"
    
    echo -ne "  ${CYAN}Setting up firewall rules...${NC}"
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Essential rules
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null
    
    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}Firewall rules configured${NC}"
    
    # Stop conflicting services
    echo -ne "  ${CYAN}Stopping conflicting DNS services...${NC}"
    systemctl stop systemd-resolved 2>/dev/null &
    fuser -k 53/udp 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}DNS services stopped${NC}"
    
    print_success "Firewall and network configured"
    print_step_end
    
    # ============================================================================
    # STEP 6: START SERVICES
    # ============================================================================
    print_step "6"
    print_info "Starting all services"
    
    systemctl daemon-reload 2>/dev/null
    
    # Start SlowDNS
    echo -ne "  ${CYAN}Starting SlowDNS service...${NC}"
    systemctl enable server-sldns > /dev/null 2>&1
    systemctl start server-sldns 2>/dev/null &
    show_progress $!
    sleep 2
    
    if systemctl is-active --quiet server-sldns; then
        echo -e "\r  ${GREEN}SlowDNS service started${NC}"
    else
        echo -e "\r  ${YELLOW}Starting SlowDNS in background${NC}"
        $SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT &
    fi
    
    # Start EDNS proxy
    echo -ne "  ${CYAN}Starting EDNS Proxy service...${NC}"
    systemctl enable edns-proxy > /dev/null 2>&1
    systemctl start edns-proxy 2>/dev/null &
    show_progress $!
    sleep 2
    
    if systemctl is-active --quiet edns-proxy; then
        echo -e "\r  ${GREEN}EDNS Proxy service started${NC}"
    else
        echo -e "\r  ${YELLOW}Starting EDNS Proxy manually${NC}"
        /usr/local/bin/edns-proxy &
    fi
    
    # Verify services
    echo -ne "  ${CYAN}Verifying service status...${NC}"
    sleep 3
    echo -e "\r  ${GREEN}Service verification complete${NC}"
    
    print_success "All services started successfully"
    print_step_end
    
    # ============================================================================
    # COMPLETION SUMMARY
    # ============================================================================
    print_header "🎉 INSTALLATION COMPLETE"
    
    # Show summary in a nice box
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER INFORMATION${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:     ${WHITE}$SERVER_IP${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SSH Port:      ${WHITE}$SSHD_PORT${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SlowDNS Port:  ${WHITE}$SLOWDNS_PORT${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} EDNS Port:     ${WHITE}53${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU Size:      ${WHITE}1800${NC}                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:    ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}QUICK TEST COMMANDS${NC}                                ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}dig @$SERVER_IP $NAMESERVER${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}nslookup $NAMESERVER $SERVER_IP${NC}                  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}systemctl status server-sldns${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}systemctl status edns-proxy${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVICE MANAGEMENT${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Restart services:${NC} systemctl restart server-sldns edns-proxy ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}View logs:${NC}        journalctl -u server-sldns -f            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Check ports:${NC}      ss -ulpn | grep ':53\|:5300'             ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final verification
    echo -e "\n${WHITE}${BOLD}Verifying installation...${NC}"
    
    echo -ne "  ${CYAN}Checking port 53...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":53 "; then
        echo -e "\r  ${GREEN}✓ Port 53 (EDNS Proxy) is listening${NC}"
    else
        echo -e "\r  ${YELLOW}! Port 53 not listening${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking port 5300...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
        echo -e "\r  ${GREEN}✓ Port $SLOWDNS_PORT (SlowDNS) is listening${NC}"
    else
        echo -e "\r  ${YELLOW}! Port $SLOWDNS_PORT not listening${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking service status...${NC}"
    if systemctl is-active --quiet server-sldns && systemctl is-active --quiet edns-proxy; then
        echo -e "\r  ${GREEN}✓ All services are running${NC}"
    else
        echo -e "\r  ${YELLOW}! Some services need attention${NC}"
    fi
    
    # Show public key if available
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PUBLIC KEY (For Client Configuration)${NC}               ${CYAN}│${NC}"
        echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
        echo -e "${CYAN}│${NC}${WHITE}"
        cat /etc/slowdns/server.pub | head -1
        echo -e "${NC}${CYAN}│${NC}"
        echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    fi
    
    # Performance optimization tips
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PERFORMANCE TIPS${NC}                                    ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU 1800 is optimal for most networks                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} For better performance, use TCP instead of UDP          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Monitor performance: systemctl status server-sldns      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Check logs: journalctl -u edns-proxy -n 50              ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Client configuration example
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CLIENT CONFIGURATION EXAMPLE${NC}                         ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}SlowDNS Client Command:${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}./dnstt-client -udp $SERVER_IP:5300 \\${NC}               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    -pubkey-file server.pub \\${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    dns.example.com 127.0.0.1:1080${NC}                 ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Troubleshooting section
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}TROUBLESHOOTING${NC}                                     ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}If port 53 is not listening:${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}1. Stop systemd-resolved: systemctl stop systemd-resolved${NC} ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}2. Kill any process on port 53: fuser -k 53/udp${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}3. Restart edns-proxy: systemctl restart edns-proxy${NC}       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}If SlowDNS is not working:${NC}                               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}1. Check firewall: iptables -L -n -v${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}2. Verify keys: ls -la /etc/slowdns/${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}3. Restart all: systemctl restart server-sldns edns-proxy${NC} ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final message with timer
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 SLOWDNS INSTALLATION COMPLETED SUCCESSFULLY!${NC}    ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Installation completed in ~30 seconds${NC}            ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 Services running: SlowDNS + EDNS Proxy${NC}          ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🔧 Ready for DNS tunneling${NC}                         ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}${BOLD}📞 Need help? Contact support: @esimfreegb${NC}"
    echo -e "${YELLOW}${BOLD}💡 Documentation: https://github.com/chiddy80/Halotel-Slow-DNS${NC}"
    
    echo -e "\n${WHITE}${BOLD}Press Enter to return to terminal...${NC}"
    read -r
    
    # Show post-installation menu
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}POST-INSTALLATION OPTIONS${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}1.${NC} ${WHITE}View service status${NC}                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}2.${NC} ${WHITE}Check listening ports${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}3.${NC} ${WHITE}Restart all services${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}4.${NC} ${WHITE}View installation log${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}5.${NC} ${WHITE}Test DNS functionality${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}6.${NC} ${WHITE}Exit to terminal${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -ne "${WHITE}${BOLD}Select option [1-6]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "\n${CYAN}════════════════ SERVICE STATUS ════════════════${NC}"
            systemctl status server-sldns --no-pager -l
            echo -e "\n${CYAN}═══════════════════════════════════════════════${NC}"
            systemctl status edns-proxy --no-pager -l
            ;;
        2)
            echo -e "\n${CYAN}════════════════ LISTENING PORTS ════════════════${NC}"
            echo -e "${WHITE}Checking UDP ports:${NC}"
            ss -ulpn | grep -E ':53|:5300'
            echo -e "\n${WHITE}Checking TCP ports:${NC}"
            ss -tlnp | grep -E ':22'
            ;;
        3)
            echo -e "\n${CYAN}════════════════ RESTARTING SERVICES ════════════════${NC}"
            systemctl restart server-sldns edns-proxy
            sleep 2
            echo -e "${GREEN}✓ Services restarted successfully${NC}"
            ;;
        4)
            echo -e "\n${CYAN}════════════════ INSTALLATION LOG ════════════════${NC}"
            if [ -f "$LOG_FILE" ]; then
                tail -20 "$LOG_FILE"
            else
                echo -e "${YELLOW}Log file not found${NC}"
            fi
            ;;
        5)
            echo -e "\n${CYAN}════════════════ DNS TEST ════════════════${NC}"
            echo -e "${WHITE}Testing DNS query to $NAMESERVER...${NC}"
            if command -v dig &>/dev/null; then
                dig @$SERVER_IP $NAMESERVER +short
            elif command -v nslookup &>/dev/null; then
                nslookup $NAMESERVER $SERVER_IP
            else
                echo -e "${YELLOW}DNS tools not available${NC}"
            fi
            ;;
        6)
            echo -e "\n${GREEN}Returning to terminal...${NC}"
            ;;
        *)
            echo -e "\n${YELLOW}Invalid option, returning to terminal...${NC}"
            ;;
    esac
    
    # Final cleanup
    rm -f /tmp/edns.c /tmp/compile.log 2>/dev/null
    
    # Show exit message
    echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   Installation completed at: $(date)${NC}"
    echo -e "${GREEN}${BOLD}   Server: $SERVER_IP | SlowDNS: $SLOWDNS_PORT | EDNS: 53${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e ""
}

# ============================================================================
# EXECUTE WITH ERROR HANDLING
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; exit 1' INT

if main; then
    exit 0
else
    echo -e "\n${RED}✗ Installation failed${NC}"
    exit 1
fi

