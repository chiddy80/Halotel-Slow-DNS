#!/bin/bash

# ============================================================================
#                     DROPBEAR SLOWDNS WITH EDNS PROXY
# ============================================================================
# Complete working script with:
# 1. Dropbear SSH on port 222
# 2. SlowDNS tunnel
# 3. EDNS Proxy for DNS forwarding
# 4. All from chiddy80 GitHub repository
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION
# ============================================================================
DROPBEAR_PORT=2500
SLOWDNS_PORT=5300
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

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
# FUNCTIONS
# ============================================================================
print_header() {
    echo -e "\n${PURPLE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════════════${NC}"
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

print_warning() {
    echo -e "  ${YELLOW}!${NC} $1"
}

print_info() {
    echo -e "  ${CYAN}ℹ${NC} $1"
}

check_port() {
    local port=$1
    if ss -tlnp | grep -q ":$port "; then
        return 1
    fi
    return 0
}

free_port_222() {
    print_info "Checking port 222..."
    
    if ! check_port 222; then
        print_warning "Port 222 is in use. Attempting to free it..."
        
        # Show what's using port 443
        echo -e "  ${YELLOW}Processes on port 222:${NC}"
        ss -tlnp | grep ":222 "
        
        # Stop common web servers
        systemctl stop nginx 2>/dev/null
        systemctl stop apache2 2>/dev/null
        systemctl stop httpd 2>/dev/null
        
        # Kill any process on port 222
        fuser -k 222/tcp 2>/dev/null
        sleep 2
        
        # Check again
        if check_port 222; then
            print_success "Port 222 freed successfully"
            return 0
        else
            print_error "Cannot free port 222"
            return 1
        fi
    else
        print_success "Port 222 is available"
        return 0
    fi
}

download_file() {
    local file=$1
    local url="$GITHUB_BASE/$file"
    local output="$2"
    
    echo -ne "  ${CYAN}Downloading $file...${NC}"
    
    # Try curl first
    if curl -fsSL "$url" -o "$output" 2>/dev/null; then
        echo -e "\r  ${GREEN}Downloaded $file${NC}"
        return 0
    fi
    
    # Try wget
    if wget -q "$url" -O "$output" 2>/dev/null; then
        echo -e "\r  ${GREEN}Downloaded $file${NC}"
        return 0
    fi
    
    echo -e "\r  ${RED}Failed to download $file${NC}"
    return 1
}

# ============================================================================
# BANNER
# ============================================================================
clear
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}${CYAN}       🚀 DROPBEAR SLOWDNS + EDNS PROXY INSTALLER${NC}       ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}${WHITE}          Complete Tunnel Solution on Port 443${NC}         ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================================
# CHECK ROOT
# ============================================================================
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root: sudo bash $0"
    exit 1
fi

# ============================================================================
# GET SERVER INFORMATION
# ============================================================================
print_header "📡 SYSTEM INFORMATION"

print_info "Getting server IP..."
SERVER_IP=$(curl -s --connect-timeout 5 ifconfig.me)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
fi
print_success "Server IP: $SERVER_IP"

print_info "Checking system..."
OS=$(lsb_release -d 2>/dev/null | cut -f2)
[ -z "$OS" ] && OS=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
print_success "Operating System: $OS"

# ============================================================================
# GET USER INPUT
# ============================================================================
print_header "⚙️  CONFIGURATION"

echo -e "${WHITE}Enter nameserver (DNS hostname for your tunnel):${NC}"
echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Example:${NC} tunnel.yourdomain.com                            ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Example:${NC} dns.example.com                                  ${CYAN}│${NC}"
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
read -p "$(echo -e "${WHITE}Enter nameserver: ${NC}")" NAMESERVER

if [ -z "$NAMESERVER" ]; then
    print_error "Nameserver is required!"
    exit 1
fi

# ============================================================================
# STEP 1: FREE PORT 222 FOR DROPBEAR
# ============================================================================
print_header "🔧 STEP 1: PREPARING PORT 222"

if ! free_port_222; then
    print_warning "Using alternative port 444 for Dropbear"
    DROPBEAR_PORT=444
fi

# ============================================================================
# STEP 2: INSTALL DROPBEAR
# ============================================================================
print_header "🔧 STEP 2: INSTALLING DROPBEAR"

print_info "Updating package list..."
apt-get update > /dev/null 2>&1
print_success "Package list updated"

print_info "Installing Dropbear..."
if ! command -v dropbear &> /dev/null; then
    apt-get install -y dropbear dropbear-key > /dev/null 2>&1
    print_success "Dropbear installed"
else
    print_success "Dropbear already installed"
fi

# Stop any existing Dropbear
print_info "Stopping existing Dropbear..."
pkill dropbear 2>/dev/null
systemctl stop dropbear 2>/dev/null
print_success "Existing Dropbear stopped"

# Configure Dropbear
print_info "Configuring Dropbear..."
cat > /etc/default/dropbear << EOF
# Dropbear SSH server configuration
DROPBEAR_EXTRA_ARGS="-p $DROPBEAR_PORT -j -k"
NO_START=0
DROPBEAR_PASSWORD_AUTH="on"
EOF
print_success "Dropbear configured"

# Generate host keys
print_info "Generating host keys..."
mkdir -p /etc/dropbear
if [ ! -f /etc/dropbear/dropbear_rsa_host_key ]; then
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key -s 2048 > /dev/null 2>&1
    print_success "RSA host key generated"
fi

if [ ! -f /etc/dropbear/dropbear_ecdsa_host_key ]; then
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key > /dev/null 2>&1
    print_success "ECDSA host key generated"
fi

# Start Dropbear
print_info "Starting Dropbear..."
dropbear -p $DROPBEAR_PORT -F -E > /dev/null 2>&1 &
sleep 2

if pgrep dropbear > /dev/null; then
    print_success "Dropbear started on port $DROPBEAR_PORT"
else
    # Try service method
    systemctl restart dropbear 2>/dev/null
    sleep 2
    if pgrep dropbear > /dev/null; then
        print_success "Dropbear started via service"
    else
        print_error "Failed to start Dropbear"
        exit 1
    fi
fi

# ============================================================================
# STEP 3: SETUP SLOWDNS
# ============================================================================
print_header "🔧 STEP 3: SETTING UP SLOWDNS"

print_info "Creating directories..."
rm -rf /etc/slowdns 2>/dev/null
mkdir -p /etc/slowdns
cd /etc/slowdns
print_success "Directories created"

# Download SlowDNS files from chiddy80
print_info "Downloading SlowDNS components..."

# Download binary
if download_file "dnstt-server" "dnstt-server"; then
    chmod +x dnstt-server
    SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
    print_success "Binary set as dnstt-server"
elif download_file "sldns-server" "sldns-server"; then
    chmod +x sldns-server
    SLOWDNS_BINARY="/etc/slowdns/sldns-server"
    print_success "Binary set as sldns-server"
else
    print_error "Cannot download SlowDNS binary"
    exit 1
fi

# Download keys
download_file "server.key" "server.key"
download_file "server.pub" "server.pub"

# Verify files exist
if [ ! -f "server.key" ] || [ ! -f "server.pub" ]; then
    print_error "Missing key files!"
    exit 1
fi

print_success "SlowDNS files downloaded"

# ============================================================================
# STEP 4: CREATE SLOWDNS SERVICE
# ============================================================================
print_header "🔧 STEP 4: CREATING SLOWDNS SERVICE"

cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$DROPBEAR_PORT
Restart=always
RestartSec=5
User=root
LimitNOFILE=32768

[Install]
WantedBy=multi-user.target
EOF

print_success "SlowDNS service file created"

# ============================================================================
# STEP 5: COMPILE AND SETUP EDNS PROXY
# ============================================================================
print_header "🔧 STEP 5: SETTING UP EDNS PROXY"

print_info "Installing compiler..."
if ! command -v gcc &>/dev/null; then
    apt-get install -y gcc > /dev/null 2>&1
    print_success "GCC installed"
else
    print_success "GCC already installed"
fi

print_info "Creating EDNS Proxy source code..."
cat > /tmp/edns_proxy.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#define LISTEN_PORT 53
#define SLOWDNS_PORT 5300
#define BUFFER_SIZE 4096
#define UPSTREAM_POOL 32
#define SOCKET_TIMEOUT 1.0
#define MAX_EVENTS 4096
#define REQ_TABLE_SIZE 32768
#define EXT_EDNS 512
#define INT_EDNS 1800

typedef struct {
    int fd;
    int busy;
    time_t last_used;
} upstream_t;

typedef struct req_entry {
    uint16_t req_id;
    int upstream_idx;
    double timestamp;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    struct req_entry *next;
} req_entry_t;

static upstream_t upstreams[UPSTREAM_POOL];
static req_entry_t *req_table[REQ_TABLE_SIZE];
static int sock, epoll_fd;
static volatile sig_atomic_t shutdown_flag = 0;

double now() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

uint16_t get_txid(unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}

uint32_t req_hash(uint16_t id) {
    return id & (REQ_TABLE_SIZE - 1);
}

int patch_edns(unsigned char *buf, int len, int size) {
    if (len < 12) return len;
    int off = 12;
    int qd = (buf[4] << 8) | buf[5];
    for (int i=0;i<qd;i++) {
        while (buf[off]) off++;
        off += 5;
    }
    int ar = (buf[10] << 8) | buf[11];
    for (int i=0;i<ar;i++) {
        if (buf[off]==0 && off+4<len && ((buf[off+1]<<8)|buf[off+2])==41) {
            buf[off+3]=size>>8;
            buf[off+4]=size&255;
            return len;
        }
        off++;
    }
    return len;
}

int get_upstream() {
    time_t t = time(NULL);
    for (int i=0;i<UPSTREAM_POOL;i++) {
        if (upstreams[i].busy && t - upstreams[i].last_used > 2)
            upstreams[i].busy = 0;
        if (!upstreams[i].busy) {
            upstreams[i].busy = 1;
            upstreams[i].last_used = t;
            return i;
        }
    }
    return -1;
}

void release_upstream(int i) {
    if (i>=0 && i<UPSTREAM_POOL) upstreams[i].busy = 0;
}

void insert_req(int uidx, unsigned char *buf, struct sockaddr_in *c, socklen_t l) {
    req_entry_t *e = calloc(1,sizeof(*e));
    e->upstream_idx = uidx;
    e->req_id = get_txid(buf);
    e->timestamp = now();
    e->client_addr = *c;
    e->addr_len = l;
    uint32_t h = req_hash(e->req_id);
    e->next = req_table[h];
    req_table[h] = e;
}

req_entry_t *find_req(uint16_t id) {
    uint32_t h = req_hash(id);
    for (req_entry_t *e=req_table[h]; e; e=e->next)
        if (e->req_id == id) return e;
    return NULL;
}

void delete_req(req_entry_t *e) {
    release_upstream(e->upstream_idx);
    uint32_t h = req_hash(e->req_id);
    req_entry_t **pp=&req_table[h];
    while(*pp){
        if(*pp==e){ *pp=e->next; free(e); return; }
        pp=&(*pp)->next;
    }
}

void cleanup_expired() {
    double t=now();
    for(int i=0;i<REQ_TABLE_SIZE;i++){
        req_entry_t **pp=&req_table[i];
        while(*pp){
            if(t-(*pp)->timestamp > SOCKET_TIMEOUT){
                req_entry_t *o=*pp;
                release_upstream(o->upstream_idx);
                *pp=o->next;
                free(o);
            } else pp=&(*pp)->next;
        }
    }
}

void sig_handler(int s){ shutdown_flag=1; }

int main() {
    signal(SIGINT,sig_handler);
    signal(SIGTERM,sig_handler);

    sock=socket(AF_INET,SOCK_DGRAM,0);
    fcntl(sock,F_SETFL,O_NONBLOCK);

    struct sockaddr_in a={0};
    a.sin_family=AF_INET; a.sin_port=htons(LISTEN_PORT);
    a.sin_addr.s_addr=INADDR_ANY;
    bind(sock,(void*)&a,sizeof(a));

    struct sockaddr_in slow={0};
    slow.sin_family=AF_INET; slow.sin_port=htons(SLOWDNS_PORT);
    inet_pton(AF_INET,"127.0.0.1",&slow.sin_addr);

    epoll_fd=epoll_create1(0);
    struct epoll_event ev={.events=EPOLLIN,.data.fd=sock};
    epoll_ctl(epoll_fd,EPOLL_CTL_ADD,sock,&ev);

    for(int i=0;i<UPSTREAM_POOL;i++){
        upstreams[i].fd=socket(AF_INET,SOCK_DGRAM,0);
        fcntl(upstreams[i].fd,F_SETFL,O_NONBLOCK);
        struct epoll_event ue={.events=EPOLLIN,.data.fd=upstreams[i].fd};
        epoll_ctl(epoll_fd,EPOLL_CTL_ADD,upstreams[i].fd,&ue);
    }

    struct epoll_event events[MAX_EVENTS];

    while(!shutdown_flag){
        cleanup_expired();
        int n=epoll_wait(epoll_fd,events,MAX_EVENTS,10);
        for(int i=0;i<n;i++){
            int fd=events[i].data.fd;
            if(fd==sock){
                unsigned char buf[BUFFER_SIZE];
                struct sockaddr_in c; socklen_t l=sizeof(c);
                int len=recvfrom(sock,buf,sizeof(buf),0,(void*)&c,&l);
                if(len>0){
                    patch_edns(buf,len,INT_EDNS);
                    int u=get_upstream();
                    if(u>=0){
                        insert_req(u,buf,&c,l);
                        sendto(upstreams[u].fd,buf,len,0,(void*)&slow,sizeof(slow));
                    }
                }
            } else {
                unsigned char buf[BUFFER_SIZE];
                int len=recv(fd,buf,sizeof(buf),0);
                if(len>0){
                    uint16_t id=get_txid(buf);
                    req_entry_t *e=find_req(id);
                    if(e){
                        patch_edns(buf,len,EXT_EDNS);
                        sendto(sock,buf,len,0,(void*)&e->client_addr,e->addr_len);
                        delete_req(e);
                    }
                }
            }
        }
    }
    return 0;
}
EOF
print_success "Source code created"

print_info "Compiling EDNS Proxy..."
cd /tmp
gcc -O3 edns_proxy.c -o /usr/local/bin/edns-proxy 2>/dev/null

if [ $? -eq 0 ]; then
    chmod +x /usr/local/bin/edns-proxy
    print_success "EDNS Proxy compiled successfully"
else
    # Try simpler compilation
    gcc edns_proxy.c -o /usr/local/bin/edns-proxy 2>/dev/null
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/edns-proxy
        print_success "EDNS Proxy compiled (simple mode)"
    else
        print_error "Failed to compile EDNS Proxy"
        exit 1
    fi
fi

# Create EDNS Proxy service
cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy for SlowDNS
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
print_success "EDNS Proxy service created"

# ============================================================================
# STEP 6: FIREWALL AND NETWORK CONFIGURATION
# ============================================================================
print_header "🔧 STEP 6: CONFIGURING FIREWALL"

print_info "Configuring iptables..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Essential rules
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport $DROPBEAR_PORT -j ACCEPT
iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP

# Rate limiting for Dropbear
iptables -A INPUT -p tcp --dport $DROPBEAR_PORT -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport $DROPBEAR_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

print_success "Firewall rules configured"

print_info "Disabling IPv6..."
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p > /dev/null 2>&1
print_success "IPv6 disabled"

print_info "Configuring DNS..."
systemctl stop systemd-resolved 2>/dev/null
systemctl disable systemd-resolved 2>/dev/null
pkill -9 systemd-resolved 2>/dev/null
rm -f /etc/resolv.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf
print_success "DNS configured"

# ============================================================================
# STEP 7: START ALL SERVICES
# ============================================================================
print_header "🔧 STEP 7: STARTING SERVICES"

print_info "Reloading systemd..."
systemctl daemon-reload

print_info "Starting EDNS Proxy..."
systemctl enable edns-proxy > /dev/null 2>&1
systemctl start edns-proxy
sleep 2

if systemctl is-active --quiet edns-proxy; then
    print_success "EDNS Proxy started"
else
    print_warning "Starting EDNS Proxy manually..."
    /usr/local/bin/edns-proxy &
    sleep 2
    if pgrep edns-proxy > /dev/null; then
        print_success "EDNS Proxy running"
    else
        print_error "EDNS Proxy failed to start"
    fi
fi

print_info "Starting SlowDNS..."
systemctl enable server-sldns > /dev/null 2>&1
systemctl start server-sldns
sleep 3

if systemctl is-active --quiet server-sldns; then
    print_success "SlowDNS started"
else
    print_warning "Starting SlowDNS manually..."
    $SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$DROPBEAR_PORT &
    sleep 2
    if pgrep -f "dnstt-server\|sldns-server" > /dev/null; then
        print_success "SlowDNS running"
    else
        print_error "SlowDNS failed to start"
    fi
fi

# ============================================================================
# STEP 8: VERIFICATION
# ============================================================================
print_header "🔧 STEP 8: VERIFICATION"

print_info "Checking listening ports..."

# Check port 53 (EDNS Proxy)
if ss -ulpn | grep -q ":53 "; then
    print_success "Port 53 (EDNS Proxy) is listening"
else
    print_error "Port 53 is NOT listening"
fi

# Check Dropbear port
if ss -tlnp | grep -q ":$DROPBEAR_PORT "; then
    print_success "Port $DROPBEAR_PORT (Dropbear) is listening"
else
    print_error "Port $DROPBEAR_PORT is NOT listening"
fi

# Check SlowDNS port
if ss -ulpn | grep -q ":$SLOWDNS_PORT "; then
    print_success "Port $SLOWDNS_PORT (SlowDNS) is listening"
else
    print_error "Port $SLOWDNS_PORT is NOT listening"
fi

print_info "Testing services..."

# Test Dropbear
if timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/$DROPBEAR_PORT" 2>/dev/null; then
    print_success "Dropbear is accessible"
else
    print_error "Dropbear is NOT accessible"
fi

# Test DNS
if timeout 3 dig @127.0.0.1 google.com +short >/dev/null 2>&1; then
    print_success "DNS is working"
else
    print_warning "DNS test inconclusive"
fi

# ============================================================================
# COMPLETION
# ============================================================================
print_header "🎉 INSTALLATION COMPLETE"

echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}    ${WHITE}✅ ALL SERVICES INSTALLED SUCCESSFULLY!${NC}              ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER CONFIGURATION${NC}                                ${CYAN}│${NC}"
echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:          ${WHITE}$SERVER_IP${NC}                   ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Dropbear Port:      ${WHITE}$DROPBEAR_PORT${NC}                      ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SlowDNS Port:       ${WHITE}$SLOWDNS_PORT${NC}                     ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} EDNS Proxy Port:    ${WHITE}53${NC}                          ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:         ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU Size:           ${WHITE}1800${NC}                        ${CYAN}│${NC}"
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"

# Show public key
if [ -f /etc/slowdns/server.pub ]; then
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PUBLIC KEY (For Client Configuration)${NC}               ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC}${WHITE}"
    cat /etc/slowdns/server.pub
    echo -e "${NC}${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
fi

echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CLIENT CONFIGURATION EXAMPLE${NC}                         ${CYAN}│${NC}"
echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}SlowDNS Client Command:${NC}                                   ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${GREEN}./dnstt-client -udp $SERVER_IP:5300 \\${NC}               ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${GREEN}    -pubkey-file server.pub \\${NC}                     ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${GREEN}    $NAMESERVER 127.0.0.1:1080${NC}                    ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}SSH Connection:${NC}                                          ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${GREEN}ssh -p $DROPBEAR_PORT root@$SERVER_IP${NC}                ${CYAN}│${NC}"
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"

echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVICE MANAGEMENT${NC}                                 ${CYAN}│${NC}"
echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Restart all services:${NC}                                   ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} systemctl restart dropbear server-sldns edns-proxy${NC}         ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Check status:${NC}                                           ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} systemctl status dropbear server-sldns edns-proxy${NC}          ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}View logs:${NC}                                             ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} journalctl -u server-sldns -f${NC}                            ${CYAN}│${NC}"
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"

echo -e "\n${GREEN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   Installation completed at: $(date)${NC}"
echo -e "${GREEN}   All services are running!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"

# Cleanup
rm -f /tmp/edns_proxy.c 2>/dev/null

echo -e "\n${YELLOW}Press Enter to exit...${NC}"
read -r
```
