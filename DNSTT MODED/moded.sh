#!/bin/bash

# ============================================================================
#                     SLOWDNS INSTALLATION SCRIPT
#              ORIGINAL FUNCTIONALITY + DPI EVASION ADDED
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION (EXACTLY FROM ORIGINAL SCRIPT)
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# DPI Evasion Additions
EVASION_PORTS=(53 443 5353 2053 2087 8443 8880)
HOP_INTERVAL=300  # 5 minutes

# ============================================================================
# COLORS (FROM ORIGINAL)
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
# ORIGINAL FUNCTIONS (PRESERVED)
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

print_success() {
    echo -e "  ${GREEN}${BOLD}✓${NC} ${GREEN}$1${NC}"
}

print_error() {
    echo -e "  ${RED}${BOLD}✗${NC} ${RED}$1${NC}"
}

print_info() {
    echo -e "  ${CYAN}${BOLD}ℹ${NC} ${CYAN}$1${NC}"
}

print_header() {
    echo -e "\n${PURPLE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${PURPLE}══════════════════════════════════════════════════════════${NC}"
}

print_banner() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          SLOWDNS INSTALLATION SCRIPT${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}           Original + DPI Evasion Added${NC}       ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================================================
# DPI EVASION FUNCTIONS (NEW ADDITIONS)
# ============================================================================
setup_dpi_evasion() {
    print_info "Setting up DPI evasion system"
    
    # 1. Create port hopper script
    cat > /usr/local/bin/port-hopper.sh << EOF
#!/bin/bash
# Simple port hopper for DPI evasion
PORTS=(${EVASION_PORTS[@]})
INTERVAL=$HOP_INTERVAL

echo "[DPI-EVASION] Starting port rotation"

while true; do
    # Pick random port
    RANDOM_PORT=\${PORTS[\$RANDOM % \${#PORTS[@]}]}
    
    # Clear old rules
    iptables -t nat -F PREROUTING 2>/dev/null
    
    # Set up redirects (UDP only for SlowDNS)
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
    iptables -t nat -A PREROUTING -p udp --dport \$RANDOM_PORT -j REDIRECT --to-port 5300
    
    # Also allow TCP on these ports (for cover)
    iptables -A INPUT -p tcp --dport \$RANDOM_PORT -j ACCEPT 2>/dev/null
    
    echo "[\$(date)] Active ports: 53 and \$RANDOM_PORT -> 5300"
    
    sleep \$INTERVAL
done
EOF
    chmod +x /usr/local/bin/port-hopper.sh
    
    # 2. Create fake DNS traffic generator
    cat > /usr/local/bin/fake-dns.sh << 'EOF'
#!/bin/bash
# Generate legitimate DNS queries
while true; do
    sleep \$((RANDOM % 30 + 20))
    
    RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    RESOLVER=\${RESOLVERS[\$RANDOM % 3]}
    
    DOMAINS=("google.com" "facebook.com" "youtube.com" "whatsapp.com" "cloudflare.com")
    DOMAIN=\${DOMAINS[\$RANDOM % 5]}
    
    dig @\$RESOLVER \$DOMAIN +short +time=1 +tries=1 >/dev/null 2>&1 &
done
EOF
    chmod +x /usr/local/bin/fake-dns.sh
    
    # 3. Create TTL manipulation script
    cat > /usr/local/bin/fix-ttl.sh << 'EOF'
#!/bin/bash
# Make DNS traffic look like web traffic
while true; do
    iptables -t mangle -F POSTROUTING 2>/dev/null
    iptables -t mangle -A POSTROUTING -p udp --dport 53 -j TTL --ttl-set 65
    iptables -t mangle -A POSTROUTING -p udp --sport 5300 -j TTL --ttl-set 65
    sleep 60
done
EOF
    chmod +x /usr/local/bin/fix-ttl.sh
    
    print_success "DPI evasion tools created"
}

# ============================================================================
# MAIN INSTALLATION (ORIGINAL CODE WITH MINIMAL CHANGES)
# ============================================================================
main() {
    print_banner
    
    # Get nameserver (from original)
    echo -e "${WHITE}${BOLD}Enter nameserver configuration:${NC}"
    read -p "$(echo -e "${WHITE}${BOLD}Enter nameserver: ${NC}")" NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    print_header "📦 GATHERING SYSTEM INFORMATION"
    
    # Get Server IP (from original)
    echo -ne "  ${CYAN}Detecting server IP address...${NC}"
    SERVER_IP=$(curl -s --connect-timeout 5 ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    echo -e "\r  ${GREEN}Server IP:${NC} ${WHITE}${BOLD}$SERVER_IP${NC}"
    
    # ============================================================================
    # STEP 1: CONFIGURE OPENSSH (ORIGINAL)
    # ============================================================================
    print_header "STEP 1: CONFIGURING OPENSSH"
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
    
    systemctl restart sshd 2>/dev/null &
    show_progress $!
    print_success "OpenSSH configured on port $SSHD_PORT"
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS (ORIGINAL)
    # ============================================================================
    print_header "STEP 2: SETTING UP SLOWDNS"
    
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns 2>/dev/null
    cd /etc/slowdns
    
    # Download binary (original method)
    print_info "Downloading SlowDNS binary"
    wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server 2>/dev/null
    chmod +x dnstt-server
    
    # Download key files (original)
    print_info "Downloading encryption keys"
    wget -q "$GITHUB_BASE/server.key" -O server.key 2>/dev/null
    wget -q "$GITHUB_BASE/server.pub" -O server.pub 2>/dev/null
    
    SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
    
    print_success "SlowDNS components installed"
    
    # ============================================================================
    # STEP 3: CREATE SLOWDNS SERVICE (ORIGINAL)
    # ============================================================================
    print_header "STEP 3: CREATING SLOWDNS SERVICE"
    
    cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "SlowDNS service created"
    
    # ============================================================================
    # STEP 4: COMPILE EDNS PROXY (ORIGINAL CODE - WORKING VERSION)
    # ============================================================================
    print_header "STEP 4: COMPILING EDNS PROXY"
    
    # Check for gcc (from original)
    if ! command -v gcc &>/dev/null; then
        print_info "Installing compiler tools"
        apt update > /dev/null 2>&1 && apt install -y gcc > /dev/null 2>&1 &
        show_progress $!
    fi
    
    # Create the EXACT C code from your original script
    cat > /tmp/edns.c << 'EOF'
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
#define MAX_EVENTS 4096
#define REQ_TABLE_SIZE 65536
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

int main() {
    sock=socket(AF_INET,SOCK_DGRAM,0);
    fcntl(sock,F_SETFL,O_NONBLOCK);

    struct sockaddr_in a={0};
    a.sin_family=AF_INET;
    a.sin_port=htons(LISTEN_PORT);
    a.sin_addr.s_addr=INADDR_ANY;
    bind(sock,(void*)&a,sizeof(a));

    struct sockaddr_in slow={0};
    slow.sin_family=AF_INET;
    slow.sin_port=htons(SLOWDNS_PORT);
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

    while(1){
        int n=epoll_wait(epoll_fd,events,MAX_EVENTS,10);
        for(int i=0;i<n;i++){
            int fd=events[i].data.fd;
            if(fd==sock){
                unsigned char buf[BUFFER_SIZE];
                struct sockaddr_in c;
                socklen_t l=sizeof(c);
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
    
    # Compile with optimizations
    echo -ne "  ${CYAN}Compiling EDNS Proxy...${NC}"
    gcc -O3 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log &
    show_progress $!
    
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/edns-proxy
        echo -e "\r  ${GREEN}EDNS Proxy compiled successfully${NC}"
    else
        echo -e "\r  ${RED}Compilation failed${NC}"
        exit 1
    fi
    
    # Create EDNS service (original)
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
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "EDNS Proxy service configured"
    
    # ============================================================================
    # STEP 5: DPI EVASION SETUP (NEW ADDITION)
    # ============================================================================
    print_header "STEP 5: SETTING UP DPI EVASION"
    setup_dpi_evasion
    
    # Create DPI evasion services
    cat > /etc/systemd/system/port-hopper.service << EOF
[Unit]
Description=Port Hopper (DPI Evasion)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/port-hopper.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    cat > /etc/systemd/system/fake-dns.service << EOF
[Unit]
Description=Fake DNS Traffic Generator
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fake-dns.sh
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    cat > /etc/systemd/system/fix-ttl.service << EOF
[Unit]
Description=TTL Manipulation
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fix-ttl.sh
Restart=always
RestartSec=30
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # ============================================================================
    # STEP 6: FIREWALL CONFIGURATION (ORIGINAL + DPI PORTS)
    # ============================================================================
    print_header "STEP 6: CONFIGURING FIREWALL"
    
    echo -ne "  ${CYAN}Setting up firewall rules...${NC}"
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Original rules
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
    
    # Add DPI evasion ports
    for port in ${EVASION_PORTS[@]}; do
        iptables -A INPUT -p udp --dport $port -j ACCEPT 2>/dev/null
        iptables -A INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
    done
    
    # Disable IPv6 (original)
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
    
    # Stop conflicting services (original)
    systemctl stop systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    
    echo -e "\r  ${GREEN}Firewall configured with DPI evasion ports${NC}"
    
    # ============================================================================
    # STEP 7: START ALL SERVICES
    # ============================================================================
    print_header "STEP 7: STARTING SERVICES"
    
    systemctl daemon-reload 2>/dev/null
    
    # Start original services
    services=("server-sldns" "edns-proxy")
    for service in "${services[@]}"; do
        echo -ne "  ${CYAN}Starting $service...${NC}"
        systemctl enable $service >/dev/null 2>&1
        systemctl start $service 2>/dev/null &
        show_progress $!
        echo -e "\r  ${GREEN}$service started${NC}"
        sleep 1
    done
    
    # Start DPI evasion services
    evasion_services=("port-hopper" "fake-dns" "fix-ttl")
    for service in "${evasion_services[@]}"; do
        echo -ne "  ${CYAN}Starting $service...${NC}"
        systemctl enable $service >/dev/null 2>&1
        systemctl start $service 2>/dev/null &
        show_progress $!
        echo -e "\r  ${GREEN}$service started${NC}"
        sleep 1
    done
    
    # ============================================================================
    # COMPLETION
    # ============================================================================
    print_header "🎉 INSTALLATION COMPLETE"
    
    echo -e "${GREEN}${BOLD}CORE SYSTEM (Original):${NC}"
    echo -e "  ${GREEN}✓${NC} SlowDNS Server: port $SLOWDNS_PORT"
    echo -e "  ${GREEN}✓${NC} EDNS Proxy: MTU 512 → 1800 boost"
    echo -e "  ${GREEN}✓${NC} SSH Server: port $SSHD_PORT"
    
    echo -e "\n${CYAN}${BOLD}DPI EVASION ADDED:${NC}"
    echo -e "  ${GREEN}✓${NC} Port Hopping: Rotates between multiple ports"
    echo -e "  ${GREEN}✓${NC} Fake Traffic: Generates legitimate DNS queries"
    echo -e "  ${GREEN}✓${NC} TTL Manipulation: Looks like web traffic"
    
    echo -e "\n${WHITE}${BOLD}CLIENT CONNECTION:${NC}"
    echo -e "  ${YELLOW}Option 1 (Standard):${NC} Use port 53 (always works)"
    echo -e "    ${WHITE}./dnstt-client -udp $SERVER_IP:53 -pubkey-file server.pub $NAMESERVER 127.0.0.1:1080${NC}"
    echo -e "  ${YELLOW}Option 2 (Evasion):${NC} Use current evasion port"
    CURRENT_PORT=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep REDIRECT | grep -o 'dpt:[0-9]*' | cut -d: -f2 | head -1)
    echo -e "    ${WHITE}./dnstt-client -udp $SERVER_IP:${CURRENT_PORT:-53} -pubkey-file server.pub $NAMESERVER 127.0.0.1:1080${NC}"
    
    echo -e "\n${YELLOW}${BOLD}IMPORTANT:${NC} Clients should ALWAYS use port 53"
    echo -e "  Port 53 automatically redirects to current active port"
    
    echo -e "\n${BLUE}${BOLD}CHECK STATUS:${NC}"
    echo -e "  Active port: ${WHITE}iptables -t nat -L -n | grep REDIRECT${NC}"
    echo -e "  Services: ${WHITE}systemctl status server-sldns edns-proxy${NC}"
    echo -e "  Port hopper: ${WHITE}journalctl -u port-hopper -f${NC}"
    
    echo -e "\n${GREEN}${BOLD}=======================================================${NC}"
    echo -e "${GREEN}${BOLD}   ORIGINAL FUNCTIONALITY PRESERVED!${NC}"
    echo -e "${GREEN}${BOLD}   DPI Evasion Added for 24/7 Operation${NC}"
    echo -e "${GREEN}${BOLD}=======================================================${NC}"
}

# ============================================================================
# EXECUTE
# ============================================================================
trap 'echo -e "\n${RED}Installation interrupted!${NC}"; exit 1' INT

if main; then
    exit 0
else
    echo -e "\n${RED}Installation failed${NC}"
    exit 1
fi
```
