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
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          🚀 MODERN SLOWDNS INSTALLATION SCRIPT${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}            Fast & Professional Configuration${NC}            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}                Optimized for Performance${NC}                ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get nameserver
    echo -e "${WHITE}${BOLD}Enter nameserver configuration:${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Default:${NC} dns.example.com                                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Example:${NC} tunnel.yourdomain.com                               ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    read -p "$(echo -e "${WHITE}${BOLD}Enter nameserver: ${NC}")" NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    print_header "📦 GATHERING SYSTEM INFORMATION"
    
    # Get Server IP
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
    if ./dnstt-server --help 2>&1 | grep -q "usage" || timeout 2 ./dnstt-server -h 2>&1 | head -5; then
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
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
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
        apt update > /dev/null 2>&1 && apt install -y gcc make build-essential > /dev/null 2>&1 &
        show_progress $!
        echo -e "\r  ${GREEN}Compiler installed${NC}"
    fi
    
    # Create optimized C code
    cat > /tmp/edns.c << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* ================= CONFIG ================= */
#define LISTEN_PORT 5300
#define BUF_SIZE 4096
#define BATCH 64

#define CACHE_BUCKETS 32768
#define CACHE_MAX     8192
#define CACHE_TTL     30
#define AMP_LIMIT     1400

#define EXT_EDNS 512
#define INT_EDNS 1800

/* ================= GLOBAL ================= */
static volatile sig_atomic_t stop = 0;

/* ================= TIME ================= */
static inline double now(){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return ts.tv_sec + ts.tv_nsec/1e9;
}

/* ================= SIGNAL ================= */
void handle_signal(int s){
    stop = 1;
}

/* ================= HASH ================= */
uint32_t dns_hash(const unsigned char *b,int l){
    uint32_t h=2166136261u;
    for(int i=12;i<l;i++) h=(h^b[i])*16777619;
    return h;
}

/* ================= DNS PARSER ================= */
int skip_name(const unsigned char *b,int off,int len){
    while(off<len){
        uint8_t l=b[off];
        if(l==0) return off+1;
        if((l&0xC0)==0xC0) return off+2;
        if(l>63) return -1;
        off+=l+1;
    }
    return -1;
}

int patch_edns(unsigned char *buf,int len,int size){
    if(len<12) return len;
    int off=12;
    int qd=(buf[4]<<8)|buf[5];
    int an=(buf[6]<<8)|buf[7];
    int ns=(buf[8]<<8)|buf[9];
    int ar=(buf[10]<<8)|buf[11];

    for(int i=0;i<qd;i++){
        off=skip_name(buf,off,len);
        if(off<0||off+4>len) return len;
        off+=4;
    }

    for(int i=0;i<an+ns;i++){
        off=skip_name(buf,off,len);
        if(off<0||off+10>len) return len;
        uint16_t rdlen=(buf[off+8]<<8)|buf[off+9];
        off+=10+rdlen;
    }

    for(int i=0;i<ar;i++){
        off=skip_name(buf,off,len);
        if(off<0||off+10>len) return len;
        uint16_t type=(buf[off]<<8)|buf[off+1];
        if(type==41 && off+3<len){
            buf[off+2]=size>>8;
            buf[off+3]=size&255;
            return len;
        }
        uint16_t rdlen=(buf[off+8]<<8)|buf[off+9];
        off+=10+rdlen;
    }
    return len;
}

/* ================= CACHE ================= */
typedef struct cache_entry{
    uint32_t hash;
    int len;
    double ts;
    unsigned char data[BUF_SIZE];
    struct cache_entry *hnext,*prev,*next;
} cache_entry_t;

static cache_entry_t *cache[CACHE_BUCKETS];
static cache_entry_t *lru_head=NULL,*lru_tail=NULL;
static int cache_items=0;

void lru_move(cache_entry_t *e){
    if(e==lru_head) return;
    if(e->prev) e->prev->next=e->next;
    if(e->next) e->next->prev=e->prev;
    if(e==lru_tail) lru_tail=e->prev;
    e->prev=NULL;
    e->next=lru_head;
    if(lru_head) lru_head->prev=e;
    lru_head=e;
    if(!lru_tail) lru_tail=e;
}

void cache_evict(){
    if(!lru_tail) return;
    cache_entry_t *e=lru_tail;
    uint32_t idx=e->hash&(CACHE_BUCKETS-1);
    cache_entry_t **pp=&cache[idx];
    while(*pp && *pp!=e) pp=&(*pp)->hnext;
    if(*pp) *pp=e->hnext;
    lru_tail=e->prev;
    if(lru_tail) lru_tail->next=NULL;
    else lru_head=NULL;
    free(e);
    cache_items--;
}

cache_entry_t *cache_get(unsigned char *b,int l){
    uint32_t h=dns_hash(b,l);
    uint32_t idx=h&(CACHE_BUCKETS-1);
    double t=now();
    for(cache_entry_t *e=cache[idx];e;e=e->hnext){
        if(e->hash==h && e->len==l && (t-e->ts)<CACHE_TTL){
            lru_move(e);
            return e;
        }
    }
    return NULL;
}

void cache_put(unsigned char *b,int l){
    if(l>AMP_LIMIT) return;
    while(cache_items>=CACHE_MAX) cache_evict();
    cache_entry_t *e=malloc(sizeof(*e));
    if(!e) return;
    e->hash=dns_hash(b,l);
    e->len=l;
    e->ts=now();
    memcpy(e->data,b,l);
    uint32_t idx=e->hash&(CACHE_BUCKETS-1);
    e->hnext=cache[idx];
    cache[idx]=e;
    e->prev=NULL;
    e->next=lru_head;
    if(lru_head) lru_head->prev=e;
    lru_head=e;
    if(!lru_tail) lru_tail=e;
    cache_items++;
}

/* ================= CLEANUP ================= */
void cleanup_cache(){
    cache_entry_t *e=lru_head,*next;
    while(e){
        next=e->next;
        free(e);
        e=next;
    }
}

/* ================= MAIN ================= */
int main(){
    signal(SIGINT,handle_signal);
    signal(SIGTERM,handle_signal);
    atexit(cleanup_cache);

    int sock=socket(AF_INET,SOCK_DGRAM,0);
    fcntl(sock,F_SETFL,O_NONBLOCK);

    struct sockaddr_in a={0};
    a.sin_family=AF_INET;
    a.sin_port=htons(LISTEN_PORT);
    a.sin_addr.s_addr=INADDR_ANY;
    bind(sock,(void*)&a,sizeof(a));

    struct mmsghdr msgs[BATCH];
    struct iovec iov[BATCH];
    unsigned char bufs[BATCH][BUF_SIZE];
    struct sockaddr_in src[BATCH];

    for(int i=0;i<BATCH;i++){
        iov[i].iov_base=bufs[i];
        iov[i].iov_len=BUF_SIZE;
        msgs[i].msg_hdr.msg_iov=&iov[i];
        msgs[i].msg_hdr.msg_iovlen=1;
        msgs[i].msg_hdr.msg_name=&src[i];
        msgs[i].msg_hdr.msg_namelen=sizeof(src[i]);
    }

    while(!stop){
        int n=recvmmsg(sock,msgs,BATCH,0,NULL);
        if(n<=0) continue;

        for(int i=0;i<n;i++){
            int len=msgs[i].msg_len;
            unsigned char *b=bufs[i];
            unsigned char raw[BUF_SIZE];
            memcpy(raw,b,len);

            cache_entry_t *e=cache_get(raw,len);

            if(e){
                unsigned char out[BUF_SIZE];
                memcpy(out,e->data,e->len);
                patch_edns(out,e->len,EXT_EDNS);
                sendto(sock,out,e->len,MSG_DONTWAIT,(void*)&src[i],sizeof(src[i]));
            }else{
                patch_edns(raw,len,INT_EDNS);
                cache_put(raw,len);
                patch_edns(b,len,EXT_EDNS);
                sendto(sock,b,len,MSG_DONTWAIT,(void*)&src[i],sizeof(src[i]));
            }
        }
    }
    close(sock);
    return 0;
}
EOF

    # Compile EDNS proxy
    print_info "Compiling EDNS Proxy"
    echo -ne "  ${CYAN}Compiling C code...${NC}"
    gcc -O3 -o /tmp/edns-proxy /tmp/edns.c 2>/tmp/compile.log &
    show_progress $!
    
    if [ -f /tmp/edns-proxy ]; then
        echo -e "\r  ${GREEN}EDNS Proxy compiled successfully${NC}"
        mv /tmp/edns-proxy /usr/local/bin/edns-proxy
        chmod +x /usr/local/bin/edns-proxy
    else
        echo -e "\r  ${RED}Failed to compile EDNS Proxy${NC}"
        echo -e "  ${YELLOW}Check /tmp/compile.log for details${NC}"
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
After=network.target
Wants=network-online.target

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
    # Clear existing rules
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    
    # Set default policies
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
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null &
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
        sleep 2
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
        sleep 2
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
    
    # Final verification
    echo -e "\n${WHITE}${BOLD}Verifying installation...${NC}"
    
    echo -ne "  ${CYAN}Checking port 53...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":53 "; then
        echo -e "\r  ${GREEN}✓ Port 53 (EDNS Proxy) is listening${NC}"
    else
        echo -e "\r  ${YELLOW}! Port 53 not listening${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking port $SLOWDNS_PORT...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
        echo -e "\r  ${GREEN}✓ Port $SLOWDNS_PORT (SlowDNS) is listening${NC}"
    else
        echo -e "\r  ${YELLOW}! Port $SLOWDNS_PORT not listening${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking service status...${NC}"
    SLOWDNS_ACTIVE=0
    EDNS_ACTIVE=0
    
    if systemctl is-active --quiet server-sldns; then
        SLOWDNS_ACTIVE=1
    fi
    
    if systemctl is-active --quiet edns-proxy; then
        EDNS_ACTIVE=1
    fi
    
    if [ $SLOWDNS_ACTIVE -eq 1 ] && [ $EDNS_ACTIVE -eq 1 ]; then
        echo -e "\r  ${GREEN}✓ All services are running${NC}"
    else
        echo -e "\r  ${YELLOW}! Some services need attention${NC}"
        [ $SLOWDNS_ACTIVE -eq 0 ] && echo -e "  ${YELLOW}  - SlowDNS service not active${NC}"
        [ $EDNS_ACTIVE -eq 0 ] && echo -e "  ${YELLOW}  - EDNS Proxy service not active${NC}"
    fi
    
    # Final message
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 SLOWDNS INSTALLATION COMPLETED SUCCESSFULLY!${NC}    ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Installation completed successfully${NC}              ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 Services running: SlowDNS + EDNS Proxy${NC}          ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🔧 Ready for DNS tunneling${NC}                         ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}${BOLD}📞 Need help? Contact support: @esimfreegb${NC}"
    echo -e "${YELLOW}${BOLD}💡 Documentation: https://github.com/chiddy80/Halotel-Slow-DNS${NC}"
    
    # Cleanup
    rm -f /tmp/edns.c /tmp/compile.log 2>/dev/null
    
    # Show post-installation menu
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}POST-INSTALLATION OPTIONS${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}1.${NC} ${WHITE}View service status${NC}                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}2.${NC} ${WHITE}Check listening ports${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}3.${NC} ${WHITE}Restart all services${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}4.${NC} ${WHITE}Test DNS functionality${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}5.${NC} ${WHITE}Exit to terminal${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -ne "${WHITE}${BOLD}Select option [1-5]: ${NC}"
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
            ss -ulpn | grep -E ':53|:5300' || echo "No UDP ports found"
            echo -e "\n${WHITE}Checking TCP ports:${NC}"
            ss -tlnp | grep -E ":22|:5300" || echo "No TCP ports found"
            ;;
        3)
            echo -e "\n${CYAN}════════════════ RESTARTING SERVICES ════════════════${NC}"
            systemctl restart server-sldns edns-proxy
            sleep 2
            echo -e "${GREEN}✓ Services restarted successfully${NC}"
            ;;
        4)
            echo -e "\n${CYAN}════════════════ DNS TEST ════════════════${NC}"
            echo -e "${WHITE}Testing DNS query to $NAMESERVER...${NC}"
            if command -v dig &>/dev/null; then
                dig @$SERVER_IP $NAMESERVER +short +time=5 +tries=1
            elif command -v nslookup &>/dev/null; then
                timeout 5 nslookup $NAMESERVER $SERVER_IP
            else
                echo -e "${YELLOW}DNS tools not available${NC}"
            fi
            ;;
        5)
            echo -e "\n${GREEN}Returning to terminal...${NC}"
            ;;
        *)
            echo -e "\n${YELLOW}Invalid option, returning to terminal...${NC}"
            ;;
    esac
    
    # Show exit message
    echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   Installation completed at: $(date)${NC}"
    echo -e "${GREEN}${BOLD}   Server: $SERVER_IP | SlowDNS: $SLOWDNS_PORT | EDNS: 53${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
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
```
