#!/bin/bash

# ============================================================================
#               ULTIMATE SLOWDNS SCRIPT - MTU BOOST + DPI EVASION
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300  # Your original port
EDNS_INT_MTU=1800  # Internal MTU (boosted)
EDNS_EXT_MTU=512   # External MTU (standard)
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# DPI Evasion Ports (rotate between these)
EVASION_PORTS=(53 443 5353 2053 2083 2087 8443 8880 7547 8080)
HOP_INTERVAL=300  # 5 minutes rotation

# ============================================================================
# COLORS
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# FUNCTIONS
# ============================================================================
show_progress() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

print_success() { echo -e "  ${GREEN}✓${NC} $1"; }
print_error() { echo -e "  ${RED}✗${NC} $1"; }
print_info() { echo -e "  ${CYAN}ℹ${NC} $1"; }
print_warning() { echo -e "  ${YELLOW}!${NC} $1"; }

print_header() {
    echo -e "\n${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}$1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║           ULTIMATE SLOWDNS - MTU BOOST + DPI EVASION     ║"
    echo "║                 Original Script Enhanced                 ║"
    echo "╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get nameserver
    echo -e "${WHITE}Enter nameserver (default: dns.example.com):${NC}"
    read -p "Nameserver: " NAMESERVER
    NAMESERVER=${NAMESERVER:-dns.example.com}
    
    # Get Server IP
    SERVER_IP=$(curl -s --connect-timeout 5 ifconfig.me || hostname -I | awk '{print $1}')
    echo -e "${GREEN}Server IP: ${WHITE}$SERVER_IP${NC}"
    
    # ============================================================================
    # STEP 1: CONFIGURE SSH
    # ============================================================================
    print_header "STEP 1: CONFIGURING SSH"
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
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
    
    systemctl restart sshd &
    show_progress $!
    print_success "SSH configured on port $SSHD_PORT"
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS
    # ============================================================================
    print_header "STEP 2: SETTING UP SLOWDNS"
    
    rm -rf /etc/slowdns
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download binary
    echo -ne "  Downloading SlowDNS binary..."
    wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}SlowDNS binary downloaded${NC}"
    chmod +x dnstt-server
    
    # Download keys
    echo -ne "  Downloading keys..."
    wget -q "$GITHUB_BASE/server.key" -O server.key 2>/dev/null &
    show_progress $!
    wget -q "$GITHUB_BASE/server.pub" -O server.pub 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}Encryption keys downloaded${NC}"
    
    # ============================================================================
    # STEP 3: COMPILE ENHANCED EDNS PROXY (YOUR ORIGINAL + DPI EVASION)
    # ============================================================================
    print_header "STEP 3: COMPILING ENHANCED EDNS PROXY"
    
    # Install compiler if needed
    if ! command -v gcc &>/dev/null; then
        apt update >/dev/null 2>&1
        apt install -y gcc >/dev/null 2>&1
    fi
    
    # Create enhanced EDNS proxy with DPI evasion
    cat > /tmp/edns_enhanced.c << 'EOF'
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
#include <netinet/ip.h>

#define MAX_PORTS 10
#define BUFFER_SIZE 4096
#define UPSTREAM_POOL 32
#define MAX_EVENTS 4096
#define REQ_TABLE_SIZE 65536

// DPI Evasion Ports (same as in bash script)
int evasion_ports[MAX_PORTS] = {53, 443, 5353, 2053, 2083, 2087, 8443, 8880, 7547, 8080};
int current_port_index = 0;
int slowdns_port = 5300;
int listen_sockets[MAX_PORTS];

// MTU Configuration
#define EXT_EDNS 512    // External: Standard 512
#define INT_EDNS 1800   // Internal: Boosted 1800

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
    uint8_t ttl_value;
    struct req_entry *next;
} req_entry_t;

static upstream_t upstreams[UPSTREAM_POOL];
static req_entry_t *req_table[REQ_TABLE_SIZE];
static int epoll_fd;
static volatile sig_atomic_t shutdown_flag = 0;
static time_t last_port_rotate = 0;

// Random delay to break timing patterns
void random_delay_ms(int max_ms) {
    struct timespec req = {0};
    req.tv_nsec = (rand() % (max_ms * 1000000));
    nanosleep(&req, NULL);
}

// Your original MTU patching function (preserved)
int patch_edns(unsigned char *buf, int len, int size) {
    if (len < 12) return len;
    int off = 12;
    int qd = (buf[4] << 8) | buf[5];
    
    // Skip questions
    for (int i = 0; i < qd; i++) {
        while (off < len && buf[off]) off++;
        if (off >= len) return len;
        off += 5;
    }
    
    // Look for EDNS OPT record
    int ar = (buf[10] << 8) | buf[11];
    for (int i = 0; i < ar && off < len; i++) {
        if (buf[off] == 0 && off + 4 < len) {
            uint16_t type = (buf[off + 1] << 8) | buf[off + 2];
            if (type == 41) { // EDNS OPT
                buf[off + 3] = size >> 8;
                buf[off + 4] = size & 255;
                return len;
            }
            off += 11; // Skip OPT record
        } else {
            off++; // Skip non-zero label
        }
    }
    
    // Add EDNS OPT if not present
    if (len + 11 <= BUFFER_SIZE) {
        // Add OPT record
        buf[off++] = 0; // Root label
        buf[off++] = 0; // Type high byte (41 = OPT)
        buf[off++] = 41; // Type low byte
        buf[off++] = size >> 8; // UDP payload size high
        buf[off++] = size & 255; // UDP payload size low
        buf[off++] = 0; // Extended RCODE
        buf[off++] = 0; // EDNS version
        buf[off++] = 0; // Flags high
        buf[off++] = 0; // Flags low
        buf[off++] = 0; // RDATA length high
        buf[off++] = 0; // RDATA length low
        
        // Update ARCOUNT
        buf[10] = (ar + 1) >> 8;
        buf[11] = (ar + 1) & 255;
        
        return off;
    }
    
    return len;
}

// Add random padding to confuse DPI
void add_random_padding(uint8_t *buf, int *len) {
    if (*len + 16 > BUFFER_SIZE) return;
    
    int pad_len = 8 + (rand() % 9); // 8-16 bytes
    int start = *len;
    
    // Add OPT padding option
    buf[start++] = 0x00; // OPTION-CODE high (12 = PADDING)
    buf[start++] = 0x0C; // OPTION-CODE low
    buf[start++] = (pad_len - 4) >> 8;
    buf[start++] = (pad_len - 4) & 0xFF;
    
    // Random padding bytes
    for (int i = 0; i < pad_len - 4; i++) {
        buf[start++] = rand() & 0xFF;
    }
    
    *len = start;
}

// Obfuscate DNS packet fingerprint
void obfuscate_packet(uint8_t *buf, int len) {
    if (len < 12) return;
    
    // Randomize DNS ID (not sequential)
    static uint16_t last_id = 0;
    uint16_t new_id;
    do {
        new_id = rand() & 0xFFFF;
    } while (abs((int)new_id - (int)last_id) < 1000);
    
    buf[0] = new_id >> 8;
    buf[1] = new_id & 0xFF;
    last_id = new_id;
    
    // Randomly set CD flag (checking disabled) - looks like resolver
    if (rand() % 5 == 0) {
        buf[2] |= 0x10;
    }
    
    // Randomly set AD flag (authenticated data)
    if (rand() % 10 == 0) {
        buf[2] |= 0x20;
    }
    
    // Mix case in domain names (breaks exact string matching)
    for (int i = 12; i < len - 1; i++) {
        if (buf[i] >= 'A' && buf[i] <= 'Z' && rand() % 4 == 0) {
            buf[i] += 32; // to lowercase
        } else if (buf[i] >= 'a' && buf[i] <= 'z' && rand() % 4 == 0) {
            buf[i] -= 32; // to uppercase
        }
    }
}

// Create listening socket on specific port
int create_listen_socket(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    // Set TTL to look like normal traffic (64=Linux, 128=Windows)
    int ttl = (rand() % 2 == 0) ? 64 : 128;
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    
    // Set non-blocking
    fcntl(sock, F_SETFL, O_NONBLOCK);
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    // Add to epoll
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = sock};
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
    
    return sock;
}

// Rotate to new port (DPI evasion)
void rotate_port() {
    time_t now = time(NULL);
    if (now - last_port_rotate < 300) return; // 5 minutes minimum
    
    // Close old sockets (keep first 3)
    for (int i = 3; i < MAX_PORTS; i++) {
        if (listen_sockets[i] > 0) {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, listen_sockets[i], NULL);
            close(listen_sockets[i]);
            listen_sockets[i] = -1;
        }
    }
    
    // Open new random ports
    for (int i = 3; i < 6; i++) { // Keep 3 active ports
        int new_port;
        do {
            new_port = evasion_ports[rand() % MAX_PORTS];
        } while (new_port == 53 || new_port == 443); // Always keep these
        
        listen_sockets[i] = create_listen_socket(new_port);
        if (listen_sockets[i] > 0) {
            printf("[DPI-EVASION] Now listening on port %d\n", new_port);
        }
    }
    
    last_port_rotate = now;
}

int main() {
    srand(time(NULL));
    signal(SIGINT, SIG_IGN);
    
    // Create epoll instance
    epoll_fd = epoll_create1(0);
    
    // Initialize upstream connections to SlowDNS
    struct sockaddr_in slow_addr = {0};
    slow_addr.sin_family = AF_INET;
    slow_addr.sin_port = htons(slowdns_port);
    inet_pton(AF_INET, "127.0.0.1", &slow_addr.sin_addr);
    
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        upstreams[i].fd = socket(AF_INET, SOCK_DGRAM, 0);
        fcntl(upstreams[i].fd, F_SETFL, O_NONBLOCK);
        
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = upstreams[i].fd};
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstreams[i].fd, &ev);
    }
    
    // Initialize listen sockets array
    for (int i = 0; i < MAX_PORTS; i++) {
        listen_sockets[i] = -1;
    }
    
    // Always listen on standard ports
    listen_sockets[0] = create_listen_socket(53);   // Standard DNS
    listen_sockets[1] = create_listen_socket(443);  // HTTPS
    listen_sockets[2] = create_listen_socket(5353); // mDNS
    
    // Start with a few random ports
    for (int i = 3; i < 6; i++) {
        int port = evasion_ports[3 + (rand() % (MAX_PORTS - 3))];
        listen_sockets[i] = create_listen_socket(port);
    }
    
    printf("[SYSTEM] Enhanced EDNS Proxy started\n");
    printf("[SYSTEM] MTU Boost: %d external -> %d internal\n", EXT_EDNS, INT_EDNS);
    printf("[DPI-EVASION] Listening on multiple ports\n");
    
    struct epoll_event events[MAX_EVENTS];
    
    while (!shutdown_flag) {
        // Rotate ports periodically
        rotate_port();
        
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            
            // Check if it's a listen socket
            int is_listen_socket = 0;
            for (int j = 0; j < MAX_PORTS; j++) {
                if (listen_sockets[j] == fd) {
                    is_listen_socket = 1;
                    break;
                }
            }
            
            if (is_listen_socket) {
                // Incoming packet from client
                uint8_t buf[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                int len = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&client_addr, &addr_len);
                
                if (len > 0) {
                    // Apply DPI evasion
                    obfuscate_packet(buf, len);
                    random_delay_ms(2); // 0-2ms random delay
                    
                    // Patch EDNS for internal MTU
                    len = patch_edns(buf, len, INT_EDNS);
                    
                    // Add random padding
                    add_random_padding(buf, &len);
                    
                    // Find available upstream
                    for (int j = 0; j < UPSTREAM_POOL; j++) {
                        if (!upstreams[j].busy) {
                            upstreams[j].busy = 1;
                            upstreams[j].last_used = time(NULL);
                            
                            // Store request
                            uint16_t req_id = (buf[0] << 8) | buf[1];
                            uint32_t hash = req_id % REQ_TABLE_SIZE;
                            
                            req_entry_t *entry = malloc(sizeof(req_entry_t));
                            entry->req_id = req_id;
                            entry->upstream_idx = j;
                            entry->timestamp = (double)time(NULL);
                            entry->client_addr = client_addr;
                            entry->addr_len = addr_len;
                            entry->next = req_table[hash];
                            req_table[hash] = entry;
                            
                            // Send to SlowDNS
                            sendto(upstreams[j].fd, buf, len, 0,
                                   (struct sockaddr*)&slow_addr, sizeof(slow_addr));
                            break;
                        }
                    }
                }
            } else {
                // Response from SlowDNS
                uint8_t buf[BUFFER_SIZE];
                int len = recv(fd, buf, sizeof(buf), 0);
                
                if (len > 0) {
                    // Patch EDNS for external MTU
                    len = patch_edns(buf, len, EXT_EDNS);
                    
                    // Find original request
                    uint16_t req_id = (buf[0] << 8) | buf[1];
                    uint32_t hash = req_id % REQ_TABLE_SIZE;
                    
                    req_entry_t **pp = &req_table[hash];
                    while (*pp) {
                        if ((*pp)->req_id == req_id) {
                            req_entry_t *entry = *pp;
                            
                            // Send response back to client
                            sendto(listen_sockets[0], buf, len, 0,
                                   (struct sockaddr*)&entry->client_addr, entry->addr_len);
                            
                            // Clean up
                            upstreams[entry->upstream_idx].busy = 0;
                            *pp = entry->next;
                            free(entry);
                            break;
                        }
                        pp = &(*pp)->next;
                    }
                }
            }
        }
        
        // Cleanup old requests (timeout after 10 seconds)
        time_t now = time(NULL);
        for (int i = 0; i < REQ_TABLE_SIZE; i++) {
            req_entry_t **pp = &req_table[i];
            while (*pp) {
                if (now - (time_t)(*pp)->timestamp > 10) {
                    req_entry_t *old = *pp;
                    upstreams[old->upstream_idx].busy = 0;
                    *pp = old->next;
                    free(old);
                } else {
                    pp = &(*pp)->next;
                }
            }
        }
    }
    
    return 0;
}
EOF
    
    # Compile enhanced EDNS proxy
    echo -ne "  Compiling enhanced EDNS proxy..."
    gcc -O3 -march=native /tmp/edns_enhanced.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log &
    show_progress $!
    
    if [ -f /usr/local/bin/edns-proxy ]; then
        chmod +x /usr/local/bin/edns-proxy
        echo -e "\r  ${GREEN}Enhanced EDNS proxy compiled${NC}"
    else
        echo -e "\r  ${RED}Compilation failed${NC}"
        cat /tmp/compile.log
        exit 1
    fi
    
    # ============================================================================
    # STEP 4: CREATE PORT HOPPER FOR DPI EVASION
    # ============================================================================
    print_header "STEP 4: SETTING UP DPI EVASION"
    
    # Create port hopper script
    cat > /usr/local/bin/port-hopper.sh << EOF
#!/bin/bash
# Port hopper for DPI evasion
PORTS=(${EVASION_PORTS[@]})
INTERVAL=$HOP_INTERVAL

echo "[DPI-EVASION] Starting port hopper on ports: \${PORTS[@]}"

while true; do
    # Select random port (always include 53 and 443)
    RANDOM_PORT=\${PORTS[\$RANDOM % \${#PORTS[@]}]}
    
    # Clear old redirects
    iptables -t nat -F PREROUTING 2>/dev/null
    
    # Redirect selected port to SlowDNS
    iptables -t nat -A PREROUTING -p udp --dport \$RANDOM_PORT -j REDIRECT --to-port $SLOWDNS_PORT
    
    # Always redirect port 53 (standard DNS)
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port $SLOWDNS_PORT
    
    # Also redirect TCP for the selected port (for complete coverage)
    iptables -t nat -A PREROUTING -p tcp --dport \$RANDOM_PORT -j REDIRECT --to-port $SLOWDNS_PORT
        # Set TTL to look like normal traffic
    iptables -t mangle -F POSTROUTING 2>/dev/null
    iptables -t mangle -A POSTROUTING -p udp --dport \$RANDOM_PORT -j TTL --ttl-set 65
    iptables -t mangle -A POSTROUTING -p udp --sport $SLOWDNS_PORT -j TTL --ttl-set 65
    
    echo "[\$(date)] Active port: \$RANDOM_PORT (Clients can use port 53 OR \$RANDOM_PORT)"
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4 2>/dev/null
    
    sleep \$INTERVAL
done
EOF
    
    chmod +x /usr/local/bin/port-hopper.sh
    
    # Create fake DNS traffic generator
    cat > /usr/local/bin/fake-dns.sh << 'EOF'
#!/bin/bash
# Generate fake DNS traffic to confuse DPI
while true; do
    # Random interval 10-60 seconds
    sleep $((RANDOM % 50 + 10))
    
    # Random resolver
    RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    RESOLVER=${RESOLVERS[$RANDOM % 3]}
    
    # Random domains from popular sites
    DOMAINS=("google.com" "facebook.com" "youtube.com" "whatsapp.com" 
             "amazon.com" "microsoft.com" "netflix.com" "twitter.com")
    DOMAIN=${DOMAINS[$RANDOM % 8]}
    
    # Make query
    dig @$RESOLVER $DOMAIN +short +time=1 +tries=1 >/dev/null 2>&1 &
done
EOF
    
    chmod +x /usr/local/bin/fake-dns.sh
    
    # ============================================================================
    # STEP 5: CREATE SYSTEMD SERVICES
    # ============================================================================
    print_header "STEP 5: CREATING SERVICES"
    
    # Original SlowDNS service (preserved from your script)
    cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :$SLOWDNS_PORT -mtu $EDNS_INT_MTU -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=3
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    
    # Enhanced EDNS proxy service
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=Enhanced EDNS Proxy (MTU Boost + DPI Evasion)
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
    
    # Port hopper service
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
    
    # Fake DNS service
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
    
    # ============================================================================
    # STEP 6: FIREWALL CONFIGURATION
    # ============================================================================
    print_header "STEP 6: CONFIGURING FIREWALL"
    
    # Clear existing
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
    
    # Allow all evasion ports
    for port in 53 $SLOWDNS_PORT ${EVASION_PORTS[@]}; do
        iptables -A INPUT -p udp --dport $port -j ACCEPT
        iptables -A INPUT -p tcp --dport $port -j ACCEPT
    done
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Drop invalid
    iptables -A INPUT -m state --state INVALID -j DROP
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4
    
    # Stop conflicting DNS services
    systemctl stop systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    
    # ============================================================================
    # STEP 7: START SERVICES
    # ============================================================================
    print_header "STEP 7: STARTING SERVICES"
    
    systemctl daemon-reload
    
    # Start services in order
    services=("server-sldns" "edns-proxy" "port-hopper" "fake-dns")
    for service in "${services[@]}"; do
        echo -ne "  Starting $service..."
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
    
    echo -e "${GREEN}${BOLD}SYSTEM STATUS:${NC}"
    echo -e "  ${GREEN}✓${NC} SlowDNS Server: port $SLOWDNS_PORT"
    echo -e "  ${GREEN}✓${NC} EDNS Proxy: MTU boost $EDNS_EXT_MTU → $EDNS_INT_MTU"
    echo -e "  ${GREEN}✓${NC} DPI Evasion: Port hopping active"
    echo -e "  ${GREEN}✓${NC} Fake Traffic: Generating legitimate DNS queries"
    
    echo -e "\n${CYAN}${BOLD}CLIENT CONFIGURATION:${NC}"
    echo -e "  ${YELLOW}Clients can connect using ANY of these:${NC}"
    echo -e "  ${WHITE}Port 53${NC} (always works): ./dnstt-client -udp $SERVER_IP:53 -pubkey-file server.pub $NAMESERVER 127.0.0.1:1080"
    echo -e "  ${WHITE}OR Port 443${NC} (HTTPS port): ./dnstt-client -udp $SERVER_IP:443 -pubkey-file server.pub $NAMESERVER 127.0.0.1:1080"
    echo -e "  ${WHITE}OR Port 5353${NC} (mDNS): ./dnstt-client -udp $SERVER_IP:5353 -pubkey-file server.pub $NAMESERVER 127.0.0.1:1080"
    
    echo -e "\n${YELLOW}${BOLD}MTU BOOST ACTIVE:${NC}"
    echo -e "  External DNS: $EDNS_EXT_MTU bytes (standard)"
    echo -e "  Internal Tunnel: $EDNS_INT_MTU bytes (boosted)"
    echo -e "  ${GREEN}Result:${NC} 3.5x more data per packet!"
    
    echo -e "\n${BLUE}${BOLD}DPI EVASION FEATURES:${NC}"
    echo -e "  1. ${GREEN}Port Hopping${NC}: Changes ports every 5 minutes"
    echo -e "  2. ${GREEN}Fake Traffic${NC}: Generates real DNS queries"
    echo -e "  3. ${GREEN}TTL Manipulation${NC}: Looks like web traffic (TTL=65)"
    echo -e "  4. ${GREEN}Packet Obfuscation${NC}: Random delays and padding"
    
    echo -e "\n${WHITE}${BOLD}MONITORING:${NC}"
    echo -e "  Check active port: ${CYAN}iptables -t nat -L -n | grep REDIRECT${NC}"
    echo -e "  Service status: ${CYAN}systemctl status server-sldns edns-proxy${NC}"
    echo -e "  View logs: ${CYAN}journalctl -u port-hopper -f${NC}"
    
    echo -e "\n${RED}${BOLD}TROUBLESHOOTING:${NC}"
    echo -e "  If clients can't connect:"
    echo -e "  1. Try port 53 first: ${WHITE}$SERVER_IP:53${NC}"
    echo -e "  2. Check firewall: ${WHITE}iptables -L -n${NC}"
    echo -e "  3. Restart all: ${WHITE}systemctl restart server-sldns edns-proxy port-hopper${NC}"
    
    # Test current port
    CURRENT_PORT=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep REDIRECT | grep -o 'dpt:[0-9]*' | cut -d: -f2 | head -1)
    echo -e "\n${GREEN}${BOLD}Current active port for clients: ${WHITE}${CURRENT_PORT:-53}${NC}"
    echo -e "${GREEN}${BOLD}But clients should always use port 53 - it automatically redirects!${NC}"
    
    echo -e "\n${YELLOW}Installation completed at: $(date)${NC}"
    echo -e "${YELLOW}Server: $SERVER_IP | SlowDNS: $SLOWDNS_PORT | MTU Boost: $EDNS_EXT_MTU→$EDNS_INT_MTU${NC}"
}

# ============================================================================
# EXECUTE
# ============================================================================
trap 'echo -e "\n${RED}Interrupted!${NC}"; exit 1' INT

if main; then
    exit 0
else
    print_error "Installation failed"
    exit 1
fi
```
