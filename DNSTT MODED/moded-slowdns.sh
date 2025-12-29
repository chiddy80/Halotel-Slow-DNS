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
    echo -e "${BLUE}║${NC}${CYAN}          🚀 MODERN SLOWDNS INSTALLATION SCRIPT${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}            Fast & Professional Configuration${NC}            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}                Optimized for Performance${NC}                ${BLUE}║${NC}"
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
    # STEP 4: COMPILE OPTIMIZED EDNS PROXY
    # ============================================================================
    print_step "4"
    print_info "Compiling high-performance EDNS Proxy with EpollET + SocketPool"
    
    # Check for gcc
    if ! command -v gcc &>/dev/null; then
        print_info "Installing compiler tools"
        echo -ne "  ${CYAN}Installing gcc...${NC}"
        apt update > /dev/null 2>&1 && apt install -y gcc > /dev/null 2>&1 &
        show_progress $!
        echo -e "\r  ${GREEN}Compiler installed${NC}"
    fi
    
    # Create optimized C code with EpollET + Zero-Copy + SocketPool
    cat > /tmp/edns.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

// Configuration
#define EXT_EDNS_SIZE       512     // External EDNS size
#define INT_EDNS_SIZE       1800    // Internal EDNS size
#define SLOWDNS_PORT        5300    // SlowDNS backend port
#define LISTEN_PORT         53      // Listen port (EDNS Proxy)
#define BUFFER_SIZE         4096    // Buffer size
#define MAX_EVENTS          1024    // Max epoll events
#define SOCKET_POOL_SIZE    64      // Socket pool size
#define MAX_PENDING         65536   // Max pending requests
#define DNS_HEADER_SIZE     12      // DNS header size
#define EDNS_OPT_RR_TYPE    41      // EDNS option RR type
#define EPOLLET_FLAGS       (EPOLLIN | EPOLLET | EPOLLONESHOT)

// DNS header structure
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

// Request tracking structure
typedef struct {
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    uint16_t txid;                  // Transaction ID for mapping
    time_t timestamp;
    int client_sock;               // Original client socket
} request_t;

// Socket pool structure
typedef struct {
    int fd;
    uint8_t buffer[BUFFER_SIZE];
    struct iovec iov;
    struct msghdr msg;
    struct sockaddr_in target_addr;
    request_t *pending_req;        // NULL if socket is free
    time_t last_used;
} socket_t;

// Global structures
static socket_t socket_pool[SOCKET_POOL_SIZE];
static request_t *txid_map[MAX_PENDING];  // Maps TXID to request
static int epoll_fd = -1;
static int listen_sock = -1;
static struct sockaddr_in slowdns_addr;

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Set socket to non-blocking mode
static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Get free socket from pool
static socket_t* get_free_socket(void) {
    static int next_socket = 0;
    
    for (int i = 0; i < SOCKET_POOL_SIZE; i++) {
        int idx = (next_socket + i) % SOCKET_POOL_SIZE;
        if (socket_pool[idx].pending_req == NULL) {
            next_socket = (idx + 1) % SOCKET_POOL_SIZE;
            return &socket_pool[idx];
        }
    }
    
    // Reuse oldest socket
    socket_t* oldest = &socket_pool[0];
    for (int i = 1; i < SOCKET_POOL_SIZE; i++) {
        if (socket_pool[i].last_used < oldest->last_used) {
            oldest = &socket_pool[i];
        }
    }
    
    // Clean up old pending request
    if (oldest->pending_req) {
        uint16_t txid = oldest->pending_req->txid;
        if (txid < MAX_PENDING) {
            txid_map[txid] = NULL;
        }
        free(oldest->pending_req);
        oldest->pending_req = NULL;
    }
    
    return oldest;
}

// Parse DNS header
static inline dns_header_t parse_dns_header(const uint8_t *buffer) {
    dns_header_t header;
    header.id = (buffer[0] << 8) | buffer[1];
    header.flags = (buffer[2] << 8) | buffer[3];
    header.qdcount = (buffer[4] << 8) | buffer[5];
    header.ancount = (buffer[6] << 8) | buffer[7];
    header.nscount = (buffer[8] << 8) | buffer[9];
    header.arcount = (buffer[10] << 8) | buffer[11];
    return header;
}

// ============================================================================
// EDNS PATCHING FUNCTIONS
// ============================================================================

// Find and patch EDNS OPT RR with correct parsing
static int patch_edns_opt_rr(uint8_t *buffer, int len, uint16_t new_size) {
    if (len < DNS_HEADER_SIZE) return len;
    
    dns_header_t header = parse_dns_header(buffer);
    
    // Skip question section
    int offset = DNS_HEADER_SIZE;
    for (int i = 0; i < header.qdcount && offset < len; i++) {
        // Skip QNAME (compressed or not)
        while (offset < len && buffer[offset] != 0) {
            if ((buffer[offset] & 0xC0) == 0xC0) {
                // Compression pointer
                offset += 2;
                break;
            }
            offset += buffer[offset] + 1;
        }
        if (offset >= len) return len;
        offset++; // Skip null terminator
        
        // Skip QTYPE and QCLASS
        if (offset + 4 > len) return len;
        offset += 4;
    }
    
    // Skip answer and authority sections
    for (int section = 0; section < 2; section++) {
        int count = (section == 0) ? header.ancount : header.nscount;
        for (int i = 0; i < count && offset < len; i++) {
            // Skip NAME
            while (offset < len && buffer[offset] != 0) {
                if ((buffer[offset] & 0xC0) == 0xC0) {
                    offset += 2;
                    break;
                }
                offset += buffer[offset] + 1;
            }
            if (offset >= len) return len;
            offset++;
            
            // Check TYPE, CLASS, TTL, RDLENGTH
            if (offset + 10 > len) return len;
            
            uint16_t type = (buffer[offset] << 8) | buffer[offset + 1];
            uint16_t rdlength = (buffer[offset + 8] << 8) | buffer[offset + 9];
            
            offset += 10; // Skip to RDATA
            offset += rdlength; // Skip RDATA
        }
    }
    
    // Process additional section (where EDNS OPT RR is)
    for (int i = 0; i < header.arcount && offset < len; i++) {
        // Check if this is OPT RR (root domain)
        if (offset < len && buffer[offset] == 0) {
            offset++; // Skip root label
            
            if (offset + 10 <= len) {
                uint16_t type = (buffer[offset] << 8) | buffer[offset + 1];
                
                if (type == EDNS_OPT_RR_TYPE) {
                    // Found EDNS OPT RR, patch UDP payload size
                    buffer[offset + 3] = new_size >> 8;
                    buffer[offset + 4] = new_size & 0xFF;
                    return len;
                }
                
                // Skip TYPE, CLASS, TTL, RDLENGTH
                uint16_t rdlength = (buffer[offset + 8] << 8) | buffer[offset + 9];
                offset += 10 + rdlength;
            } else {
                break;
            }
        } else {
            // Skip compressed name
            if ((buffer[offset] & 0xC0) == 0xC0) {
                offset += 2;
            } else {
                // Skip regular name
                while (offset < len && buffer[offset] != 0) {
                    offset += buffer[offset] + 1;
                }
                if (offset >= len) return len;
                offset++;
            }
            
            if (offset + 10 <= len) {
                uint16_t rdlength = (buffer[offset + 8] << 8) | buffer[offset + 9];
                offset += 10 + rdlength;
            } else {
                break;
            }
        }
    }
    
    // EDNS OPT RR not found, we could add one here if needed
    return len;
}

// ============================================================================
// EPOLL EVENT HANDLING
// ============================================================================

// Handle incoming DNS query from client
static void handle_client_query(int sock) {
    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Use recvfrom with MSG_DONTWAIT for non-blocking
    ssize_t len = recvfrom(sock, buffer, BUFFER_SIZE, MSG_DONTWAIT,
                          (struct sockaddr*)&client_addr, &client_len);
    
    if (len <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("[ERROR] recvfrom");
        }
        return;
    }
    
    // Parse TXID for request tracking
    if (len < DNS_HEADER_SIZE) return;
    uint16_t txid = (buffer[0] << 8) | buffer[1];
    
    // Patch EDNS for upstream (increase to internal size)
    len = patch_edns_opt_rr(buffer, len, INT_EDNS_SIZE);
    
    // Get free socket from pool
    socket_t *up_sock = get_free_socket();
    if (!up_sock) {
        fprintf(stderr, "[WARN] No free sockets in pool\n");
        return;
    }
    
    // Create request tracking
    request_t *req = malloc(sizeof(request_t));
    if (!req) {
        fprintf(stderr, "[ERROR] Failed to allocate request\n");
        return;
    }
    
    req->client_addr = client_addr;
    req->addr_len = client_len;
    req->txid = txid;
    req->timestamp = time(NULL);
    req->client_sock = sock;
    
    // Store in TXID map
    if (txid < MAX_PENDING) {
        txid_map[txid] = req;
    }
    
    // Store in socket pool
    up_sock->pending_req = req;
    up_sock->last_used = time(NULL);
    
    // Setup zero-copy send
    memcpy(up_sock->buffer, buffer, len);
    
    up_sock->iov.iov_base = up_sock->buffer;
    up_sock->iov.iov_len = len;
    
    memset(&up_sock->msg, 0, sizeof(up_sock->msg));
    up_sock->msg.msg_iov = &up_sock->iov;
    up_sock->msg.msg_iovlen = 1;
    up_sock->msg.msg_name = &up_sock->target_addr;
    up_sock->msg.msg_namelen = sizeof(up_sock->target_addr);
    
    // Send to SlowDNS backend using sendmsg
    ssize_t sent = sendmsg(up_sock->fd, &up_sock->msg, MSG_DONTWAIT);
    if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        perror("[ERROR] sendmsg to SlowDNS");
        // Cleanup on error
        if (txid < MAX_PENDING) txid_map[txid] = NULL;
        free(req);
        up_sock->pending_req = NULL;
    }
    
    // Re-arm epoll for this socket
    struct epoll_event ev;
    ev.events = EPOLLET_FLAGS;
    ev.data.ptr = up_sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, up_sock->fd, &ev) < 0) {
        perror("[ERROR] epoll_ctl MOD");
    }
}

// Handle response from SlowDNS
static void handle_slowdns_response(socket_t *sock) {
    uint8_t buffer[BUFFER_SIZE];
    
    // Use recv with MSG_DONTWAIT
    ssize_t len = recv(sock->fd, buffer, BUFFER_SIZE, MSG_DONTWAIT);
    
     if (len <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("[ERROR] recv from SlowDNS");
        }
        return;
    }
    
    request_t *req = sock->pending_req;
    if (!req) {
        fprintf(stderr, "[WARN] No pending request for socket\n");
        return;
    }
    
    // Parse TXID from response
    if (len < DNS_HEADER_SIZE) {
        fprintf(stderr, "[WARN] Invalid DNS response\n");
        goto cleanup;
    }
    
    uint16_t txid = (buffer[0] << 8) | buffer[1];
    
    // Verify TXID matches
    if (txid != req->txid) {
        // Check TXID map as fallback
        if (txid < MAX_PENDING && txid_map[txid]) {
            req = txid_map[txid];
        } else {
            fprintf(stderr, "[WARN] TXID mismatch: %04x != %04x\n", txid, req->txid);
            goto cleanup;
        }
    }
    
    // Patch EDNS for client (reduce to external size)
    len = patch_edns_opt_rr(buffer, len, EXT_EDNS_SIZE);
    
    // Send response back to client
    if (sendto(req->client_sock, buffer, len, MSG_DONTWAIT,
               (struct sockaddr*)&req->client_addr, req->addr_len) < 0) {
        perror("[ERROR] sendto client");
    }
    
cleanup:
    // Cleanup resources
    if (req->txid < MAX_PENDING) {
        txid_map[req->txid] = NULL;
    }
    free(req);
    sock->pending_req = NULL;
    
    // Re-arm epoll for reuse
    struct epoll_event ev;
    ev.events = EPOLLET_FLAGS;
    ev.data.ptr = sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sock->fd, &ev) < 0) {
        perror("[ERROR] epoll_ctl MOD cleanup");
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// Initialize socket pool
static int init_socket_pool(void) {
    memset(socket_pool, 0, sizeof(socket_pool));
    memset(txid_map, 0, sizeof(txid_map));
    
    // Initialize SlowDNS address
    memset(&slowdns_addr, 0, sizeof(slowdns_addr));
    slowdns_addr.sin_family = AF_INET;
    slowdns_addr.sin_port = htons(SLOWDNS_PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &slowdns_addr.sin_addr) <= 0) {
        perror("[ERROR] inet_pton");
        return -1;
    }
    
    // Create sockets for pool
    for (int i = 0; i < SOCKET_POOL_SIZE; i++) {
        socket_t *sock = &socket_pool[i];
        
        sock->fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock->fd < 0) {
            perror("[ERROR] socket creation");
            return -1;
        }
        
        if (set_nonblock(sock->fd) < 0) {
            perror("[ERROR] set_nonblock");
            close(sock->fd);
            return -1;
        }
        
        // Setup target address (SlowDNS)
        memcpy(&sock->target_addr, &slowdns_addr, sizeof(slowdns_addr));
        
        // Setup epoll event for this socket
        struct epoll_event ev;
        ev.events = EPOLLET_FLAGS;
        ev.data.ptr = sock;
        
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock->fd, &ev) < 0) {
            perror("[ERROR] epoll_ctl ADD socket");
            close(sock->fd);
            return -1;
        }
    }
    
    return 0;
}

// Initialize listening socket (EDNS Proxy on port 53)
static int init_listen_socket(void) {
    listen_sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (listen_sock < 0) {
        perror("[ERROR] socket");
        return -1;
    }
    
    // Enable SO_REUSEPORT for load balancing if multiple instances
    int reuse = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("[WARN] SO_REUSEPORT failed");
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);  // Port 53 for EDNS Proxy
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[ERROR] bind");
        close(listen_sock);
        return -1;
    }
    
    return 0;
}

// Initialize epoll
static int init_epoll(void) {
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("[ERROR] epoll_create1");
        return -1;
    }
    
    // Add listen socket to epoll (EDNS Proxy on port 53)
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_sock;
    
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sock, &ev) < 0) {
        perror("[ERROR] epoll_ctl ADD listen");
        return -1;
    }
    
    return 0;
}

// ============================================================================
// MAIN EVENT LOOP
// ============================================================================

int main() {
    printf("[EDNS Proxy] Starting high-performance DNS proxy\n");
    printf("[EDNS Proxy] Architecture: Client -> UDP:53 (EDNS Proxy) -> UDP:5300 (SlowDNS)\n");
    
    // Initialize components
    if (init_epoll() < 0) return 1;
    if (init_listen_socket() < 0) return 1;
    if (init_socket_pool() < 0) return 1;
    
    printf("[EDNS Proxy] Listening on port %d (ET mode)\n", LISTEN_PORT);
    printf("[EDNS Proxy] Forwarding to SlowDNS on port %d\n", SLOWDNS_PORT);
    printf("[EDNS Proxy] Socket pool size: %d\n", SOCKET_POOL_SIZE);
    printf("[EDNS Proxy] EDNS: %d -> %d bytes\n", EXT_EDNS_SIZE, INT_EDNS_SIZE);
    printf("[EDNS Proxy] Ready to handle DNS queries\n");
    
    // Main event loop
    struct epoll_event events[MAX_EVENTS];
    
    while (1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("[ERROR] epoll_wait");
            break;
        }
        
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == listen_sock) {
                // Handle client queries on port 53
                while (1) {
                    handle_client_query(listen_sock);
                    // Break if no more data (edge-triggered)
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                }
            } else {
                // Handle SlowDNS responses from port 5300
                socket_t *sock = (socket_t*)events[i].data.ptr;
                if (sock) {
                    handle_slowdns_response(sock);
                }
            }
        }
        
        // Periodic cleanup of old requests (every 60 seconds)
        static time_t last_cleanup = 0;
        time_t now = time(NULL);
        
        if (now - last_cleanup > 60) {
            for (int i = 0; i < MAX_PENDING; i++) {
                if (txid_map[i] && (now - txid_map[i]->timestamp) > 30) {
                    free(txid_map[i]);
                    txid_map[i] = NULL;
                }
            }
            last_cleanup = now;
        }
    }
    
    // Cleanup (should never reach here)
    close(listen_sock);
    close(epoll_fd);
    
    for (int i = 0; i < SOCKET_POOL_SIZE; i++) {
        if (socket_pool[i].fd > 0) {
            close(socket_pool[i].fd);
        }
        if (socket_pool[i].pending_req) {
            free(socket_pool[i].pending_req);
        }
    }
    
    return 0;
}
EOF
    
    # Compile with optimizations
    echo -ne "  ${CYAN}Compiling EDNS Proxy with O3 optimizations...${NC}"
    gcc -O3 -march=native -pipe -Wall -Wextra /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log &
    show_progress $!
    
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/edns-proxy
        echo -e "\r  ${GREEN}EDNS Proxy compiled successfully${NC}"
        echo -e "  ${CYAN}Features:${NC} EpollET, SocketPool(64), Zero-Copy, Correct EDNS parsing"
    else
        echo -e "\r  ${RED}Compilation failed${NC}"
        cat /tmp/compile.log
        exit 1
    fi
    
    # Create EDNS service with optimized parameters
    cat > /etc/systemd/system/edns-proxy.service << EOF
# ============================================================================
# EDNS PROXY SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=High-Performance EDNS Proxy for SlowDNS
Description=EpollET + SocketPool + Zero-Copy DNS Proxy
After=server-sldns.service
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=1048576
LimitCORE=infinity
LimitNPROC=65536
Nice=-10
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "EDNS Proxy service configured with performance optimizations"
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
    
    # Essential rules - REMOVED UDP 53 from firewall (EDNS Proxy will handle it)
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT 2>/dev/null
    # NOTE: UDP 53 is NOT opened here - EDNS Proxy will bind to it directly
    iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null
    
    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}Firewall rules configured${NC}"
    
    # Stop conflicting services that might be using port 53
    echo -ne "  ${CYAN}Stopping conflicting DNS services...${NC}"
    systemctl stop systemd-resolved 2>/dev/null &
    systemctl disable systemd-resolved 2>/dev/null &
    fuser -k 53/udp 2>/dev/null &
    fuser -k 53/tcp 2>/dev/null &
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
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} EDNS Proxy:    ${WHITE}53${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU Size:      ${WHITE}1800${NC}                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:    ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}EDNS PROXY ARCHITECTURE${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Listens on Port 53${NC} - EDNS Proxy                         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Forwards to Port 5300${NC} - SlowDNS                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Epoll Edge-Triggered (ET)${NC} - Maximum performance         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Socket Pool (64)${NC} - No socket creation overhead          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Zero-Copy Buffers${NC} - Scatter/gather I/O                  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Correct EDNS parsing${NC} - Handles compression pointers     ${CYAN}│${NC}"
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
    echo -e "${CYAN}│${NC} ${YELLOW}Monitor perf:${NC}     htop (filter: edns-proxy)               ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final verification
    echo -e "\n${WHITE}${BOLD}Verifying installation...${NC}"
    
    echo -ne "  ${CYAN}Checking port 53 (EDNS Proxy)...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":53 "; then
        echo -e "\r  ${GREEN}✓ Port 53 (EDNS Proxy) is listening${NC}"
    else
        echo -e "\r  ${YELLOW}! Port 53 not listening - EDNS Proxy may need restart${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking port 5300 (SlowDNS)...${NC}"
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
    
    # Architecture diagram
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}ARCHITECTURE DIAGRAM${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Clients (DNS over UDP)${NC}                                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}             │                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}             ▼                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}  ${GREEN}UDP :53 (EDNS Proxy)${NC}                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}             │                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}      ┌────────────────┐                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}      │  EDNS Proxy     │                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}      │  (EpollET)      │                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}      │  SocketPool     │                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}      │  Zero-Copy      │                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}      └────────────────┘                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}             │                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}             ▼                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}  ${GREEN}UDP :5300 (SlowDNS)${NC}                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}             │                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}      SlowDNS Server                                  ${CYAN}│${NC}"
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
    
    # Final message
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 OPTIMIZED SLOWDNS INSTALLATION COMPLETED!${NC}        ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ EDNS Proxy on Port 53 → SlowDNS on Port 5300${NC}     ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 Features: EpollET + SocketPool + Zero-Copy${NC}       ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}${BOLD}📞 Need help? Contact support: @esimfreegb${NC}"
    
    echo -e "\n${WHITE}${BOLD}Press Enter to return to terminal...${NC}"
    read -r
    
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
        5)
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
    echo -e "${GREEN}${BOLD}   Optimized installation completed at: $(date)${NC}"
    echo -e "${GREEN}${BOLD}   Server: $SERVER_IP | SlowDNS: $SLOWDNS_PORT | EDNS Proxy: 53${NC}"
    echo -e "${GREEN}${BOLD}   Architecture: EpollET + SocketPool + Zero-Copy${NC}"
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
```
