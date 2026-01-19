#!/bin/bash

# ============================================================================
#                     SLOWDNS MODERN INSTALLATION SCRIPT (OPTIMIZED)
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION - OPTIMIZED FOR PERFORMANCE
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# Performance tuning
CPU_CORES=$(nproc)
THREADS=$((CPU_CORES * 2))
CONNECTIONS_PER_THREAD=2048
MAX_CONNECTIONS=$((THREADS * CONNECTIONS_PER_THREAD))
BUFFER_SIZE=65536
MTU_SIZE=1500  # Changed from 1800 for better compatibility

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
    while kill -0 $pid 2>/dev/null; do
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

print_banner() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          🚀 OPTIMIZED SLOWDNS INSTALLATION SCRIPT${NC}        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}        Multi-Core Optimized for Maximum Performance${NC}     ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}                  CPU Cores: $CPU_CORES | Threads: $THREADS${NC}              ${BLUE}║${NC}"
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
# SYSTEM OPTIMIZATION FUNCTIONS
# ============================================================================
optimize_system() {
    print_header "⚡ SYSTEM OPTIMIZATION"
    
    # Increase file descriptors
    cat >> /etc/security/limits.conf << EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
    
    # Optimize kernel parameters
    cat >> /etc/sysctl.conf << EOF
# Network optimization for SlowDNS
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
fs.file-max = 2097152
EOF
    
    # Apply sysctl
    sysctl -p > /dev/null 2>&1
    
    # Set CPU governor to performance
    if command -v cpupower &> /dev/null; then
        cpupower frequency-set -g performance > /dev/null 2>&1
    fi
    
    print_success "System optimized for high performance"
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main() {
    print_banner
    
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
    SERVER_IP=$(curl -s --connect-timeout 5 --max-time 10 ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    echo -e "\r  ${GREEN}Server IP:${NC} ${WHITE}${BOLD}$SERVER_IP${NC}"
    echo -e "  ${GREEN}CPU Cores:${NC} ${WHITE}${BOLD}$CPU_CORES${NC}"
    echo -e "  ${GREEN}Max Connections:${NC} ${WHITE}${BOLD}$MAX_CONNECTIONS${NC}"
    
    # Optimize system first
    optimize_system
    
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
MaxSessions $MAX_CONNECTIONS
MaxStartups $MAX_CONNECTIONS
LoginGraceTime 30
UseDNS no
TCPKeepAlive yes
ClientAliveInterval 120
ClientAliveCountMax 3
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
    if curl -fsSL --connect-timeout 30 "$GITHUB_BASE/dnstt-server" -o dnstt-server 2>/dev/null; then
        echo -e "\r  ${GREEN}Binary downloaded via curl${NC}"
    elif wget -q --timeout=30 "$GITHUB_BASE/dnstt-server" -O dnstt-server 2>/dev/null; then
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
    wget -q --timeout=30 "$GITHUB_BASE/server.key" -O server.key 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}server.key downloaded${NC}"
    
    echo -ne "  ${CYAN}Downloading server.pub...${NC}"
    wget -q --timeout=30 "$GITHUB_BASE/server.pub" -O server.pub 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}server.pub downloaded${NC}"
    
    print_success "SlowDNS components installed"
    print_step_end
    
    # ============================================================================
    # STEP 3: CREATE MULTI-CORE SLOWDNS SERVICE
    # ============================================================================
    print_step "3"
    print_info "Creating Multi-Core SlowDNS system service"
    
    # Create startup script for multi-core support
    cat > /etc/slowdns/start-multi.sh << EOF
#!/bin/bash

# Start multiple instances for multi-core support
for i in \$(seq 0 $((CPU_CORES - 1))); do
    port=\$((SLOWDNS_PORT + i))
    /etc/slowdns/dnstt-server -udp :\$port -mtu $MTU_SIZE \\
        -privkey-file /etc/slowdns/server.key \\
        $NAMESERVER 127.0.0.1:$SSHD_PORT &
    echo "Started instance \$i on port \$port"
done

# Wait for all instances
wait
EOF
    
    chmod +x /etc/slowdns/start-multi.sh
    
    cat > /etc/systemd/system/server-sldns.service << EOF
# ============================================================================
# MULTI-CORE SLOWDNS SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=SlowDNS Server (Multi-Core)
After=network.target sshd.service
Wants=network-online.target
Conflicts=systemd-resolved.service

[Service]
Type=simple
ExecStart=/etc/slowdns/start-multi.sh
Restart=always
RestartSec=3
User=root
LimitNOFILE=1048576
LimitNPROC=unlimited
LimitCORE=infinity
Nice=-10
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
CPUAffinity=0-$((CPU_CORES - 1))
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "Multi-core service configuration created"
    print_step_end
    
    # ============================================================================
    # STEP 4: COMPILE MULTI-THREADED EDNS PROXY
    # ============================================================================
    print_step "4"
    print_info "Compiling Multi-Threaded EDNS Proxy"
    
    # Install dependencies
    if ! command -v gcc &>/dev/null; then
        print_info "Installing compiler tools"
        echo -ne "  ${CYAN}Installing build essentials...${NC}"
        apt update > /dev/null 2>&1 && apt install -y gcc libssl-dev build-essential > /dev/null 2>&1 &
        show_progress $!
        echo -e "\r  ${GREEN}Compiler tools installed${NC}"
    fi
    
    # Create optimized multi-threaded C code
    cat > /tmp/edns_multi.c << 'EOF'

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
#include <pthread.h>
#include <openssl/ssl.h>

#define LISTEN_PORT 53
#define SLOWDNS_BASE_PORT 5300
#define BUFFER_SIZE 65536
#define MAX_EVENTS 8192
#define MAX_THREADS 16
#define CONNECTIONS_PER_THREAD 2048
#define CACHE_SIZE 10000
#define SOCKET_TIMEOUT 2.0

typedef struct {
    int thread_id;
    int epoll_fd;
    pthread_t thread;
    int running;
    int slowdns_socks[MAX_THREADS];
    int slowdns_count;
} worker_t;

typedef struct {
    uint16_t req_id;
    time_t timestamp;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    int thread_id;
} request_cache_t;

static worker_t workers[MAX_THREADS];
static request_cache_t cache[CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t shutdown_flag = 0;
static int listen_sock;
static int cpu_count;

double now() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

uint16_t get_txid(unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}

uint32_t hash_request(uint16_t id) {
    return (id * 2654435761U) % CACHE_SIZE;
}

void cache_request(uint16_t id, struct sockaddr_in *addr, socklen_t addr_len, int thread_id) {
    pthread_mutex_lock(&cache_mutex);
    uint32_t idx = hash_request(id);
    cache[idx].req_id = id;
    cache[idx].timestamp = time(NULL);
    cache[idx].client_addr = *addr;
    cache[idx].addr_len = addr_len;
    cache[idx].thread_id = thread_id;
    pthread_mutex_unlock(&cache_mutex);
}

int find_cached_request(uint16_t id, struct sockaddr_in *addr, socklen_t *addr_len, int *thread_id) {
    pthread_mutex_lock(&cache_mutex);
    uint32_t idx = hash_request(id);
    if (cache[idx].req_id == id && time(NULL) - cache[idx].timestamp < SOCKET_TIMEOUT) {
        *addr = cache[idx].client_addr;
        *addr_len = cache[idx].addr_len;
        *thread_id = cache[idx].thread_id;
        cache[idx].req_id = 0; // Invalidate cache entry
        pthread_mutex_unlock(&cache_mutex);
        return 1;
    }
    pthread_mutex_unlock(&cache_mutex);
    return 0;
}

void cleanup_cache() {
    time_t now_time = time(NULL);
    pthread_mutex_lock(&cache_mutex);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cache[i].req_id != 0 && now_time - cache[i].timestamp > SOCKET_TIMEOUT) {
            cache[i].req_id = 0;
        }
    }
    pthread_mutex_unlock(&cache_mutex);
}

int patch_edns(unsigned char *buf, int len, int size) {
    if (len < 12) return len;
    int off = 12;
    int qd = (buf[4] << 8) | buf[5];
    
    for (int i = 0; i < qd; i++) {
        while (off < len && buf[off]) off++;
        if (off + 5 >= len) return len;
        off += 5;
    }
    
    int ar = (buf[10] << 8) | buf[11];
    for (int i = 0; i < ar; i++) {
        if (off < len && buf[off] == 0 && off + 4 < len && 
            ((buf[off+1]<<8)|buf[off+2]) == 41) {
            buf[off+3] = size >> 8;
            buf[off+4] = size & 255;
            return len;
        }
        off++;
    }
    return len;
}

void *worker_thread(void *arg) {
    worker_t *worker = (worker_t *)arg;
    struct epoll_event events[MAX_EVENTS];
    
    while (!shutdown_flag && worker->running) {
        cleanup_cache();
        
        int n = epoll_wait(worker->epoll_fd, events, MAX_EVENTS, 10);
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            
            if (fd == listen_sock) {
                // Handle incoming DNS query
                unsigned char buf[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                int len = recvfrom(fd, buf, sizeof(buf), 0, 
                                 (struct sockaddr *)&client_addr, &addr_len);
                if (len > 0) {
                    uint16_t id = get_txid(buf);
                    int slowdns_sock = worker->slowdns_socks[id % worker->slowdns_count];
                    
                    // Cache the request
                    cache_request(id, &client_addr, addr_len, worker->thread_id);
                    
                    // Patch EDNS and forward to SlowDNS
                    patch_edns(buf, len, 1400);
                    struct sockaddr_in slowdns_addr = {
                        .sin_family = AF_INET,
                        .sin_port = htons(SLOWDNS_BASE_PORT + (id % cpu_count)),
                        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
                    };
                    
                    sendto(slowdns_sock, buf, len, 0, 
                          (struct sockaddr *)&slowdns_addr, sizeof(slowdns_addr));
                }
            } else {
                // Handle response from SlowDNS
                unsigned char buf[BUFFER_SIZE];
                int len = recv(fd, buf, sizeof(buf), 0);
                if (len > 0) {
                    uint16_t id = get_txid(buf);
                    struct sockaddr_in client_addr;
                    socklen_t addr_len;
                    int req_thread_id;
                    
                    if (find_cached_request(id, &client_addr, &addr_len, &req_thread_id)) {
                        patch_edns(buf, len, 512);
                        sendto(listen_sock, buf, len, 0, 
                              (struct sockaddr *)&client_addr, addr_len);
                    }
                }
            }
        }
    }
    return NULL;
}

void sig_handler(int sig) {
    shutdown_flag = 1;
}

int main() {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count > MAX_THREADS) cpu_count = MAX_THREADS;
    if (cpu_count < 1) cpu_count = 1;
    
    printf("Starting EDNS Proxy with %d threads\n", cpu_count);
    
    // Create listen socket
    listen_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_sock < 0) {
        perror("socket");
        return 1;
    }
    
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(LISTEN_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    
    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_sock);
        return 1;
    }
    
    // Create worker threads
    for (int i = 0; i < cpu_count; i++) {
        workers[i].thread_id = i;
        workers[i].running = 1;
        workers[i].epoll_fd = epoll_create1(0);
        
        // Add listen socket to worker's epoll
        struct epoll_event ev = {
            .events = EPOLLIN,
            .data.fd = listen_sock
        };
        epoll_ctl(workers[i].epoll_fd, EPOLL_CTL_ADD, listen_sock, &ev);
        
        // Create SlowDNS sockets for this worker
        for (int j = 0; j < cpu_count; j++) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock >= 0) {
                fcntl(sock, F_SETFL, O_NONBLOCK);
                workers[i].slowdns_socks[j] = sock;
                
                struct epoll_event sev = {
                    .events = EPOLLIN,
                    .data.fd = sock
                };
                epoll_ctl(workers[i].epoll_fd, EPOLL_CTL_ADD, sock, &sev);
            }
        }
        workers[i].slowdns_count = cpu_count;
        
        pthread_create(&workers[i].thread, NULL, worker_thread, &workers[i]);
        
        // Set CPU affinity for thread
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i % cpu_count, &cpuset);
        pthread_setaffinity_np(workers[i].thread, sizeof(cpu_set_t), &cpuset);
    }
    
    // Wait for shutdown
    while (!shutdown_flag) {
        sleep(1);
    }
    
    // Cleanup
    for (int i = 0; i < cpu_count; i++) {
        workers[i].running = 0;
        pthread_join(workers[i].thread, NULL);
        close(workers[i].epoll_fd);
        for (int j = 0; j < workers[i].slowdns_count; j++) {
            close(workers[i].slowdns_socks[j]);
        }
    }
    
    close(listen_sock);
    return 0;
}
EOF
    
    # Compile with optimizations
    echo -ne "  ${CYAN}Compiling Multi-Threaded EDNS Proxy...${NC}"
    gcc -O3 -march=native -pipe -pthread /tmp/edns_multi.c -o /usr/local/bin/edns-proxy -lssl 2>/tmp/compile.log &
    show_progress $!
    
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/edns-proxy
        echo -e "\r  ${GREEN}Multi-threaded EDNS Proxy compiled successfully${NC}"
    else
        # Try without SSL
        gcc -O3 -march=native -pipe -pthread /tmp/edns_multi.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log
        if [ $? -eq 0 ]; then
            chmod +x /usr/local/bin/edns-proxy
            echo -e "\r  ${GREEN}Multi-threaded EDNS Proxy compiled (without SSL)${NC}"
        else
            echo -e "\r  ${RED}Compilation failed${NC}"
            cat /tmp/compile.log | tail -5
            exit 1
        fi
    fi
    
    # Create optimized EDNS service
    cat > /etc/systemd/system/edns-proxy.service << EOF
# ============================================================================
# MULTI-THREADED EDNS PROXY SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=Multi-Threaded EDNS Proxy for SlowDNS
After=server-sldns.service
Requires=server-sldns.service
Conflicts=systemd-resolved.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=1048576
LimitNPROC=unlimited
LimitCORE=infinity
Nice=-10
IOSchedulingClass=realtime
IOSchedulingPriority=0
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
CPUAffinity=0-$((CPU_CORES - 1))
OOMScoreAdjust=-1000
Environment="LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4"
Environment="GOGC=50"
Environment="GOMAXPROCS=$CPU_CORES"

[Install]
WantedBy=multi-user.target
EOF
    
    # Install tcmalloc for better memory management
    echo -ne "  ${CYAN}Installing performance libraries...${NC}"
    apt install -y libgoogle-perftools4 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}Performance libraries installed${NC}"
    
    print_success "Multi-threaded EDNS Proxy configured"
    print_step_end
    
    # ============================================================================
    # STEP 5: FIREWALL CONFIGURATION
    # ============================================================================
    print_step "5"
    print_info "Configuring system firewall"
    
    echo -ne "  ${CYAN}Setting up optimized firewall rules...${NC}"
    
    # Flush existing rules
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    iptables -P INPUT DROP 2>/dev/null
    iptables -P FORWARD DROP 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    
    # Localhost
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    
    # Established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    
    # SSH
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT 2>/dev/null
    
    # SlowDNS ports (multiple instances)
    for i in $(seq 0 $((CPU_CORES - 1))); do
        port=$((SLOWDNS_PORT + i))
        iptables -A INPUT -p udp --dport $port -j ACCEPT 2>/dev/null
    done
    
    # DNS ports
    iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null
    
    # ICMP (ping)
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null
    
    # Protection rules
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 2>/dev/null
    iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP 2>/dev/null
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP 2>/dev/null
    iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null
    
    # Connection limiting for protection
    iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name dnslimit --hashlimit-mode srcip --hashlimit-upto 10/second --hashlimit-burst 20 --hashlimit-htable-expire 30000 -j ACCEPT 2>/dev/null
    
    # Disable IPv6 completely
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p > /dev/null 2>&1
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    
    # Kill anything on port 53
    fuser -k 53/udp 2>/dev/null || true
    fuser -k 53/tcp 2>/dev/null || true
    
    echo -e "\r  ${GREEN}Optimized firewall rules configured${NC}"
    
    print_success "Firewall and network optimized"
    print_step_end
    
    # ============================================================================
    # STEP 6: START SERVICES
    # ============================================================================
    print_step "6"
    print_info "Starting all services with performance tuning"
    
    systemctl daemon-reload 2>/dev/null
    
    # Start SlowDNS
    echo -ne "  ${CYAN}Starting Multi-Core SlowDNS service...${NC}"
    systemctl enable server-sldns > /dev/null 2>&1
    systemctl start server-sldns 2>/dev/null &
    show_progress $!
    sleep 3
    
    # Start EDNS proxy
    echo -ne "  ${CYAN}Starting Multi-Threaded EDNS Proxy...${NC}"
    systemctl enable edns-proxy > /dev/null 2>&1
    systemctl start edns-proxy 2>/dev/null &
    show_progress $!
    sleep 3
    
    # Verify services
    echo -ne "  ${CYAN}Verifying service status...${NC}"
    sleep 2
    
    slowdns_running=$(systemctl is-active server-sldns)
    edns_running=$(systemctl is-active edns-proxy)
    
    if [ "$slowdns_running" = "active" ] && [ "$edns_running" = "active" ]; then
        echo -e "\r  ${GREEN}✓ All services are running${NC}"
    else
        echo -e "\r  ${YELLOW}! Some services may need attention${NC}"
        if [ "$slowdns_running" != "active" ]; then
            echo -e "    ${YELLOW}SlowDNS: $slowdns_running${NC}"
        fi
        if [ "$edns_running" != "active" ]; then
            echo -e "    ${YELLOW}EDNS Proxy: $edns_running${NC}"
        fi
    fi
    
    print_success "Services started with performance tuning"
    print_step_end
    
    # ============================================================================
    # COMPLETION SUMMARY
    # ============================================================================
    print_header "🎉 OPTIMIZED INSTALLATION COMPLETE"
    
    # Show summary
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER INFORMATION${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:     ${WHITE}$SERVER_IP${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} CPU Cores:     ${WHITE}$CPU_CORES${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Threads:       ${WHITE}$THREADS${NC}                         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Max Conn:      ${WHITE}$MAX_CONNECTIONS${NC}                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SSH Port:      ${WHITE}$SSHD_PORT${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SlowDNS Ports: ${WHITE}$SLOWDNS_PORT-$((SLOWDNS_PORT + CPU_CORES - 1))${NC}     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} EDNS Port:     ${WHITE}53${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU Size:      ${WHITE}$MTU_SIZE${NC}                         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:    ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Performance monitoring commands
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PERFORMANCE MONITORING${NC}                              ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}htop${NC} - View CPU utilization per core              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}iftop -i eth0${NC} - Monitor network traffic           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}nload eth0${NC} - Real-time bandwidth monitoring       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}ss -ulnp | grep ':53\|:53'${NC} - Check ports          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}journalctl -u server-sldns -f${NC} - View logs         ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Daytime performance tips
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}DAYTIME PERFORMANCE OPTIMIZATION${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Daytime performance issues are often due to:            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}1.${NC} Network congestion - Try different ports              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}2.${NC} ISP throttling - Use standard DNS port (53)           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}3.${NC} High latency - Consider TCP mode for better stability ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}4.${NC} Client-side limits - Increase client buffer sizes     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}5.${NC} Server load - Monitor with 'htop'                     ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Client configuration for multi-port
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CLIENT CONFIGURATION FOR MULTI-PORT${NC}                  ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}For better performance, clients can:${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} 1. Use multiple ports for load balancing             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} 2. Implement client-side connection pooling          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} 3. Use TCP instead of UDP for stable connections    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} 4. Increase buffer sizes on client side             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Client command example:${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ./dnstt-client -udp $SERVER_IP:5300,5301,5302 \\${NC}      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}     -pubkey-file server.pub \\${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}     $NAMESERVER 127.0.0.1:1080${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final verification
    echo -e "\n${WHITE}${BOLD}PERFORMANCE VERIFICATION:${NC}"
    
    # Check CPU affinity
    echo -ne "  ${CYAN}Checking CPU affinity...${NC}"
    if ps aux | grep -E "dnstt-server|edns-proxy" | grep -v grep | head -1; then
        echo -e "\r  ${GREEN}✓ Processes running with CPU affinity${NC}"
    else
        echo -e "\r  ${YELLOW}! CPU affinity may not be set${NC}"
    fi
    
    # Check memory usage
    echo -ne "  ${CYAN}Checking memory allocation...${NC}"
    if ps aux | grep edns-proxy | grep -v grep; then
        echo -e "\r  ${GREEN}✓ EDNS Proxy running with tcmalloc${NC}"
    fi
    
    # Check all ports
    echo -ne "  ${CYAN}Checking all listening ports...${NC}"
    echo ""
    for i in $(seq 0 $((CPU_CORES - 1))); do
        port=$((SLOWDNS_PORT + i))
        if ss -ulpn 2>/dev/null | grep -q ":$port "; then
            echo -e "    ${GREEN}✓ Port $port (SlowDNS $i) is listening${NC}"
        else
            echo -e "    ${YELLOW}! Port $port not listening${NC}"
        fi
    done
    
    if ss -ulpn 2>/dev/null | grep -q ":53 "; then
        echo -e "    ${GREEN}✓ Port 53 (EDNS Proxy) is listening${NC}"
    else
        echo -e "    ${YELLOW}! Port 53 not listening${NC}"
    fi
    
    # Final message
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 MULTI-CORE SLOWDNS INSTALLATION COMPLETE!${NC}         ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Optimized for $CPU_CORES CPU cores${NC}                   ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 Max concurrent connections: $MAX_CONNECTIONS${NC}       ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🔧 Ready for high-performance DNS tunneling${NC}           ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}${BOLD}💡 For daytime performance issues:${NC}"
    echo -e "  1. Monitor with: ${GREEN}htop${NC} and ${GREEN}iftop${NC}"
    echo -e "  2. Consider TCP mode for stability"
    echo -e "  3. Adjust MTU size if needed (currently: $MTU_SIZE)"
    echo -e "  4. Use multiple client connections to different ports"
    
    echo -e "\n${WHITE}${BOLD}Press Enter to return to terminal...${NC}"
    read -r
    
    # Cleanup
    rm -f /tmp/edns_multi.c /tmp/compile.log 2>/dev/null
}

# ============================================================================
# EXECUTE WITH ERROR HANDLING
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; exit 1' INT

# Create log file
LOG_FILE="/tmp/slowdns_install_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

if main; then
    echo -e "\n${GREEN}✓ Installation completed successfully at: $(date)${NC}"
    echo -e "${GREEN}✓ Log saved to: $LOG_FILE${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Installation failed${NC}"
    echo -e "${RED}✗ Check log file: $LOG_FILE${NC}"
    exit 1
fi
```

    
