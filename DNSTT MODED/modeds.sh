#!/bin/bash

# ============================================================================
#                     SLOWDNS MULTI-CORE INSTALLATION SCRIPT
# ============================================================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31m[✗]\033[0m Please run this script as root"
    exit 1
fi

# ============================================================================
# CONFIGURATION - MULTI-CORE OPTIMIZED
# ============================================================================
SSHD_PORT=22
SLOWDNS_BASE_PORT=5300
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
EXTERNAL_EDNS=512   # External DNS queries
INTERNAL_EDNS=1800  # Internal tunnel MTU

# Detect CPU cores for multi-core optimization
CPU_CORES=$(nproc)
MAX_THREADS=$CPU_CORES
CONNECTIONS_PER_CORE=2048
TOTAL_CONNECTIONS=$((CPU_CORES * CONNECTIONS_PER_CORE))

echo -e "${GREEN}Detected $CPU_CORES CPU cores - Optimizing for multi-core performance${NC}"

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

print_banner() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          🚀 MULTI-CORE SLOWDNS INSTALLATION${NC}               ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}        Optimized for $CPU_CORES CPU Cores - Maximum Performance${NC}  ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}              Total Connections: $TOTAL_CONNECTIONS${NC}              ${BLUE}║${NC}"
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
# SYSTEM OPTIMIZATION FOR MULTI-CORE
# ============================================================================
optimize_multi_core() {
    print_header "⚡ MULTI-CORE SYSTEM OPTIMIZATION"
    
    # Increase system limits
    cat >> /etc/security/limits.conf << EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
* soft nproc unlimited
* hard nproc unlimited
EOF
    
    # Optimize kernel for multi-core performance
    cat >> /etc/sysctl.conf << EOF
# Multi-core optimization
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.ipv4.tcp_rmem = 4096 87380 268435456
net.ipv4.tcp_wmem = 4096 65536 268435456
net.core.netdev_max_backlog = 500000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.ip_local_port_range = 20000 65535
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
fs.file-max = 2097152
kernel.pid_max = 4194304
vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF
    
    # Apply sysctl settings
    sysctl -p > /dev/null 2>&1
    
    # Set CPU governor to performance mode
    if command -v cpupower &> /dev/null; then
        cpupower frequency-set -g performance > /dev/null 2>&1
    fi
    
    # Disable CPU frequency scaling
    for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo "performance" > "$governor" 2>/dev/null
    done
    
    print_success "System optimized for $CPU_CORES CPU cores"
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
    SERVER_IP=$(curl -s --connect-timeout 5 ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    echo -e "\r  ${GREEN}Server IP:${NC} ${WHITE}${BOLD}$SERVER_IP${NC}"
    echo -e "  ${GREEN}CPU Cores:${NC} ${WHITE}${BOLD}$CPU_CORES${NC}"
    echo -e "  ${GREEN}Max Connections:${NC} ${WHITE}${BOLD}$TOTAL_CONNECTIONS${NC}"
    
    # Optimize system for multi-core
    optimize_multi_core
    
    # ============================================================================
    # STEP 1: CONFIGURE OPENSSH FOR MULTI-CORE
    # ============================================================================
    print_step "1"
    print_info "Configuring OpenSSH for $CPU_CORES cores"
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null
    
    cat > /etc/ssh/sshd_config << EOF
# ============================================================================
# MULTI-CORE SSH CONFIGURATION
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
MaxSessions $TOTAL_CONNECTIONS
MaxStartups $TOTAL_CONNECTIONS
LoginGraceTime 30
UseDNS no
AcceptEnv LANG LC_*
GSSAPIAuthentication no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF
    
    systemctl restart sshd
    print_success "OpenSSH configured for $CPU_CORES cores"
    print_step_end
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS MULTI-CORE
    # ============================================================================
    print_step "2"
    print_info "Setting up Multi-Core SlowDNS"
    
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download binary
    print_info "Downloading SlowDNS binary..."
    if ! curl -fsSL "$GITHUB_BASE/dnstt-server" -o dnstt-server; then
        wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server
    fi
    
    chmod +x dnstt-server
    SLOWDNS_BINARY="/etc/slowdns/dnstt-server"
    
    # Download keys
    print_info "Downloading encryption keys..."
    if ! curl -fsSL "$GITHUB_BASE/server.key" -o server.key; then
        wget -q "$GITHUB_BASE/server.key" -O server.key
    fi
    
    if ! curl -fsSL "$GITHUB_BASE/server.pub" -o server.pub; then
        wget -q "$GITHUB_BASE/server.pub" -O server.pub
    fi
    
    print_success "SlowDNS components downloaded"
    print_step_end
    
    # ============================================================================
    # STEP 3: CREATE MULTI-CORE SLOWDNS SERVICE
    # ============================================================================
    print_step "3"
    print_info "Creating Multi-Core SlowDNS services"
    
    # Create startup script for multiple instances
    cat > /etc/slowdns/start_all.sh << EOF
#!/bin/bash

# Start multiple SlowDNS instances, one per CPU core
echo "Starting $CPU_CORES SlowDNS instances..."

for ((i=0; i<$CPU_CORES; i++)); do
    PORT=\$((SLOWDNS_BASE_PORT + i))
    echo "Starting instance \$i on port \$PORT"
    
    # Set CPU affinity for each instance
    taskset -c \$i $SLOWDNS_BINARY -udp :\$PORT -mtu $INTERNAL_EDNS \\
        -privkey-file /etc/slowdns/server.key \\
        $NAMESERVER 127.0.0.1:$SSHD_PORT &
    
    # Store PID for management
    echo \$! > /var/run/slowdns-\$i.pid
    sleep 0.1
done

echo "All $CPU_CORES instances started"
wait
EOF
    
    chmod +x /etc/slowdns/start_all.sh
    
    # Create service file
    cat > /etc/systemd/system/server-sldns.service << EOF
# ============================================================================
# MULTI-CORE SLOWDNS SERVICE
# ============================================================================
[Unit]
Description=Multi-Core SlowDNS Server
After=network.target sshd.service
Conflicts=systemd-resolved.service

[Service]
Type=forking
ExecStart=/etc/slowdns/start_all.sh
ExecStop=/bin/bash -c 'for pidfile in /var/run/slowdns-*.pid; do [ -f "\$pidfile" ] && kill \$(cat "\$pidfile") 2>/dev/null; done'
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
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Create individual service files for each core (for better control)
    for ((i=0; i<CPU_CORES; i++)); do
        PORT=$((SLOWDNS_BASE_PORT + i))
        
        cat > /etc/systemd/system/slowdns-core-$i.service << EOF
[Unit]
Description=SlowDNS Instance on Core $i (Port $PORT)
PartOf=server-sldns.service
After=server-sldns.service

[Service]
Type=simple
ExecStart=taskset -c $i $SLOWDNS_BINARY -udp :$PORT -mtu $INTERNAL_EDNS \\
    -privkey-file /etc/slowdns/server.key \\
    $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=3
User=root
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
CPUAffinity=$i
Nice=-10

[Install]
WantedBy=multi-user.target
EOF
    done
    
    print_success "Multi-core SlowDNS services created"
    print_step_end
    
    # ============================================================================
    # STEP 4: COMPILE MULTI-THREADED EDNS PROXY
    # ============================================================================
    print_step "4"
    print_info "Compiling Multi-Threaded EDNS Proxy"
    
    # Install compiler if needed
    if ! command -v gcc &>/dev/null; then
        apt update > /dev/null 2>&1 && apt install -y gcc build-essential > /dev/null 2>&1
    fi
    
    # Create MULTI-THREADED EDNS proxy in C
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

#define LISTEN_PORT 53
#define SLOWDNS_BASE_PORT 5300
#define BUFFER_SIZE 65536
#define MAX_THREADS 32
#define MAX_EVENTS_PER_THREAD 8192
#define CACHE_SIZE 100000
#define EXT_EDNS 512
#define INT_EDNS 1800
#define TIMEOUT 2.0

typedef struct {
    int thread_id;
    int epoll_fd;
    pthread_t thread;
    int running;
    int cpu_core;
    int slowdns_count;
    int slowdns_socks[MAX_THREADS];
} worker_t;

typedef struct {
    uint16_t txid;
    time_t timestamp;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    int thread_id;
} cache_entry_t;

static worker_t workers[MAX_THREADS];
static cache_entry_t *cache[CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t shutdown_flag = 0;
static int listen_sock;
static int cpu_count = 1;

// Hash function for cache
uint32_t cache_hash(uint16_t txid) {
    return (txid * 2654435761U) % CACHE_SIZE;
}

// Get current time in seconds
double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

// Get transaction ID from DNS packet
uint16_t get_txid(unsigned char *buf) {
    return (buf[0] << 8) | buf[1];
}

// Patch EDNS size in DNS packet
int patch_edns(unsigned char *buf, int len, int new_size) {
    if (len < 12) return len;
    
    int qdcount = (buf[4] << 8) | buf[5];
    int ancount = (buf[6] << 8) | buf[7];
    int nscount = (buf[8] << 8) | buf[9];
    int arcount = (buf[10] << 8) | buf[11];
    
    int offset = 12;
    
    // Skip questions
    for (int i = 0; i < qdcount && offset < len; i++) {
        while (offset < len && buf[offset] != 0) offset++;
        if (offset + 5 > len) return len;
        offset += 5;
    }
    
    // Skip answers
    for (int i = 0; i < ancount && offset < len; i++) {
        if (buf[offset] & 0xC0) { // Compressed name
            offset += 2;
        } else { // Uncompressed name
            while (offset < len && buf[offset] != 0) offset++;
            offset++;
        }
        if (offset + 10 > len) return len;
        int rdlength = (buf[offset+8] << 8) | buf[offset+9];
        offset += 10 + rdlength;
    }
    
    // Skip authority records
    for (int i = 0; i < nscount && offset < len; i++) {
        if (buf[offset] & 0xC0) {
            offset += 2;
        } else {
            while (offset < len && buf[offset] != 0) offset++;
            offset++;
        }
        if (offset + 10 > len) return len;
        int rdlength = (buf[offset+8] << 8) | buf[offset+9];
        offset += 10 + rdlength;
    }
    
    // Look for OPT record in additional section
    for (int i = 0; i < arcount && offset < len; i++) {
        if (buf[offset] == 0) { // Root label for OPT
            if (offset + 11 <= len) {
                uint16_t rrtype = (buf[offset+1] << 8) | buf[offset+2];
                if (rrtype == 41) { // OPT RR type
                    buf[offset+3] = (new_size >> 8) & 0xFF;
                    buf[offset+4] = new_size & 0xFF;
                    return len;
                }
            }
        }
        
        // Skip to next record
        if (buf[offset] & 0xC0) {
            offset += 2;
        } else {
            while (offset < len && buf[offset] != 0) offset++;
            offset++;
        }
        if (offset + 10 > len) break;
        int rdlength = (buf[offset+8] << 8) | buf[offset+9];
        offset += 10 + rdlength;
    }
    
    return len;
}

// Cache management
void cache_put(uint16_t txid, struct sockaddr_in *addr, socklen_t addr_len, int thread_id) {
    pthread_mutex_lock(&cache_mutex);
    uint32_t idx = cache_hash(txid);
    if (cache[idx] == NULL) {
        cache[idx] = malloc(sizeof(cache_entry_t));
    }
    if (cache[idx]) {
        cache[idx]->txid = txid;
        cache[idx]->timestamp = time(NULL);
        cache[idx]->client_addr = *addr;
        cache[idx]->addr_len = addr_len;
        cache[idx]->thread_id = thread_id;
    }
    pthread_mutex_unlock(&cache_mutex);
}

int cache_get(uint16_t txid, struct sockaddr_in *addr, socklen_t *addr_len, int *thread_id) {
    pthread_mutex_lock(&cache_mutex);
    uint32_t idx = cache_hash(txid);
    if (cache[idx] && cache[idx]->txid == txid && 
        time(NULL) - cache[idx]->timestamp < TIMEOUT) {
        *addr = cache[idx]->client_addr;
        *addr_len = cache[idx]->addr_len;
        *thread_id = cache[idx]->thread_id;
        free(cache[idx]);
        cache[idx] = NULL;
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
        if (cache[i] && now_time - cache[i]->timestamp > TIMEOUT) {
            free(cache[i]);
            cache[i] = NULL;
        }
    }
    pthread_mutex_unlock(&cache_mutex);
}

// Worker thread function
void *worker_thread(void *arg) {
    worker_t *worker = (worker_t *)arg;
    struct epoll_event events[MAX_EVENTS_PER_THREAD];
    
    printf("Worker %d started on CPU core %d\n", worker->thread_id, worker->cpu_core);
    
    while (!shutdown_flag && worker->running) {
        cleanup_cache();
        
        int n = epoll_wait(worker->epoll_fd, events, MAX_EVENTS_PER_THREAD, 10);
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            
            if (fd == listen_sock) {
                // Incoming DNS query
                unsigned char buf[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                int len = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&client_addr, &addr_len);
                if (len > 0) {
                    uint16_t txid = get_txid(buf);
                    
                    // Patch EDNS size UP for tunnel
                    patch_edns(buf, len, INT_EDNS);
                    
                    // Store in cache
                    cache_put(txid, &client_addr, addr_len, worker->thread_id);
                    
                    // Distribute to SlowDNS instance based on TXID hash
                    int slowdns_idx = txid % worker->slowdns_count;
                    struct sockaddr_in slowdns_addr = {
                        .sin_family = AF_INET,
                        .sin_port = htons(SLOWDNS_BASE_PORT + (txid % cpu_count)),
                        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
                    };
                    
                    sendto(worker->slowdns_socks[slowdns_idx], buf, len, 0,
                          (struct sockaddr *)&slowdns_addr, sizeof(slowdns_addr));
                }
            } else {
                                // Response from SlowDNS
                unsigned char buf[BUFFER_SIZE];
                int len = recv(fd, buf, sizeof(buf), 0);
                if (len > 0) {
                    uint16_t txid = get_txid(buf);
                    struct sockaddr_in client_addr;
                    socklen_t addr_len;
                    int req_thread_id;
                    
                    if (cache_get(txid, &client_addr, &addr_len, &req_thread_id)) {
                        // Patch EDNS size DOWN for external
                        patch_edns(buf, len, EXT_EDNS);
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
    
    // Get CPU count
    cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count > MAX_THREADS) cpu_count = MAX_THREADS;
    if (cpu_count < 1) cpu_count = 1;
    
    printf("Starting Multi-Threaded EDNS Proxy with %d threads (CPU cores)\n", cpu_count);
    printf("External EDNS: %d, Internal MTU: %d\n", EXT_EDNS, INT_EDNS);
    
    // Create listening socket
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
    
    fcntl(listen_sock, F_SETFL, O_NONBLOCK);
    
    // Initialize cache
    for (int i = 0; i < CACHE_SIZE; i++) {
        cache[i] = NULL;
    }
    
    // Create worker threads
    for (int i = 0; i < cpu_count; i++) {
        workers[i].thread_id = i;
        workers[i].running = 1;
        workers[i].cpu_core = i;
        workers[i].epoll_fd = epoll_create1(0);
        
        // Add listening socket to this worker
        struct epoll_event ev = {
            .events = EPOLLIN,
            .data.fd = listen_sock
        };
        epoll_ctl(workers[i].epoll_fd, EPOLL_CTL_ADD, listen_sock, &ev);
        
        // Create SlowDNS sockets for this worker
        workers[i].slowdns_count = cpu_count;
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
        
        pthread_create(&workers[i].thread, NULL, worker_thread, &workers[i]);
        
        // Set CPU affinity for thread
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i, &cpuset);
        pthread_setaffinity_np(workers[i].thread, sizeof(cpu_set_t), &cpuset);
    }
    
    printf("EDNS Proxy started successfully. Workers running on all %d CPU cores.\n", cpu_count);
    
    // Main loop
    while (!shutdown_flag) {
        sleep(1);
    }
    
    // Cleanup
    printf("Shutting down...\n");
    for (int i = 0; i < cpu_count; i++) {
        workers[i].running = 0;
        pthread_join(workers[i].thread, NULL);
        close(workers[i].epoll_fd);
        for (int j = 0; j < workers[i].slowdns_count; j++) {
            if (workers[i].slowdns_socks[j] > 0) {
                close(workers[i].slowdns_socks[j]);
            }
        }
    }
    
    close(listen_sock);
    
    // Clean cache
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cache[i]) free(cache[i]);
    }
    
    return 0;
}
EOF
    
    # Compile the multi-threaded EDNS proxy
    echo -ne "  ${CYAN}Compiling Multi-Threaded EDNS Proxy...${NC}"
    gcc -O3 -pthread -march=native /tmp/edns_multi.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log
    
    if [ $? -eq 0 ] && [ -f "/usr/local/bin/edns-proxy" ]; then
        chmod +x /usr/local/bin/edns-proxy
        echo -e "\r  ${GREEN}Multi-Threaded EDNS Proxy compiled successfully${NC}"
        echo -e "  ${GREEN}Threads: ${WHITE}$CPU_CORES${NC}"
        echo -e "  ${GREEN}External EDNS: ${WHITE}$EXTERNAL_EDNS${NC}"
        echo -e "  ${GREEN}Internal MTU: ${WHITE}$INTERNAL_EDNS${NC}"
    else
        echo -e "\r  ${RED}Compilation failed${NC}"
        exit 1
    fi
    
    # Create EDNS proxy service with CPU affinity
    cat > /etc/systemd/system/edns-proxy.service << EOF
# ============================================================================
# MULTI-THREADED EDNS PROXY SERVICE
# ============================================================================
[Unit]
Description=Multi-Threaded EDNS Proxy
After=network.target server-sldns.service
Requires=server-sldns.service

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
Environment="GOMAXPROCS=$CPU_CORES"

[Install]
WantedBy=multi-user.target
EOF
    
    # Install performance libraries
    apt install -y libgoogle-perftools4 2>/dev/null
    
    print_success "Multi-threaded EDNS Proxy configured"
    print_step_end
    
    # ============================================================================
    # STEP 5: FIREWALL CONFIGURATION FOR MULTI-PORT
    # ============================================================================
    print_step "5"
    print_info "Configuring firewall for multi-port"
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    fuser -k 53/tcp 2>/dev/null
    
    # Flush iptables
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Allow localhost
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT
    
    # Allow all SlowDNS ports (one per core)
    for ((i=0; i<CPU_CORES; i++)); do
        PORT=$((SLOWDNS_BASE_PORT + i))
        iptables -A INPUT -p udp --dport $PORT -j ACCEPT
        echo -e "  ${GREEN}✓ Port $PORT allowed (Core $i)${NC}"
    done
    
    # Allow DNS port
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    
    # Drop invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP
    
    # Enable connection tracking
    modprobe nf_conntrack 2>/dev/null
    echo 1000000 > /proc/sys/net/nf_conntrack_max 2>/dev/null
    
    print_success "Firewall configured for multi-port"
    print_step_end
    
    # ============================================================================
    # STEP 6: START ALL SERVICES
    # ============================================================================
    print_step "6"
    print_info "Starting all multi-core services"
    
    systemctl daemon-reload
    
    # Start SlowDNS
    echo -ne "  ${CYAN}Starting $CPU_CORES SlowDNS instances...${NC}"
    systemctl enable server-sldns > /dev/null 2>&1
    systemctl start server-sldns
    
    # Start individual core services
    for ((i=0; i<CPU_CORES; i++)); do
        systemctl enable slowdns-core-$i > /dev/null 2>&1
        systemctl start slowdns-core-$i 2>/dev/null
    done
    
    sleep 3
    echo -e "\r  ${GREEN}$CPU_CORES SlowDNS instances started${NC}"
    
    # Start EDNS proxy
    echo -ne "  ${CYAN}Starting Multi-Threaded EDNS Proxy...${NC}"
    systemctl enable edns-proxy > /dev/null 2>&1
    systemctl start edns-proxy
    sleep 2
    echo -e "\r  ${GREEN}Multi-Threaded EDNS Proxy started${NC}"
    
    print_success "All services started with multi-core optimization"
    print_step_end
    
    # ============================================================================
    # VERIFICATION
    # ============================================================================
    print_header "🔍 VERIFICATION"
    
    # Check if all ports are listening
    echo -e "${WHITE}Checking all SlowDNS ports:${NC}"
    ALL_PORTS_OK=true
    for ((i=0; i<CPU_CORES; i++)); do
        PORT=$((SLOWDNS_BASE_PORT + i))
        if ss -ulpn 2>/dev/null | grep -q ":$PORT "; then
            echo -e "  ${GREEN}✓ Port $PORT (Core $i) is listening${NC}"
        else
            echo -e "  ${RED}✗ Port $PORT (Core $i) NOT listening${NC}"
            ALL_PORTS_OK=false
        fi
    done
    
    # Check EDNS proxy
    echo -e "\n${WHITE}Checking EDNS Proxy:${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":53 "; then
        echo -e "  ${GREEN}✓ Port 53 (EDNS Proxy) is listening${NC}"
    else
        echo -e "  ${RED}✗ Port 53 NOT listening${NC}"
        ALL_PORTS_OK=false
    fi
    
    # Check services
    echo -e "\n${WHITE}Checking services:${NC}"
    if systemctl is-active --quiet server-sldns; then
        echo -e "  ${GREEN}✓ SlowDNS main service is running${NC}"
    else
        echo -e "  ${RED}✗ SlowDNS main service NOT running${NC}"
    fi
    
    if systemctl is-active --quiet edns-proxy; then
        echo -e "  ${GREEN}✓ EDNS Proxy service is running${NC}"
    else
        echo -e "  ${RED}✗ EDNS Proxy service NOT running${NC}"
    fi
    
    # Check CPU usage
    echo -e "\n${WHITE}Checking CPU affinity:${NC}"
    for ((i=0; i<CPU_CORES; i++)); do
        if ps aux | grep "slowdns-core-$i" | grep -v grep > /dev/null; then
            echo -e "  ${GREEN}✓ SlowDNS Core $i is assigned to CPU $i${NC}"
        fi
    done
    
    # ============================================================================
    # FINAL INFORMATION
    # ============================================================================
    print_header "🎉 MULTI-CORE INSTALLATION COMPLETE"
    
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}MULTI-CORE CONFIGURATION${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} CPU Cores:          ${WHITE}$CPU_CORES${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SlowDNS Instances:  ${WHITE}$CPU_CORES${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Port Range:         ${WHITE}$SLOWDNS_BASE_PORT-$((SLOWDNS_BASE_PORT + CPU_CORES - 1))${NC}            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Max Connections:    ${WHITE}$TOTAL_CONNECTIONS${NC}                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:          ${WHITE}$SERVER_IP${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SSH Port:           ${WHITE}$SSHD_PORT${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} External EDNS:      ${WHITE}$EXTERNAL_EDNS${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Internal MTU:       ${WHITE}$INTERNAL_EDNS${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:         ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Client configuration for load balancing
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CLIENT CONFIGURATION (Load Balancing)${NC}                   ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} For best performance, configure clients to use:           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}                                                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Multiple ports for load balancing:${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ./dnstt-client -udp $SERVER_IP:${SLOWDNS_BASE_PORT} \\${NC}          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}     -udp $SERVER_IP:$((SLOWDNS_BASE_PORT + 1)) \\${NC}               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}     -udp $SERVER_IP:$((SLOWDNS_BASE_PORT + 2)) \\${NC}               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}     -pubkey-file server.pub \\${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}     $NAMESERVER 127.0.0.1:1080${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Management commands
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}MANAGEMENT COMMANDS${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Check all instances:${NC} systemctl status 'slowdns-core-*'     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Restart all:${NC} systemctl restart server-sldns edns-proxy     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}View logs:${NC} journalctl -u server-sldns -f                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}CPU usage:${NC} htop                                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}Network stats:${NC} ss -ulnp                                    ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Performance monitoring
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PERFORMANCE MONITORING${NC}                              ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}To monitor CPU utilization across all cores:${NC}              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}htop${NC} - Real-time CPU usage per core               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}mpstat -P ALL 1${NC} - CPU statistics per core         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}pidstat -C 'dnstt-server' 1${NC} - Process stats       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}iftop -i eth0${NC} - Network bandwidth                  ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final message
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 MULTI-CORE SLOWDNS INSTALLATION COMPLETE!${NC}         ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Utilizing all $CPU_CORES CPU cores${NC}                   ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 Max concurrent connections: $TOTAL_CONNECTIONS${NC}       ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🔧 Ready for maximum performance DNS tunneling${NC}          ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    # Cleanup
    rm -f /tmp/edns_multi.c /tmp/compile.log 2>/dev/null
}

# ============================================================================
# EXECUTE
# ============================================================================
trap 'echo -e "\n${RED}✗ Installation interrupted!${NC}"; exit 1' INT

if main; then
    exit 0
else
    echo -e "\n${RED}✗ Installation failed${NC}"
    exit 1
fi
```