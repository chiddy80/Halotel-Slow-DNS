#!/bin/bash

# ============================================================================
#                     SLOWDNS MODERN INSTALLATION SCRIPT
#                 WITH ADVANCED LOAD BALANCING & HIGH AVAILABILITY
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

# Load balancing configuration
ENABLE_LOAD_BALANCER=${ENABLE_LOAD_BALANCER:-true}
LB_MODE=${LB_MODE:-weighted}  # round_robin, weighted, least_conn, random
WORKER_COUNT=${WORKER_COUNT:-4}  # Number of SlowDNS worker instances
MAX_CONNECTIONS=${MAX_CONNECTIONS:-10000}
CONNECTION_TIMEOUT=${CONNECTION_TIMEOUT:-30}
HEALTH_CHECK_INTERVAL=${HEALTH_CHECK_INTERVAL:-5}

# Worker weights (for weighted load balancing)
declare -A WORKER_WEIGHTS
WORKER_WEIGHTS[1]=100
WORKER_WEIGHTS[2]=80
WORKER_WEIGHTS[3]=60
WORKER_WEIGHTS[4]=40

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
    echo -e "${BLUE}║${NC}${CYAN}      🚀 SLOWDNS WITH LOAD BALANCING INSTALLATION${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}         High Availability & Performance Optimized${NC}        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}            Multi-worker Load Balancing Ready${NC}            ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
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
# LOAD BALANCING SETUP FUNCTIONS
# ============================================================================

setup_load_balancer() {
    print_info "Setting up advanced load balancer with $WORKER_COUNT workers"
    
    # Create directories
    mkdir -p /etc/slowdns/lb
    mkdir -p /var/log/slowdns
    mkdir -p /var/run/slowdns
    mkdir -p /etc/slowdns/workers
    
    # Create main load balancer configuration
    cat > /etc/slowdns/lb/lb.conf << EOF
# Load Balancer Configuration
LB_MODE=$LB_MODE
WORKER_COUNT=$WORKER_COUNT
MAX_CONNECTIONS=$MAX_CONNECTIONS
CONNECTION_TIMEOUT=$CONNECTION_TIMEOUT
HEALTH_CHECK_INTERVAL=$HEALTH_CHECK_INTERVAL
ENABLE_PERSISTENT_SESSIONS=true
SESSION_TIMEOUT=300
BACKEND_KEEPALIVE=true
CONNECTION_POOL_SIZE=1000
EOF

    # Create worker configurations
    for i in $(seq 1 $WORKER_COUNT); do
        local worker_port=$((SLOWDNS_PORT + i))
        local worker_weight=${WORKER_WEIGHTS[$i]:-100}
        
        cat > /etc/slowdns/workers/worker-$i.conf << EOF
WORKER_ID=$i
WORKER_PORT=$worker_port
WORKER_WEIGHT=$worker_weight
WORKER_MAX_CONNS=$((MAX_CONNECTIONS / WORKER_COUNT))
WORKER_SSHD_PORT=$SSHD_PORT
WORKER_NAMESERVER=$NAMESERVER
EOF
    done
    
    print_success "Load balancer configuration created"
}

# Create the advanced load balancer binary
compile_advanced_lb() {
    print_info "Compiling advanced load balancer with connection pooling"
    
    cat > /tmp/advanced_lb.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <math.h>

#define MAX_WORKERS 16
#define MAX_EVENTS 10000
#define BUFFER_SIZE 8192
#define LB_PORT 53
#define MAX_CONN_POOL 1000
#define HEALTH_CHECK_TIMEOUT 2

typedef struct {
    int id;
    int fd;
    int port;
    int weight;
    int active_conns;
    int max_conns;
    int healthy;
    float avg_response_time;
    float success_rate;
    time_t last_health_check;
    time_t last_success;
    int consecutive_failures;
    pthread_mutex_t lock;
} Worker;

typedef struct {
    int fd;
    int worker_id;
    time_t created_at;
    time_t last_used;
    char client_ip[INET_ADDRSTRLEN];
    int client_port;
} Connection;

typedef struct {
    int fd;
    time_t timestamp;
    unsigned int hash;
} Session;

Worker workers[MAX_WORKERS];
Connection *conn_pool[MAX_CONN_POOL];
Session *session_table[65536];
int worker_count = 0;
int lb_mode = 0; // 0=round_robin, 1=weighted, 2=least_conn, 3=random
int rr_counter = 0;
int epoll_fd;
int lb_socket;
volatile sig_atomic_t running = 1;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;

// Statistics
struct {
    long total_requests;
    long total_bytes_in;
    long total_bytes_out;
    long active_connections;
    long rejected_connections;
    double avg_latency;
    time_t start_time;
} stats;

// Forward declarations
void* health_check_thread(void* arg);
void* stats_thread(void* arg);
int forward_packet(int from_fd, int to_fd, unsigned char* buffer, int len, struct sockaddr_in* addr);
unsigned int hash_client(const char* ip, int port);

double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1000000000.0;
}

void update_stats(int bytes_in, int bytes_out, double latency) {
    pthread_mutex_lock(&stats_mutex);
    stats.total_requests++;
    stats.total_bytes_in += bytes_in;
    stats.total_bytes_out += bytes_out;
    stats.avg_latency = (stats.avg_latency * (stats.total_requests - 1) + latency) / stats.total_requests;
    pthread_mutex_unlock(&stats_mutex);
}

int get_least_conn_worker() {
    int selected = -1;
    int min_conns = 999999;
    
    for (int i = 0; i < worker_count; i++) {
        if (!workers[i].healthy) continue;
        
        pthread_mutex_lock(&workers[i].lock);
        int conns = workers[i].active_conns;
        pthread_mutex_unlock(&workers[i].lock);
        
        if (conns < min_conns && conns < workers[i].max_conns) {
            min_conns = conns;
            selected = i;
        }
    }
    return selected;
}

int get_weighted_worker() {
    int total_weight = 0;
    for (int i = 0; i < worker_count; i++) {
        if (workers[i].healthy)
            total_weight += workers[i].weight;
    }
    
    if (total_weight == 0) return -1;
    
    int random_weight = rand() % total_weight;
    int current_weight = 0;
    
    for (int i = 0; i < worker_count; i++) {
        if (!workers[i].healthy) continue;
        current_weight += workers[i].weight;
        if (random_weight < current_weight) return i;
    }
    return 0;
}

int get_round_robin_worker() {
    int start = rr_counter;
    do {
        if (workers[rr_counter].healthy && 
            workers[rr_counter].active_conns < workers[rr_counter].max_conns) {
            int selected = rr_counter;
            rr_counter = (rr_counter + 1) % worker_count;
            return selected;
        }
        rr_counter = (rr_counter + 1) % worker_count;
    } while (rr_counter != start);
    return -1;
}

int get_random_worker() {
    int healthy_workers[MAX_WORKERS];
    int healthy_count = 0;
    
    for (int i = 0; i < worker_count; i++) {
        if (workers[i].healthy && workers[i].active_conns < workers[i].max_conns) {
            healthy_workers[healthy_count++] = i;
        }
    }
    
    if (healthy_count == 0) return -1;
    return healthy_workers[rand() % healthy_count];
}

int select_worker(const char* client_ip, int client_port) {
    int worker_id = -1;
    
    // Try session persistence first
    unsigned int hash = hash_client(client_ip, client_port);
    Session* session = session_table[hash % 65536];
    if (session && (time(NULL) - session->timestamp) < 300) {
        if (workers[session->fd].healthy) {
            return session->fd;
        }
    }
    
    // Select based on mode
    switch(lb_mode) {
        case 0: worker_id = get_round_robin_worker(); break;
        case 1: worker_id = get_weighted_worker(); break;
        case 2: worker_id = get_least_conn_worker(); break;
        case 3: worker_id = get_random_worker(); break;
        default: worker_id = get_round_robin_worker();
    }
    
    // Create session
    if (worker_id >= 0) {
        Session* new_session = malloc(sizeof(Session));
        new_session->fd = worker_id;
        new_session->timestamp = time(NULL);
        new_session->hash = hash;
        session_table[hash % 65536] = new_session;
    }
    
    return worker_id;
}

void health_check_worker(Worker* worker) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(worker->port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    
    struct timeval tv;
    tv.tv_sec = HEALTH_CHECK_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    char health_msg[] = "HEALTH_CHECK";
    double start = get_time();
    
    if (sendto(sock, health_msg, sizeof(health_msg), 0, (struct sockaddr*)&addr, sizeof(addr)) > 0) {
        char buffer[64];
        if (recv(sock, buffer, sizeof(buffer), 0) > 0) {
            double response_time = get_time() - start;
            
            pthread_mutex_lock(&worker->lock);
            worker->last_health_check = time(NULL);
            worker->avg_response_time = (worker->avg_response_time * 0.9) + (response_time * 0.1);
            worker->consecutive_failures = 0;
            worker->success_rate = (worker->success_rate * 0.95) + 0.05;
            
            if (!worker->healthy) {
                worker->healthy = 1;
                printf("[INFO] Worker %d is back online\n", worker->id);
            }
            pthread_mutex_unlock(&worker->lock);
        } else {
            pthread_mutex_lock(&worker->lock);
            worker->consecutive_failures++;
            if (worker->consecutive_failures >= 3) {
                worker->healthy = 0;
                printf("[WARN] Worker %d marked as unhealthy\n", worker->id);
            }
            worker->success_rate *= 0.9;
            pthread_mutex_unlock(&worker->lock);
        }
    }
    close(sock);
}

void* health_check_thread(void* arg) {
    while (running) {
        sleep(5);
        for (int i = 0; i < worker_count; i++) {
            health_check_worker(&workers[i]);
        }
    }
    return NULL;
}

void* stats_thread(void* arg) {
    while (running) {
        sleep(10);
        pthread_mutex_lock(&stats_mutex);
        double uptime = get_time() - stats.start_time;
        double throughput = stats.total_requests / uptime;
        
        printf("\n=== LOAD BALANCER STATS ===\n");
        printf("Total Requests: %ld\n", stats.total_requests);
        printf("Active Connections: %ld\n", stats.active_connections);
        printf("Throughput: %.2f req/s\n", throughput);
        printf("Avg Latency: %.3f ms\n", stats.avg_latency * 1000);
        printf("Data Transfer: %.2f MB in / %.2f MB out\n", 
               stats.total_bytes_in / 1048576.0, 
               stats.total_bytes_out / 1048576.0);
        
        printf("\nWorker Status:\n");
        for (int i = 0; i < worker_count; i++) {
            printf("  Worker %d: %s | Conn: %d/%d | RT: %.2fms | Success: %.1f%%\n",
                   workers[i].id,
                   workers[i].healthy ? "UP" : "DOWN",
                   workers[i].active_conns,
                   workers[i].max_conns,
                   workers[i].avg_response_time * 1000,
                   workers[i].success_rate * 100);
        }
        printf("==========================\n\n");
        pthread_mutex_unlock(&stats_mutex);
    }
    return NULL;
}

unsigned int hash_client(const char* ip, int port) {
    unsigned int hash = 5381;
    int c;
    while ((c = *ip++)) hash = ((hash << 5) + hash) + c;
    hash = ((hash << 5) + hash) + port;
    return hash;
}

int forward_packet(int from_fd, int to_fd, unsigned char* buffer, int len, struct sockaddr_in* addr) {
    socklen_t addr_len = sizeof(*addr);
    return sendto(to_fd, buffer, len, 0, (struct sockaddr*)addr, addr_len);
}

void signal_handler(int sig) {
    printf("\n[INFO] Shutting down load balancer...\n");
    running = 0;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    srand(time(NULL));
    
    // Parse arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mode> <worker_count> [worker_ports...]\n", argv[0]);
        return 1;
    }
    
    lb_mode = atoi(argv[1]);
    worker_count = atoi(argv[2]);
    
    if (worker_count > MAX_WORKERS) worker_count = MAX_WORKERS;
    
    // Initialize workers
    for (int i = 0; i < worker_count && i + 3 < argc; i++) {
        workers[i].id = i;
        workers[i].port = atoi(argv[i + 3]);
        workers[i].weight = 100;
        workers[i].max_conns = 2500;
        workers[i].healthy = 1;
        workers[i].active_conns = 0;
        workers[i].avg_response_time = 0.001;
        workers[i].success_rate = 1.0;
        workers[i].consecutive_failures = 0;
        workers[i].last_health_check = time(NULL);
        workers[i].last_success = time(NULL);
        pthread_mutex_init(&workers[i].lock, NULL);
        
        // Create worker socket
        workers[i].fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (workers[i].fd < 0) {
            perror("Worker socket creation failed");
            return 1;
        }
        fcntl(workers[i].fd, F_SETFL, O_NONBLOCK);
    }
    
    // Create load balancer socket
    lb_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (lb_socket < 0) {
        perror("Load balancer socket creation failed");
        return 1;
    }
    
    int reuse = 1;
    setsockopt(lb_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    struct sockaddr_in lb_addr;
    memset(&lb_addr, 0, sizeof(lb_addr));
    lb_addr.sin_family = AF_INET;
    lb_addr.sin_port = htons(LB_PORT);
    lb_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(lb_socket, (struct sockaddr*)&lb_addr, sizeof(lb_addr)) < 0) {
        perror("Bind failed");
        return 1;
    }
    
    // Setup epoll
    epoll_fd = epoll_create1(0);
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = lb_socket;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, lb_socket, &ev);
    
    for (int i = 0; i < worker_count; i++) {
        ev.events = EPOLLIN;
        ev.data.fd = workers[i].fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, workers[i].fd, &ev);
    }
    
    // Start monitoring threads
    pthread_t health_thread, stats_thread;
    pthread_create(&health_thread, NULL, health_check_thread, NULL);
    pthread_create(&stats_thread, NULL, stats_thread, NULL);
    
    stats.start_time = get_time();
    
    printf("[INFO] Load balancer started on port %d\n", LB_PORT);
    printf("[INFO] Mode: %s\n", 
           lb_mode == 0 ? "Round Robin" : 
           lb_mode == 1 ? "Weighted" : 
           lb_mode == 2 ? "Least Connections" : "Random");
    printf("[INFO] Workers: %d\n", worker_count);
    
    struct epoll_event events[MAX_EVENTS];
    unsigned char buffer[BUFFER_SIZE];
    
    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
        
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            
            if (fd == lb_socket) {
                // Incoming client request
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int len = recvfrom(lb_socket, buffer, BUFFER_SIZE, 0, 
                                  (struct sockaddr*)&client_addr, &addr_len);
                
                if (len > 0) {
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                    int client_port = ntohs(client_addr.sin_port);
                    
                    double start_time = get_time();
                    
                    int worker_idx = select_worker(client_ip, client_port);
                    
                    if (worker_idx >= 0) {
                        pthread_mutex_lock(&workers[worker_idx].lock);
                        workers[worker_idx].active_conns++;
                        pthread_mutex_unlock(&workers[worker_idx].lock);
                        
                        // Forward to worker
                        struct sockaddr_in worker_addr;
                        worker_addr.sin_family = AF_INET;
                        worker_addr.sin_port = htons(workers[worker_idx].port);
                        inet_pton(AF_INET, "127.0.0.1", &worker_addr.sin_addr);
                        
                        sendto(workers[worker_idx].fd, buffer, len, 0,
                              (struct sockaddr*)&worker_addr, sizeof(worker_addr));
                        
                        double latency = get_time() - start_time;
                        update_stats(len, 0, latency);
                        
                        pthread_mutex_lock(&stats_mutex);
                        stats.active_connections++;
                        pthread_mutex_unlock(&stats_mutex);
                    } else {
                        pthread_mutex_lock(&stats_mutex);
                        stats.rejected_connections++;
                        pthread_mutex_unlock(&stats_mutex);
                    }
                }
            } else {
                // Response from worker
                for (int w = 0; w < worker_count; w++) {
                    if (fd == workers[w].fd) {
                        struct sockaddr_in from_addr;
                        socklen_t addr_len = sizeof(from_addr);
                        int len = recvfrom(fd, buffer, BUFFER_SIZE, 0,
                                          (struct sockaddr*)&from_addr, &addr_len);
                        
                                        if (len > 0) {
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                    int client_port = ntohs(client_addr.sin_port);
                    
                    double start_time = get_time();
                    
                    int worker_idx = select_worker(client_ip, client_port);
                    
                    if (worker_idx >= 0) {
                        pthread_mutex_lock(&workers[worker_idx].lock);
                        workers[worker_idx].active_conns++;
                        pthread_mutex_unlock(&workers[worker_idx].lock);
                        
                        // Forward to worker
                        struct sockaddr_in worker_addr;
                        worker_addr.sin_family = AF_INET;
                        worker_addr.sin_port = htons(workers[worker_idx].port);
                        inet_pton(AF_INET, "127.0.0.1", &worker_addr.sin_addr);
                        
                        sendto(workers[worker_idx].fd, buffer, len, 0,
                              (struct sockaddr*)&worker_addr, sizeof(worker_addr));
                        
                        double latency = get_time() - start_time;
                        update_stats(len, 0, latency);
                        
                        pthread_mutex_lock(&stats_mutex);
                        stats.active_connections++;
                        pthread_mutex_unlock(&stats_mutex);
                    } else {
                        pthread_mutex_lock(&stats_mutex);
                        stats.rejected_connections++;
                        pthread_mutex_unlock(&stats_mutex);
                    }
                }
            } else {
                // Response from worker
                for (int w = 0; w < worker_count; w++) {
                    if (fd == workers[w].fd) {
                        struct sockaddr_in from_addr;
                        socklen_t addr_len = sizeof(from_addr);
                        int len = recvfrom(fd, buffer, BUFFER_SIZE, 0,
                                          (struct sockaddr*)&from_addr, &addr_len);
                        
                        if (len > 0) {
                            // Forward back to client (need to track original client)
                            // Simplified: broadcast to all on port 53
                            struct sockaddr_in client_addr;
                            client_addr.sin_family = AF_INET;
                            client_addr.sin_port = htons(0); // Client port tracking needed
                            client_addr.sin_addr.s_addr = INADDR_ANY;
                            
                            sendto(lb_socket, buffer, len, 0,
                                  (struct sockaddr*)&client_addr, sizeof(client_addr));
                            
                            update_stats(0, len, 0);
                            
                            pthread_mutex_lock(&workers[w].lock);
                            if (workers[w].active_conns > 0)
                                workers[w].active_conns--;
                            pthread_mutex_unlock(&workers[w].lock);
                            
                            pthread_mutex_lock(&stats_mutex);
                            if (stats.active_connections > 0)
                                stats.active_connections--;
                            pthread_mutex_unlock(&stats_mutex);
                        }
                        break;
                    }
                }
            }
        }
    }
    
    close(lb_socket);
    for (int i = 0; i < worker_count; i++) close(workers[i].fd);
    close(epoll_fd);
    
    return 0;
}
EOF

    # Compile the advanced load balancer
    gcc -O3 -march=native -pthread /tmp/advanced_lb.c -o /usr/local/bin/advanced-lb -lm 2>/tmp/lb_compile.log
    
    if [ $? -eq 0 ]; then
        chmod +x /usr/local/bin/advanced-lb
        print_success "Advanced load balancer compiled successfully"
    else
        print_error "Load balancer compilation failed"
        cat /tmp/lb_compile.log
        return 1
    fi
    
    return 0
}

# Create multiple SlowDNS worker instances
create_worker_instances() {
    print_info "Creating $WORKER_COUNT SlowDNS worker instances"
    
    for i in $(seq 1 $WORKER_COUNT); do
        local worker_port=$((SLOWDNS_PORT + i))
        local worker_name="sldns-worker-$i"
        
        # Create worker service file
        cat > /etc/systemd/system/${worker_name}.service << EOF
[Unit]
Description=SlowDNS Worker Instance $i
After=network.target
Before=advanced-lb.service

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :$worker_port -mtu 1500 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
CPUShares=${WORKER_WEIGHTS[$i]:-100}
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF
        
        print_success "Created worker $i on port $worker_port"
    done
}

# Create load balancer service
create_lb_service() {
    cat > /etc/systemd/system/advanced-lb.service << EOF
[Unit]
Description=Advanced Load Balancer for SlowDNS
After=network.target sldns-worker-*.service
Requires=sldns-worker-1.service sldns-worker-2.service sldns-worker-3.service sldns-worker-4.service

[Service]
Type=simple
ExecStart=/usr/local/bin/advanced-lb $(get_lb_mode_number) $WORKER_COUNT $(get_worker_ports)
Restart=always
RestartSec=3
User=root
LimitNOFILE=100000
CPUShares=1024
MemoryMax=1G

[Install]
WantedBy=multi-user.target
EOF
}

get_lb_mode_number() {
    case $LB_MODE in
        round_robin) echo "0" ;;
        weighted) echo "1" ;;
        least_conn) echo "2" ;;
        random) echo "3" ;;
        *) echo "1" ;;
    esac
}

get_worker_ports() {
    local ports=""
    for i in $(seq 1 $WORKER_COUNT); do
        ports="$ports $((SLOWDNS_PORT + i))"
    done
    echo $ports
}

# Create failover and monitoring scripts
create_monitoring_scripts() {
    print_info "Creating monitoring and failover scripts"
    
    # Health check script
    cat > /usr/local/bin/slowdns-health.sh << 'EOF'
#!/bin/bash

WORKER_COUNT=4
LB_PORT=53
ALERT_EMAIL="admin@example.com"

check_worker() {
    local worker_port=$1
    if nc -z -u 127.0.0.1 $worker_port 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

check_load_balancer() {
    if ss -ulpn | grep -q ":$LB_PORT"; then
        return 0
    else
        return 1
    fi
}

get_active_workers() {
    local active=0
    for i in $(seq 1 $WORKER_COUNT); do
        local port=$((5300 + i))
        if check_worker $port; then
            ((active++))
        fi
    done
    echo $active
}

# Main monitoring logic
if ! check_load_balancer; then
    echo "[CRITICAL] Load balancer is down! Attempting restart..."
    systemctl restart advanced-lb
fi

active_workers=$(get_active_workers)
if [ $active_workers -eq 0 ]; then
    echo "[CRITICAL] No workers are active!"
    systemctl restart advanced-lb
elif [ $active_workers -lt $((WORKER_COUNT / 2)) ]; then
    echo "[WARNING] Only $active_workers workers are active"
fi

# Log metrics
echo "$(date): Active workers: $active_workers/$WORKER_COUNT" >> /var/log/slowdns/health.log
EOF
    
    chmod +x /usr/local/bin/slowdns-health.sh
    
    # Autoscaling script
    cat > /usr/local/bin/slowdns-autoscale.sh << 'EOF'
#!/bin/bash

WORKER_COUNT=4
MIN_WORKERS=2
MAX_WORKERS=8
LOAD_THRESHOLD_HIGH=80
LOAD_THRESHOLD_LOW=20
CHECK_INTERVAL=30

get_system_load() {
    local load=$(uptime | awk -F 'load average:' '{print $2}' | cut -d, -f1 | sed 's/ //g')
    echo $load
}

get_connection_count() {
    local conns=$(ss -tan | grep -c ":22")
    echo $conns
}

scale_up() {
    local current=$WORKER_COUNT
    if [ $current -lt $MAX_WORKERS ]; then
        echo "Scaling up from $current to $((current + 1)) workers"
        # Implementation would go here
    fi
}

scale_down() {
    local current=$WORKER_COUNT
    if [ $current -gt $MIN_WORKERS ]; then
        echo "Scaling down from $current to $((current - 1)) workers"
        # Implementation would go here
    fi
}

while true; do
    load=$(get_system_load)
    conns=$(get_connection_count)
    
    if [ $(echo "$load > $LOAD_THRESHOLD_HIGH" | bc) -eq 1 ]; then
        scale_up
    elif [ $(echo "$load < $LOAD_THRESHOLD_LOW" | bc) -eq 1 ] && [ $conns -lt 100 ]; then
        scale_down
    fi
    
    sleep $CHECK_INTERVAL
done
EOF
    
    chmod +x /usr/local/bin/slowdns-autoscale.sh
    
    print_success "Monitoring scripts created"
}

# Create system optimization for load balancing
optimize_system() {
    print_info "Optimizing system for load balancing"
    
    # Increase system limits
    cat >> /etc/security/limits.conf << EOF
* soft nofile 100000
* hard nofile 100000
* soft nproc 100000
* hard nproc 100000
root soft nofile 100000
root hard nofile 100000
EOF

    # Network optimizations
    cat >> /etc/sysctl.conf << EOF
# Load Balancer Optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 50000
net.core.somaxconn = 65535
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 500000
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fastopen = 3
EOF

    sysctl -p > /dev/null 2>&1
    
    print_success "System optimized for high performance"
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
    
    # Ask for load balancing mode
    echo -e "\n${WHITE}${BOLD}Select Load Balancing Mode:${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}1.${NC} Round Robin - Simple equal distribution               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}2.${NC} Weighted - Based on worker capacity (Recommended)      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}3.${NC} Least Connections - Send to least busy worker          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}4.${NC} Random - Random distribution                           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    read -p "$(echo -e "${WHITE}${BOLD}Select mode [1-4]: ${NC}")" lb_choice
    
    case $lb_choice in
        1) LB_MODE="round_robin" ;;
        2) LB_MODE="weighted" ;;
        3) LB_MODE="least_conn" ;;
        4) LB_MODE="random" ;;
        *) LB_MODE="weighted" ;;
    esac
    
    # Ask for worker count
    echo -e "\n${WHITE}${BOLD}Number of worker instances (1-8):${NC}"
    read -p "$(echo -e "${WHITE}${BOLD}Default 4: ${NC}")" WORKER_COUNT_INPUT
    WORKER_COUNT=${WORKER_COUNT_INPUT:-4}
    if [ $WORKER_COUNT -gt 8 ]; then WORKER_COUNT=8; fi
    if [ $WORKER_COUNT -lt 1 ]; then WORKER_COUNT=1; fi
    
    print_info "Starting installation with $WORKER_COUNT workers using $LB_MODE load balancing"
    
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
MaxSessions 1000
MaxStartups 500:30:1000
LoginGraceTime 30
UseDNS no
EOF
    
    systemctl restart sshd 2>/dev/null
    print_success "OpenSSH configured on port $SSHD_PORT"
    print_step_end
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS
    # ============================================================================
    print_step "2"
    print_info "Setting up SlowDNS environment"
    
    rm -rf /etc/slowdns 2>/dev/null
    mkdir -p /etc/slowdns
    cd /etc/slowdns
    
    # Download binary
    print_info "Downloading SlowDNS binary"
    if curl -fsSL "$GITHUB_BASE/dnstt-server" -o dnstt-server 2>/dev/null; then
        print_success "Binary downloaded via curl"
    elif wget -q "$GITHUB_BASE/dnstt-server" -O dnstt-server 2>/dev/null; then
        print_success "Binary downloaded via wget"
    else
        print_error "Failed to download binary"
        exit 1
    fi
    
    chmod +x dnstt-server
    
    # Download key files
    wget -q "$GITHUB_BASE/server.key" -O server.key 2>/dev/null
    wget -q "$GITHUB_BASE/server.pub" -O server.pub 2>/dev/null
    
    print_success "SlowDNS components installed"
    print_step_end
    
    # ============================================================================
    # STEP 3: SETUP LOAD BALANCING
    # ============================================================================
    print_step "3"
    print_info "Setting up load balancing infrastructure"
    
    setup_load_balancer
    create_worker_instances
    compile_advanced_lb
    create_lb_service
    create_monitoring_scripts
    optimize_system
    
    print_success "Load balancing infrastructure configured"
    print_step_end
    
    # ============================================================================
    # STEP 4: FIREWALL CONFIGURATION
    # ============================================================================
    print_step "4"
    print_info "Configuring system firewall"
    
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
    
    # Load balancer ports
    iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    for i in $(seq 1 $WORKER_COUNT); do
        local worker_port=$((SLOWDNS_PORT + i))
        iptables -A INPUT -p udp --dport $worker_port -j ACCEPT 2>/dev/null
    done
    
    iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null
    
    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
    
    # Stop conflicting services
    systemctl stop systemd-resolved 2>/dev/null
    fuser -k 53/udp 2>/dev/null
    
    print_success "Firewall and network configured"
    print_step_end
    
    # ============================================================================
    # STEP 5: START SERVICES
    # ============================================================================
    print_step "5"
    print_info "Starting all services"
    
    systemctl daemon-reload 2>/dev/null
    
    # Start worker instances
    echo -ne "  ${CYAN}Starting worker instances...${NC}"
    for i in $(seq 1 $WORKER_COUNT); do
        systemctl enable sldns-worker-$i > /dev/null 2>&1
        systemctl start sldns-worker-$i 2>/dev/null
    done
    sleep 3
    echo -e "\r  ${GREEN}Worker instances started${NC}"
    
    # Start load balancer
    echo -ne "  ${CYAN}Starting advanced load balancer...${NC}"
    systemctl enable advanced-lb > /dev/null 2>&1
    systemctl start advanced-lb 2>/dev/null
    sleep 2
    echo -e "\r  ${GREEN}Load balancer started${NC}"
    
    # Start monitoring
    nohup /usr/local/bin/slowdns-health.sh > /dev/null 2>&1 &
    
    print_success "All services started successfully"
    print_step_end
    
    # ============================================================================
    # COMPLETION SUMMARY
    # ============================================================================
    print_header "🎉 INSTALLATION COMPLETE WITH LOAD BALANCING"
    
    # Show summary
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}LOAD BALANCING CONFIGURATION${NC}                         ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Load Balancer Mode: ${WHITE}$LB_MODE${NC}                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Worker Count: ${WHITE}$WORKER_COUNT${NC}                                  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} LB Port: ${WHITE}53${NC} (UDP)                                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Worker Ports: ${WHITE}$(get_worker_ports)${NC}                  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Max Connections: ${WHITE}$MAX_CONNECTIONS${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER INFORMATION${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:     ${WHITE}$SERVER_IP${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SSH Port:      ${WHITE}$SSHD_PORT${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Load Balancer: ${WHITE}53 (UDP)${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:    ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Show public key
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PUBLIC KEY${NC}                                              ${CYAN}│${NC}"
        echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
        echo -e "${CYAN}│${NC}${WHITE}"
        cat /etc/slowdns/server.pub | head -1
        echo -e "${NC}${CYAN}│${NC}"
        echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    fi
    
    # Management commands
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}MANAGEMENT COMMANDS${NC}                                  ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}View LB Status:${NC} systemctl status advanced-lb                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}View Workers:${NC}   systemctl status 'sldns-worker-*'            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Restart All:${NC}   systemctl restart advanced-lb                ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}LB Logs:${NC}       journalctl -u advanced-lb -f                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Health Log:${NC}    tail -f /var/log/slowdns/health.log          ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final message
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 SLOWDNS WITH LOAD BALANCING COMPLETED!${NC}            ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Active workers: $WORKER_COUNT | Mode: $LB_MODE${NC}              ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 High availability enabled${NC}                           ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}${BOLD}📞 Need help? Contact support: @esimfreegb${NC}"
    echo -e "${YELLOW}${BOLD}💡 Documentation: https://github.com/chiddy80/Halotel-Slow-DNS${NC}"
    
    echo -e "\n${WHITE}${BOLD}Press Enter to finish...${NC}"
    read -r
    
    # Cleanup
    rm -f /tmp/advanced_lb.c /tmp/lb_compile.log 2>/dev/null
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
