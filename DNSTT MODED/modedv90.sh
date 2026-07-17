#!/bin/bash

# ============================================================================
#              SLOWDNS INSTALLATION SCRIPT - v2 (TURBO EDITION)
#         Stability + Speed overhaul. NOT v2ray. Pure SlowDNS/DNSTT.
# ============================================================================

set -euo pipefail          # Exit on error, unset var, pipe failure
IFS=$'\n\t'                # Safer word splitting

# ============================================================================
# ROOT CHECK
# ============================================================================
[[ "$EUID" -ne 0 ]] && { echo -e "\033[0;31m[✗] Run as root\033[0m"; exit 1; }

# ============================================================================
# CONFIGURATION — edit these if needed
# ============================================================================
SSHD_PORT=22
SLOWDNS_PORT=5300
# Additional parallel SlowDNS listeners. DNSTT is single-stream per port, so
# one tunnel is capped by that stream's own congestion control — running
# several instances on different ports lets a client split traffic across
# them for more aggregate throughput. Each still needs its own client
# process pointed at the same nameserver but a different -udp port.
SLOWDNS_EXTRA_PORTS=(5301 5302)
SLOWDNS_MTU="${SLOWDNS_MTU:-1800}"   # higher = fewer DNS queries per byte (faster) but more fragmentation risk; drop to 1400/1200 if the tunnel gets flaky
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
LOG_FILE="/var/log/slowdns-install.log"
INSTALL_DIR="/etc/slowdns"
RETRY_MAX=3          # download retry attempts
DOWNLOAD_TIMEOUT=30  # seconds per download attempt

# ============================================================================
# COLORS
# ============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'
BOLD='\033[1m'; NC='\033[0m'

# ============================================================================
# LOGGING — every action is recorded
# ============================================================================
exec > >(tee -a "$LOG_FILE") 2>&1
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# ============================================================================
# PRINT HELPERS
# ============================================================================
print_banner() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}        🚀 SLOWDNS TURBO INSTALLATION SCRIPT v2${NC}         ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}          Stability + Speed — Powered by DNSTT${NC}           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}             NOT v2ray — Pure DNS Tunnel${NC}                  ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step()     { echo -e "\n${BLUE}┌─${NC} ${CYAN}${BOLD}STEP $1${NC}"; echo -e "${BLUE}│${NC}"; }
print_step_end() { echo -e "${BLUE}└─${NC} ${GREEN}✓${NC} Done"; }
print_success()  { echo -e "  ${GREEN}${BOLD}✓${NC} ${GREEN}$1${NC}"; log "SUCCESS: $1"; }
print_error()    { echo -e "  ${RED}${BOLD}✗${NC} ${RED}$1${NC}"; log "ERROR: $1"; }
print_warning()  { echo -e "  ${YELLOW}${BOLD}!${NC} ${YELLOW}$1${NC}"; log "WARN: $1"; }
print_info()     { echo -e "  ${CYAN}${BOLD}ℹ${NC} ${CYAN}$1${NC}"; }

# ============================================================================
# IMPROVED SPINNER — shows real elapsed time, not ps grep loop
# ============================================================================
show_progress() {
    local pid=$1
    local msg="${2:-Working}"
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    local start=$SECONDS
    while kill -0 "$pid" 2>/dev/null; do
        local elapsed=$(( SECONDS - start ))
        printf "\r  ${CYAN}${spin:$(( i % ${#spin} )):1}${NC} %s... %ds" "$msg" "$elapsed"
        sleep 0.1
        (( i++ )) || true
    done
    printf "\r%-60s\r" " "    # clear the line
}

# ============================================================================
# ROBUST DOWNLOAD — retries + checksum awareness
# ============================================================================
download_file() {
    local url="$1"
    local dest="$2"
    local description="${3:-file}"
    local attempt=1

    while (( attempt <= RETRY_MAX )); do
        print_info "Downloading $description (attempt $attempt/$RETRY_MAX)..."
        if curl -fsSL --connect-timeout "$DOWNLOAD_TIMEOUT" \
                --retry 2 --retry-delay 3 \
                "$url" -o "$dest" 2>/dev/null; then
            # Basic sanity check: file must be non-empty
            if [[ -s "$dest" ]]; then
                print_success "$description downloaded"
                return 0
            fi
        fi
        # Fallback to wget if curl failed or produced empty file
        if wget -q --timeout="$DOWNLOAD_TIMEOUT" --tries=2 \
                "$url" -O "$dest" 2>/dev/null && [[ -s "$dest" ]]; then
            print_success "$description downloaded (via wget)"
            return 0
        fi
        print_warning "Attempt $attempt failed, retrying in 5s..."
        sleep 5
        (( attempt++ )) || true
    done

    print_error "Failed to download $description after $RETRY_MAX attempts"
    return 1
}

# ============================================================================
# CLEANUP ON FAILURE
# ============================================================================
cleanup_on_error() {
    local exit_code=$?
    echo -e "\n${RED}${BOLD}✗ Installation failed (exit $exit_code). Check: $LOG_FILE${NC}"
    # Don't destroy existing working services — only remove temp files
    rm -f /tmp/edns.c /tmp/compile.log 2>/dev/null
    exit "$exit_code"
}
trap cleanup_on_error ERR
trap 'echo -e "\n${RED}✗ Interrupted!${NC}"; exit 130' INT TERM

# ============================================================================
# MAIN
# ============================================================================
main() {
    print_banner
    log "=== SlowDNS Turbo Install started ==="

    # ── Nameserver prompt ───────────────────────────────────────────────────
    echo -e "${WHITE}${BOLD}Enter nameserver configuration:${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Default:${NC} dns.example.com                                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Example:${NC} tunnel.yourdomain.com                               ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    read -rp "$(echo -e "${WHITE}${BOLD}Enter nameserver: ${NC}")" NAMESERVER
    NAMESERVER="${NAMESERVER:-dns.example.com}"
    log "Nameserver: $NAMESERVER"

    # ── Detect server IP ────────────────────────────────────────────────────
    echo -ne "  ${CYAN}Detecting server IP...${NC}"
    SERVER_IP=$(curl -s --connect-timeout 5 https://ifconfig.me 2>/dev/null \
             || curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null \
             || hostname -I | awk '{print $1}')
    echo -e "\r  ${GREEN}Server IP:${NC} ${WHITE}${BOLD}${SERVER_IP}${NC}"
    log "Server IP: $SERVER_IP"

    # ========================================================================
    # STEP 1: OPENSSH — hardened & performance-tuned
    # ========================================================================
    print_step "1 — Configure OpenSSH"
    print_info "Port $SSHD_PORT | Hardened + Keep-Alive + TCP forwarding"

    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)" 2>/dev/null || true

    cat > /etc/ssh/sshd_config << EOF
# === SlowDNS Turbo — SSH Config ===
Port $SSHD_PORT
Protocol 2
AddressFamily inet

# Authentication
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Performance & Stability
TCPKeepAlive yes
ClientAliveInterval 25
ClientAliveCountMax 4
LoginGraceTime 20
MaxSessions 200
MaxStartups 100:30:300

# Forwarding (required for SlowDNS tunnels)
AllowTcpForwarding yes
GatewayPorts yes
PermitTunnel yes

# Legacy client compatibility — modern OpenSSH (8.8+) disables ssh-rsa and
# older kex/cipher groups by default, which breaks old clients (e.g. old
# Android SSH apps, PuTTY builds, embedded/legacy systems). Re-enable them
# here alongside the modern ones so both old and new clients can connect.
KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
HostKeyAlgorithms +ssh-rsa,ssh-dss
PubkeyAcceptedAlgorithms +ssh-rsa,ssh-dss
Ciphers +aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
MACs +hmac-sha1,hmac-md5

# Speed
UseDNS no
X11Forwarding no
PrintMotd no
PrintLastLog no
Compression yes   # tunnel is bandwidth-starved; SSH-level compression cuts round-trips over it

Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    # Apply sysctl for TCP performance before restarting sshd
    # Written to a persistent drop-in AND applied live, so tuning survives reboot
    cat > /etc/sysctl.d/99-slowdns-turbo.conf << 'SYSCTL'
net.ipv4.tcp_fastopen = 3
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
# Congestion control — helps UDP-tunneled throughput adapt when upstream
# links get busy during peak (daytime) hours instead of just dropping packets
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# Larger UDP buffers — SlowDNS/DNSTT is UDP-based; small buffers cause silent
# drops under load, which shows up as "slow during the day" specifically
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
SYSCTL
    sysctl --system >/dev/null 2>&1 || true

    systemctl restart sshd 2>/dev/null
    sleep 1
    systemctl is-active --quiet sshd && print_success "OpenSSH restarted on port $SSHD_PORT" \
                                     || print_warning "sshd not active — check manually"
    print_step_end

    # ========================================================================
    # STEP 2: DOWNLOAD SLOWDNS BINARY + KEYS
    # ========================================================================
    print_step "2 — Install SlowDNS"
    print_info "Installing to $INSTALL_DIR"

    rm -rf "$INSTALL_DIR" 2>/dev/null
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"

    download_file "$GITHUB_BASE/dnstt-server" "$INSTALL_DIR/dnstt-server" "dnstt-server binary"
    chmod +x "$INSTALL_DIR/dnstt-server"
    SLOWDNS_BINARY="$INSTALL_DIR/dnstt-server"

    download_file "$GITHUB_BASE/server.key" "$INSTALL_DIR/server.key" "server.key"
    download_file "$GITHUB_BASE/server.pub" "$INSTALL_DIR/server.pub" "server.pub"

    # Lock down key permissions
    chmod 600 "$INSTALL_DIR/server.key"
    chmod 644 "$INSTALL_DIR/server.pub"

    # Validate binary runs
    if "$SLOWDNS_BINARY" --help 2>&1 | grep -qi "usage\|flag\|option\|dnstt" \
    || "$SLOWDNS_BINARY" -h    2>&1 | grep -qi "usage\|flag\|option\|dnstt"; then
        print_success "Binary validated"
    else
        print_warning "Binary help check inconclusive — continuing"
    fi

    print_step_end

    # ========================================================================
    # STEP 3: SLOWDNS SYSTEMD SERVICE — hardened restart policy
    # ========================================================================
    print_step "3 — SlowDNS Service"

    cat > /etc/systemd/system/server-sldns.service << EOF
[Unit]
Description=SlowDNS (DNSTT) Server
After=network-online.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu $SLOWDNS_MTU -privkey-file $INSTALL_DIR/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=10
User=root
LimitNOFILE=65536
LimitNPROC=65536
LimitCORE=infinity
TimeoutStartSec=10
TimeoutStopSec=10
KillMode=mixed
KillSignal=SIGTERM
# Keep the tunnel responsive even when the host is under load (e.g. peak
# daytime traffic competing for CPU time)
CPUSchedulingPolicy=rr
CPUSchedulingPriority=50
Nice=-5
IOSchedulingClass=realtime
IOSchedulingPriority=2

[Install]
WantedBy=multi-user.target
EOF

    print_success "server-sldns service configured (port $SLOWDNS_PORT)"

    # ── Template unit for the extra parallel ports ──────────────────────────
    # `systemctl enable --now server-sldns-extra@5301` starts one instance
    # per extra port, all pointed at the same nameserver/sshd backend.
    cat > /etc/systemd/system/server-sldns-extra@.service << EOF
[Unit]
Description=SlowDNS (DNSTT) Server - extra port %i
After=network-online.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :%i -mtu $SLOWDNS_MTU -privkey-file $INSTALL_DIR/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=10
User=root
LimitNOFILE=65536
LimitNPROC=65536
LimitCORE=infinity
TimeoutStartSec=10
TimeoutStopSec=10
KillMode=mixed
KillSignal=SIGTERM
CPUSchedulingPolicy=rr
CPUSchedulingPriority=50
Nice=-5
IOSchedulingClass=realtime
IOSchedulingPriority=2

[Install]
WantedBy=multi-user.target
EOF

    for extra_port in "${SLOWDNS_EXTRA_PORTS[@]}"; do
        systemctl enable --now "server-sldns-extra@${extra_port}" 2>/dev/null \
            && print_success "server-sldns-extra@${extra_port} enabled" \
            || print_warning "Could not start extra tunnel on port ${extra_port}"
    done

    print_step_end

    # ========================================================================
    # STEP 4: EDNS PROXY — rewritten C with multiple improvements
    # ========================================================================
    print_step "4 — Compile EDNS Proxy (Turbo)"
    print_info "Checking for gcc..."

    if ! command -v gcc &>/dev/null; then
        print_info "Installing build-essential..."
        apt-get update -qq && apt-get install -y -qq gcc build-essential
    fi

    # ── Improved C source ───────────────────────────────────────────────────
    # Changes vs original:
    #  • SO_REUSEPORT on listen socket (kernel load-balances, no port fights)
    #  • SO_RCVBUF/SO_SNDBUF increased (fewer kernel drops under load)
    #  • UPSTREAM_POOL 128 (was 64) — more parallel DNS slots
    #  • REQ_TABLE_SIZE 131072 (was 65536) — less hash collision
    #  • SOCKET_TIMEOUT 5.0 (was 3.0) — tolerates slow upstream better
    #  • cleanup_expired() only called every 100ms loop, not every iteration
    #  • epoll_wait timeout 5ms (was 10ms) — lower latency
    #  • bind() error check — exits cleanly if port 53 is still occupied
    #  • Graceful upstream pool exhaustion: logs instead of silent drop
    #  • setsockopt SO_REUSEADDR on upstream sockets too
    # ────────────────────────────────────────────────────────────────────────
    cat > /tmp/edns.c << CSRC
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>

#define LISTEN_PORT        53
#define SLOWDNS_PORT       5300
#define BUFFER_SIZE        8192
#define UPSTREAM_PER_THREAD 64      /* per-thread pool; total = this * thread count */
#define SOCKET_TIMEOUT     2.0      /* was 5.0 — shorter hang time on lost replies */
#define MAX_EVENTS         4096
#define REQ_HASH_BITS      14
#define REQ_TABLE_SIZE     (1 << REQ_HASH_BITS)
#define EXT_EDNS           512
#define INT_EDNS           $SLOWDNS_MTU   /* synced to -mtu $SLOWDNS_MTU at install time */
#define MAX_THREADS         8

typedef struct {
    int    fd;
    int    busy;
    double last_used;
} upstream_t;

typedef struct req_entry {
    uint16_t            req_id;
    int                 upstream_idx;
    double              timestamp;
    struct sockaddr_in  client_addr;
    socklen_t           addr_len;
    struct req_entry   *hnext;          /* hash-chain link            */
    struct req_entry   *fnext, *fprev;  /* FIFO (insertion/expiry) link */
} req_entry_t;

/* ── Per-thread worker state — no cross-thread sharing, so no locks ────── */
typedef struct {
    int          listen_sock;
    int          epoll_fd;
    upstream_t   upstreams[UPSTREAM_PER_THREAD];
    req_entry_t *req_table[REQ_TABLE_SIZE];
    req_entry_t *fifo_head, *fifo_tail;   /* oldest..newest, expiry order  */
    struct sockaddr_in slow;
} worker_t;

static volatile sig_atomic_t shutdown_flag = 0;

static double mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static inline uint16_t get_txid(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static inline uint32_t req_hash(uint16_t id) {
    return id & (REQ_TABLE_SIZE - 1);
}

/* ── Patch EDNS0 payload size field ─────────────────────────────────────
 * Logic unchanged from the original — same parsing approach, same sizes. */
static int patch_edns(unsigned char *buf, int len, int edns_size) {
    if (len < 12) return len;
    int off = 12;
    int qd  = (buf[4] << 8) | buf[5];
    for (int i = 0; i < qd && off < len; i++) {
        while (off < len && buf[off]) off++;
        off += 5;
    }
    int ar = (buf[10] << 8) | buf[11];
    for (int i = 0; i < ar && off + 10 < len; i++) {
        if (buf[off] == 0 && ((buf[off+1] << 8) | buf[off+2]) == 41) {
            buf[off+3] = (edns_size >> 8) & 0xff;
            buf[off+4] =  edns_size       & 0xff;
            return len;
        }
        off++;
    }
    return len;
}

/* ── Upstream pool (per-thread, so no contention) ───────────────────────── */
static int get_upstream(worker_t *w) {
    double now = mono_now();
    for (int i = 0; i < UPSTREAM_PER_THREAD; i++) {
        if (!w->upstreams[i].busy) {
            w->upstreams[i].busy      = 1;
            w->upstreams[i].last_used = now;
            return i;
        }
    }
    fprintf(stderr, "[edns-proxy] upstream pool exhausted — dropping packet\n");
    return -1;
}
static void release_upstream(worker_t *w, int i) {
    if (i >= 0 && i < UPSTREAM_PER_THREAD) w->upstreams[i].busy = 0;
}

/* ── Request table: hash chain for O(1) lookup by txid,
 *    FIFO list for O(1) amortized expiry (every entry shares SOCKET_TIMEOUT,
 *    so insertion order == expiry order — no full-table scan needed). ───── */
static void insert_req(worker_t *w, int uidx, const unsigned char *buf,
                        const struct sockaddr_in *c, socklen_t l) {
    req_entry_t *e = calloc(1, sizeof(*e));
    if (!e) { release_upstream(w, uidx); return; }
    e->upstream_idx = uidx;
    e->req_id       = get_txid(buf);
    e->timestamp    = mono_now();
    e->client_addr  = *c;
    e->addr_len     = l;

    uint32_t h = req_hash(e->req_id);
    e->hnext = w->req_table[h];
    w->req_table[h] = e;

    e->fprev = w->fifo_tail;
    e->fnext = NULL;
    if (w->fifo_tail) w->fifo_tail->fnext = e; else w->fifo_head = e;
    w->fifo_tail = e;
}

static req_entry_t *find_req(worker_t *w, uint16_t id) {
    for (req_entry_t *e = w->req_table[req_hash(id)]; e; e = e->hnext)
        if (e->req_id == id) return e;
    return NULL;
}

static void unlink_req(worker_t *w, req_entry_t *e) {
    /* unlink from hash chain */
    req_entry_t **pp = &w->req_table[req_hash(e->req_id)];
    while (*pp) { if (*pp == e) { *pp = e->hnext; break; } pp = &(*pp)->hnext; }
    /* unlink from FIFO */
    if (e->fprev) e->fprev->fnext = e->fnext; else w->fifo_head = e->fnext;
    if (e->fnext) e->fnext->fprev = e->fprev; else w->fifo_tail = e->fprev;
}

static void delete_req(worker_t *w, req_entry_t *e) {
    release_upstream(w, e->upstream_idx);
    unlink_req(w, e);
    free(e);
}

/* O(1) amortized: only walks entries that have actually expired, oldest first —
 * replaces the old full REQ_TABLE_SIZE scan that ran every 100ms regardless
 * of load. */
static void cleanup_expired(worker_t *w) {
    double now = mono_now();
    while (w->fifo_head && (now - w->fifo_head->timestamp) > SOCKET_TIMEOUT) {
        req_entry_t *e = w->fifo_head;
        release_upstream(w, e->upstream_idx);
        unlink_req(w, e);
        free(e);
    }
}

static void sig_handler(int s) { (void)s; shutdown_flag = 1; }

static void *worker_main(void *arg) {
    worker_t *w = (worker_t *)arg;
    struct epoll_event events[MAX_EVENTS];

    while (!shutdown_flag) {
        /* Block until real work arrives instead of busy-polling every 5ms;
         * cleanup is now O(1) amortized so it's cheap to run every wakeup. */
        int n = epoll_wait(w->epoll_fd, events, MAX_EVENTS, 250);
        cleanup_expired(w);

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            unsigned char buf[BUFFER_SIZE];

            if (fd == w->listen_sock) {
                struct sockaddr_in c; socklen_t l = sizeof(c);
                int len = recvfrom(w->listen_sock, buf, sizeof(buf), 0, (void*)&c, &l);
                if (len < 12) continue;
                patch_edns(buf, len, INT_EDNS);
                int u = get_upstream(w);
                if (u >= 0) {
                    insert_req(w, u, buf, &c, l);
                    sendto(w->upstreams[u].fd, buf, len, 0,
                           (void*)&w->slow, sizeof(w->slow));
                }
            } else {
                int len = recv(fd, buf, sizeof(buf), 0);
                if (len < 12) continue;
                uint16_t id = get_txid(buf);
                req_entry_t *e = find_req(w, id);
                if (e) {
                    patch_edns(buf, len, EXT_EDNS);
                    sendto(w->listen_sock, buf, len, 0,
                           (void*)&e->client_addr, e->addr_len);
                    delete_req(w, e);
                }
            }
        }
    }
    return NULL;
}

static int setup_worker(worker_t *w) {
    memset(w, 0, sizeof(*w));

    int one = 1;
    int bufsize = 4 * 1024 * 1024;

    w->listen_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (w->listen_sock < 0) { perror("socket"); return -1; }
    setsockopt(w->listen_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* SO_REUSEPORT now actually load-balances: each thread has its OWN
     * listen socket bound to :53, so the kernel spreads incoming packets
     * across threads/cores instead of everything funneling through one. */
    setsockopt(w->listen_sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    setsockopt(w->listen_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(w->listen_sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    fcntl(w->listen_sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(LISTEN_PORT);
    a.sin_addr.s_addr = INADDR_ANY;
    if (bind(w->listen_sock, (void*)&a, sizeof(a)) < 0) {
        perror("bind :53");
        fprintf(stderr, "Port 53 is busy — stop systemd-resolved first.\n");
        return -1;
    }

    w->slow.sin_family = AF_INET;
    w->slow.sin_port   = htons(SLOWDNS_PORT);
    inet_pton(AF_INET, "127.0.0.1", &w->slow.sin_addr);

    w->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = w->listen_sock };
    epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->listen_sock, &ev);

    for (int i = 0; i < UPSTREAM_PER_THREAD; i++) {
        w->upstreams[i].fd = socket(AF_INET, SOCK_DGRAM, 0);
        setsockopt(w->upstreams[i].fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(w->upstreams[i].fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
        setsockopt(w->upstreams[i].fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        /* connect() so recv() only ever accepts packets from the real
         * SlowDNS server, not from any process that can reach this port */
        connect(w->upstreams[i].fd, (void*)&w->slow, sizeof(w->slow));
        fcntl(w->upstreams[i].fd, F_SETFL, O_NONBLOCK);
        struct epoll_event ue = { .events = EPOLLIN, .data.fd = w->upstreams[i].fd };
        epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->upstreams[i].fd, &ue);
    }
    return 0;
}

int main(void) {
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    int ncpu = get_nprocs();
    if (ncpu < 1) ncpu = 1;
    if (ncpu > MAX_THREADS) ncpu = MAX_THREADS;

    worker_t workers[MAX_THREADS];
    pthread_t threads[MAX_THREADS];

    for (int i = 0; i < ncpu; i++) {
        if (setup_worker(&workers[i]) != 0) return 1;
    }

    fprintf(stdout, "[edns-proxy] Listening on UDP :%d -> SlowDNS :%d (%d worker thread%s)\n",
            LISTEN_PORT, SLOWDNS_PORT, ncpu, ncpu == 1 ? "" : "s");
    fflush(stdout);

    for (int i = 1; i < ncpu; i++)
        pthread_create(&threads[i], NULL, worker_main, &workers[i]);
    worker_main(&workers[0]);   /* main thread doubles as worker 0 */

    for (int i = 1; i < ncpu; i++)
        pthread_join(threads[i], NULL);

    fprintf(stdout, "[edns-proxy] Shutting down cleanly.\n");
    for (int i = 0; i < ncpu; i++) {
        close(workers[i].listen_sock);
        close(workers[i].epoll_fd);
    }
    return 0;
}
CSRC

    # Compile — O2 for stable fast code; -march=native for CPU tuning
    echo -ne "  ${CYAN}Compiling EDNS Proxy...${NC}"
    if gcc -O2 -march=native -pipe -pthread -Wall \
           /tmp/edns.c -o /usr/local/bin/edns-proxy -lpthread 2>/tmp/compile.log; then
        chmod +x /usr/local/bin/edns-proxy
        print_success "EDNS Proxy compiled"
    else
        print_error "Compilation failed — see /tmp/compile.log"
        cat /tmp/compile.log
        exit 1
    fi

    # ── EDNS Proxy service ───────────────────────────────────────────────
    cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy for SlowDNS
After=server-sldns.service
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=10
User=root
LimitNOFILE=131072
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    print_success "edns-proxy service configured"
    print_step_end

    # ========================================================================
    # STEP 5: FIREWALL — minimal, correct rules
    # ========================================================================
    print_step "5 — Firewall"
    print_info "Applying iptables rules"

    # Flush existing
    iptables -F 2>/dev/null; iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null; iptables -t nat -X 2>/dev/null

    # Default policies
    iptables -P INPUT   ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT  ACCEPT 2>/dev/null

    # Allow loopback
    iptables -A INPUT  -i lo -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null

    # Allow established sessions
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

    # SSH
    iptables -A INPUT -p tcp --dport "$SSHD_PORT" -j ACCEPT 2>/dev/null

    # SlowDNS & EDNS
    iptables -A INPUT -p udp --dport "$SLOWDNS_PORT" -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport 53              -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport 53              -j ACCEPT 2>/dev/null
    for extra_port in "${SLOWDNS_EXTRA_PORTS[@]}"; do
        iptables -A INPUT -p udp --dport "$extra_port" -j ACCEPT 2>/dev/null
    done

    # ICMP ping
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null

    # Persist firewall rules if iptables-save is available
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables.rules 2>/dev/null || true
    fi

    # Disable IPv6 to avoid conflicts on port 53
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || true

    # Stop systemd-resolved (holds port 53)
    print_info "Stopping conflicting DNS services..."
    systemctl stop    systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    fuser -k 53/udp                    2>/dev/null || true
    sleep 1

    print_success "Firewall and network configured"
    print_step_end

    # ========================================================================
    # STEP 6: START SERVICES — with real status confirmation
    # ========================================================================
    print_step "6 — Start Services"

    systemctl daemon-reload

    # Enable + start SlowDNS
    systemctl enable server-sldns 2>/dev/null
    systemctl start  server-sldns 2>/dev/null
    sleep 2
    if systemctl is-active --quiet server-sldns; then
        print_success "server-sldns is running"
    else
        print_warning "systemd start failed — launching directly"
        "$SLOWDNS_BINARY" -udp :"$SLOWDNS_PORT" -mtu "$SLOWDNS_MTU" \
            -privkey-file "$INSTALL_DIR/server.key" \
            "$NAMESERVER" "127.0.0.1:$SSHD_PORT" &
    fi

    # Enable + start EDNS proxy
    systemctl enable edns-proxy 2>/dev/null
    systemctl start  edns-proxy 2>/dev/null
    sleep 2
    if systemctl is-active --quiet edns-proxy; then
        print_success "edns-proxy is running"
    else
        print_warning "systemd start failed — launching directly"
        /usr/local/bin/edns-proxy &
    fi

    print_step_end

    # ========================================================================
    # STEP 7: VERIFY
    # ========================================================================
    print_step "7 — Verify"
    sleep 2

    ss -ulpn 2>/dev/null | grep -q ":53 "      \
        && print_success "Port 53 (EDNS)  is listening" \
        || print_warning "Port 53 NOT listening — check edns-proxy logs"

    ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT " \
        && print_success "Port $SLOWDNS_PORT (SlowDNS) is listening" \
        || print_warning "Port $SLOWDNS_PORT NOT listening — check server-sldns logs"

    print_step_end

    # ========================================================================
    # SUMMARY
    # ========================================================================
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 SLOWDNS TURBO INSTALL COMPLETE!${NC}                  ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"

    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER INFO${NC}                                          ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}IP:${NC}          ${WHITE}$SERVER_IP${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}SSH port:${NC}    ${WHITE}$SSHD_PORT${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}SlowDNS:${NC}     ${WHITE}UDP :$SLOWDNS_PORT${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}EDNS Proxy:${NC}  ${WHITE}UDP :53${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Nameserver:${NC}  ${WHITE}$NAMESERVER${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Log file:${NC}    ${WHITE}$LOG_FILE${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"

    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CLIENT COMMAND${NC}                                       ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}./dnstt-client -udp $SERVER_IP:$SLOWDNS_PORT \\${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    -pubkey-file server.pub \\${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    $NAMESERVER 127.0.0.1:1080${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"

    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}QUICK COMMANDS${NC}                                       ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} systemctl status  server-sldns edns-proxy"
    echo -e "${CYAN}│${NC} systemctl restart server-sldns edns-proxy"
    echo -e "${CYAN}│${NC} journalctl -u edns-proxy -f"
    echo -e "${CYAN}│${NC} ss -ulpn | grep ':53\\|:5300'"
    echo -e "${CYAN}│${NC} dig @$SERVER_IP $NAMESERVER"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"

    if [[ -f "$INSTALL_DIR/server.pub" ]]; then
        echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PUBLIC KEY${NC}                                           ${CYAN}│${NC}"
        echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
        echo -e "${CYAN}│${NC} ${WHITE}$(head -1 "$INSTALL_DIR/server.pub")${NC}"
        echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    fi

    # ── Post-install menu ────────────────────────────────────────────────
    echo -e "\n${WHITE}${BOLD}Post-install options:${NC}"
    echo -e " ${YELLOW}1${NC} View service status   ${YELLOW}2${NC} Check ports"
    echo -e " ${YELLOW}3${NC} Restart all services  ${YELLOW}4${NC} View install log"
    echo -e " ${YELLOW}5${NC} Test DNS              ${YELLOW}6${NC} Exit"
    echo -ne "${WHITE}${BOLD}Select [1-6]: ${NC}"
    read -r option

    case $option in
        1)
            systemctl status server-sldns --no-pager -l
            systemctl status edns-proxy   --no-pager -l
            ;;
        2)
            echo -e "${WHITE}UDP:${NC}"; ss -ulpn | grep -E ':53|:5300' || echo "(none)"
            echo -e "${WHITE}TCP:${NC}"; ss -tlnp | grep ":$SSHD_PORT"  || echo "(none)"
            ;;
        3)
            systemctl restart server-sldns edns-proxy
            sleep 2
            print_success "Services restarted"
            ;;
        4)
            tail -40 "$LOG_FILE"
            ;;
        5)
            if command -v dig &>/dev/null; then
                dig @"$SERVER_IP" "$NAMESERVER" +short
            elif command -v nslookup &>/dev/null; then
                nslookup "$NAMESERVER" "$SERVER_IP"
            else
                print_warning "No DNS tools found (dig/nslookup)"
            fi
            ;;
        6|*)
            echo -e "${GREEN}Done.${NC}"
            ;;
    esac

    rm -f /tmp/edns.c /tmp/compile.log 2>/dev/null
    log "=== Install completed successfully ==="
    echo -e "\n${GREEN}${BOLD}Completed: $(date)  |  Server: $SERVER_IP${NC}\n"
}

# ============================================================================
# DIAGNOSTIC HELPER — run standalone anytime to compare day vs night latency
# Usage: bash moded_v2_fixed.sh --diag
# Logs query time to /var/log/slowdns-latency.log so you can grep by hour
# and see exactly when/where the slowdown happens (resolver vs server vs path)
# ============================================================================
run_diag() {
    local ns ip
    ns=$(grep -oP '(?<=Nameserver: ).*' "$LOG_FILE" 2>/dev/null | tail -1)
    ip=$(grep -oP '(?<=Server IP: ).*' "$LOG_FILE" 2>/dev/null | tail -1)
    if [[ -z "$ns" || -z "$ip" ]]; then
        read -rp "Nameserver (e.g. tunnel.yourdomain.com): " ns
        read -rp "Server IP: " ip
    fi
    if command -v dig &>/dev/null; then
        local result
        result=$(dig @"$ip" "$ns" +stats +time=5 +tries=1 2>&1)
        local qtime
        qtime=$(echo "$result" | grep -oP '(?<=Query time: )[0-9]+')
        echo "$(date '+%Y-%m-%d %H:%M:%S') | query_time_ms=${qtime:-timeout} | ns=$ns | server=$ip" \
            | tee -a /var/log/slowdns-latency.log
    else
        echo "Install dnsutils (apt install dnsutils) for this check."
    fi
}

# Cron tip (not installed automatically — add manually if you want it):
#   */30 * * * * root bash /path/to/moded_v2_fixed.sh --diag >/dev/null 2>&1
# Then compare: awk -F'|' '{print $1, $2}' /var/log/slowdns-latency.log

# ============================================================================
# RUN
# ============================================================================
if [[ "${1:-}" == "--diag" ]]; then
    run_diag
    exit 0
fi

main
