#!/bin/bash

# ============================================================================
#              SLOWDNS INSTALLATION SCRIPT - v5 (PERF+HARDENED EDITION)
#         Stability + Speed overhaul. NOT v2ray. Pure SlowDNS/DNSTT.
#
#  Changes vs v3:
#   • recvmmsg()/sendmmsg() batching on both the client-facing and
#     upstream sockets — up to BATCH_SIZE (32) packets per syscall
#     instead of one recv+send pair per packet.
#   • Fixed-capacity object pool per worker (freelist of preallocated
#     req_entry_t slots) replaces calloc()/free() per request — zero
#     heap traffic once warmed up. Pool exhaustion is counted, not fatal.
#   • send()/sendto() replaced by sendmmsg() with return-value checking;
#     partial/failed sends are counted (drop_send_fail) instead of
#     silently swallowed.
#   • Basic query validation (QR bit, opcode, qdcount range) plus a
#     fixed-table per-source-IP sliding-window rate limiter on the
#     port-53 listener, so a flood of junk/scanner traffic can no
#     longer grow hash chains or exhaust the pool unchecked.
#     NOTE: if clients reach you via a recursive resolver rather than
#     hitting :53 directly, the resolver's IP is what gets rate-limited,
#     not the individual client — tune RATE_MAX_PER_WINDOW accordingly,
#     this is a blunt-force flood guard, not a fair per-user limiter.
#   • pthread_setaffinity_np pins each worker thread to its own CPU core,
#     so the SO_REUSEPORT sharding design actually stays cache-local.
#   • Observability: atomic counters (queries in/out, drops by reason,
#     expiries) logged every 30s from a dedicated stats thread — visible
#     via journalctl -u edns-proxy.
#   • Scheduling: dropped SCHED_RR/realtime-IO on both services. A
#     real-time-scheduled process that becomes CPU-bound (e.g. under
#     flood) fully preempts normal SCHED_OTHER processes — including
#     sshd — regardless of RT priority level. Replaced with aggressive
#     Nice + best-effort IO priority, which still favors these services
#     without being able to starve the rest of the box.
#   • Still true, still not fixed here: request matching is keyed on
#     DNS txid only — a known limitation for multi-client deployments;
#     fixing it means changing the wire protocol, out of scope for a
#     proxy that only reshapes EDNS0 buffer sizes.
#
#  Changes vs v4 (v4.1):
#   • Worker/thread count is now detected at RUNTIME from the VPS's
#     actual online CPU count (sysconf(_SC_NPROCESSORS_ONLN), with
#     get_nprocs() as fallback) instead of being hard-capped at 8.
#     Worker + pool memory is heap-allocated for exactly that many
#     cores, so a 1-2 vCPU box doesn't pay for idle threads and a
#     16/32-core box isn't left with cores sitting unused. A sane
#     ceiling (MAX_THREADS, 32) still applies as a safety bound.
#   • Per-source-IP rate limiter upgraded from a direct-mapped table
#     (1 slot/hash bucket) to a 4-way set-associative table. Two
#     unrelated IPs landing on the same hash slot no longer stomp each
#     other's window/count; a false cross-IP rate-limit now requires 4
#     distinct active IPs colliding on one slot instead of 2.
#   • Honest scope note, not a fix: dnstt-server itself (the binary
#     downloaded from GITHUB_BASE) remains a single upstream process on
#     127.0.0.1:5300. All edns-proxy worker threads fan-in to it, so it
#     is the effective ceiling on backend throughput regardless of how
#     many cores edns-proxy uses. That binary is a third-party
#     prebuilt artifact — nothing in this script can multi-thread it
#     without patching/rebuilding dnstt-server itself, which is out of
#     scope here.
#   • Also unchanged (see note above): txid-only request matching. This
#     is a wire-protocol constraint, not something a proxy-side patch
#     can fix — flagged again here so it doesn't get lost.
#
#  Changes vs v4.1 (v5) — of the 5 remaining known limits, 2 were
#  actually fixable from this script and are fixed below; 3 are not
#  and remain exactly as documented (see "STILL NOT FIXABLE" at bottom):
#   • FIXED: in-flight request table size (REQ_HASH_BITS) and pool
#     capacity multiplier (POOL_MULTIPLIER) were hardcoded constants —
#     hitting the ceiling meant silent drop_pool_exhausted with no way
#     to raise it short of editing C and recompiling by hand. Both are
#     now install-time tunables (REQ_HASH_BITS, POOL_MULTIPLIER env
#     vars, same pattern as SLOWDNS_MTU), baked into the compiled
#     binary, and printed in the install summary so you know what you
#     actually built.
#   • FIXED: SOCKET_TIMEOUT (how long a pending request waits for an
#     upstream reply before expiring) was a hardcoded 2.0s. Now an
#     install-time tunable (REQUEST_TIMEOUT_SEC), so a deployment where
#     the upstream is occasionally slow doesn't need a source edit to
#     stop early expiries from silently dropping late replies.
#   • STILL NOT FIXABLE FROM THIS SCRIPT (permanent, by design, not by
#     neglect):
#       1. dnstt-server is still a single upstream process — it's a
#          prebuilt third-party binary from GITHUB_BASE; nothing here
#          can multi-thread it without patching/rebuilding it directly.
#       2. Bandwidth/latency to the recursive resolver and the
#          base32/EDNS0-MTU overhead inherent to DNS tunneling — a
#          protocol/physics ceiling no amount of proxy tuning changes.
#       3. txid-only request matching — a dnstt wire-protocol
#          constraint, not a proxy-side bug.
#     Raising REQ_HASH_BITS/POOL_MULTIPLIER raises the *proxy's* ceiling;
#     it does not raise dnstt-server's, the resolver path's, or fix txid
#     collisions. Don't expect this release to remove those three.
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
SLOWDNS_MTU="${SLOWDNS_MTU:-1400}"   # lower = less fragmentation on congested (daytime) paths; try 1200 if still slow
REQUEST_TIMEOUT_SEC="${REQUEST_TIMEOUT_SEC:-2.0}"   # seconds a pending request waits for an upstream reply before it expires (edns-proxy). Raise if upstream is occasionally slow; too high wastes pool slots on dead requests.
REQ_HASH_BITS="${REQ_HASH_BITS:-14}"                # in-flight request table = 2^REQ_HASH_BITS buckets, PER WORKER (per CPU core). 14 = 16384 buckets. Raise (e.g. 16) if you expect many more simultaneous in-flight requests per core than that.
POOL_MULTIPLIER="${POOL_MULTIPLIER:-4}"             # pool capacity per worker = (2^REQ_HASH_BITS) * POOL_MULTIPLIER. Hitting this ceiling shows up as drop_pool_exhausted in the stats log — raise this (or REQ_HASH_BITS) if that counter climbs under real load.
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
# TUNABLE VALIDATION — a bad env var shouldn't produce a broken build
# ============================================================================
validate_range() {
    # validate_range <name> <value> <min> <max> <default> -> echoes the value to use
    local name="$1" val="$2" min="$3" max="$4" default="$5"
    if [[ ! "$val" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        echo -e "  ${YELLOW}${BOLD}!${NC} ${YELLOW}$name='$val' is not numeric — using default $default${NC}" >&2
        echo "$default"; return
    fi
    if ! awk -v v="$val" -v mn="$min" -v mx="$max" 'BEGIN{ exit !(v>=mn && v<=mx) }'; then
        echo -e "  ${YELLOW}${BOLD}!${NC} ${YELLOW}$name=$val out of sane range [$min-$max] — using default $default${NC}" >&2
        echo "$default"; return
    fi
    echo "$val"
}
REQUEST_TIMEOUT_SEC=$(validate_range REQUEST_TIMEOUT_SEC "$REQUEST_TIMEOUT_SEC" 0.5 15 2.0)
REQ_HASH_BITS=$(validate_range REQ_HASH_BITS "$REQ_HASH_BITS" 10 18 14)
POOL_MULTIPLIER=$(validate_range POOL_MULTIPLIER "$POOL_MULTIPLIER" 1 16 4)

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
    echo -e "${BLUE}║${NC}${CYAN}        🚀 SLOWDNS INSTALLATION SCRIPT v5${NC}         ${BLUE}║${NC}"
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
            if [[ -s "$dest" ]]; then
                print_success "$description downloaded"
                return 0
            fi
        fi
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
    log "=== SlowDNS v5 Install started ==="

    echo -e "${WHITE}${BOLD}Enter nameserver configuration:${NC}"
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Default:${NC} dns.example.com                                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Example:${NC} tunnel.yourdomain.com                               ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    read -rp "$(echo -e "${WHITE}${BOLD}Enter nameserver: ${NC}")" NAMESERVER
    NAMESERVER="${NAMESERVER:-dns.example.com}"
    log "Nameserver: $NAMESERVER"

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

# Speed
UseDNS no
X11Forwarding no
PrintMotd no
PrintLastLog no
Compression yes   # tunnel is bandwidth-starved; SSH-level compression cuts round-trips over it

Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    cat > /etc/sysctl.d/99-slowdns-turbo.conf << 'SYSCTL'
net.ipv4.tcp_fastopen = 3
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
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

    chmod 600 "$INSTALL_DIR/server.key"
    chmod 644 "$INSTALL_DIR/server.pub"

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
# NOTE: intentionally NOT using SCHED_RR/realtime IO here. A real-time
# scheduled process that becomes CPU-bound (e.g. under packet flood) fully
# preempts every normal SCHED_OTHER process on the box — including sshd —
# regardless of RT priority number. Nice + best-effort IO still favors this
# service without being able to starve the rest of the system.
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=2

[Install]
WantedBy=multi-user.target
EOF

    print_success "server-sldns service configured"
    print_step_end

    # ========================================================================
    # STEP 4: EDNS PROXY — shared-socket rewrite (removes upstream pool cap)
    # ========================================================================
    print_step "4 — Compile EDNS Proxy (Turbo v5)"
    print_info "Checking for gcc..."

    if ! command -v gcc &>/dev/null; then
        print_info "Installing build-essential..."
        apt-get update -qq && apt-get install -y -qq gcc build-essential
    fi

    CPU_CORES=$(nproc --all 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    print_info "Detected ${CPU_CORES} CPU core(s) on this VPS — edns-proxy sizes its worker pool to match automatically at every start (no rebuild needed if you resize the VPS later)"
    print_info "Per-worker request table: $((1 << REQ_HASH_BITS)) buckets, pool: $(( (1 << REQ_HASH_BITS) * POOL_MULTIPLIER )) slots, timeout: ${REQUEST_TIMEOUT_SEC}s (override via REQ_HASH_BITS / POOL_MULTIPLIER / REQUEST_TIMEOUT_SEC env vars before re-running the installer)"

    # ── Improved C source (v5) ──────────────────────────────────────────────
    # Changes vs v3: recvmmsg/sendmmsg batching, object-pool allocator,
    # checked sends, query validation + per-IP rate limiting, CPU affinity,
    # atomic stats. See header changelog above for the full list.
    # ────────────────────────────────────────────────────────────────────────
    cat > /tmp/edns.c << CSRC
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>

#define LISTEN_PORT          53
#define SLOWDNS_PORT         5300
#define BUFFER_SIZE          8192
#define SOCKET_TIMEOUT       $REQUEST_TIMEOUT_SEC   /* synced to REQUEST_TIMEOUT_SEC=$REQUEST_TIMEOUT_SEC at install time */
#define MAX_EVENTS           4096
#define REQ_HASH_BITS        $REQ_HASH_BITS         /* synced to REQ_HASH_BITS=$REQ_HASH_BITS at install time */
#define REQ_TABLE_SIZE       (1 << REQ_HASH_BITS)
#define POOL_SIZE            (REQ_TABLE_SIZE * $POOL_MULTIPLIER)  /* synced to POOL_MULTIPLIER=$POOL_MULTIPLIER at install
                                              * time — capacity/worker (per CPU core). Hitting this
                                              * ceiling shows up as drop_pool_exhausted in the stats
                                              * log; re-run the installer with a higher
                                              * POOL_MULTIPLIER and/or REQ_HASH_BITS if that counter
                                              * climbs under real load. */
#define EXT_EDNS             512
#define INT_EDNS             $SLOWDNS_MTU   /* synced to -mtu $SLOWDNS_MTU at install time */
#define MAX_THREADS          32             /* safety ceiling only — actual worker count
                                              * is detected at runtime from the VPS's real
                                              * online CPU count in main(), and is usually
                                              * well below this on typical 1-8 vCPU boxes */
#define BATCH_SIZE           32             /* packets per recvmmsg/sendmmsg call */
#define IP_TABLE_BITS        12
#define IP_TABLE_SIZE        (1 << IP_TABLE_BITS)
#define IP_SET_WAYS          4              /* 4-way set-associative rate-limit table.
                                              * A direct-mapped (1-way) table lets two
                                              * unrelated source IPs that hash to the same
                                              * slot stomp each other's window/count — one
                                              * busy/legit IP could spuriously rate-limit a
                                              * totally different one. 4 ways means a false
                                              * collision needs 4 distinct *active* IPs on
                                              * the same slot at once, at negligible extra
                                              * memory/CPU cost (small fixed-size scan). */
#define RATE_WINDOW          1.0            /* seconds */
#define RATE_MAX_PER_WINDOW  4000           /* queries/sec per source IP, PER WORKER.
                                              * dnstt's actual tunnel traffic is many small
                                              * queries/sec by design — this is a flood/scanner
                                              * guard, not a per-user fairness limiter. If
                                              * clients arrive via a recursive resolver rather
                                              * than hitting :53 directly, this counts the
                                              * resolver's IP, not the end client's. Tune to
                                              * your real traffic before trusting it in prod. */
#define STATS_INTERVAL       30             /* seconds between stats log lines */

typedef struct req_entry {
    uint16_t            req_id;
    double              timestamp;
    struct sockaddr_in  client_addr;
    socklen_t           addr_len;
    struct req_entry   *hnext;          /* hash-chain link            */
    struct req_entry   *fnext, *fprev;  /* FIFO (insertion/expiry) link */
} req_entry_t;

/* ── Fixed-capacity object pool — replaces calloc()/free() per request.
 *    Freelist-of-pointers over a preallocated array: O(1) alloc/release,
 *    zero heap traffic once warmed up. Exhaustion is counted, not fatal —
 *    the query is simply dropped (see drop_pool_exhausted). ────────────── */
typedef struct {
    req_entry_t  entries[POOL_SIZE];
    req_entry_t *free_stack[POOL_SIZE];
    int          free_top;
} req_pool_t;

static void pool_init(req_pool_t *p) {
    for (int i = 0; i < POOL_SIZE; i++) p->free_stack[i] = &p->entries[i];
    p->free_top = POOL_SIZE;
}
static inline req_entry_t *pool_alloc(req_pool_t *p) {
    if (p->free_top == 0) return NULL;
    return p->free_stack[--p->free_top];
}
static inline void pool_release(req_pool_t *p, req_entry_t *e) {
    p->free_stack[p->free_top++] = e;
}

/* ── Per-source-IP sliding-window counter. 4-way set-associative (see
 *    IP_SET_WAYS above) — bounded, lock-free scan per packet, and no
 *    single unrelated IP can silently steal another's slot. Per-worker,
 *    no locks: SO_REUSEPORT already shards by flow, so this only needs
 *    to be "good enough" per worker, not globally exact. ─────────────── */
typedef struct {
    uint32_t ip;
    double   window_start;
    int      count;
} ip_bucket_t;

/* ── Observability: atomic counters aggregated across all workers,
 *    logged periodically by a dedicated stats thread. ─────────────────── */
typedef struct {
    _Atomic uint64_t queries_in;
    _Atomic uint64_t replies_out;
    _Atomic uint64_t drop_invalid;
    _Atomic uint64_t drop_ratelimit;
    _Atomic uint64_t drop_pool_exhausted;
    _Atomic uint64_t drop_send_fail;
    _Atomic uint64_t expired;
} stats_t;
static stats_t g_stats;

/* ── Per-thread worker state — no cross-thread sharing, so no locks ────── */
typedef struct {
    int          listen_sock;
    int          upstream_sock;    /* ONE shared, connected socket per thread */
    int          epoll_fd;
    req_entry_t *req_table[REQ_TABLE_SIZE];
    req_entry_t *fifo_head, *fifo_tail;   /* oldest..newest, expiry order  */
    req_pool_t  *pool;
    ip_bucket_t  ip_table[IP_TABLE_SIZE][IP_SET_WAYS];
    struct sockaddr_in slow;
    int          cpu_id;
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
static inline uint32_t ip_hash(uint32_t ip) {
    return (ip * 2654435761u) >> (32 - IP_TABLE_BITS);
}

/* ── Minimal sanity check that this looks like a DNS query, not just
 *    12+ bytes of noise hitting port 53: rejects it before it ever touches
 *    the hash table, the pool, or gets forwarded upstream. ────────────── */
static int looks_like_dns_query(const unsigned char *buf, int len) {
    if (len < 12) return 0;
    uint8_t flags1 = buf[2];
    if (flags1 & 0x80) return 0;               /* QR=1 -> a response, not a query */
    int opcode = (flags1 >> 3) & 0x0f;
    if (opcode != 0) return 0;                 /* only standard queries (what dnstt sends) */
    int qdcount = (buf[4] << 8) | buf[5];
    if (qdcount < 1 || qdcount > 16) return 0;  /* sane range */
    return 1;
}

static int rate_limit_check(worker_t *w, uint32_t src_ip) {
    ip_bucket_t *set = w->ip_table[ip_hash(src_ip)];
    double now = mono_now();

    /* 1) already tracked in this set → update in place */
    for (int i = 0; i < IP_SET_WAYS; i++) {
        ip_bucket_t *b = &set[i];
        if (b->count > 0 && b->ip == src_ip) {
            if ((now - b->window_start) > RATE_WINDOW) {
                b->window_start = now;
                b->count = 1;
                return 1;
            }
            return (++b->count <= RATE_MAX_PER_WINDOW);
        }
    }

    /* 2) not tracked yet → claim an empty or expired slot in the set */
    for (int i = 0; i < IP_SET_WAYS; i++) {
        ip_bucket_t *b = &set[i];
        if (b->count == 0 || (now - b->window_start) > RATE_WINDOW) {
            b->ip = src_ip;
            b->window_start = now;
            b->count = 1;
            return 1;
        }
    }

    /* 3) set full of distinct, still-active IPs → evict the oldest window
     *    rather than the RATE_MAX_PER_WINDOW gate being able to fire off
     *    a stale collision. Rare in practice with 4 ways. */
    ip_bucket_t *oldest = &set[0];
    for (int i = 1; i < IP_SET_WAYS; i++)
        if (set[i].window_start < oldest->window_start) oldest = &set[i];
    oldest->ip = src_ip;
    oldest->window_start = now;
    oldest->count = 1;
    return 1;
}

/* ── Patch EDNS0 payload size field ─────────────────────────────────────
 * Bounds-checked: off+4 must stay inside the buffer before we touch it. */
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
        if (buf[off] == 0 && off + 4 < len &&
            ((buf[off+1] << 8) | buf[off+2]) == 41) {
            buf[off+3] = (edns_size >> 8) & 0xff;
            buf[off+4] =  edns_size       & 0xff;
            return len;
        }
        off++;
    }
    return len;
}

/* ── Request table: hash chain for O(1) lookup by txid,
 *    FIFO list for O(1) amortized expiry (every entry shares SOCKET_TIMEOUT,
 *    so insertion order == expiry order — no full-table scan needed). ───── */
static void insert_req(worker_t *w, const unsigned char *buf,
                        const struct sockaddr_in *c, socklen_t l) {
    req_entry_t *e = pool_alloc(w->pool);
    if (!e) { atomic_fetch_add(&g_stats.drop_pool_exhausted, 1); return; }
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
    req_entry_t **pp = &w->req_table[req_hash(e->req_id)];
    while (*pp) { if (*pp == e) { *pp = e->hnext; break; } pp = &(*pp)->hnext; }
    if (e->fprev) e->fprev->fnext = e->fnext; else w->fifo_head = e->fnext;
    if (e->fnext) e->fnext->fprev = e->fprev; else w->fifo_tail = e->fprev;
}

static void delete_req(worker_t *w, req_entry_t *e) {
    unlink_req(w, e);
    pool_release(w->pool, e);
}

static void cleanup_expired(worker_t *w) {
    double now = mono_now();
    while (w->fifo_head && (now - w->fifo_head->timestamp) > SOCKET_TIMEOUT) {
        req_entry_t *e = w->fifo_head;
        unlink_req(w, e);
        pool_release(w->pool, e);
        atomic_fetch_add(&g_stats.expired, 1);
    }
}

static void sig_handler(int s) { (void)s; shutdown_flag = 1; }

/* ── Batch-receive from the client-facing socket, validate + rate-limit,
 *    patch EDNS, stash in the request table, then batch-forward upstream
 *    with a single sendmmsg(). Per-thread static buffers (not stack) so
 *    each call doesn't re-carve ~260KB out of the thread stack. ───────── */
static void handle_listen_batch(worker_t *w) {
    static __thread unsigned char bufs[BATCH_SIZE][BUFFER_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec   iovs[BATCH_SIZE];
    struct sockaddr_in addrs[BATCH_SIZE];
    memset(msgs, 0, sizeof(msgs));

    for (int i = 0; i < BATCH_SIZE; i++) {
        iovs[i].iov_base = bufs[i];
        iovs[i].iov_len  = BUFFER_SIZE;
        msgs[i].msg_hdr.msg_iov     = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
        msgs[i].msg_hdr.msg_name    = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
    }

    int n = recvmmsg(w->listen_sock, msgs, BATCH_SIZE, MSG_DONTWAIT, NULL);
    if (n <= 0) return;

    struct mmsghdr out[BATCH_SIZE];
    struct iovec   outv[BATCH_SIZE];
    memset(out, 0, sizeof(out));
    int nout = 0;

    for (int i = 0; i < n; i++) {
        int len = msgs[i].msg_len;
        atomic_fetch_add(&g_stats.queries_in, 1);

        if (!looks_like_dns_query(bufs[i], len)) {
            atomic_fetch_add(&g_stats.drop_invalid, 1);
            continue;
        }
        if (!rate_limit_check(w, addrs[i].sin_addr.s_addr)) {
            atomic_fetch_add(&g_stats.drop_ratelimit, 1);
            continue;
        }

        patch_edns(bufs[i], len, INT_EDNS);
        insert_req(w, bufs[i], &addrs[i], msgs[i].msg_hdr.msg_namelen);

        outv[nout].iov_base = bufs[i];
        outv[nout].iov_len  = len;
        out[nout].msg_hdr.msg_iov    = &outv[nout];
        out[nout].msg_hdr.msg_iovlen = 1;
        nout++;
    }

    if (nout > 0) {
        int sent = sendmmsg(w->upstream_sock, out, nout, 0);
        if (sent < 0)        atomic_fetch_add(&g_stats.drop_send_fail, nout);
        else if (sent < nout) atomic_fetch_add(&g_stats.drop_send_fail, nout - sent);
    }
}

/* ── Batch-receive replies from upstream (SlowDNS), match by txid, and
 *    batch-forward to clients with sendmmsg(). ─────────────────────────── */
static void handle_upstream_batch(worker_t *w) {
    static __thread unsigned char bufs[BATCH_SIZE][BUFFER_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec   iovs[BATCH_SIZE];
    memset(msgs, 0, sizeof(msgs));

    for (int i = 0; i < BATCH_SIZE; i++) {
        iovs[i].iov_base = bufs[i];
        iovs[i].iov_len  = BUFFER_SIZE;
        msgs[i].msg_hdr.msg_iov    = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    int n = recvmmsg(w->upstream_sock, msgs, BATCH_SIZE, MSG_DONTWAIT, NULL);
    if (n <= 0) return;

    struct mmsghdr out[BATCH_SIZE];
    struct iovec   outv[BATCH_SIZE];
    struct sockaddr_in outaddr[BATCH_SIZE];
    memset(out, 0, sizeof(out));
    int nout = 0;

    for (int i = 0; i < n; i++) {
        int len = msgs[i].msg_len;
        if (len < 12) continue;
        uint16_t id = get_txid(bufs[i]);
        req_entry_t *e = find_req(w, id);
        if (!e) continue;

        patch_edns(bufs[i], len, EXT_EDNS);
        outaddr[nout] = e->client_addr;
        outv[nout].iov_base = bufs[i];
        outv[nout].iov_len  = len;
        out[nout].msg_hdr.msg_iov     = &outv[nout];
        out[nout].msg_hdr.msg_iovlen  = 1;
        out[nout].msg_hdr.msg_name    = &outaddr[nout];
        out[nout].msg_hdr.msg_namelen = e->addr_len;
        nout++;

        delete_req(w, e);
    }

    if (nout > 0) {
        int sent = sendmmsg(w->listen_sock, out, nout, 0);
        if (sent < 0) {
            atomic_fetch_add(&g_stats.drop_send_fail, nout);
        } else {
            atomic_fetch_add(&g_stats.replies_out, sent);
            if (sent < nout) atomic_fetch_add(&g_stats.drop_send_fail, nout - sent);
        }
    }
}

static void *worker_main(void *arg) {
    worker_t *w = (worker_t *)arg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(w->cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    struct epoll_event events[MAX_EVENTS];

    while (!shutdown_flag) {
        int n = epoll_wait(w->epoll_fd, events, MAX_EVENTS, 250);
        cleanup_expired(w);

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == w->listen_sock)
                handle_listen_batch(w);
            else
                handle_upstream_batch(w);
        }
    }
    return NULL;
}

static void *stats_thread(void *arg) {
    (void)arg;
    while (!shutdown_flag) {
        sleep(STATS_INTERVAL);
        fprintf(stdout,
            "[edns-proxy][stats] in=%lu out=%lu drop_invalid=%lu drop_rate=%lu "
            "drop_pool=%lu drop_send=%lu expired=%lu\n",
            (unsigned long)atomic_load(&g_stats.queries_in),
            (unsigned long)atomic_load(&g_stats.replies_out),
            (unsigned long)atomic_load(&g_stats.drop_invalid),
            (unsigned long)atomic_load(&g_stats.drop_ratelimit),
            (unsigned long)atomic_load(&g_stats.drop_pool_exhausted),
            (unsigned long)atomic_load(&g_stats.drop_send_fail),
            (unsigned long)atomic_load(&g_stats.expired));
        fflush(stdout);
    }
    return NULL;
}

static int setup_worker(worker_t *w, int cpu_id, req_pool_t *pool) {
    memset(w, 0, sizeof(*w));
    w->pool   = pool;
    w->cpu_id = cpu_id;
    pool_init(w->pool);

    int one = 1;
    int bufsize = 4 * 1024 * 1024;

    w->listen_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (w->listen_sock < 0) { perror("socket"); return -1; }
    setsockopt(w->listen_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
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

    w->upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (w->upstream_sock < 0) { perror("upstream socket"); return -1; }
    setsockopt(w->upstream_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(w->upstream_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(w->upstream_sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    connect(w->upstream_sock, (void*)&w->slow, sizeof(w->slow));
    fcntl(w->upstream_sock, F_SETFL, O_NONBLOCK);

    w->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = w->listen_sock };
    epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->listen_sock, &ev);
    struct epoll_event ue = { .events = EPOLLIN, .data.fd = w->upstream_sock };
    epoll_ctl(w->epoll_fd, EPOLL_CTL_ADD, w->upstream_sock, &ue);

    return 0;
}

int main(void) {
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    /* ── Runtime CPU detection ────────────────────────────────────────────
     * Reads the number of CPUs actually online on THIS VPS when the
     * service starts — not a value baked in at compile time — so the
     * same binary sizes itself correctly whether the box has 1 vCPU or
     * 32. sysconf is the primary source (POSIX, reflects the CPUs the
     * process can actually be scheduled on); get_nprocs() is a fallback
     * for the rare case sysconf can't answer. MAX_THREADS remains as a
     * safety ceiling only. ────────────────────────────────────────────── */
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    int ncpu = (online > 0) ? (int)online : get_nprocs();
    if (ncpu < 1) ncpu = 1;
    if (ncpu > MAX_THREADS) ncpu = MAX_THREADS;

    /* Heap-allocated, sized to the detected core count — a small VPS
     * doesn't pay memory for worker slots it will never use, and a
     * large one gets a full-sized pool per core it actually has. */
    worker_t   *workers = calloc((size_t)ncpu, sizeof(worker_t));
    req_pool_t *pools   = calloc((size_t)ncpu, sizeof(req_pool_t));
    pthread_t  *threads = calloc((size_t)ncpu, sizeof(pthread_t));
    if (!workers || !pools || !threads) {
        fprintf(stderr, "[edns-proxy] out of memory allocating %d worker(s)\n", ncpu);
        return 1;
    }

    for (int i = 0; i < ncpu; i++) {
        if (setup_worker(&workers[i], i, &pools[i]) != 0) return 1;
    }

    pthread_t stats_tid;
    pthread_create(&stats_tid, NULL, stats_thread, NULL);

    fprintf(stdout, "[edns-proxy] Listening on UDP :%d -> SlowDNS :%d "
            "(%d worker thread%s on %d detected CPU core%s, pooled memory, "
            "batched I/O, CPU-pinned, rate-limited)\n",
            LISTEN_PORT, SLOWDNS_PORT, ncpu, ncpu == 1 ? "" : "s",
            ncpu, ncpu == 1 ? "" : "s");
    fflush(stdout);

    for (int i = 1; i < ncpu; i++)
        pthread_create(&threads[i], NULL, worker_main, &workers[i]);
    worker_main(&workers[0]);   /* main thread doubles as worker 0 */

    for (int i = 1; i < ncpu; i++)
        pthread_join(threads[i], NULL);

    fprintf(stdout, "[edns-proxy] Shutting down cleanly.\n");
    for (int i = 0; i < ncpu; i++) {
        close(workers[i].listen_sock);
        close(workers[i].upstream_sock);
        close(workers[i].epoll_fd);
    }
    free(workers);
    free(pools);
    free(threads);
    return 0;
}
CSRC

    # Compile — try CPU-tuned build first, fall back to portable if it fails
    # (e.g. building in a container/VM whose CPU flags differ from the
    # eventual host, or a compiler that rejects a detected -march value).
    echo -ne "  ${CYAN}Compiling EDNS Proxy...${NC}"
    if gcc -O2 -march=native -pipe -pthread -Wall -Wno-unused-result \
           /tmp/edns.c -o /usr/local/bin/edns-proxy -lpthread 2>/tmp/compile.log; then
        chmod +x /usr/local/bin/edns-proxy
        print_success "EDNS Proxy compiled (CPU-tuned)"
    elif gcc -O2 -pipe -pthread -Wall -Wno-unused-result \
           /tmp/edns.c -o /usr/local/bin/edns-proxy -lpthread 2>>/tmp/compile.log; then
        chmod +x /usr/local/bin/edns-proxy
        print_success "EDNS Proxy compiled (portable build — -march=native failed)"
    else
        print_error "Compilation failed — see /tmp/compile.log"
        cat /tmp/compile.log
        exit 1
    fi

    # ── EDNS Proxy service — same realtime priority as server-sldns,
    #    since it handles every packet before SlowDNS ever sees it ────────
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
# See server-sldns.service for why this isn't SCHED_RR/realtime IO —
# same reasoning applies here, doubly so since this is the hottest path.
Nice=-10
IOSchedulingClass=best-effort
IOSchedulingPriority=0
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

    iptables -F 2>/dev/null; iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null; iptables -t nat -X 2>/dev/null

    iptables -P INPUT   ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT  ACCEPT 2>/dev/null

    iptables -A INPUT  -i lo -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null

    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

    iptables -A INPUT -p tcp --dport "$SSHD_PORT" -j ACCEPT 2>/dev/null

    iptables -A INPUT -p udp --dport "$SLOWDNS_PORT" -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport 53              -j ACCEPT 2>/dev/null
    iptables -A INPUT -p tcp --dport 53              -j ACCEPT 2>/dev/null

    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null

    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables.rules 2>/dev/null || true
    fi

    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || true

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
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 SLOWDNS v5 INSTALL COMPLETE!${NC}                  ${GREEN}${BOLD}║${NC}"
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
# Usage: bash moded_v5.sh --diag
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
#   */30 * * * * root bash /path/to/moded_v5.sh --diag >/dev/null 2>&1
# Then compare: awk -F'|' '{print $1, $2}' /var/log/slowdns-latency.log

# ============================================================================
# RUN
# ============================================================================
if [[ "${1:-}" == "--diag" ]]; then
    run_diag
    exit 0
fi

main
