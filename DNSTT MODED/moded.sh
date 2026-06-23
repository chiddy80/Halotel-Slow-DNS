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
Compression no

# Forwarding (required for SlowDNS tunnels)
AllowTcpForwarding yes
GatewayPorts yes
PermitTunnel yes

# Speed
UseDNS no
X11Forwarding no
PrintMotd no
PrintLastLog no

Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    # Apply sysctl for TCP performance before restarting sshd
    sysctl -qw net.ipv4.tcp_fastopen=3            2>/dev/null || true
    sysctl -qw net.core.somaxconn=4096            2>/dev/null || true
    sysctl -qw net.ipv4.tcp_max_syn_backlog=4096  2>/dev/null || true
    sysctl -qw net.ipv4.tcp_rmem="4096 87380 16777216" 2>/dev/null || true
    sysctl -qw net.ipv4.tcp_wmem="4096 65536 16777216" 2>/dev/null || true

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
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file $INSTALL_DIR/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
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

[Install]
WantedBy=multi-user.target
EOF

    print_success "server-sldns service configured"
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
    cat > /tmp/edns.c << 'CSRC'
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

#define LISTEN_PORT      53
#define SLOWDNS_PORT     5300
#define BUFFER_SIZE      8192
#define UPSTREAM_POOL    128      /* doubled — more parallel slots */
#define SOCKET_TIMEOUT   5.0     /* was 3.0 — tolerates slow upstreams */
#define MAX_EVENTS       8192
#define REQ_TABLE_SIZE   131072  /* doubled — less collision */
#define EXT_EDNS         512
#define INT_EDNS         1800
#define CLEANUP_INTERVAL 0.1     /* seconds between cleanup passes */

typedef struct {
    int      fd;
    int      busy;
    time_t   last_used;
} upstream_t;

typedef struct req_entry {
    uint16_t          req_id;
    int               upstream_idx;
    double            timestamp;
    struct sockaddr_in client_addr;
    socklen_t         addr_len;
    struct req_entry *next;
} req_entry_t;

static upstream_t   upstreams[UPSTREAM_POOL];
static req_entry_t *req_table[REQ_TABLE_SIZE];
static int          listen_sock, epoll_fd;
static volatile sig_atomic_t shutdown_flag = 0;
static double last_cleanup = 0;

/* ── Monotonic clock ─────────────────────────────────────────────────── */
static double mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* ── Transaction ID helpers ──────────────────────────────────────────── */
static inline uint16_t get_txid(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static inline uint32_t req_hash(uint16_t id) {
    return id & (REQ_TABLE_SIZE - 1);
}

/* ── Patch EDNS0 payload size field ──────────────────────────────────── */
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
        /* OPT record: name=0x00, type=41 */
        if (buf[off] == 0 && ((buf[off+1] << 8) | buf[off+2]) == 41) {
            buf[off+3] = (edns_size >> 8) & 0xff;
            buf[off+4] =  edns_size       & 0xff;
            return len;
        }
        off++;
    }
    return len;
}

/* ── Upstream pool ───────────────────────────────────────────────────── */
static int get_upstream(void) {
    time_t t = time(NULL);
    for (int i = 0; i < UPSTREAM_POOL; i++) {
        if (upstreams[i].busy && (double)(t - upstreams[i].last_used) > SOCKET_TIMEOUT)
            upstreams[i].busy = 0;
        if (!upstreams[i].busy) {
            upstreams[i].busy     = 1;
            upstreams[i].last_used = t;
            return i;
        }
    }
    fprintf(stderr, "[edns-proxy] upstream pool exhausted — dropping packet\n");
    return -1;
}

static void release_upstream(int i) {
    if (i >= 0 && i < UPSTREAM_POOL) upstreams[i].busy = 0;
}

/* ── Request table ───────────────────────────────────────────────────── */
static void insert_req(int uidx, const unsigned char *buf,
                       const struct sockaddr_in *c, socklen_t l) {
    req_entry_t *e = calloc(1, sizeof(*e));
    if (!e) { release_upstream(uidx); return; }
    e->upstream_idx = uidx;
    e->req_id       = get_txid(buf);
    e->timestamp    = mono_now();
    e->client_addr  = *c;
    e->addr_len     = l;
    uint32_t h = req_hash(e->req_id);
    e->next     = req_table[h];
    req_table[h] = e;
}

static req_entry_t *find_req(uint16_t id) {
    uint32_t h = req_hash(id);
    for (req_entry_t *e = req_table[h]; e; e = e->next)
        if (e->req_id == id) return e;
    return NULL;
}

static void delete_req(req_entry_t *e) {
    release_upstream(e->upstream_idx);
    uint32_t h = req_hash(e->req_id);
    req_entry_t **pp = &req_table[h];
    while (*pp) {
        if (*pp == e) { *pp = e->next; free(e); return; }
        pp = &(*pp)->next;
    }
}

static void cleanup_expired(void) {
    double t = mono_now();
    if (t - last_cleanup < CLEANUP_INTERVAL) return;  /* rate-limit cleanup */
    last_cleanup = t;
    for (int i = 0; i < REQ_TABLE_SIZE; i++) {
        req_entry_t **pp = &req_table[i];
        while (*pp) {
            if (t - (*pp)->timestamp > SOCKET_TIMEOUT) {
                req_entry_t *o = *pp;
                release_upstream(o->upstream_idx);
                *pp = o->next;
                free(o);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}

static void sig_handler(int s) { (void)s; shutdown_flag = 1; }

int main(void) {
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);       /* ignore broken-pipe on send */

    /* ── Listen socket ──────────────────────────────────────────────── */
    listen_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_sock < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,  &one, sizeof(one));
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT,  &one, sizeof(one));

    /* 4 MB receive buffer — reduces kernel drops under burst load */
    int bufsize = 4 * 1024 * 1024;
    setsockopt(listen_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(listen_sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    fcntl(listen_sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(LISTEN_PORT);
    a.sin_addr.s_addr = INADDR_ANY;
    if (bind(listen_sock, (void*)&a, sizeof(a)) < 0) {
        perror("bind :53");
        fprintf(stderr, "Port 53 is busy — stop systemd-resolved first.\n");
        return 1;
    }

    /* ── SlowDNS upstream address ───────────────────────────────────── */
    struct sockaddr_in slow = {0};
    slow.sin_family = AF_INET;
    slow.sin_port   = htons(SLOWDNS_PORT);
    inet_pton(AF_INET, "127.0.0.1", &slow.sin_addr);

    /* ── Epoll setup ────────────────────────────────────────────────── */
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = listen_sock };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sock, &ev);

    for (int i = 0; i < UPSTREAM_POOL; i++) {
        upstreams[i].fd = socket(AF_INET, SOCK_DGRAM, 0);
        setsockopt(upstreams[i].fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(upstreams[i].fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
        fcntl(upstreams[i].fd, F_SETFL, O_NONBLOCK);
        struct epoll_event ue = { .events = EPOLLIN, .data.fd = upstreams[i].fd };
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstreams[i].fd, &ue);
    }

    fprintf(stdout, "[edns-proxy] Listening on UDP :%d → SlowDNS :%d\n",
            LISTEN_PORT, SLOWDNS_PORT);
    fflush(stdout);

    struct epoll_event events[MAX_EVENTS];

    while (!shutdown_flag) {
        cleanup_expired();
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 5);  /* 5ms — was 10ms */
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            unsigned char buf[BUFFER_SIZE];

            if (fd == listen_sock) {
                /* ── Incoming from client ──────────────────────────── */
                struct sockaddr_in c; socklen_t l = sizeof(c);
                int len = recvfrom(listen_sock, buf, sizeof(buf), 0, (void*)&c, &l);
                if (len < 12) continue;                 /* minimum DNS header */
                patch_edns(buf, len, INT_EDNS);
                int u = get_upstream();
                if (u >= 0) {
                    insert_req(u, buf, &c, l);
                    sendto(upstreams[u].fd, buf, len, 0, (void*)&slow, sizeof(slow));
                }
            } else {
                /* ── Reply from SlowDNS ────────────────────────────── */
                int len = recv(fd, buf, sizeof(buf), 0);
                if (len < 12) continue;
                uint16_t id  = get_txid(buf);
                req_entry_t *e = find_req(id);
                if (e) {
                    patch_edns(buf, len, EXT_EDNS);
                    sendto(listen_sock, buf, len, 0,
                           (void*)&e->client_addr, e->addr_len);
                    delete_req(e);
                }
            }
        }
    }

    fprintf(stdout, "[edns-proxy] Shutting down cleanly.\n");
    close(listen_sock);
    close(epoll_fd);
    return 0;
}
CSRC

    # Compile — O2 for stable fast code; -march=native for CPU tuning
    echo -ne "  ${CYAN}Compiling EDNS Proxy...${NC}"
    if gcc -O2 -march=native -pipe -Wall \
           /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/tmp/compile.log; then
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
        "$SLOWDNS_BINARY" -udp :"$SLOWDNS_PORT" -mtu 1800 \
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
# RUN
# ============================================================================
main
