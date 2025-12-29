#!/bin/bash

# ============================================================================
#                     POWERDNS SLOWDNS MODERN INSTALLATION SCRIPT
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
PDNS_PORT=53
GITHUB_BASE="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# PowerDNS Configuration
PDNS_USER="pdns"
PDNS_GROUP="pdns"
PDNS_CACHE_SIZE=10000
PDNS_THREADS=4
PDNS_MAX_TCP_CLIENTS=100
PDNS_RECURSION=true

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

print_box() {
    local text="$1"
    local color="$2"
    local width=60
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
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${CYAN}          🚀 POWERDNS SLOWDNS INSTALLATION SCRIPT${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${WHITE}          Powered by PowerDNS Recursor Architecture${NC}      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}${YELLOW}                Optimized for DNS Performance${NC}                ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================================================
# POWERDNS FUNCTIONS
# ============================================================================

install_powerdns_recursor() {
    print_info "Installing PowerDNS Recursor"
    
    echo -ne "  ${CYAN}Updating package list...${NC}"
    apt-get update > /dev/null 2>&1 &
    show_progress $!
    echo -e "\r  ${GREEN}Package list updated${NC}"
    
    echo -ne "  ${CYAN}Installing dependencies...${NC}"
    apt-get install -y gnupg2 ca-certificates wget curl > /dev/null 2>&1 &
    show_progress $!
    echo -e "\r  ${GREEN}Dependencies installed${NC}"
    
    # Add PowerDNS repository
    echo -ne "  ${CYAN}Adding PowerDNS repository...${NC}"
    wget -O- https://repo.powerdns.com/FD380FBB-pub.asc | sudo apt-key add - > /dev/null 2>&1 &
    show_progress $!
    
    echo "deb [arch=amd64] https://repo.powerdns.com/ubuntu focal-recursor-48 main" > /etc/apt/sources.list.d/pdns.list
    apt-get update > /dev/null 2>&1
    echo -e "\r  ${GREEN}PowerDNS repository added${NC}"
    
    # Install PowerDNS Recursor
    echo -ne "  ${CYAN}Installing PowerDNS Recursor...${NC}"
    apt-get install -y pdns-recursor > /dev/null 2>&1 &
    show_progress $!
    echo -e "\r  ${GREEN}PowerDNS Recursor installed${NC}"
    
    # Create PowerDNS user if not exists
    if ! id "$PDNS_USER" &>/dev/null; then
        echo -ne "  ${CYAN}Creating PowerDNS user...${NC}"
        useradd -r -s /bin/false "$PDNS_USER" 2>/dev/null
        echo -e "\r  ${GREEN}PowerDNS user created${NC}"
    fi
    
    print_success "PowerDNS Recursor installed successfully"
}

configure_powerdns_edns_proxy() {
    print_info "Configuring PowerDNS as EDNS Proxy"
    
    # Stop PowerDNS service if running
    systemctl stop pdns-recursor 2>/dev/null
    
    # Backup original configuration
    echo -ne "  ${CYAN}Backing up configuration...${NC}"
    cp /etc/powerdns/recursor.conf /etc/powerdns/recursor.conf.backup 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}Configuration backed up${NC}"
    
    # Create main PowerDNS configuration
    cat > /etc/powerdns/recursor.conf << EOF
# ============================================================================
# POWERDNS RECURSOR EDNS PROXY CONFIGURATION
# Optimized for SlowDNS tunneling with EDNS support
# ============================================================================

# Basic settings
local-address=0.0.0.0
local-port=${PDNS_PORT}
threads=${PDNS_THREADS}

# Performance optimizations
packetcache-entries=${PDNS_CACHE_SIZE}
max-cache-entries=${PDNS_CACHE_SIZE}
max-tcp-clients=${PDNS_MAX_TCP_CLIENTS}
server-down-max-fails=3
server-down-throttle-time=60

# EDNS Configuration
edns-outgoing-bufsize=1800
edns-subnet-whitelist=0.0.0.0/0
edns-subnet-add-for=0.0.0.0/0
edns-subnet-option-number=8

# Timeouts
network-timeout=2000
query-local-address6=
socket-recv-bufsize=2097152
socket-send-bufsize=2097152

# Security
allow-from=0.0.0.0/0, ::/0
allow-notify-from=0.0.0.0/0, ::/0
allow-unexpected-packets=yes

# Forwarding to SlowDNS
forward-zones-recurse=.=127.0.0.1:${SLOWDNS_PORT}

# Logging
quiet=no
loglevel=6
log-common-errors=yes
log-timestamp=yes

# Advanced optimizations
serve-rfc1918=yes
dont-throttle-names=.
dont-throttle-netmasks=0.0.0.0/0, ::/0
use-incoming-edns-subnet=yes
max-mthreads=500
max-negative-ttl=3600
max-queue-length=5000

# Lua scripting for advanced EDNS handling
lua-dns-script=/etc/powerdns/slowdns-edns.lua
EOF
    
    print_success "Main PowerDNS configuration created"
    
    # Create Lua script for EDNS manipulation
    cat > /etc/powerdns/slowdns-edns.lua << 'EOF'
-- ============================================================================
-- POWERDNS LUA SCRIPT FOR SLOWDNS EDNS PROXY
-- Advanced EDNS manipulation for DNS tunneling
-- ============================================================================

local log = pdnslog
local dq = nil

-- Function to modify EDNS options
function modifyEDNS(dq)
    -- Log incoming query
    local client = dq.remoteaddr:toString()
    local qname = dq.qname:toString()
    local qtype = pdns.tostring(dq.qtype)
    
    -- EDNS client subnet handling
    if dq.ednsSubnet then
        log("EDNS Client Subnet: " .. dq.ednsSubnet:toString() .. " from " .. client)
        
        -- Modify EDNS buffer size for tunneling
        if dq.ednsValid then
            -- Set optimal buffer size for SlowDNS
            dq.ednsEffectivePayloadSize = 1800
            
            -- Add custom EDNS options if needed
            local ecs = "192.168.0.0/24"
            dq.ednsSubnet = pdns.parseCA(ecs)
            dq:setVariable()
        end
    end
    
    -- MTU optimization for DNS tunneling
    if dq.ednsValid then
        -- Ensure minimum payload size
        if dq.ednsEffectivePayloadSize < 1800 then
            dq.ednsEffectivePayloadSize = 1800
            log("Increased EDNS payload to 1800 for " .. client)
        end
    end
    
    -- Add EDNS padding for privacy
    if dq.ednsValid then
        local padding = 128  -- Pad to 128 bytes boundary
        dq:setEDNSOption(pdns.EDNSOptionCodes.EDNSOPTION_PADDING, string.rep("\0", padding))
        log("Added EDNS padding for " .. client)
    end
    
    return false
end

-- preresolve hook: called before resolving
function preresolve(dq)
    -- Call EDNS modification function
    modifyEDNS(dq)
    
    -- Log query for monitoring
    log("Query: " .. dq.qname:toString() .. " (" .. pdns.tostring(dq.qtype) .. 
        ") from " .. dq.remoteaddr:toString() .. 
        " via " .. dq.localaddr:toString())
    
    -- Forward to SlowDNS (already configured in forward-zones)
    return false
end

-- postresolve hook: called after resolving
function postresolve(dq)
    -- Modify response EDNS if needed
    if dq.ednsValid then
        -- Ensure response EDNS size matches tunnel MTU
        dq.ednsEffectivePayloadSize = 1800
    end
    
    -- Log response
    local answers = ""
    for i=1, dq:getRecords().size() do
        answers = answers .. dq:getRecords()[i].content .. " "
    end
    
    if #answers > 0 then
        log("Response to " .. dq.remoteaddr:toString() .. ": " .. answers)
    end
    
    return false
end

-- Function to handle EDNS subnet
function gettag(dq)
    -- Tag queries based on source for different EDNS handling
    local subnet = dq.ednsSubnet
    if subnet then
        local subnet_str = subnet:toString()
        if subnet_str:find("^10%.") then
            return 10  -- Internal network
        elseif subnet_str:find("^192%.168%.") then
            return 20  -- Local network
        else
            return 30  -- External network
        end
    end
    return 0
end

-- Function to handle variable EDNS options
function gettag_ffi(dq)
    -- Fast C-based tagging for performance
    local cs = ffi.C.dnsdist_ffi_get_cs(dq)
    if cs then
        return tonumber(cs)
    end
    return 0
end

-- Monitoring function
function slowdns_monitor()
    local stats = {}
    stats.queries = pdns.recursor.get("queries")
    stats.cache_hits = pdns.recursor.get("cache-hits")
    stats.cache_misses = pdns.recursor.get("cache-misses")
    stats.edns_queries = pdns.recursor.get("edns-queries")
    
    log("SlowDNS Monitor - Queries: " .. stats.queries .. 
        ", Cache hit ratio: " .. (stats.cache_hits / math.max(1, stats.queries)) * 100 .. "%" ..
        ", EDNS queries: " .. stats.edns_queries)
    
    return stats
end

-- Initialize monitoring
pdnslog("PowerDNS SlowDNS EDNS Proxy initialized at " .. os.date())
EOF
    
    chmod 644 /etc/powerdns/slowdns-edns.lua
    print_success "Lua scripting for EDNS created"
    
    # Create systemd override for better integration
    mkdir -p /etc/systemd/system/pdns-recursor.service.d/
    
    cat > /etc/systemd/system/pdns-recursor.service.d/override.conf << EOF
[Service]
# Performance tuning
LimitNOFILE=65536
LimitNPROC=65536
LimitCORE=infinity
TimeoutSec=30

# Security
User=${PDNS_USER}
Group=${PDNS_GROUP}
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/powerdns /var/cache/powerdns /run/powerdns

# Restart policy
Restart=always
RestartSec=5
StartLimitInterval=0
EOF
    
    print_success "Systemd overrides configured"
}

create_powerdns_monitoring() {
    print_info "Creating PowerDNS monitoring setup"
    
    # Create monitoring script
    cat > /usr/local/bin/powerdns-monitor << 'EOF'
#!/bin/bash
# PowerDNS SlowDNS Monitor

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}${GREEN}           POWERDNS SLOWDNS MONITOR${NC}                   ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Get statistics
STATS=$(rec_control get-all)

echo -e "${YELLOW}┌───────────────── PERFORMANCE STATISTICS ─────────────────┐${NC}"
echo -e "${YELLOW}│${NC}${BLUE} Queries per second:${NC} $(echo "$STATS" | grep 'qps' | cut -d= -f2)"
echo -e "${YELLOW}│${NC}${BLUE} Cache hit ratio:${NC} $(echo "$STATS" | grep 'cache-hitratio' | cut -d= -f2)"
echo -e "${YELLOW}│${NC}${BLUE} Packet cache size:${NC} $(echo "$STATS" | grep 'packetcache-size' | cut -d= -f2)"
echo -e "${YELLOW}│${NC}${BLUE} EDNS queries:${NC} $(echo "$STATS" | grep 'edns-queries' | cut -d= -f2)"
echo -e "${YELLOW}│${NC}${BLUE} Threads busy:${NC} $(echo "$STATS" | grep 'mthreads-busy' | cut -d= -f2)"
echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"
echo ""

# Check service status
if systemctl is-active --quiet pdns-recursor; then
    echo -e "${GREEN}✓ PowerDNS Recursor is running${NC}"
else
    echo -e "${RED}✗ PowerDNS Recursor is not running${NC}"
fi

# Check listening ports
echo -e "\n${YELLOW}┌────────────────── LISTENING PORTS ───────────────────┐${NC}"
ss -ulpn | grep -E ':53|:5300' | while read line; do
    echo -e "${YELLOW}│${NC} ${GREEN}$line${NC}"
done
echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"

# Show recent logs
echo -e "\n${YELLOW}┌─────────────────── RECENT LOGS ───────────────────┐${NC}"
journalctl -u pdns-recursor -n 10 --no-pager | tail -10 | while read line; do
    if echo "$line" | grep -q "error\|Error\|ERROR\|failed\|Failed"; then
        echo -e "${YELLOW}│${NC} ${RED}$line${NC}"
    elif echo "$line" | grep -q "warning\|Warning\|WARNING"; then
        echo -e "${YELLOW}│${NC} ${YELLOW}$line${NC}"
    else
        echo -e "${YELLOW}│${NC} $line"
    fi
done
echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"
EOF
    
    chmod +x /usr/local/bin/powerdns-monitor
    print_success "Monitoring script created"
    
    # Create log rotation
    cat > /etc/logrotate.d/powerdns-slowdns << EOF
/var/log/powerdns/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 ${PDNS_USER} ${PDNS_GROUP}
    postrotate
        systemctl kill -s HUP pdns-recursor
    endscript
}
EOF
    
    print_success "Log rotation configured"
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
    # STEP 4: INSTALL & CONFIGURE POWERDNS RECURSOR
    # ============================================================================
    print_step "4"
    print_info "Installing PowerDNS Recursor as EDNS Proxy"
    
    install_powerdns_recursor
    configure_powerdns_edns_proxy
    create_powerdns_monitoring
    
    print_success "PowerDNS Recursor configured as EDNS Proxy"
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
    
    # PowerDNS specific rules
    iptables -A INPUT -p tcp --dport $PDNS_PORT -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp --dport $PDNS_PORT -j ACCEPT 2>/dev/null
    
    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}Firewall rules configured${NC}"
    
    # Stop conflicting services
    echo -ne "  ${CYAN}Stopping conflicting DNS services...${NC}"
    systemctl stop systemd-resolved 2>/dev/null &
    systemctl stop bind9 2>/dev/null &
    systemctl stop dnsmasq 2>/dev/null &
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
    
    # Start PowerDNS Recursor
    echo -ne "  ${CYAN}Starting PowerDNS Recursor...${NC}"
    systemctl enable pdns-recursor > /dev/null 2>&1
    systemctl start pdns-recursor 2>/dev/null &
    show_progress $!
    sleep 3
    
    if systemctl is-active --quiet pdns-recursor; then
        echo -e "\r  ${GREEN}PowerDNS Recursor started${NC}"
    else
        echo -e "\r  ${YELLOW}Starting PowerDNS manually${NC}"
        /usr/sbin/pdns_recursor &
        sleep 2
    fi
    
    # Verify services
    echo -ne "  ${CYAN}Verifying service status...${NC}"
    sleep 3
    echo -e "\r  ${GREEN}Service verification complete${NC}"
    
    # Test PowerDNS functionality
    echo -ne "  ${CYAN}Testing PowerDNS EDNS functionality...${NC}"
    if rec_control ping 2>/dev/null | grep -q "pong"; then
        echo -e "\r  ${GREEN}PowerDNS EDNS functionality OK${NC}"
    else
        echo -e "\r  ${YELLOW}PowerDNS control test inconclusive${NC}"
    fi
    
    print_success "All services started successfully"
    print_step_end
    
    # ============================================================================
    # COMPLETION SUMMARY
    # ============================================================================
    print_header "🎉 POWERDNS SLOWDNS INSTALLATION COMPLETE"
    
    # Show summary in a nice box
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER INFORMATION${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:     ${WHITE}$SERVER_IP${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SSH Port:      ${WHITE}$SSHD_PORT${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SlowDNS Port:  ${WHITE}$SLOWDNS_PORT${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} PowerDNS Port: ${WHITE}53${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU Size:      ${WHITE}1800${NC}                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:    ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} PowerDNS User: ${WHITE}$PDNS_USER${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}QUICK TEST COMMANDS${NC}                                ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}dig @$SERVER_IP $NAMESERVER +edns${NC}                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}powerdns-monitor${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}rec_control get-all${NC}                               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}systemctl status pdns-recursor${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}systemctl status server-sldns${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVICE MANAGEMENT${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Restart services:${NC} systemctl restart pdns-recursor${NC}   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}View logs:${NC} journalctl -u pdns-recursor -f${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Reload Lua:${NC} rec_control reload-lua-script${NC}          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Check stats:${NC} rec_control get-all${NC}                   ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # PowerDNS specific features
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}POWERDNS EDNS FEATURES${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Native EDNS client-subnet support                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Lua scripting for custom EDNS logic                  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Built-in packet cache with 10,000 entries            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Multi-threaded architecture (4 threads)              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} EDNS padding and buffer size control                 ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final verification
    echo -e "\n${WHITE}${BOLD}Verifying PowerDNS installation...${NC}"
    
    echo -ne "  ${CYAN}Checking PowerDNS port 53...${NC}"
    if ss -ulpn 2>/dev/null | grep -q "pdns_recursor.*:53"; then
        echo -e "\r  ${GREEN}✓ PowerDNS is listening on port 53${NC}"
    else
        echo -e "\r  ${YELLOW}! PowerDNS not listening on port 53${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking PowerDNS control...${NC}"
    if rec_control ping 2>/dev/null | grep -q "pong"; then
        echo -e "\r  ${GREEN}✓ PowerDNS control interface working${NC}"
    else
        echo -e "\r  ${YELLOW}! PowerDNS control interface issue${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking SlowDNS port 5300...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
        echo -e "\r  ${GREEN}✓ SlowDNS is listening on port $SLOWDNS_PORT${NC}"
    else
        echo -e "\r  ${YELLOW}! SlowDNS not listening on port $SLOWDNS_PORT${NC}"
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
    
    # Performance optimization tips
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}POWERDNS PERFORMANCE TIPS${NC}                          ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Adjust threads in /etc/powerdns/recursor.conf${NC}     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Modify cache size based on RAM${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Use powerdns-monitor for real-time stats${NC}         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Edit Lua script for custom EDNS logic${NC}             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Enable query logging in Lua for debugging${NC}         ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Client configuration example
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CLIENT CONFIGURATION EXAMPLE${NC}                         ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}SlowDNS Client Command:${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}./dnstt-client -udp $SERVER_IP:53 \\${NC}                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    -pubkey-file server.pub \\${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    dns.example.com 127.0.0.1:1080${NC}                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}Note:${NC} Connect to port 53 (PowerDNS) now!                ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Troubleshooting section
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}TROUBLESHOOTING${NC}                                     ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}If PowerDNS fails to start:${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}1. Check logs: journalctl -u pdns-recursor -n 50${NC}         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}2. Test config: pdns_recursor --config-check${NC}             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}3. Free port 53: fuser -k 53/udp; fuser -k 53/tcp${NC}       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}If EDNS not working:${NC}                                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}1. Check Lua script: cat /etc/powerdns/slowdns-edns.lua${NC}  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}2. Reload Lua: rec_control reload-lua-script${NC}            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}3. Test EDNS: dig @$SERVER_IP example.com +edns${NC}    ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final message with timer
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 POWERDNS SLOWDNS INSTALLATION COMPLETED!${NC}       ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Powered by PowerDNS Recursor Architecture${NC}      ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 Services: PowerDNS + SlowDNS (No epoll)${NC}        ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🔧 Full EDNS support with Lua scripting${NC}           ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}${BOLD}📞 Need help? Contact support: @esimfreegb${NC}"
    echo -e "${YELLOW}${BOLD}💡 PowerDNS Docs: https://docs.powerdns.com/recursor/${NC}"
    echo -e "${YELLOW}${BOLD}🐙 GitHub: https://github.com/chiddy80/Halotel-Slow-DNS${NC}"
    
    echo -e "\n${WHITE}${BOLD}Press Enter to return to terminal...${NC}"
    read -r
    
    # Show post-installation menu
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}POST-INSTALLATION OPTIONS${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}1.${NC} ${WHITE}View PowerDNS status & stats${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}2.${NC} ${WHITE}Check listening ports${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}3.${NC} ${WHITE}Restart all services${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}4.${NC} ${WHITE}Test EDNS functionality${NC}                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}5.${NC} ${WHITE}Edit Lua script for custom EDNS${NC}                  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}6.${NC} ${WHITE}Exit to terminal${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -ne "${WHITE}${BOLD}Select option [1-6]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "\n${CYAN}════════════════ POWERDNS STATUS ════════════════${NC}"
            powerdns-monitor
            ;;
        2)
            echo -e "\n${CYAN}════════════════ LISTENING PORTS ════════════════${NC}"
            echo -e "${WHITE}Checking UDP ports:${NC}"
            ss -ulpn | grep -E ':53|:5300'
            echo -e "\n${WHITE}Checking TCP ports:${NC}"
            ss -tlnp | grep -E ':22|:53'
            ;;
        3)
            echo -e "\n${CYAN}════════════════ RESTARTING SERVICES ════════════════${NC}"
            systemctl restart pdns-recursor server-sldns
            sleep 3
            echo -e "${GREEN}✓ Services restarted successfully${NC}"
            ;;
        4)
            echo -e "\n${CYAN}════════════════ EDNS FUNCTIONALITY TEST ════════════════${NC}"
            echo -e "${WHITE}Testing EDNS query to $NAMESERVER...${NC}"
            if command -v dig &>/dev/null; then
                echo -e "${YELLOW}Standard query:${NC}"
                dig @$SERVER_IP $NAMESERVER +short
                echo -e "\n${YELLOW}EDNS query:${NC}"
                dig @$SERVER_IP $NAMESERVER +edns=0 +bufsize=1800
                echo -e "\n${YELLOW}Checking EDNS support:${NC}"
                dig @$SERVER_IP $NAMESERVER +dnssec +edns=0
            else
                echo -e "${YELLOW}Install dig for DNS testing: apt install dnsutils${NC}"
            fi
            ;;
        5)
            echo -e "\n${CYAN}════════════════ EDIT LUA SCRIPT ════════════════${NC}"
            echo -e "${WHITE}Lua script location: /etc/powerdns/slowdns-edns.lua${NC}"
            echo -e "${YELLOW}Edit with: nano /etc/powerdns/slowdns-edns.lua${NC}"
            echo -e "${YELLOW}Reload after edit: rec_control reload-lua-script${NC}"
            echo -e "\n${WHITE}Current Lua script preview:${NC}"
            head -20 /etc/powerdns/slowdns-edns.lua
            ;;
        6)
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
    echo -e "${GREEN}${BOLD}   PowerDNS SlowDNS Installation completed at: $(date)${NC}"
    echo -e "${GREEN}${BOLD}   Server: $SERVER_IP | PowerDNS: 53 | SlowDNS: $SLOWDNS_PORT${NC}"
    echo -e "${GREEN}${BOLD}   Architecture: PowerDNS Recursor (No epoll)${NC}"
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
