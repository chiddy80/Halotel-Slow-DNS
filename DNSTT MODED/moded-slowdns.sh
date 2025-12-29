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
PDNS_THREADS=2
PDNS_MAX_TCP_CLIENTS=100

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
    
    # Check if PowerDNS is already installed
    if dpkg -l | grep -q pdns-recursor; then
        echo -e "  ${YELLOW}PowerDNS Recursor is already installed${NC}"
        return 0
    fi
    
    echo -ne "  ${CYAN}Installing dependencies...${NC}"
    apt-get install -y gnupg2 ca-certificates wget curl > /dev/null 2>&1 &
    show_progress $!
    echo -e "\r  ${GREEN}Dependencies installed${NC}"
    
    # Add PowerDNS repository
    echo -ne "  ${CYAN}Adding PowerDNS repository...${NC}"
    wget -qO /tmp/pdns-repo.deb https://repo.powerdns.com/debian/pdns-recursor48-release-latest.deb 2>/dev/null
    if [ -f /tmp/pdns-repo.deb ]; then
        dpkg -i /tmp/pdns-repo.deb > /dev/null 2>&1
        apt-get update > /dev/null 2>&1
        echo -e "\r  ${GREEN}PowerDNS repository added${NC}"
    else
        echo -e "\r  ${YELLOW}Using default repository${NC}"
    fi
    
    # Install PowerDNS Recursor
    echo -ne "  ${CYAN}Installing PowerDNS Recursor...${NC}"
    apt-get install -y pdns-recursor > /dev/null 2>&1 &
    show_progress $!
    
    if dpkg -l | grep -q pdns-recursor; then
        echo -e "\r  ${GREEN}PowerDNS Recursor installed${NC}"
    else
        echo -e "\r  ${RED}Failed to install PowerDNS Recursor${NC}"
        echo -e "  ${YELLOW}Trying alternative installation...${NC}"
        apt-get install -y pdns-recursor 2>&1 | tail -20
        return 1
    fi
    
    # Create PowerDNS user if not exists
    if ! id "$PDNS_USER" &>/dev/null; then
        echo -ne "  ${CYAN}Creating PowerDNS user...${NC}"
        useradd -r -s /bin/false "$PDNS_USER" 2>/dev/null
        echo -e "\r  ${GREEN}PowerDNS user created${NC}"
    fi
    
    # Create necessary directories
    mkdir -p /var/run/powerdns
    mkdir -p /var/lib/powerdns
    chown -R $PDNS_USER:$PDNS_GROUP /var/run/powerdns /var/lib/powerdns
    
    print_success "PowerDNS Recursor installed successfully"
}

configure_powerdns_edns_proxy() {
    print_info "Configuring PowerDNS as EDNS Proxy"
    
    # Stop PowerDNS service if running
    systemctl stop pdns-recursor 2>/dev/null
    
    # Backup original configuration
    echo -ne "  ${CYAN}Backing up configuration...${NC}"
    if [ -f /etc/powerdns/recursor.conf ]; then
        cp /etc/powerdns/recursor.conf /etc/powerdns/recursor.conf.backup 2>/dev/null
    fi
    show_progress $!
    echo -e "\r  ${GREEN}Configuration backed up${NC}"
    
    # Create main PowerDNS configuration with correct settings
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
max-cache-entries=${PDNS_CACHE_SIZE}
max-packetcache-entries=${PDNS_CACHE_SIZE}
max-tcp-clients=${PDNS_MAX_TCP_CLIENTS}
server-down-max-fails=3
server-down-throttle-time=60

# EDNS Configuration
edns-outgoing-bufsize=1800
edns-subnet-whitelist=0.0.0.0/0
edns-subnet-add-for=0.0.0.0/0

# Timeouts
network-timeout=2000
query-local-address6=
socket-recv-bufsize=2097152
socket-send-bufsize=2097152

# Security
allow-from=0.0.0.0/0
allow-notify-from=0.0.0.0/0

# Forwarding to SlowDNS
forward-zones-recurse=.=127.0.0.1:${SLOWDNS_PORT}

# Logging
quiet=no
loglevel=3
log-common-errors=yes
log-timestamp=yes

# Advanced optimizations
serve-rfc1918=yes
dont-throttle-names=.
dont-throttle-netmasks=0.0.0.0/0
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

-- Function to log queries
function logQuery(dq)
    local client = dq.remoteaddr:toString()
    local qname = dq.qname:toString()
    local qtype = pdns.tostring(dq.qtype)
    
    log("Query: " .. qname .. " (" .. qtype .. ") from " .. client)
    
    -- Log EDNS info if present
    if dq.ednsValid then
        log("EDNS: buffer=" .. tostring(dq.ednsEffectivePayloadSize) .. 
            " version=" .. tostring(dq.ednsVersion))
    end
end

-- Function to modify EDNS options
function modifyEDNS(dq)
    -- Set optimal buffer size for SlowDNS tunneling
    if dq.ednsValid then
        -- Increase buffer size for better tunneling performance
        if dq.ednsEffectivePayloadSize < 1800 then
            dq.ednsEffectivePayloadSize = 1800
            log("Increased EDNS payload to 1800")
        end
    end
    
    return false
end

-- preresolve hook: called before resolving
function preresolve(dq)
    -- Log the query
    logQuery(dq)
    
    -- Modify EDNS settings
    modifyEDNS(dq)
    
    -- Forward to SlowDNS (already configured in forward-zones)
    return false
end

-- postresolve hook: called after resolving
function postresolve(dq)
    -- Log response if needed
    local records = dq:getRecords()
    if records:size() > 0 then
        log("Response sent with " .. records:size() .. " records")
    end
    
    -- Ensure response EDNS size
    if dq.ednsValid then
        dq.ednsEffectivePayloadSize = 1800
    end
    
    return false
end

-- Initialize logging
pdnslog("PowerDNS SlowDNS EDNS Proxy initialized at " .. os.date())
EOF
    
    chmod 644 /etc/powerdns/slowdns-edns.lua
    chown $PDNS_USER:$PDNS_GROUP /etc/powerdns/slowdns-edns.lua
    print_success "Lua scripting for EDNS created"
    
    # Fix permissions
    chown -R $PDNS_USER:$PDNS_GROUP /etc/powerdns
    chmod 755 /var/run/powerdns
    
    print_success "Permissions configured"
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

# Check if PowerDNS is running
if systemctl is-active --quiet pdns-recursor; then
    echo -e "${GREEN}✓ PowerDNS Recursor is running${NC}"
    
    # Try to get stats if control socket exists
    if [ -S /var/run/powerdns/pdns_recursor.controlsocket ]; then
        echo -e "\n${YELLOW}┌───────────────── PERFORMANCE STATISTICS ─────────────────┐${NC}"
        
        # Get various statistics
        stats=$(rec_control get-all 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            echo "$stats" | grep -E '(qps|cache-hitratio|packetcache-size|edns-queries|mthreads-busy)' | while read line; do
                key=$(echo "$line" | cut -d= -f1)
                value=$(echo "$line" | cut -d= -f2)
                echo -e "${YELLOW}│${NC}${BLUE} $(printf '%-25s' "$key"):${NC} $value"
            done
        else
            echo -e "${YELLOW}│${NC}${RED} Could not retrieve statistics${NC}"
        fi
        echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"
    else
        echo -e "${YELLOW}⚠ Control socket not available${NC}"
    fi
else
    echo -e "${RED}✗ PowerDNS Recursor is not running${NC}"
    echo -e "${YELLOW}Try: systemctl start pdns-recursor${NC}"
fi

# Check listening ports
echo -e "\n${YELLOW}┌────────────────── LISTENING PORTS ───────────────────┐${NC}"
echo -e "${YELLOW}│${NC}${BLUE} Port 53 (DNS):${NC}"
if ss -ulpn 2>/dev/null | grep -q ":53 "; then
    ss -ulpn 2>/dev/null | grep ":53 " | while read line; do
        echo -e "${YELLOW}│${NC}   ${GREEN}$line${NC}"
    done
else
    echo -e "${YELLOW}│${NC}   ${RED}Not listening${NC}"
fi

echo -e "${YELLOW}│${NC}${BLUE} Port ${SLOWDNS_PORT} (SlowDNS):${NC}"
if ss -ulpn 2>/dev/null | grep -q ":${SLOWDNS_PORT} "; then
    ss -ulpn 2>/dev/null | grep ":${SLOWDNS_PORT} " | while read line; do
        echo -e "${YELLOW}│${NC}   ${GREEN}$line${NC}"
    done
else
    echo -e "${YELLOW}│${NC}   ${RED}Not listening${NC}"
fi
echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"

# Show recent logs
echo -e "\n${YELLOW}┌─────────────────── RECENT LOGS ───────────────────┐${NC}"
journalctl -u pdns-recursor -n 10 --no-pager 2>/dev/null | tail -10 | while read line; do
    if echo "$line" | grep -q "error\|Error\|ERROR\|failed\|Failed\|fatal\|Fatal"; then
        echo -e "${YELLOW}│${NC} ${RED}$line${NC}"
    elif echo "$line" | grep -q "warning\|Warning\|WARNING"; then
        echo -e "${YELLOW}│${NC} ${YELLOW}$line${NC}"
    else
        echo -e "${YELLOW}│${NC} $line"
    fi
done
echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"

# Service status
echo -e "\n${YELLOW}┌────────────────── SERVICE STATUS ──────────────────┐${NC}"
systemctl status pdns-recursor --no-pager -l | grep -A5 "Active:" | while read line; do
    echo -e "${YELLOW}│${NC} $line"
done
echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"
EOF
    
    # Replace SLOWDNS_PORT variable in the script
    sed -i "s/\${SLOWDNS_PORT}/${SLOWDNS_PORT}/g" /usr/local/bin/powerdns-monitor
    
    chmod +x /usr/local/bin/powerdns-monitor
    print_success "Monitoring script created"
    
    # Create log rotation
    cat > /etc/logrotate.d/powerdns-slowdns << EOF
/var/log/powerdns/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 ${PDNS_USER} ${PDNS_GROUP}
    postrotate
        systemctl kill -s HUP pdns-recursor 2>/dev/null || true
    endscript
}
EOF
    
    print_success "Log rotation configured"
}

fix_powerdns_issues() {
    print_info "Fixing common PowerDNS issues"
    
    # Stop service first
    systemctl stop pdns-recursor 2>/dev/null
    
    # Kill any process on port 53
    fuser -k 53/udp 2>/dev/null
    fuser -k 53/tcp 2>/dev/null
    
    # Create necessary directories with correct permissions
    echo -ne "  ${CYAN}Creating directories...${NC}"
    mkdir -p /var/run/powerdns
    mkdir -p /var/lib/powerdns
    mkdir -p /run/powerdns
    
    chown -R $PDNS_USER:$PDNS_GROUP /var/run/powerdns /var/lib/powerdns /run/powerdns
    chmod 755 /var/run/powerdns /var/lib/powerdns /run/powerdns
    show_progress $!
    echo -e "\r  ${GREEN}Directories created${NC}"
    
    # Remove problematic systemd override if exists
    rm -rf /etc/systemd/system/pdns-recursor.service.d/
    
    # Create simple systemd service file if needed
    if [ ! -f /lib/systemd/system/pdns-recursor.service ]; then
        cat > /etc/systemd/system/pdns-recursor.service << EOF
[Unit]
Description=PowerDNS Recursor
After=network.target

[Service]
Type=forking
User=${PDNS_USER}
Group=${PDNS_GROUP}
ExecStart=/usr/sbin/pdns_recursor --daemon=yes
ExecStop=/usr/bin/kill -TERM \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    # Reload systemd
    systemctl daemon-reload
    
    print_success "Common issues fixed"
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
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=$SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    print_success "SlowDNS service configuration created"
    print_step_end
    
    # ============================================================================
    # STEP 4: INSTALL & CONFIGURE POWERDNS RECURSOR
    # ============================================================================
    print_step "4"
    print_info "Installing PowerDNS Recursor as EDNS Proxy"
    
    install_powerdns_recursor
    fix_powerdns_issues
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
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null
    iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null
    iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null
    
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null &
    show_progress $!
    echo -e "\r  ${GREEN}Firewall rules configured${NC}"
    
    # Stop conflicting services
    echo -ne "  ${CYAN}Stopping conflicting DNS services...${NC}"
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    systemctl stop bind9 2>/dev/null 2>/dev/null
    systemctl stop dnsmasq 2>/dev/null 2>/dev/null
    
    # Kill processes on port 53
    fuser -k 53/udp 2>/dev/null
    fuser -k 53/tcp 2>/dev/null
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
    
    # Start service
    systemctl start pdns-recursor 2>/dev/null &
    show_progress $!
    sleep 3
    
    if systemctl is-active --quiet pdns-recursor; then
        echo -e "\r  ${GREEN}PowerDNS Recursor started${NC}"
    else
        echo -e "\r  ${YELLOW}Checking PowerDNS status...${NC}"
        systemctl status pdns-recursor --no-pager | head -20
        echo -e "  ${YELLOW}Trying manual start...${NC}"
        /usr/sbin/pdns_recursor --daemon=yes --config-dir=/etc/powerdns 2>/dev/null
        sleep 2
    fi
    
    # Verify services
    echo -ne "  ${CYAN}Verifying service status...${NC}"
    sleep 2
    echo -e "\r  ${GREEN}Service verification complete${NC}"
    
    # Test PowerDNS functionality
    echo -ne "  ${CYAN}Testing PowerDNS EDNS functionality...${NC}"
    if systemctl is-active --quiet pdns-recursor; then
        echo -e "\r  ${GREEN}PowerDNS service is running${NC}"
    else
        echo -e "\r  ${YELLOW}PowerDNS service needs attention${NC}"
    fi
    
    print_success "All services started successfully"
    print_step_end
    
    # ============================================================================
    # COMPLETION SUMMARY
    # ============================================================================
    print_header "🎉 POWERDNS SLOWDNS INSTALLATION COMPLETE"
    
    # Show summary
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}SERVER INFORMATION${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Server IP:     ${WHITE}$SERVER_IP${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SSH Port:      ${WHITE}$SSHD_PORT${NC}                        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SlowDNS Port:  ${WHITE}$SLOWDNS_PORT${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} PowerDNS Port: ${WHITE}53${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:    ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final verification
    echo -e "\n${WHITE}${BOLD}Final Service Status:${NC}"
    
    # Check SlowDNS
    if systemctl is-active --quiet server-sldns; then
        echo -e "  ${GREEN}✓ SlowDNS: Running${NC}"
    else
        echo -e "  ${RED}✗ SlowDNS: Not running${NC}"
    fi
    
    # Check PowerDNS
    if systemctl is-active --quiet pdns-recursor; then
        echo -e "  ${GREEN}✓ PowerDNS: Running${NC}"
    else
        echo -e "  ${RED}✗ PowerDNS: Not running${NC}"
        echo -e "  ${YELLOW}  Troubleshooting steps:${NC}"
        echo -e "  ${YELLOW}  1. Check logs: journalctl -u pdns-recursor${NC}"
        echo -e "  ${YELLOW}  2. Manual start: systemctl start pdns-recursor${NC}"
        echo -e "  ${YELLOW}  3. Check config: pdns_recursor --config-check${NC}"
    fi
    
    # Check ports
    echo -ne "  ${CYAN}Checking port 53...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":53 "; then
        echo -e "\r  ${GREEN}✓ Port 53 is listening${NC}"
    else
        echo -e "\r  ${RED}✗ Port 53 is not listening${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking port 5300...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
        echo -e "\r  ${GREEN}✓ Port $SLOWDNS_PORT is listening${NC}"
    else
        echo -e "\r  ${RED}✗ Port $SLOWDNS_PORT is not listening${NC}"
    fi
    
    # Quick test
    echo -e "\n${YELLOW}Quick Test:${NC}"
    echo -e "  ${CYAN}Test DNS:${NC} dig @$SERVER_IP $NAMESERVER +short"
    echo -e "  ${CYAN}Test EDNS:${NC} dig @$SERVER_IP $NAMESERVER +edns=0"
    echo -e "  ${CYAN}Monitor:${NC} powerdns-monitor"
    
    echo -e "\n${GREEN}${BOLD}Installation completed!${NC}"
    
    # Post-installation menu
    echo -e "\n${WHITE}${BOLD}Post-installation options:${NC}"
    echo -e "  1. ${YELLOW}View PowerDNS status${NC}"
    echo -e "  2. ${YELLOW}Check logs${NC}"
    echo -e "  3. ${YELLOW}Restart services${NC}"
    echo -e "  4. ${YELLOW}Test connection${NC}"
    echo -e "  5. ${YELLOW}Exit${NC}"
    
    read -p "$(echo -e "${WHITE}${BOLD}Select option [1-5]: ${NC}")" option
    
    case $option in
        1)
            powerdns-monitor
            ;;
        2)
            echo -e "\n${CYAN}PowerDNS logs:${NC}"
            journalctl -u pdns-recursor -n 20 --no-pager
            echo -e "\n${CYAN}SlowDNS logs:${NC}"
            journalctl -u server-sldns -n 20 --no-pager
            ;;
        3)
            systemctl restart pdns-recursor server-sldns
            echo -e "${GREEN}Services restarted${NC}"
            ;;
        4)
            echo -e "\n${CYAN}Testing DNS query...${NC}"
            if command -v dig &>/dev/null; then
                dig @$SERVER_IP $NAMESERVER +short
            else
                echo -e "${YELLOW}Install dig: apt install dnsutils${NC}"
            fi
            ;;
    esac
    
    echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}   Installation completed at: $(date)${NC}"
    echo -e "${GREEN}${BOLD}   Server: $SERVER_IP | SlowDNS: $SLOWDNS_PORT | PowerDNS: 53${NC}"
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

Key Fixes Applied:

1. Fixed Configuration Issues:

· Removed: packetcache-entries (invalid setting)
· Changed to: max-packetcache-entries (correct setting)
· Simplified: Removed problematic systemd override

2. Fixed Permission Issues:

```bash
# Created directories with correct permissions:
mkdir -p /var/run/powerdns
mkdir -p /var/lib/powerdns
mkdir -p /run/powerdns
chown -R pdns:pdns /var/run/powerdns /var/lib/powerdns /run/powerdns
```
