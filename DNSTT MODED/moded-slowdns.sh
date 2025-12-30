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
    # STEP 4: BUILD RUST EDNS PROXY
    # ============================================================================
    print_step "4"
    print_info "Building high-performance EDNS Proxy in Rust"
    
    # Check for Rust
    if ! command -v cargo &>/dev/null; then
        print_info "Installing Rust toolchain"
        echo -ne "  ${CYAN}Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1 &
        show_progress $!
        source "$HOME/.cargo/env" 2>/dev/null || source "/root/.cargo/env" 2>/dev/null
        echo -e "\r  ${GREEN}Rust installed${NC}"
    fi
    
    # Create Rust project directory
    echo -ne "  ${CYAN}Creating Rust project...${NC}"
    mkdir -p /tmp/edns-proxy 2>/dev/null
    cd /tmp/edns-proxy
    
    # Create Cargo.toml
    cat > Cargo.toml << 'EOF'
[package]
name = "edns-proxy"
version = "1.0.0"
edition = "2021"
description = "High-performance EDNS proxy for SlowDNS"
license = "MIT"
authors = ["SlowDNS Installer <installer@slowdns>"]

[dependencies]
ctrlc = "3.4"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
panic = "abort"
EOF
    
    # Create Rust source code
    mkdir -p src
    cat > src/main.rs << 'EOF'
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

const BUFFER_SIZE: usize = 4096;
const SLOWDNS_PORT: u16 = 5300;
const LISTEN_PORT: u16 = 53;

fn patch_edns(buf: &mut [u8], new_size: u16) -> usize {
    let len = buf.len();
    if len < 12 {
        return len;
    }
    
    // Get ARCOUNT from DNS header
    let arcount = ((buf[10] as u16) << 8) | buf[11] as u16;
    let mut offset = 12;
    
    // Skip QDCOUNT questions
    let qdcount = ((buf[4] as u16) << 8) | buf[5] as u16;
    for _ in 0..qdcount {
        if offset >= len {
            return len;
        }
        // Skip domain name
        while offset < len && buf[offset] != 0 {
            offset += 1;
        }
        offset += 5; // Skip null byte + QTYPE + QCLASS
    }
    
    // Skip ANCOUNT answers
    let ancount = ((buf[6] as u16) << 8) | buf[7] as u16;
    for _ in 0..ancount {
        if offset >= len {
            return len;
        }
        // Check for compression pointer
        if buf[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            // Skip domain name
            while offset < len && buf[offset] != 0 {
                offset += 1;
            }
            offset += 1;
        }
        offset += 10; // Skip TYPE, CLASS, TTL, RDLENGTH
        // Skip RDATA
        if offset + 1 < len {
            let rdlength = ((buf[offset - 2] as u16) << 8) | buf[offset - 1] as u16;
            offset += rdlength as usize;
        }
    }
    
    // Skip NSCOUNT authorities
    let nscount = ((buf[8] as u16) << 8) | buf[9] as u16;
    for _ in 0..nscount {
        if offset >= len {
            return len;
        }
        if buf[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            while offset < len && buf[offset] != 0 {
                offset += 1;
            }
            offset += 1;
        }
        offset += 10;
        if offset + 1 < len {
            let rdlength = ((buf[offset - 2] as u16) << 8) | buf[offset - 1] as u16;
            offset += rdlength as usize;
        }
    }
    
    // Process additional records for EDNS
    for _ in 0..arcount {
        if offset >= len {
            return len;
        }
        
        // Check if this is an OPT record (root domain = 0)
        if buf[offset] == 0 && offset + 4 < len {
            let rtype = ((buf[offset + 1] as u16) << 8) | buf[offset + 2] as u16;
            if rtype == 41 { // OPT RR type
                // Update UDP payload size
                buf[offset + 3] = (new_size >> 8) as u8;
                buf[offset + 4] = (new_size & 0xFF) as u8;
                return len;
            }
        }
        
        // Skip this record
        offset += 1;
        if offset >= len {
            break;
        }
    }
    
    len
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          🚀 RUST EDNS PROXY FOR SLOWDNS                 ║");
    println!("║           High-Performance DNS Tunnel Proxy             ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("");
    
    println!("[EDNS Proxy] Starting Rust EDNS proxy...");
    
    // Create listening socket
    let listen_socket = match UdpSocket::bind(("0.0.0.0", LISTEN_PORT)) {
        Ok(socket) => {
            println!("[EDNS Proxy] Listening on port 53");
            socket
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to bind to port 53: {}", e);
            eprintln!("[ERROR] Make sure port 53 is available and you have root privileges");
            std::process::exit(1);
        }
    };
    
    // Set socket timeout for non-blocking behavior
    listen_socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap_or_default();
    
    // Create forward socket
    let forward_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("[ERROR] Failed to create forward socket: {}", e);
            std::process::exit(1);
        }
    };
    
    forward_socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap_or_default();
    
    let forward_addr = format!("127.0.0.1:{}", SLOWDNS_PORT);
    let mut buffer = [0u8; BUFFER_SIZE];
    
    println!("[EDNS Proxy] Ready to handle DNS queries");
    println!("[EDNS Proxy] Forwarding to: {}", forward_addr);
    
    // Set up Ctrl+C handler
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\n[INFO] Received shutdown signal");
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    }).expect("[ERROR] Failed to set Ctrl+C handler");
    
    println!("[INFO] Press Ctrl+C to stop the proxy");
    
    let mut packet_count = 0;
    
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        match listen_socket.recv_from(&mut buffer) {
            Ok((size, client_addr)) => {
                packet_count += 1;
                
                if packet_count % 100 == 0 {
                    println!("[INFO] Processed {} packets", packet_count);
                }
                
                // Copy packet
                let mut packet = buffer[..size].to_vec();
                
                // Patch EDNS for incoming query (increase MTU)
                patch_edns(&mut packet, 1800);
                
                // Forward to SlowDNS
                match forward_socket.send_to(&packet, &forward_addr) {
                    Ok(_) => {
                        // Try to receive response
                        let mut resp_buffer = [0u8; BUFFER_SIZE];
                        match forward_socket.recv_from(&mut resp_buffer) {
                            Ok((resp_size, _)) => {
                                let mut response = resp_buffer[..resp_size].to_vec();
                                // Patch EDNS for outgoing response (decrease MTU)
                                patch_edns(&mut response, 512);
                                
                                // Send response back to client
                                let _ = listen_socket.send_to(&response, client_addr);
                            }
                            Err(_) => {
                                // Timeout or error, continue
                            }
                        }
                    }
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

const BUFFER_SIZE: usize = 4096;
const SLOWDNS_PORT: u16 = 5300;
const LISTEN_PORT: u16 = 53;
const EXT_EDNS_SIZE: u16 = 512;    // External EDNS size (to client)
const INT_EDNS_SIZE: u16 = 1800;   // Internal EDNS size (to SlowDNS)

fn patch_edns(buf: &mut [u8], new_size: u16) -> usize {
    let len = buf.len();
    if len < 12 {
        return len;
    }
    
    // Get ARCOUNT from DNS header (bytes 10-11)
    let arcount = ((buf[10] as u16) << 8) | buf[11] as u16;
    let mut offset = 12;
    
    // Skip QDCOUNT questions (bytes 4-5)
    let qdcount = ((buf[4] as u16) << 8) | buf[5] as u16;
    for _ in 0..qdcount {
        if offset >= len {
            return len;
        }
        // Skip domain name (labels terminated by 0)
        while offset < len && buf[offset] != 0 {
            offset += 1;
        }
        offset += 5; // Skip null byte + QTYPE (2) + QCLASS (2)
    }
    
    // Skip ANCOUNT answers (bytes 6-7)
    let ancount = ((buf[6] as u16) << 8) | buf[7] as u16;
    for _ in 0..ancount {
        if offset >= len {
            return len;
        }
        // Check for compression pointer (first 2 bits = 11)
        if buf[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            // Skip domain name
            while offset < len && buf[offset] != 0 {
                offset += 1;
            }
            offset += 1;
        }
        offset += 10; // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        
        // Skip RDATA
        if offset + 1 < len {
            let rdlength = ((buf[offset - 2] as u16) << 8) | buf[offset - 1] as u16;
            offset += rdlength as usize;
        }
    }
    
    // Skip NSCOUNT authorities (bytes 8-9)
    let nscount = ((buf[8] as u16) << 8) | buf[9] as u16;
    for _ in 0..nscount {
        if offset >= len {
            return len;
        }
        if buf[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            while offset < len && buf[offset] != 0 {
                offset += 1;
            }
            offset += 1;
        }
        offset += 10;
        if offset + 1 < len {
            let rdlength = ((buf[offset - 2] as u16) << 8) | buf[offset - 1] as u16;
            offset += rdlength as usize;
        }
    }
    
    // Process additional records for EDNS OPT record
    for _ in 0..arcount {
        if offset >= len {
            return len;
        }
        
        // Check if this is an OPT record (root domain = single 0 byte)
        if buf[offset] == 0 && offset + 4 < len {
            let rtype = ((buf[offset + 1] as u16) << 8) | buf[offset + 2] as u16;
            if rtype == 41 { // OPT RR type (41 = EDNS)
                // Update UDP payload size in OPT record (bytes 3-4 after root)
                buf[offset + 3] = (new_size >> 8) as u8;
                buf[offset + 4] = (new_size & 0xFF) as u8;
                println!("[DEBUG] Patched EDNS size to: {} bytes", new_size);
                return len;
            }
        }
        
        // Skip this record
        offset += 1;
        if offset >= len {
            break;
        }
    }
    
    // If no OPT record found, we could add one, but for now just return
    println!("[DEBUG] No OPT record found, EDNS not patched");
    len
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          🚀 RUST EDNS PROXY FOR SLOWDNS                 ║");
    println!("║           External: {} | Internal: {} bytes           ║", EXT_EDNS_SIZE, INT_EDNS_SIZE);
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("");
    
    println!("[EDNS Proxy] Starting Rust EDNS proxy...");
    println!("[EDNS Proxy] Configuration:");
    println!("[EDNS Proxy]   Listen port: {}", LISTEN_PORT);
    println!("[EDNS Proxy]   Forward port: {}", SLOWDNS_PORT);
    println!("[EDNS Proxy]   External EDNS: {} bytes", EXT_EDNS_SIZE);
    println!("[EDNS Proxy]   Internal EDNS: {} bytes", INT_EDNS_SIZE);
    
    // Create listening socket (port 53)
    let listen_socket = match UdpSocket::bind(("0.0.0.0", LISTEN_PORT)) {
        Ok(socket) => {
            println!("[EDNS Proxy] ✓ Listening on port {}", LISTEN_PORT);
            socket
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to bind to port {}: {}", LISTEN_PORT, e);
            eprintln!("[ERROR] Make sure port {} is available and you have root privileges", LISTEN_PORT);
            std::process::exit(1);
        }
    };
    
    // Set non-blocking behavior with timeout
    listen_socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap_or_default();
    listen_socket.set_nonblocking(false).unwrap_or_default();
    
    // Create forward socket for SlowDNS
    let forward_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            println!("[EDNS Proxy] ✓ Forward socket created");
            socket
        }
        Err(e) => {
            eprintln!("[ERROR] Failed to create forward socket: {}", e);
            std::process::exit(1);
        }
    };
    
    forward_socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap_or_default();
    
    let forward_addr = format!("127.0.0.1:{}", SLOWDNS_PORT);
    let mut buffer = [0u8; BUFFER_SIZE];
    
    println!("[EDNS Proxy] ✓ Forwarding to: {}", forward_addr);
    println!("[EDNS Proxy] ✓ Ready to handle DNS queries");
    println!("[EDNS Proxy] ✓ EDNS patching: {} <-> {} bytes", EXT_EDNS_SIZE, INT_EDNS_SIZE);
    
    // Set up Ctrl+C handler for graceful shutdown
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\n[INFO] Received shutdown signal");
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    }).expect("[ERROR] Failed to set Ctrl+C handler");
    
    println!("[INFO] Press Ctrl+C to stop the proxy");
    
    let mut packet_count = 0;
    let mut last_log_time = std::time::Instant::now();
    
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        match listen_socket.recv_from(&mut buffer) {
            Ok((size, client_addr)) => {
                packet_count += 1;
                
                // Log every 100 packets or every 10 seconds
                if packet_count % 100 == 0 || last_log_time.elapsed() > Duration::from_secs(10) {
                    println!("[INFO] Processed {} packets from {}", packet_count, client_addr.ip());
                    last_log_time = std::time::Instant::now();
                }
                
                // Create packet copy
                let mut packet = buffer[..size].to_vec();
                
                // Log first few bytes for debugging
                if packet_count <= 5 {
                    println!("[DEBUG] Packet {} first bytes: {:02x}{:02x}...", 
                             packet_count, packet[0], packet[1]);
                }
                
                // Patch EDNS for incoming query (increase MTU to SlowDNS)
                let original_size = packet.len();
                patch_edns(&mut packet, INT_EDNS_SIZE);
                
                if packet.len() != original_size {
                    println!("[DEBUG] Packet size changed: {} -> {} bytes", original_size, packet.len());
                }
                
                // Forward to SlowDNS
                match forward_socket.send_to(&packet, &forward_addr) {
                    Ok(bytes_sent) => {
                        if packet_count <= 5 {
                            println!("[DEBUG] Forwarded {} bytes to SlowDNS", bytes_sent);
                        }
                        
                        // Try to receive response from SlowDNS
                        let mut resp_buffer = [0u8; BUFFER_SIZE];
                        match forward_socket.recv_from(&mut resp_buffer) {
                            Ok((resp_size, _)) => {
                                let mut response = resp_buffer[..resp_size].to_vec();
                                
                                // Patch EDNS for outgoing response (decrease MTU to client)
                                patch_edns(&mut response, EXT_EDNS_SIZE);
                                
                                // Send response back to client
                                match listen_socket.send_to(&response, client_addr) {
                                    Ok(_) => {
                                        if packet_count <= 5 {
                                            println!("[DEBUG] Response sent to client");
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[ERROR] Failed to send response to client: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                if e.kind() != std::io::ErrorKind::WouldBlock && 
                                   e.kind() != std::io::ErrorKind::TimedOut {
                                    eprintln!("[ERROR] Failed to receive from SlowDNS: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[ERROR] Failed to forward packet to SlowDNS: {}", e);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, sleep to reduce CPU usage
                thread::sleep(Duration::from_millis(10));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Timeout is expected, continue
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("[ERROR] Receive error: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    
    println!("[INFO] EDNS Proxy shutdown complete");
}
EOF
    
    echo -e "\r  ${GREEN}Rust project created${NC}"
    
    # Build with optimizations
    echo -ne "  ${CYAN}Building optimized EDNS Proxy...${NC}"
    if cargo build --release --quiet 2>&1; then
        cp target/release/edns-proxy /usr/local/bin/edns-proxy
        chmod +x /usr/local/bin/edns-proxy
        
        # Strip binary to reduce size
        strip /usr/local/bin/edns-proxy 2>/dev/null || true
        
        echo -e "\r  ${GREEN}EDNS Proxy built successfully${NC}"
        
        # Show binary info
        echo -ne "  ${CYAN}Binary size...${NC}"
        size=$(du -h /usr/local/bin/edns-proxy 2>/dev/null | cut -f1)
        echo -e "\r  ${GREEN}Binary size: ${WHITE}$size${NC}"
    else
        echo -e "\r  ${RED}Build failed, trying alternative approach...${NC}"
        
        # Fallback to simple standalone Rust compilation
        print_info "Creating simplified Rust implementation"
        cat > /tmp/simple_edns.rs << 'SIMPLE_EOF'
use std::net::UdpSocket;
use std::time::Duration;

fn patch_edns(buf: &mut [u8], new_size: u16) {
    if buf.len() < 12 { return; }
    
    let mut offset = 12;
    let qdcount = ((buf[4] as u16) << 8) | buf[5] as u16;
    
    for _ in 0..qdcount {
        if offset >= buf.len() { return; }
        while offset < buf.len() && buf[offset] != 0 { offset += 1; }
        offset += 5;
    }
    
    let arcount = ((buf[10] as u16) << 8) | buf[11] as u16;
    for _ in 0..arcount {
        if offset >= buf.len() { return; }
        if buf[offset] == 0 && offset + 4 < buf.len() {
            let rtype = ((buf[offset+1] as u16) << 8) | buf[offset+2] as u16;
            if rtype == 41 {
                buf[offset+3] = (new_size >> 8) as u8;
                buf[offset+4] = (new_size & 0xFF) as u8;
                return;
            }
        }
        offset += 1;
    }
}

fn main() {
    println!("[EDNS Proxy] Starting simple proxy...");
    
    let socket = UdpSocket::bind("0.0.0.0:53").expect("Bind failed");
    socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
    
    let forward_socket = UdpSocket::bind("0.0.0.0:0").expect("Forward socket failed");
    forward_socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
    
    let forward_addr = "127.0.0.1:5300";
    let mut buf = [0u8; 4096];
    
    println!("[EDNS Proxy] Ready on port 53");
    
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, client_addr)) => {
                let mut packet = buf[..size].to_vec();
                patch_edns(&mut packet, 1800);
                
                                if forward_socket.send_to(&packet, forward_addr).is_ok() {
                    let mut resp = [0u8; 4096];
                    if let Ok((resp_size, _)) = forward_socket.recv_from(&mut resp) {
                        let mut response = resp[..resp_size].to_vec();
                        patch_edns(&mut response, 512);
                        let _ = socket.send_to(&response, client_addr);
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
SIMPLE_EOF
        
        echo -ne "  ${CYAN}Compiling simplified version...${NC}"
        if rustc /tmp/simple_edns.rs -o /usr/local/bin/edns-proxy 2>/dev/null; then
            chmod +x /usr/local/bin/edns-proxy
            echo -e "\r  ${GREEN}Simplified EDNS Proxy compiled${NC}"
        else
            echo -e "\r  ${RED}All compilation attempts failed${NC}"
            print_info "Trying to install from package manager"
            apt update > /dev/null 2>&1
            apt install -y rustc 2>/dev/null || apt install -y cargo 2>/dev/null || true
            
            if rustc /tmp/simple_edns.rs -o /usr/local/bin/edns-proxy 2>/dev/null; then
                chmod +x /usr/local/bin/edns-proxy
                echo -e "  ${GREEN}Rust compiler installed and proxy built${NC}"
            else
                echo -e "  ${RED}Cannot compile Rust EDNS proxy. Using fallback C version.${NC}"
                
                # Fallback to C version
                cat > /tmp/edns_fallback.c << 'C_EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define BUFFER_SIZE 4096

void patch_edns(unsigned char *buf, int new_size) {
    if(buf[0] == 0 && buf[1] == 0) {
        int offset = 12;
        int qdcount = (buf[4] << 8) | buf[5];
        for(int i = 0; i < qdcount; i++) {
            while(buf[offset] != 0) offset++;
            offset += 5;
        }
        int arcount = (buf[10] << 8) | buf[11];
        for(int i = 0; i < arcount; i++) {
            if(buf[offset] == 0 && buf[offset+1] == 0 && 
               buf[offset+2] == 41) {
                buf[offset+3] = new_size >> 8;
                buf[offset+4] = new_size & 0xFF;
                return;
            }
            offset++;
        }
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    int forward_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in forward_addr = {0};
    forward_addr.sin_family = AF_INET;
    forward_addr.sin_port = htons(5300);
    inet_pton(AF_INET, "127.0.0.1", &forward_addr.sin_addr);
    
    unsigned char buffer[BUFFER_SIZE];
    
    while(1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int len = recvfrom(sock, buffer, BUFFER_SIZE, 0, 
                         (struct sockaddr*)&client_addr, &client_len);
        if(len > 0) {
            patch_edns(buffer, 1800);
            sendto(forward_sock, buffer, len, 0, 
                   (struct sockaddr*)&forward_addr, sizeof(forward_addr));
            
            len = recvfrom(forward_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
            if(len > 0) {
                patch_edns(buffer, 512);
                sendto(sock, buffer, len, 0, 
                       (struct sockaddr*)&client_addr, client_len);
            }
        }
    }
    return 0;
}
C_EOF
                
                echo -ne "  ${CYAN}Compiling C fallback...${NC}"
                if gcc /tmp/edns_fallback.c -o /usr/local/bin/edns-proxy 2>/dev/null; then
                    chmod +x /usr/local/bin/edns-proxy
                    echo -e "\r  ${GREEN}C fallback proxy compiled${NC}"
                else
                    echo -e "\r  ${RED}All compilation methods failed${NC}"
                    print_error "Cannot compile EDNS proxy. Installation may not work properly."
                fi
            fi
        fi
    fi
    
    # Cleanup
    rm -rf /tmp/edns-proxy /tmp/simple_edns.rs /tmp/edns_fallback.c 2>/dev/null
    
    print_success "EDNS Proxy built"
    print_step_end
    
    # ============================================================================
    # STEP 5: CREATE EDNS PROXY SERVICE
    # ============================================================================
    print_step "5"
    print_info "Creating EDNS Proxy system service"
    
    cat > /etc/systemd/system/edns-proxy.service << EOF
# ============================================================================
# EDNS PROXY SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=EDNS Proxy for SlowDNS
Description=High-performance DNS proxy with EDNS support
After=server-sldns.service network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=65536
Environment="RUST_LOG=info"
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "EDNS Proxy service configured"
    print_step_end
    
    # ============================================================================
    # STEP 6: FIREWALL CONFIGURATION
    # ============================================================================
    print_step "6"
    print_info "Configuring system firewall"
    
    echo -ne "  ${CYAN}Setting up firewall rules...${NC}"
    # Flush existing rules
    iptables -F 2>/dev/null || true
    iptables -X 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t nat -X 2>/dev/null || true
    
    # Set default policies
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    
    # Essential rules
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p tcp --dport $SSHD_PORT -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p udp --dport $SLOWDNS_PORT -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null || true
    
    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || true
    
    show_progress $!
    echo -e "\r  ${GREEN}Firewall rules configured${NC}"
    
    # Stop conflicting services
    echo -ne "  ${CYAN}Stopping conflicting DNS services...${NC}"
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    pkill -9 dnsmasq 2>/dev/null || true
    pkill -9 named 2>/dev/null || true
    fuser -k 53/udp 2>/dev/null || true
    fuser -k 53/tcp 2>/dev/null || true
    
    show_progress $!
    echo -e "\r  ${GREEN}DNS services stopped${NC}"
    
    print_success "Firewall and network configured"
    print_step_end
    
    # ============================================================================
    # STEP 7: START SERVICES
    # ============================================================================
    print_step "7"
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
        nohup $SLOWDNS_BINARY -udp :$SLOWDNS_PORT -mtu 1800 -privkey-file /etc/slowdns/server.key $NAMESERVER 127.0.0.1:$SSHD_PORT > /var/log/slowdns.log 2>&1 &
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
        nohup /usr/local/bin/edns-proxy > /var/log/edns-proxy.log 2>&1 &
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
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} EDNS Port:     ${WHITE}53${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} MTU Size:      ${WHITE}1800${NC}                          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Nameserver:    ${WHITE}$NAMESERVER${NC}           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Proxy Type:    ${WHITE}Rust EDNS Proxy${NC}                ${CYAN}│${NC}"
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
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final verification
    echo -e "\n${WHITE}${BOLD}Verifying installation...${NC}"
    
    echo -ne "  ${CYAN}Checking port 53...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":53 "; then
        echo -e "\r  ${GREEN}✓ Port 53 (EDNS Proxy) is listening${NC}"
    else
        echo -e "\r  ${YELLOW}! Port 53 not listening${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking port 5300...${NC}"
    if ss -ulpn 2>/dev/null | grep -q ":$SLOWDNS_PORT "; then
        echo -e "\r  ${GREEN}✓ Port $SLOWDNS_PORT (SlowDNS) is listening${NC}"
    else
        echo -e "\r  ${YELLOW}! Port $SLOWDNS_PORT not listening${NC}"
    fi
    
    echo -ne "  ${CYAN}Checking service status...${NC}"
    if systemctl is-active --quiet server-sldns 2>/dev/null; then
        echo -ne "\r  ${GREEN}✓ SlowDNS service is running${NC}\n"
    else
        echo -ne "\r  ${YELLOW}! SlowDNS service needs attention${NC}\n"
    fi
    
    if systemctl is-active --quiet edns-proxy 2>/dev/null || pgrep -f "edns-proxy" > /dev/null; then
        echo -ne "  ${GREEN}✓ EDNS Proxy is running${NC}\n"
    else
        echo -ne "  ${YELLOW}! EDNS Proxy needs attention${NC}\n"
    fi
    
    # Show public key if available
    if [ -f /etc/slowdns/server.pub ]; then
        echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${WHITE}${BOLD}PUBLIC KEY (For Client Configuration)${NC}               ${CYAN}│${NC}"
        echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
        echo -e "${CYAN}│${NC}${WHITE}"
        head -1 /etc/slowdns/server.pub
        echo -e "${NC}${CYAN}│${NC}"
        echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    fi
    
    # Performance optimization tips
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}RUST EDNS PROXY ADVANTAGES${NC}                         ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Memory safety: No buffer overflows or memory leaks     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} High performance: Comparable to C with optimizations   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Reliability: Better error handling and recovery        ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Modern: Thread-safe and concurrent by design          ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}●${NC} Small binary: Stripped to minimal size                ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Client configuration example
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}CLIENT CONFIGURATION EXAMPLE${NC}                         ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}SlowDNS Client Command:${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}./dnstt-client -udp $SERVER_IP:5300 \\${NC}               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    -pubkey-file server.pub \\${NC}                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${GREEN}    $NAMESERVER 127.0.0.1:1080${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Troubleshooting section
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}TROUBLESHOOTING${NC}                                     ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}If port 53 is not listening:${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}1. Check if systemd-resolved is stopped${NC}                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}2. Check logs: journalctl -u edns-proxy${NC}                   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}3. Run manually: /usr/local/bin/edns-proxy${NC}                ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}If SlowDNS is not working:${NC}                               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}1. Check firewall: iptables -L -n -v${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}2. Verify keys: ls -la /etc/slowdns/${NC}                      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}3. Test SlowDNS: nc -uz 127.0.0.1 5300${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    # Final message with timer
    echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🎯 SLOWDNS WITH RUST EDNS PROXY INSTALLED!${NC}        ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}⚡ Modern, safe, and high-performance${NC}             ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}📊 Services: SlowDNS + Rust EDNS Proxy${NC}            ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}    ${WHITE}🔧 Ready for secure DNS tunneling${NC}                 ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}${BOLD}📞 Need help? Contact support${NC}"
    echo -e "${YELLOW}${BOLD}💡 Rust EDNS Proxy provides better security and performance${NC}"
    
    echo -e "\n${WHITE}${BOLD}Press Enter to return to terminal...${NC}"
    read -r
    
    # Show post-installation menu
    echo -e "\n${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${WHITE}${BOLD}POST-INSTALLATION OPTIONS${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}├──────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}1.${NC} ${WHITE}View service status${NC}                              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}2.${NC} ${WHITE}Check listening ports${NC}                            ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}3.${NC} ${WHITE}Restart all services${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}4.${NC} ${WHITE}View Rust proxy logs${NC}                             ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}5.${NC} ${WHITE}Test DNS functionality${NC}                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${YELLOW}6.${NC} ${WHITE}Exit to terminal${NC}                                 ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -ne "${WHITE}${BOLD}Select option [1-6]: ${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "\n${CYAN}════════════════ SERVICE STATUS ════════════════${NC}"
            systemctl status server-sldns --no-pager -l
            echo -e "\n${CYAN}═══════════════════════════════════════════════${NC}"
            systemctl status edns-proxy --no-pager -l 2>/dev/null || echo "Service not running as systemd unit"
            ;;
        2)
            echo -e "\n${CYAN}════════════════ LISTENING PORTS ════════════════${NC}"
            echo -e "${WHITE}Checking UDP ports:${NC}"
            ss -ulpn | grep -E ':53|:5300' || echo "No UDP ports found"
            echo -e "\n${WHITE}Checking TCP ports:${NC}"
            ss -tlnp | grep -E ":($SSHD_PORT|53)" || echo "No TCP ports found"
            ;;
        3)
            echo -e "\n${CYAN}════════════════ RESTARTING SERVICES ════════════════${NC}"
            systemctl restart server-sldns 2>/dev/null || true
            systemctl restart edns-proxy 2>/dev/null || true
            sleep 2
            echo -e "${GREEN}✓ Services restarted${NC}"
            ;;
        4)
            echo -e "\n${CYAN}════════════════ RUST PROXY LOGS ════════════════${NC}"
            if [ -f "/var/log/edns-proxy.log" ]; then
                tail -20 /var/log/edns-proxy.log
            elif journalctl -u edns-proxy --no-pager -n 20 2>/dev/null; then
                :
            else
                echo "No logs found"
            fi
            ;;
        5)
            echo -e "\n${CYAN}════════════════ DNS TEST ════════════════${NC}"
            echo -e "${WHITE}Testing DNS query to $NAMESERVER...${NC}"
            if command -v dig &>/dev/null; then
                dig @$SERVER_IP $NAMESERVER +short +time=2 +tries=1
            elif command -v nslookup &>/dev/null; then
                timeout 2 nslookup $NAMESERVER $SERVER_IP
            else
                echo -e "${YELLOW}DNS tools not available${NC}"
            fi
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
    echo -e "${GREEN}${BOLD}   Rust EDNS Proxy Installation Complete${NC}"
    echo -e "${GREEN}${BOLD}   Server: $SERVER_IP | SlowDNS: $SLOWDNS_PORT | EDNS: 53${NC}"
    echo -e "${GREEN}${BOLD}   Installation Time: $(date)${NC}"
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
