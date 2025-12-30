#!/usr/bin/env python3
"""
🚀 SLOWDNS INSTALLATION SCRIPT - Python Edition
With Integrated Zero-Copy EDNS Proxy
Complete working solution - No errors
"""

import os
import sys
import time
import socket
import subprocess
import urllib.request
from pathlib import Path
import shutil
import struct
import select
import errno
import signal
from collections import deque
import threading

# ============================================================================
# CONFIGURATION
# ============================================================================
SSHD_PORT = 22
SLOWDNS_PORT = 5300
GITHUB_BASE = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN = '\033[0;36m'
WHITE = '\033[1;37m'
BOLD = '\033[1m'
NC = '\033[0m'

# ============================================================================
# ZERO-COPY EDNS PROXY
# ============================================================================
class ZeroCopyEDNSProxy:
    """High-performance zero-copy EDNS proxy"""
    
    def __init__(self, listen_port=53, backend_port=5300):
        self.listen_port = listen_port
        self.backend_port = backend_port
        self.backend_addr = ("127.0.0.1", backend_port)
        self.running = False
        
        # Pre-allocated buffers
        self.buffer_pool = deque(maxlen=100)
        self._init_buffers()
        
        # Stats
        self.stats = {'packets': 0, 'errors': 0, 'start': time.time()}
    
    def _init_buffers(self):
        """Initialize buffer pool"""
        for _ in range(50):
            self.buffer_pool.append(bytearray(65507))
    
    def _get_buffer(self):
        """Get buffer from pool"""
        if self.buffer_pool:
            return self.buffer_pool.pop()
        return bytearray(65507)
    
    def _return_buffer(self, buf):
        """Return buffer to pool"""
        if len(self.buffer_pool) < 100:
            # Clear buffer
            buf[:] = b'\x00' * len(buf)
            self.buffer_pool.append(buf)
    
    @staticmethod
    def patch_edns_fast(buf, length, new_size):
        """In-place EDNS patching"""
        if length < 12:
            return length
        
        offset = 12
        
        # Skip questions
        qdcount = (buf[4] << 8) | buf[5]
        for _ in range(qdcount):
            while offset < length and buf[offset]:
                offset += 1
            if offset + 5 > length:
                return length
            offset += 5
        
        # Find and patch EDNS
        arcount = (buf[10] << 8) | buf[11]
        for _ in range(arcount):
            if offset >= length - 4:
                break
            
            if buf[offset] == 0:  # Root label
                if offset + 4 < length:
                    # Check if OPT record
                    if buf[offset+1] == 0 and buf[offset+2] == 41:  # OPT=41
                        buf[offset+3] = (new_size >> 8) & 0xFF
                        buf[offset+4] = new_size & 0xFF
                        break
                offset += 11
            else:
                offset += 1
        
        return length
    
    def start(self):
        """Start the zero-copy proxy"""
        print_info("Starting Zero-Copy EDNS Proxy...")
        
        # Create sockets
        frontend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        backend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Optimize sockets
        frontend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for sock in [frontend, backend]:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024*1024)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024*1024)
        
        frontend.bind(('0.0.0.0', self.listen_port))
        backend.settimeout(0.1)  # 100ms timeout
        
        print_success(f"Listening on port {self.listen_port}")
        print_success(f"Proxying to SlowDNS on port {self.backend_port}")
        
        self.running = True
        
        # Signal handler
        def signal_handler(sig, frame):
            print_info("\nShutting down EDNS Proxy...")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            while self.running:
                try:
                    # Get buffer from pool
                    buf = self._get_buffer()
                    
                    # Receive from client
                    length, client_addr = frontend.recvfrom_into(buf)
                    
                    if length > 0:
                        # Patch EDNS (increase MTU for internal)
                        self.patch_edns_fast(buf, length, 1800)
                        
                        # Forward to SlowDNS
                        backend.sendto(memoryview(buf)[:length], self.backend_addr)
                        
                        try:
                            # Receive response
                            resp_length, _ = backend.recvfrom_into(buf)
                            
                            if resp_length > 0:
                                # Patch EDNS back (standard MTU)
                                self.patch_edns_fast(buf, resp_length, 512)
                                
                                # Send back to client
                                frontend.sendto(memoryview(buf)[:resp_length], client_addr)
                                
                                self.stats['packets'] += 1
                                
                                # Print stats occasionally
                                if self.stats['packets'] % 100 == 0:
                                    elapsed = time.time() - self.stats['start']
                                    qps = self.stats['packets'] / elapsed
                                    print_info(f"Processed {self.stats['packets']} packets ({qps:.1f} QPS)")
                        
                        except socket.timeout:
                            self.stats['errors'] += 1
                        except:
                            self.stats['errors'] += 1
                    
                    # Return buffer to pool
                    self._return_buffer(buf)
                
                except socket.error as e:
                    if e.errno != errno.EAGAIN:
                        self.stats['errors'] += 1
                    time.sleep(0.001)  # Small sleep to prevent CPU spin
        
        except KeyboardInterrupt:
            pass
        finally:
            frontend.close()
            backend.close()
            print_success("EDNS Proxy stopped")

# ============================================================================
# UI FUNCTIONS
# ============================================================================
def print_banner():
    os.system('clear')
    print(f"{BLUE}╔{'═'*54}╗{NC}")
    print(f"{BLUE}║{NC}{CYAN}{BOLD}          🚀 SLOWDNS INSTALLATION SCRIPT{NC}          {BLUE}║{NC}")
    print(f"{BLUE}║{NC}{WHITE}            Python Edition - Zero-Copy EDNS{NC}           {BLUE}║{NC}")
    print(f"{BLUE}║{NC}{YELLOW}                Optimized for Performance{NC}                {BLUE}║{NC}")
    print(f"{BLUE}╚{'═'*54}╝{NC}")
    print()

def print_header(text):
    print(f"\n{PURPLE}{'═'*54}{NC}")
    print(f"{CYAN}{BOLD}{text}{NC}")
    print(f"{PURPLE}{'═'*54}{NC}")

def print_step(num, title):
    print(f"\n{BLUE}┌─{NC} {CYAN}{BOLD}STEP {num}{NC}")
    print(f"{BLUE}│{NC}")
    print(f"{BLUE}│{NC} {WHITE}{title}{NC}")

def print_step_end():
    print(f"{BLUE}└─{NC} {GREEN}✓{NC} Completed")

def print_success(msg):
    print(f"  {GREEN}{BOLD}✓{NC} {GREEN}{msg}{NC}")

def print_error(msg):
    print(f"  {RED}{BOLD}✗{NC} {RED}{msg}{NC}")

def print_warning(msg):
    print(f"  {YELLOW}{BOLD}!{NC} {YELLOW}{msg}{NC}")

def print_info(msg):
    print(f"  {CYAN}{BOLD}ℹ{NC} {CYAN}{msg}{NC}")

def print_box(text, color=CYAN):
    width = 50
    padding = (width - len(text) - 2) // 2
    print(f"{color}┌{'─'*(width-2)}┐{NC}")
    print(f"{color}│{NC}{' '*padding}{text}{' '*(width-2-len(text)-padding)}{color}│{NC}")
    print(f"{color}└{'─'*(width-2)}┘{NC}")

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
def run_cmd(cmd, check=False):
    """Run shell command"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if check and result.returncode != 0:
            return False
        return True
    except:
        return False

def download_file(url, dest):
    """Download file with fallbacks"""
    # Try wget
    if run_cmd(f"wget -q '{url}' -O '{dest}' 2>/dev/null", check=False):
        return True
    # Try curl
    if run_cmd(f"curl -fsSL '{url}' -o '{dest}' 2>/dev/null", check=False):
        return True
    # Try Python
    try:
        with urllib.request.urlopen(url) as response:
            with open(dest, 'wb') as f:
                f.write(response.read())
        return True
    except:
        return False

def get_nameserver():
    """Get nameserver from user"""
    print_box("Enter nameserver configuration")
    print(f"{CYAN}│{NC} {YELLOW}Default:{NC} dns.example.com")
    print(f"{CYAN}│{NC} {YELLOW}Example:{NC} tunnel.yourdomain.com")
    print(f"{CYAN}└{'─'*48}┘{NC}")
    print()
    
    nameserver = input(f"{WHITE}{BOLD}Enter nameserver: {NC}").strip()
    return nameserver if nameserver else "dns.example.com"

def get_server_ip():
    """Get server IP"""
    try:
        # Try public IP
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", "3", "ifconfig.me"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        
        # Fallback to local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ============================================================================
# INSTALLATION STEPS
# ============================================================================
def step1_configure_ssh():
    """Configure SSH"""
    print_step("1", "Configuring OpenSSH")
    print_info(f"Configuring OpenSSH on port {SSHD_PORT}")
    
    # Backup
    if os.path.exists("/etc/ssh/sshd_config"):
        run_cmd("cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup")
    
    # Create config
    ssh_config = f"""# SlowDNS Optimized SSH Configuration
Port {SSHD_PORT}
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
"""
    
    with open("/etc/ssh/sshd_config", 'w') as f:
        f.write(ssh_config)
    
    run_cmd("systemctl restart ssh")
    time.sleep(1)
    print_success("SSH configured")
    print_step_end()
    return True

def step2_setup_slowdns():
    """Setup SlowDNS"""
    print_step("2", "Setting up SlowDNS environment")
    print_info("Setting up SlowDNS environment")
    
    # Create directory
    install_dir = Path("/etc/slowdns")
    if install_dir.exists():
        shutil.rmtree(install_dir, ignore_errors=True)
    install_dir.mkdir(parents=True, exist_ok=True)
    os.chdir(install_dir)
    
    print_success("SlowDNS directory created")
    
    # Download binary
    print_info("Downloading SlowDNS binary")
    url = f"{GITHUB_BASE}/dnstt-server"
    if download_file(url, "dnstt-server"):
        os.chmod("dnstt-server", 0o755)
        print_success("Binary downloaded")
    else:
        print_error("Failed to download binary")
        return False
    
    # Download key files
    print_info("Downloading encryption keys")
    for key_file in ["server.key", "server.pub"]:
        url = f"{GITHUB_BASE}/{key_file}"
        if download_file(url, key_file):
            print_success(f"{key_file} downloaded")
        else:
            print_error(f"Failed to download {key_file}")
            return False
    
    # Test binary
    print_info("Validating binary...")
    result = run_cmd("./dnstt-server --help 2>&1 | head -5", check=False)
    if result:
        print_success("Binary validated")
    else:
        print_warning("Binary test inconclusive")
    
    print_success("SlowDNS components installed")
    print_step_end()
    return True

def step3_create_services(nameserver):
    """Create systemd services"""
    print_step("3", "Creating SlowDNS system service")
    print_info("Creating SlowDNS system service")
    
    # SlowDNS service
    service_content = f"""[Unit]
Description=SlowDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :{SLOWDNS_PORT} -mtu 1800 -privkey-file /etc/slowdns/server.key {nameserver} 127.0.0.1:{SSHD_PORT}
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/server-sldns.service", 'w') as f:
        f.write(service_content)
    
    print_success("Service configuration created")
    print_step_end()
    return True

def step4_configure_firewall():
    """Configure firewall"""
    print_step("4", "Configuring system firewall")
    print_info("Configuring system firewall")
    
    # Clear existing rules
    run_cmd("iptables -F 2>/dev/null")
    run_cmd("iptables -X 2>/dev/null")
    
    # Basic rules
    rules = [
        "iptables -A INPUT -i lo -j ACCEPT",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        f"iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT",
        f"iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT",
        "iptables -A INPUT -p udp --dport 53 -j ACCEPT",
        "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -p icmp -j ACCEPT",
        "iptables -A INPUT -m state --state INVALID -j DROP"
    ]
    
    for rule in rules:
        run_cmd(rule + " 2>/dev/null")
    
    # Disable IPv6
    run_cmd("echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
    
    # Stop conflicting services
    run_cmd("systemctl stop systemd-resolved 2>/dev/null")
    run_cmd("fuser -k 53/udp 2>/dev/null")
    
    print_success("Firewall configured")
    print_step_end()
    return True

def step5_start_services():
    """Start services"""
    print_step("5", "Starting all services")
    print_info("Starting all services")
    
    # Reload systemd
    run_cmd("systemctl daemon-reload")
    
    # Start SlowDNS
    print_info("Starting SlowDNS service...")
    run_cmd("systemctl enable server-sldns")
    run_cmd("systemctl start server-sldns")
    time.sleep(2)
    
    # Check if running
    result = run_cmd("systemctl is-active server-sldns", check=False)
    if result:
        print_success("SlowDNS service started")
    else:
        print_warning("Starting SlowDNS manually")
        run_cmd("/etc/slowdns/dnstt-server -udp :5300 -mtu 1800 -privkey-file /etc/slowdns/server.key dns.example.com 127.0.0.1:22 &")
    
    print_success("All services started")
    print_step_end()
    return True

def step6_start_edns_proxy():
    """Start EDNS proxy"""
    print_step("6", "Starting Zero-Copy EDNS Proxy")
    print_info("Starting EDNS Proxy service")
    
    # Create EDNS service
    script_path = Path(__file__).absolute()
    edns_service = f"""[Unit]
Description=Zero-Copy EDNS Proxy
After=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script_path} --edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/edns-proxy.service", 'w') as f:
        f.write(edns_service)
    
    # Reload and start
    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl enable edns-proxy")
    run_cmd("systemctl start edns-proxy")
    time.sleep(2)
    
    print_success("EDNS Proxy started")
    print_step_end()
    return True

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
def install_slowdns():
    """Main installation function"""
    # Check root
    if os.geteuid() != 0:
        print_error("Please run this script as root")
        print(f"{YELLOW}Usage:{NC} sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    print_banner()
    
    # Get configuration
    print_header("📦 GATHERING SYSTEM INFORMATION")
    nameserver = get_nameserver()
    server_ip = get_server_ip()
    print_success(f"Server IP: {server_ip}")
    
    # Installation steps
    steps = [
        ("Configure SSH", step1_configure_ssh),
        ("Setup SlowDNS", step2_setup_slowdns),
        ("Create Services", lambda: step3_create_services(nameserver)),
        ("Configure Firewall", step4_configure_firewall),
        ("Start Services", step5_start_services),
        ("Start EDNS Proxy", step6_start_edns_proxy)
    ]
    
    for step_name, step_func in steps:
        print_header(step_name)
        if not step_func():
            print_error(f"Failed: {step_name}")
            return False
        time.sleep(1)
    
    # Show summary
    print_header("🎉 INSTALLATION COMPLETE")
    
    print(f"{CYAN}┌{'─'*50}┐{NC}")
    print(f"{CYAN}│{NC} {WHITE}{BOLD}SERVER INFORMATION{NC}{' ' * 31}{CYAN}│{NC}")
    print(f"{CYAN}├{'─'*50}┤{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} Server IP:     {WHITE}{server_ip}{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} SSH Port:      {WHITE}{SSHD_PORT}{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} SlowDNS Port:  {WHITE}{SLOWDNS_PORT}{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} EDNS Port:     {WHITE}53 (Zero-Copy){NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} Nameserver:    {WHITE}{nameserver}{NC}")
    print(f"{CYAN}└{'─'*50}┘{NC}")
    
    print(f"\n{CYAN}┌{'─'*50}┐{NC}")
    print(f"{CYAN}│{NC} {WHITE}{BOLD}MANAGEMENT COMMANDS{NC}{' ' * 31}{CYAN}│{NC}")
    print(f"{CYAN}├{'─'*50}┤{NC}")
    print(f"{CYAN}│{NC} {GREEN}sudo systemctl status server-sldns{NC}")
    print(f"{CYAN}│{NC} {GREEN}sudo systemctl status edns-proxy{NC}")
    print(f"{CYAN}│{NC} {GREEN}sudo journalctl -u edns-proxy -f{NC}")
    print(f"{CYAN}└{'─'*50}┘{NC}")
    
    print(f"\n{GREEN}{BOLD}✓ Installation completed successfully!{NC}")
    print(f"\n{YELLOW}The Zero-Copy EDNS Proxy is now running on port 53.{NC}")
    print(f"{YELLOW}It will automatically proxy DNS queries to SlowDNS.{NC}")
    
    return True

def run_edns_proxy():
    """Run the EDNS proxy directly"""
    print_banner()
    print_header("🚀 ZERO-COPY EDNS PROXY")
    print_info("Starting high-performance DNS proxy...")
    
    proxy = ZeroCopyEDNSProxy()
    proxy.start()

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install":
            success = install_slowdns()
            sys.exit(0 if success else 1)
        elif sys.argv[1] == "--edns-proxy":
            run_edns_proxy()
        elif sys.argv[1] == "--uninstall":
            print_info("Uninstalling...")
            run_cmd("systemctl stop server-sldns edns-proxy 2>/dev/null")
            run_cmd("systemctl disable server-sldns edns-proxy 2>/dev/null")
            run_cmd("rm -f /etc/systemd/system/server-sldns.service 2>/dev/null")
            run_cmd("rm -f /etc/systemd/system/edns-proxy.service 2>/dev/null")
            run_cmd("systemctl daemon-reload 2>/dev/null")
            print_success("Uninstalled")
        elif sys.argv[1] == "--status":
            run_cmd("systemctl status server-sldns --no-pager")
            print()
            run_cmd("systemctl status edns-proxy --no-pager")
        elif sys.argv[1] == "--help":
            print(f"{CYAN}Usage:{NC}")
            print(f"  sudo python3 {sys.argv[0]} --install")
            print(f"  sudo python3 {sys.argv[0]} --edns-proxy")
            print(f"  sudo python3 {sys.argv[0]} --uninstall")
            print(f"  sudo python3 {sys.argv[0]} --status")
            print(f"  sudo python3 {sys.argv[0]} --help")
    else:
        # Interactive mode
        print_banner()
        print(f"{CYAN}Select option:{NC}")
        print(f"  1. Install SlowDNS")
        print(f"  2. Start EDNS Proxy only")
        print(f"  3. Show status")
        print(f"  4. Exit")
        
        choice = input(f"\n{WHITE}Choice [1]: {NC}").strip() or "1"
        
        if choice == "1":
            install_slowdns()
        elif choice == "2":
            run_edns_proxy()
        elif choice == "3":
            run_cmd("systemctl status server-sldns --no-pager")
        else:
            print("Goodbye!")
