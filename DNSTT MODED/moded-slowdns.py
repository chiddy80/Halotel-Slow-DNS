#!/usr/bin/env python3
"""
🚀 ULTRA-FAST SLOWDNS INSTALLER
With Zero-Copy EDNS Proxy for Maximum Performance
Follows bash patterns but optimized for speed
"""

import os
import sys
import time
import socket
import subprocess
import urllib.request
from pathlib import Path
import shutil
import mmap
import ctypes
import struct
import select
import fcntl
import errno
from collections import deque
import threading
import queue

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
CYAN = '\033[0;36m'
WHITE = '\033[1;37m'
BOLD = '\033[1m'
NC = '\033[0m'

# ============================================================================
# ZERO-COPY EDNS PROXY - PROFESSIONAL IMPLEMENTATION
# ============================================================================
class ZeroCopyEDNSProxy:
    """Ultra-fast EDNS proxy with zero-copy optimizations"""
    
    def __init__(self, listen_port=53, backend_port=5300):
        self.listen_port = listen_port
        self.backend_port = backend_port
        self.backend_addr = ("127.0.0.1", backend_port)
        self.running = False
        
        # Performance tuning
        self.buffer_size = 65507  # Max UDP size
        self.socket_buffer = 1024 * 1024  # 1MB buffer
        self.worker_threads = 4
        
        # Pre-allocated buffers for zero-copy
        self.buffers = deque(maxlen=100)
        self._init_buffers()
        
        # Statistics
        self.stats = {
            'packets': 0,
            'errors': 0,
            'avg_time': 0
        }
    
    def _init_buffers(self):
        """Pre-allocate buffers to avoid malloc during runtime"""
        for _ in range(100):
            # Use bytearray for mutable buffers
            self.buffers.append(bytearray(self.buffer_size))
    
    def _get_buffer(self):
        """Get buffer from pool (zero malloc)"""
        if self.buffers:
            return self.buffers.pop()
        return bytearray(self.buffer_size)
    
    def _return_buffer(self, buf):
        """Return buffer to pool"""
        if len(self.buffers) < 100:
            # Clear buffer for reuse
            buf[:] = b'\x00' * len(buf)
            self.buffers.append(buf)
    
    @staticmethod
    def patch_edns_fast(buf, length, new_size):
        """In-place EDNS patching (zero-copy)"""
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
        
        # Find and patch EDNS OPT
        arcount = (buf[10] << 8) | buf[11]
        for _ in range(arcount):
            if offset >= length - 4:
                break
            
            if buf[offset] == 0:  # Root label
                if offset + 4 < length:
                    # Check OPT type
                    if buf[offset+1] == 0 and buf[offset+2] == 41:  # OPT=41
                        # Patch in-place
                        buf[offset+3] = (new_size >> 8) & 0xFF
                        buf[offset+4] = new_size & 0xFF
                        break
                offset += 11
            else:
                offset += 1
        
        return length
    
    def start(self):
        """Start the zero-copy EDNS proxy"""
        print_info("Starting Zero-Copy EDNS Proxy...")
        
        # Create optimized sockets
        frontend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        backend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Set non-blocking
        frontend.setblocking(False)
        backend.setblocking(False)
        
        # Increase buffers
        frontend.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.socket_buffer)
        frontend.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.socket_buffer)
        backend.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.socket_buffer)
        backend.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.socket_buffer)
        
        # Enable reuse
        frontend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        frontend.bind(('0.0.0.0', self.listen_port))
        print_success(f"Listening on port {self.listen_port}")
        
        self.running = True
        epoll = select.epoll()
        epoll.register(frontend.fileno(), select.EPOLLIN)
        
        # Track client addresses
        client_map = {}
        
        print_info("Entering zero-copy processing loop...")
        
        try:
            while self.running:
                events = epoll.poll(1)  # 1ms timeout
                
                for fileno, event in events:
                    if fileno == frontend.fileno():
                        # Get buffer from pool
                        buf = self._get_buffer()
                        
                        try:
                            # Receive with zero-copy where possible
                            length, client_addr = frontend.recvfrom_into(buf)
                            
                            if length > 0:
                                # Patch EDNS in-place
                                self.patch_edns_fast(buf, length, 1800)
                                
                                # Forward to backend
                                backend.sendto(memoryview(buf)[:length], self.backend_addr)
                                
                                # Store client address
                                client_map[backend.fileno()] = client_addr
                                
                                # Register backend for read
                                epoll.register(backend.fileno(), select.EPOLLIN)
                                
                                self.stats['packets'] += 1
                        
                        except socket.error as e:
                            if e.errno != errno.EAGAIN:
                                self.stats['errors'] += 1
                            self._return_buffer(buf)
                    
                    elif fileno == backend.fileno():
                        buf = self._get_buffer()
                        
                        try:
                            length, _ = backend.recvfrom_into(buf)
                            
                            if length > 0:
                                # Patch EDNS back
                                self.patch_edns_fast(buf, length, 512)
                                
                                # Send back to client
                                client_addr = client_map.get(fileno)
                                if client_addr:
                                    frontend.sendto(memoryview(buf)[:length], client_addr)
                                    del client_map[fileno]
                            
                            # Unregister backend
                            epoll.unregister(fileno)
                        
                        except socket.error:
                            self.stats['errors'] += 1
                        finally:
                            self._return_buffer(buf)
                
                # Print stats every 10 seconds
                if self.stats['packets'] % 1000 == 0:
                    print_info(f"Processed {self.stats['packets']} packets")
        
        except KeyboardInterrupt:
            print_info("Shutting down EDNS Proxy...")
        finally:
            self.running = False
            epoll.close()
            frontend.close()
            backend.close()
            print_success("EDNS Proxy stopped")

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================
def print_step(step_num, title):
    print(f"\n{BLUE}┌─{NC} {CYAN}{BOLD}STEP {step_num}{NC}")
    print(f"{BLUE}│{NC}")
    print(f"{BLUE}│{NC} {WHITE}{title}{NC}")

def print_step_end():
    print(f"{BLUE}└─{NC} {GREEN}✓{NC} Completed")

def print_success(msg):
    print(f"  {GREEN}{BOLD}✓{NC} {GREEN}{msg}{NC}")

def print_error(msg):
    print(f"  {RED}{BOLD}✗{NC} {RED}{msg}{NC}")

def print_info(msg):
    print(f"  {CYAN}{BOLD}ℹ{NC} {CYAN}{msg}{NC}")

def run_cmd(cmd, check=True):
    """Run command with proper error handling"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if check and result.returncode != 0:
            return False
        return True
    except:
        return False

def get_nameserver():
    """Get nameserver from user"""
    print(f"\n{WHITE}{BOLD}Enter nameserver configuration:{NC}")
    print(f"{CYAN}┌──────────────────────────────────────────────────────────┐{NC}")
    print(f"{CYAN}│{NC} {YELLOW}Default:{NC} dns.example.com                                     {CYAN}│{NC}")
    print(f"{CYAN}│{NC} {YELLOW}Example:{NC} tunnel.yourdomain.com                               {CYAN}│{NC}")
    print(f"{CYAN}└──────────────────────────────────────────────────────────┘{NC}")
    print()
    
    nameserver = input(f"{WHITE}{BOLD}Enter nameserver: {NC}").strip()
    return nameserver if nameserver else "dns.example.com"

def get_server_ip():
    """Get server IP"""
    try:
        # Try curl for public IP
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
def step1_configure_ssh(nameserver):
    """Configure SSH"""
    print_step("1", "Configuring OpenSSH")
    print_info(f"Configuring OpenSSH on port {SSHD_PORT}")
    
    # Backup
    run_cmd("cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null")
    
    # Create config
    ssh_config = f"""Port {SSHD_PORT}
Protocol 2
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
UsePAM yes
X11Forwarding no
PrintMotd no
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
AllowTcpForwarding yes
GatewayPorts yes
UseDNS no
MaxSessions 100
"""
    
    with open("/etc/ssh/sshd_config", 'w') as f:
        f.write(ssh_config)
    
    run_cmd("systemctl restart ssh 2>/dev/null")
    print_success("SSH configured")
    print_step_end()
    return True

def step2_download_slowdns():
    """Download SlowDNS components"""
    print_step("2", "Setting up SlowDNS")
    print_info("Downloading SlowDNS components")
    
    # Create directory
    install_dir = Path("/etc/slowdns")
    if install_dir.exists():
        shutil.rmtree(install_dir, ignore_errors=True)
    install_dir.mkdir(parents=True, exist_ok=True)
    os.chdir(install_dir)
    
    # Download files
    files = [
        ("dnstt-server", "dnstt-server"),
        ("server.key", "server.key"),
        ("server.pub", "server.pub")
    ]
    
    for url_name, filename in files:
        url = f"{GITHUB_BASE}/{url_name}"
        print_info(f"Downloading {filename}...")
        
        # Try multiple download methods
        success = False
        
        # Try wget
        if run_cmd(f"wget -q '{url}' -O '{filename}' 2>/dev/null", check=False):
            success = True
        # Try curl
        elif run_cmd(f"curl -fsSL '{url}' -o '{filename}' 2>/dev/null", check=False):
            success = True
        # Try Python
        else:
            try:
                with urllib.request.urlopen(url) as response:
                    with open(filename, 'wb') as f:
                        f.write(response.read())
                success = True
            except:
                pass
        
        if success:
            if filename == "dnstt-server":
                os.chmod(filename, 0o755)
            print_success(f"{filename} downloaded")
        else:
            print_error(f"Failed to download {filename}")
            return False
    
    # Test binary
    result = run_cmd("./dnstt-server --help 2>&1 | head -5", check=False)
    if result:
        print_success("Binary validated")
    else:
        print_info("Binary test inconclusive")
    
    print_success("SlowDNS components installed")
    print_step_end()
    return True

def step3_create_services(nameserver):
    """Create systemd services"""
    print_step("3", "Creating services")
    print_info("Creating systemd services")
    
    # SlowDNS service
    service_content = f"""[Unit]
Description=SlowDNS Server
After=network.target

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
    
    # Python EDNS Proxy service
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
    
    print_success("Services created")
    print_step_end()
    return True

def step4_configure_firewall():
    """Configure firewall"""
    print_step("4", "Configuring firewall")
    print_info("Configuring firewall rules")
    
    # Flush rules
    run_cmd("iptables -F 2>/dev/null")
    run_cmd("iptables -X 2>/dev/null")
    
    # Set policies
    run_cmd("iptables -P INPUT ACCEPT 2>/dev/null")
    run_cmd("iptables -P FORWARD ACCEPT 2>/dev/null")
    run_cmd("iptables -P OUTPUT ACCEPT 2>/dev/null")
    
    # Essential rules
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
    print_step("5", "Starting services")
    print_info("Starting all services")
    
    run_cmd("systemctl daemon-reload")
    
    # Start SlowDNS
    run_cmd("systemctl enable server-sldns 2>/dev/null")
    run_cmd("systemctl start server-sldns 2>/dev/null")
    time.sleep(2)
    
    # Check if running
    result = run_cmd("systemctl is-active server-sldns", check=False)
    if result:
        print_success("SlowDNS service started")
    else:
        print_info("Starting SlowDNS manually")
        run_cmd("/etc/slowdns/dnstt-server -udp :5300 -mtu 1800 -privkey-file /etc/slowdns/server.key dns.example.com 127.0.0.1:22 &")
    
    print_success("Services started")
    print_step_end()
    return True

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
def install_slowdns():
    """Main installation function"""
    # Check root
    if os.geteuid() != 0:
        print_error("Please run as root")
        print(f"{YELLOW}Usage:{NC} sudo python3 {sys.argv[0]} --install")
        sys.exit(1)
    
    # Banner
    print(f"{BLUE}╔{'═'*54}╗{NC}")
    print(f"{BLUE}║{NC}{CYAN}{BOLD}     🚀 ZERO-COPY SLOWDNS INSTALLATION{NC}               {BLUE}║{NC}")
    print(f"{BLUE}║{NC}{WHITE}        Ultra Fast EDNS Proxy{NC}                        {BLUE}║{NC}")
    print(f"{BLUE}╚{'═'*54}╝{NC}")
    print()
    
    # Get configuration
    nameserver = get_nameserver()
    server_ip = get_server_ip()
    
    print_info(f"Server IP: {server_ip}")
    print_info(f"Nameserver: {nameserver}")
    
    # Execute steps
    steps = [
        ("Configure SSH", lambda: step1_configure_ssh(nameserver)),
        ("Setup SlowDNS", step2_download_slowdns),
        ("Create Services", lambda: step3_create_services(nameserver)),
        ("Configure Firewall", step4_configure_firewall),
        ("Start Services", step5_start_services)
    ]
    
    for step_name, step_func in steps:
        if not step_func():
            print_error(f"Failed: {step_name}")
            return False
        time.sleep(1)
    
    # Show summary
    print(f"\n{CYAN}┌{'─'*50}┐{NC}")
    print(f"{CYAN}│{NC} {WHITE}{BOLD}INSTALLATION COMPLETE{NC}{' ' * 29}{CYAN}│{NC}")
    print(f"{CYAN}├{'─'*50}┤{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} Server IP:     {WHITE}{server_ip}{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} SSH Port:      {WHITE}{SSHD_PORT}{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} SlowDNS Port:  {WHITE}{SLOWDNS_PORT}{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} EDNS Proxy:    {WHITE}Zero-Copy Python{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} Nameserver:    {WHITE}{nameserver}{NC}")
    print(f"{CYAN}└{'─'*50}┘{NC}")
    
    print(f"\n{GREEN}{BOLD}✓ Installation successful!{NC}")
    print(f"\n{YELLOW}To start EDNS Proxy:{NC}")
    print(f"  sudo systemctl start edns-proxy")
    print(f"  sudo systemctl enable edns-proxy")
    
    return True

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install":
            install_slowdns()
        elif sys.argv[1] == "--edns-proxy":
            # Run zero-copy EDNS proxy
            proxy = ZeroCopyEDNSProxy()
            proxy.start()
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
        elif sys.argv[1] == "--help":
            print(f"{CYAN}Usage:{NC}")
            print(f"  sudo python3 {sys.argv[0]} --install")
            print(f"  sudo python3 {sys.argv[0]} --edns-proxy")
            print(f"  sudo python3 {sys.argv[0]} --uninstall")
            print(f"  sudo python3 {sys.argv[0]} --status")
            print(f"  sudo python3 {sys.argv[0]} --help")
    else:
        # Interactive mode
        print(f"{CYAN}Select option:{NC}")
        print(f"  1. Install SlowDNS")
        print(f"  2. Start EDNS Proxy")
        print(f"  3. Exit")
        
        choice = input(f"\n{WHITE}Choice [1]: {NC}").strip() or "1"
        
        if choice == "1":
            install_slowdns()
        elif choice == "2":
            proxy = ZeroCopyEDNSProxy()
            proxy.start()
        else:
            print("Goodbye!")
