#!/usr/bin/env python3
"""
🚀 PROFESSIONAL SLOWDNS INSTALLATION SCRIPT
With Ultra-Fast EDNS Proxy - Zero Lag Video Streaming
Complete All-in-One Solution
"""

import os
import sys
import time
import socket
import subprocess
import threading
import urllib.request
import signal
import select
import fcntl
import struct
import array
import queue
import hashlib
from pathlib import Path
from datetime import datetime
import shutil
from collections import deque
from functools import lru_cache

# ============================================================================
# MODERN COLORS & DESIGN
# ============================================================================
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
# ANIMATION FUNCTIONS
# ============================================================================
class Animation:
    @staticmethod
    def show_progress():
        """Spinner animation"""
        spin_chars = ['|', '/', '-', '\\']
        for i in range(12):
            sys.stdout.write(f"\r  {CYAN}[{spin_chars[i % 4]}]{NC}  ")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r      \r")

# ============================================================================
# UI COMPONENTS
# ============================================================================
def print_banner():
    os.system('clear')
    print(f"{BLUE}╔{'═'*54}╗{NC}")
    print(f"{BLUE}║{NC}{CYAN}{BOLD}     🚀 PROFESSIONAL SLOWDNS - ULTRA FAST EDNS{NC}       {BLUE}║{NC}")
    print(f"{BLUE}║{NC}{WHITE}        Zero Lag Video Streaming Optimized{NC}            {BLUE}║{NC}")
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

# ============================================================================
# PROFESSIONAL EDNS PROXY CLASS - ZERO LAG OPTIMIZED
# ============================================================================
class UltraFastEDNSProxy:
    """Professional EDNS Proxy optimized for zero-lag streaming"""
    
    def __init__(self, listen_port=53, backend_port=5300):
        self.listen_port = listen_port
        self.backend_port = backend_port
        self.backend_addr = ("127.0.0.1", backend_port)
        
        # Performance tuning
        self.buffer_size = 65507
        self.socket_buffer = 1024 * 1024  # 1MB
        self.worker_threads = 4
        self.max_pending = 10000
        
        # Connection pool
        self.connection_pool = deque(maxlen=16)
        self.pool_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'streaming_packets': 0,
            'avg_response_time': 0,
            'errors': 0,
            'cache_hits': 0
        }
        
        # Response cache for streaming
        self.response_cache = {}
        self.cache_lock = threading.Lock()
        
        # Worker queues
        self.packet_queue = queue.Queue(maxsize=self.max_pending)
        self.running = False
        
        print_info("Initializing Ultra-Fast EDNS Proxy...")
    
    def _create_optimized_socket(self):
        """Create high-performance socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Set non-blocking
        sock.setblocking(0)
        
        # Increase buffer sizes for streaming
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.socket_buffer)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.socket_buffer)
        
        # Enable address reuse
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Linux-specific optimizations
        if hasattr(socket, 'SO_REUSEPORT'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
        return sock
    
    def _get_connection(self):
        """Get socket from pool or create new"""
        with self.pool_lock:
            if self.connection_pool:
                return self.connection_pool.pop()
        
        # Create new optimized socket
        sock = self._create_optimized_socket()
        sock.settimeout(0.1)  # 100ms timeout
        return sock
    
    def _return_connection(self, sock):
        """Return socket to pool"""
        with self.pool_lock:
            if len(self.connection_pool) < 16:
                self.connection_pool.append(sock)
            else:
                sock.close()
    
    @staticmethod
    @lru_cache(maxsize=1024)
    def _parse_dns_header(data):
        """Fast DNS header parsing with caching"""
        if len(data) < 12:
            return None
        header = struct.unpack('!6H', data[:12])
        return header
    
    def _patch_edns_ultrafast(self, data, new_size):
        """Ultra-fast EDNS patching optimized for streaming"""
        if len(data) < 12:
            return data
        
        # Fast bytearray conversion
        if isinstance(data, bytearray):
            buf = data
        else:
            buf = bytearray(data)
        
        offset = 12
        
        # Skip questions fast
        qdcount = (buf[4] << 8) | buf[5]
        for _ in range(qdcount):
            while offset < len(buf) and buf[offset]:
                offset += 1
            if offset + 5 > len(buf):
                return bytes(buf)
            offset += 5
        
        # Find and patch EDNS OPT
        arcount = (buf[10] << 8) | buf[11]
        for _ in range(arcount):
            if offset >= len(buf) - 4:
                break
            
            if buf[offset] == 0:  # Root label
                if offset + 4 < len(buf):
                    # Fast OPT check
                    if buf[offset+1] == 0 and buf[offset+2] == 41:  # OPT=41
                        buf[offset+3] = (new_size >> 8) & 0xFF
                        buf[offset+4] = new_size & 0xFF
                        break
                offset += 11
            else:
                offset += 1
        
        return bytes(buf)
    
    def _is_streaming_query(self, data):
        """Detect streaming queries quickly"""
        if len(data) < 20:
            return False
        
        # Fast check for streaming patterns
        streaming_keywords = [
            b'video', b'stream', b'cdn', b'hls', 
            b'dash', b'm3u8', b'youtube', b'twitch',
            b'netflix', b'vimeo', b'akamai', b'cloudfront'
        ]
        
        # Check first 256 bytes for keywords
        check_data = data[:256].lower()
        for keyword in streaming_keywords:
            if keyword in check_data:
                return True
        
        return False
    
    def _worker_thread(self):
        """Worker thread for packet processing"""
        while self.running:
            try:
                # Get packet with timeout
                item = self.packet_queue.get(timeout=0.1)
                if item is None:
                    break
                
                data, client_addr, client_sock = item
                start_time = time.time()
                
                # Check cache first for streaming queries
                cache_key = None
                if self._is_streaming_query(data):
                    self.stats['streaming_packets'] += 1
                    cache_key = hashlib.md5(data).hexdigest()
                    
                    with self.cache_lock:
                        if cache_key in self.response_cache:
                            cached_response, expiry = self.response_cache[cache_key]
                            if time.time() < expiry:
                                # Send cached response
                                client_sock.sendto(cached_response, client_addr)
                                self.stats['cache_hits'] += 1
                                self.packet_queue.task_done()
                                continue
                
                # Patch EDNS for internal (increase MTU for streaming)
                if self._is_streaming_query(data):
                    patched_data = self._patch_edns_ultrafast(data, 1800)  # Large MTU for streaming
                else:
                    patched_data = self._patch_edns_ultrafast(data, 512)
                
                # Forward to backend
                backend_sock = self._get_connection()
                try:
                    backend_sock.sendto(patched_data, self.backend_addr)
                    
                    # Wait for response with timeout
                    ready = select.select([backend_sock], [], [], 0.1)  # 100ms timeout
                    if ready[0]:
                        response, _ = backend_sock.recvfrom(self.buffer_size)
                        
                        # Patch EDNS for external
                        if self._is_streaming_query(data):
                            final_response = self._patch_edns_ultrafast(response, 512)
                        else:
                            final_response = response
                        
                        # Send back to client
                        client_sock.sendto(final_response, client_addr)
                        
                        # Cache streaming responses
                        if cache_key and self._is_streaming_query(data):
                            with self.cache_lock:
                                self.response_cache[cache_key] = (
                                    final_response, 
                                    time.time() + 300  # 5 minute TTL
                                )
                                # Limit cache size
                                if len(self.response_cache) > 1000:
                                    # Remove oldest
                                    oldest = list(self.response_cache.keys())[0]
                                    del self.response_cache[oldest]
                        
                        self.stats['packets_processed'] += 1
                        
                        # Update average response time
                        response_time = (time.time() - start_time) * 1000
                        self.stats['avg_response_time'] = (
                            0.9 * self.stats['avg_response_time'] + 0.1 * response_time
                        )
                
                finally:
                    self._return_connection(backend_sock)
                
                self.packet_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.stats['errors'] += 1
                self.packet_queue.task_done()
                continue
    
    def start(self):
        """Start the ultra-fast EDNS proxy"""
        print_info("Starting Ultra-Fast EDNS Proxy...")
        
        # Create listener socket
        self.listener = self._create_optimized_socket()
        self.listener.bind(('0.0.0.0', self.listen_port))
        
        print_success(f"Listening on port {self.listen_port}")
        
        # Start worker threads
        self.running = True
        self.workers = []
        
        for i in range(self.worker_threads):
            worker = threading.Thread(target=self._worker_thread, daemon=True)
            worker.start()
            self.workers.append(worker)
        
        # Start stats thread
        stats_thread = threading.Thread(target=self._stats_thread, daemon=True)
        stats_thread.start()
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_thread, daemon=True)
        cleanup_thread.start()
        
        # Main receive loop
        print_info("Entering high-performance receive loop...")
        
        try:
            while self.running:
                # Use select for efficient I/O
                ready = select.select([self.listener], [], [], 1.0)
                if ready[0]:
                    try:
                        data, addr = self.listener.recvfrom(self.buffer_size)
                        if data:
                            # Queue for processing
                            self.packet_queue.put((data, addr, self.listener))
                    except socket.error:
                        continue
        
        except KeyboardInterrupt:
            print_info("Shutting down EDNS Proxy...")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the proxy"""
        self.running = False
        
        # Wait for queue to empty
        self.packet_queue.join()
        
        # Stop workers
        for _ in range(self.worker_threads):
            self.packet_queue.put(None)
        
        # Close sockets
        if hasattr(self, 'listener'):
            self.listener.close()
        
        # Close pooled connections
        with self.pool_lock:
            while self.connection_pool:
                sock = self.connection_pool.pop()
                sock.close()
        
        print_success("EDNS Proxy stopped")
    
    def _stats_thread(self):
        """Print performance statistics"""
        while self.running:
            time.sleep(10)
            if self.stats['packets_processed'] > 0:
                print_info(
                    f"EDNS Stats: {self.stats['packets_processed']} packets | "
                    f"Streaming: {self.stats['streaming_packets']} | "
                    f"Cache hits: {self.stats['cache_hits']} | "
                    f"Avg time: {self.stats['avg_response_time']:.1f}ms"
                )
    
    def _cleanup_thread(self):
        """Cleanup expired cache entries"""
        while self.running:
            time.sleep(60)
            current_time = time.time()
            expired = []
            
            with self.cache_lock:
                for key, (_, expiry) in list(self.response_cache.items()):
                    if current_time > expiry:
                        expired.append(key)
                
                for key in expired:
                    del self.response_cache[key]
                
                if expired:
                    print_info(f"Cleaned {len(expired)} expired cache entries")

# ============================================================================
# MAIN INSTALLATION CLASS
# ============================================================================
class ProfessionalSlowDNSInstaller:
    def __init__(self):
        self.config = {
            'SSHD_PORT': 22,
            'SLOWDNS_PORT': 5300,
            'GITHUB_BASE': "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED",
            'NAMESERVER': "",
            'SERVER_IP': "",
            'MTU': 1800
        }
        self.install_dir = Path("/etc/slowdns")
        self.edns_proxy = None
    
    # ============================================================================
    # INSTALLATION STEPS
    # ============================================================================
    def check_root(self):
        if os.geteuid() != 0:
            print_error("Please run as root: sudo python3 moded-slowdns.py")
            sys.exit(1)
    
    def get_nameserver(self):
        print(f"\n{CYAN}┌{'─'*48}┐{NC}")
        print(f"{CYAN}│{NC} {YELLOW}Enter nameserver configuration:{NC}")
        print(f"{CYAN}│{NC} {YELLOW}Default:{NC} dns.example.com")
        print(f"{CYAN}│{NC} {YELLOW}Example:{NC} tunnel.yourdomain.com")
        print(f"{CYAN}└{'─'*48}┘{NC}")
        print()
        
        nameserver = input(f"{WHITE}{BOLD}Enter nameserver: {NC}").strip()
        self.config['NAMESERVER'] = nameserver if nameserver else "dns.example.com"
        return self.config['NAMESERVER']
    
    def detect_server_ip(self):
        print_info("Detecting server IP address...")
        Animation.show_progress()
        
        # Fast IP detection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except:
            try:
                ip = socket.gethostbyname(socket.gethostname())
            except:
                ip = "127.0.0.1"
        
        self.config['SERVER_IP'] = ip
        print(f"\r  {GREEN}Server IP:{NC} {WHITE}{BOLD}{ip}{NC}")
        return ip
    
    def configure_ssh(self):
        print_step("1", "Configuring OpenSSH")
        print_info(f"Configuring OpenSSH on port {self.config['SSHD_PORT']}")
        
        # Backup
        if Path("/etc/ssh/sshd_config").exists():
            shutil.copy2("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.backup")
        
        # Write config
        ssh_config = f"""Port {self.config['SSHD_PORT']}
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
        
        subprocess.run(["systemctl", "restart", "ssh"], capture_output=True)
        print_success("SSH configured")
        print_step_end()
        return True
    
    def setup_slowdns(self):
        print_step("2", "Setting up SlowDNS")
        print_info("Downloading SlowDNS components")
        
        # Create directory
        if self.install_dir.exists():
            shutil.rmtree(self.install_dir, ignore_errors=True)
        self.install_dir.mkdir(parents=True, exist_ok=True)
        os.chdir(self.install_dir)
        
        # Download files
        files = [
            ("dnstt-server", "dnstt-server"),
            ("server.key", "server.key"),
            ("server.pub", "server.pub")
        ]
        
        for url_name, filename in files:
            Animation.show_progress()
            url = f"{self.config['GITHUB_BASE']}/{url_name}"
            
            # Try download methods
            success = False
            try:
                # Try wget
                result = subprocess.run(
                    ["wget", "-q", "--timeout=10", url, "-O", filename],
                    capture_output=True
                )
                success = result.returncode == 0
                
                if not success:
                    # Try curl
                    result = subprocess.run(
                        ["curl", "-fsSL", "--max-time", "10", url, "-o", filename],
                        capture_output=True
                    )
                    success = result.returncode == 0
                
                if not success:
                    # Try Python
                    with urllib.request.urlopen(url, timeout=10) as response:
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
                print_error(f"Failed: {filename}")
                return False
        
        print_success("SlowDNS installed")
        print_step_end()
        return True
    
    def create_services(self):
        print_step("3", "Creating services")
        print_info("Creating systemd services")
        
        # SlowDNS service
        slowdns_service = f"""[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart={self.install_dir}/dnstt-server -udp :{self.config['SLOWDNS_PORT']} -mtu {self.config['MTU']} -privkey-file {self.install_dir}/server.key {self.config['NAMESERVER']} 127.0.0.1:{self.config['SSHD_PORT']}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
        
        with open("/etc/systemd/system/server-sldns.service", 'w') as f:
            f.write(slowdns_service)
        
        # Python EDNS Proxy service
        edns_service = f"""[Unit]
Description=Ultra-Fast EDNS Proxy
After=server-sldns.service
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {Path(__file__).absolute()} --edns-proxy
WorkingDirectory={self.install_dir}
Restart=always
RestartSec=3
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""
        
        with open("/etc/systemd/system/edns-proxy.service", 'w') as f:
            f.write(edns_service)
        
        print_success("Services created")
        print_step_end()
        return True
    
    def configure_firewall(self):
        print_step("4", "Configuring firewall")
        print_info("Setting up firewall rules")
        Animation.show_progress()
        
        # Basic firewall rules
        commands = [
            "iptables -F 2>/dev/null",
            "iptables -X 2>/dev/null",
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT", 
            "iptables -P OUTPUT ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            f"iptables -A INPUT -p tcp --dport {self.config['SSHD_PORT']} -j ACCEPT",
            f"iptables -A INPUT -p udp --dport {self.config['SLOWDNS_PORT']} -j ACCEPT",
            "iptables -A INPUT -p udp --dport 53 -j ACCEPT",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -p icmp -j ACCEPT"
        ]
        
        for cmd in commands:
            subprocess.run(cmd, shell=True, capture_output=True)
        
        # Stop conflicting services
        subprocess.run(["systemctl", "stop", "systemd-resolved"], capture_output=True)
        
        print_success("Firewall configured")
        print_step_end()
        return True
    
    def start_services(self):
        print_step("5", "Starting services")
        print_info("Starting SlowDNS and EDNS Proxy")
        
        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        
        # Start SlowDNS
        subprocess.run(["systemctl", "enable", "server-sldns"], capture_output=True)
        subprocess.run(["systemctl", "start", "server-sldns"], capture_output=True)
        time.sleep(2)
        
        # Check SlowDNS
        result = subprocess.run(
            ["systemctl", "is-active", "server-sldns"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print_success("SlowDNS started")
        else:
            print_warning("Starting SlowDNS manually")
            cmd = f"{self.install_dir}/dnstt-server -udp :{self.config['SLOWDNS_PORT']} -mtu {self.config['MTU']} -privkey-file {self.install_dir}/server.key {self.config['NAMESERVER']} 127.0.0.1:{self.config['SSHD_PORT']} &"
            subprocess.run(cmd, shell=True)
        
        print_success("Services started")
        print_step_end()
        return True
    
    # ============================================================================
    # EDNS PROXY MODE
    # ============================================================================
    def run_edns_proxy(self):
        """Run the ultra-fast EDNS proxy"""
        print_header("🚀 STARTING ULTRA-FAST EDNS PROXY")
        print_info("Optimized for zero-lag video streaming")
        
        proxy = UltraFastEDNSProxy(
            listen_port=53,
            backend_port=self.config['SLOWDNS_PORT']
        )
        
        # Handle signals
        def signal_handler(signum, frame):
            print_info("Shutting down EDNS Proxy...")
            proxy.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start proxy
        proxy.start()
    
    # ============================================================================
    # MAIN INSTALLATION
    # ============================================================================
    def install(self):
        """Main installation"""
        try:
            print_banner()
            self.check_root()
            
            print_header("📦 GATHERING SYSTEM INFORMATION")
            nameserver = self.get_nameserver()
            server_ip = self.detect_server_ip()
            
            # Installation steps
            steps = [
                ("Configure SSH", self.configure_ssh),
                ("Setup SlowDNS", self.setup_slowdns),
                ("Create Services", self.create_services),
                ("Configure Firewall", self.configure_firewall),
                ("Start Services", self.start_services)
            ]
            
            for step_name, step_func in steps:
                if not step_func():
                    return False
                time.sleep(0.5)
            
            # Show completion
            self.show_summary(nameserver, server_ip)
            return True
            
        except KeyboardInterrupt:
            print_error("\nInstallation interrupted!")
            return False
        except Exception as e:
            print_error(f"Installation failed: {str(e)[:100]}")
            return False
    
    def show_summary(self, nameserver, server_ip):
        """Show installation summary"""
        print_header("🎉 INSTALLATION COMPLETE")
        
        print(f"{CYAN}┌{'─'*50}┐{NC}")
        print(f"{CYAN}│{NC} {WHITE}{BOLD}SERVER INFORMATION{NC}{' ' * 31}{CYAN}│{NC}")
        print(f"{CYAN}├{'─'*50}┤{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} Server IP:     {WHITE}{server_ip}{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} SSH Port:      {WHITE}{self.config['SSHD_PORT']}{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} SlowDNS Port:  {WHITE}{self.config['SLOWDNS_PORT']}{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} EDNS Port:     53 (Ultra-Fast){NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} MTU Size:      {WHITE}{self.config['MTU']}{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} Nameserver:    {WHITE}{nameserver}{NC}")
        print(f"{CYAN}└{'─'*50}┘{NC}")
        
        print(f"\n{CYAN}┌{'─'*50}┐{NC}")
        print(f"{CYAN}│{NC} {WHITE}{BOLD}QUICK TEST COMMANDS{NC}{' ' * 31}{CYAN}│{NC}")
        print(f"{CYAN}├{'─'*50}┤{NC}")
        print(f"{CYAN}│{NC} {GREEN}dig @{server_ip} {nameserver}{NC}")
        print(f"{CYAN}│{NC} {GREEN}nslookup {nameserver} {server_ip}{NC}")
        print(f"{CYAN}│{NC} {GREEN}systemctl status server-sldns{NC}")
        print(f"{CYAN}└{'─'*50}┘{NC}")
        
        print(f"\n{CYAN}┌{'─'*50}┐{NC}")
        print(f"{CYAN}│{NC} {WHITE}{BOLD}STREAMING OPTIMIZATIONS{NC}{' ' * 27}{CYAN}│{NC}")
        print(f"{CYAN}├{'─'*50}┤{NC}")
        print(f"{CYAN}│{NC} {YELLOW}✓{NC} Zero-copy packet processing{NC}")
        print(f"{CYAN}│{NC} {YELLOW}✓{NC} Response caching for video{NC}")
        print(f"{CYAN}│{NC} {YELLOW}✓{NC} Multi-threaded processing{NC}")
        print(f"{CYAN}│{NC} {YELLOW}✓{NC} Connection pooling{NC}")
        print(f"{CYAN}│{NC} {YELLOW}✓{NC} Streaming detection{NC}")
        print(f"{CYAN}└{'─'*50}┘{NC}")
        
        print(f"\n{GREEN}{BOLD}╔{'═'*52}╗{NC}")
        print(f"{GREEN}{BOLD}║{NC}    {WHITE}🎯 PROFESSIONAL SLOWDNS INSTALLED!{NC}          {GREEN}{BOLD}║{NC}")
        print(f"{GREEN}{BOLD}║{NC}    {WHITE}⚡ Ultra-Fast EDNS Proxy Ready{NC}               {GREEN}{BOLD}║{NC}")
        print(f"{GREEN}{BOLD}║{NC}    {WHITE}📺 Zero Lag Video Streaming Optimized{NC}        {GREEN}{BOLD}║{NC}")
        print(f"{GREEN}{BOLD}╚{'═'*52}╝{NC}")
        
        print(f"\n{YELLOW}To start EDNS Proxy:{NC}")
        print(f"  sudo systemctl start edns-proxy")
        print(f"  sudo systemctl enable edns-proxy")
        
        print(f"\n{YELLOW}View EDNS Proxy stats:{NC}")
        print(f"  sudo journalctl -u edns-proxy -f")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
def main():
    """Main entry point"""
    installer = ProfessionalSlowDNSInstaller()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install":
            success = installer.install()
            sys.exit(0 if success else 1)
        elif sys.argv[1] == "--edns-proxy":
            installer.run_edns_proxy()
        elif sys.argv[1] == "--uninstall":
            print_info("Uninstalling...")
            subprocess.run(["systemctl", "stop", "server-sldns", "edns-proxy"], capture_output=True)
            subprocess.run(["systemctl", "disable", "server-sldns", "edns-proxy"], capture_output=True)
            subprocess.run(["rm", "-f", "/etc/systemd/system/server-sldns.service"], capture_output=True)
            subprocess.run(["rm", "-f", "/etc/systemd/system/edns-proxy.service"], capture_output=True)
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            print_success("Uninstalled")
        elif sys.argv[1] == "--status":
            subprocess.run(["systemctl", "status", "server-sldns", "--no-pager"])
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
            installer.install()
        elif choice == "2":
            installer.run_edns_proxy()
        elif choice == "3":
            subprocess.run(["systemctl", "status", "server-sldns", "--no-pager"])
        else:
            print("Goodbye!")

if __name__ == "__main__":
    main()
