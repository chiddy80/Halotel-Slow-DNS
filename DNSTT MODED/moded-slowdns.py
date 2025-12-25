#!/usr/bin/env python3
"""
ULTRA-FAST SLOWDNS + EDNS PROXY INSTALLER
Complete optimized stack with high-performance EDNS proxy
"""

import os
import sys
import time
import socket
import struct
import threading
import queue
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Tuple

# ================= CONFIGURATION =================
SSHD_PORT = 22
SLOWDNS_PORT = 5300
EDNS_LISTEN_PORT = 53

# Performance settings
EXTERNAL_EDNS_SIZE = 512
INTERNAL_EDNS_SIZE = 1232
MAX_WORKERS = max(os.cpu_count() or 4, 4)
SOCKET_POOL_SIZE = 8
REQUEST_TIMEOUT = 2.0

# GitHub URLs
SERVER_KEY_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
SERVER_PUB_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
SERVER_BIN_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"

# Directories
SLOWDNS_DIR = "/etc/slowdns"
SLOWDNS_BIN = f"{SLOWDNS_DIR}/dnstt-server"
EDNS_PROXY_PATH = "/usr/local/bin/edns-proxy.py"

# ================= PERFORMANCE EDNS PROXY =================
EDNS_PROXY_CODE = '''#!/usr/bin/env python3
"""
HIGH-PERFORMANCE EDNS PROXY
- Connection pooling (reuses sockets)
- Multi-threaded processing
- Fast EDNS patching
- Optimized socket buffers
"""

import socket
import struct
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Tuple

# Configuration
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 5300
EXTERNAL_EDNS_SIZE = 512
INTERNAL_EDNS_SIZE = 1232

# Performance tuning
MAX_WORKERS = 4
SOCKET_POOL_SIZE = 8
REQUEST_TIMEOUT = 2.0
BUFFER_SIZE = 4096

# Connection pool for upstream sockets
class SocketPool:
    def __init__(self, size: int):
        self.pool = queue.Queue(maxsize=size)
        for _ in range(size):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(REQUEST_TIMEOUT)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            self.pool.put(sock)
    
    def get_socket(self):
        try:
            return self.pool.get(timeout=1.0)
        except queue.Empty:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(REQUEST_TIMEOUT)
            return sock
    
    def return_socket(self, sock):
        if self.pool.full():
            sock.close()
        else:
            self.pool.put(sock)

socket_pool = SocketPool(SOCKET_POOL_SIZE)

# Ultra-fast EDNS patching
def patch_edns_udp_size_fast(data: bytes, new_size: int) -> bytes:
    """Fast EDNS patching without full DNS parsing"""
    if len(data) < 12:
        return data
    
    try:
        # Quick header parse
        qdcount = struct.unpack("!H", data[4:6])[0]
        arcount = struct.unpack("!H", data[10:12])[0]
        
        if arcount == 0:
            return data
        
        offset = 12
        
        # Skip questions
        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                if data[offset] & 0xC0:
                    offset += 2
                    break
                offset += data[offset] + 1
            if offset >= len(data) - 4:
                return data
            offset += 5
        
        # Scan for OPT RR (type 41)
        search_pos = offset
        for _ in range(arcount):
            if search_pos >= len(data) - 4:
                break
            
            if search_pos + 2 <= len(data):
                rr_type = struct.unpack("!H", data[search_pos:search_pos+2])[0]
                if rr_type == 41:
                    if search_pos + 4 <= len(data):
                        new_data = bytearray(data)
                        new_data[search_pos+2:search_pos+4] = struct.pack("!H", new_size)
                        return bytes(new_data)
            
            search_pos += 12
        
        return data
    except:
        return data

def process_request(server_sock: socket.socket, data: bytes, client_addr: Tuple[str, int]):
    """Process single DNS request"""
    upstream_sock = None
    
    try:
        upstream_sock = socket_pool.get_socket()
        upstream_data = patch_edns_udp_size_fast(data, INTERNAL_EDNS_SIZE)
        upstream_sock.sendto(upstream_data, (UPSTREAM_HOST, UPSTREAM_PORT))
        
        try:
            resp, _ = upstream_sock.recvfrom(BUFFER_SIZE)
            resp_patched = patch_edns_udp_size_fast(resp, EXTERNAL_EDNS_SIZE)
            server_sock.sendto(resp_patched, client_addr)
        except socket.timeout:
            pass
            
    except Exception:
        pass
    finally:
        if upstream_sock:
            socket_pool.return_socket(upstream_sock)

def main():
    """Main proxy server"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    
    print(f"[EDNS Proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[EDNS Proxy] Upstream: {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    print(f"[EDNS Proxy] EDNS: {EXTERNAL_EDNS_SIZE} → {INTERNAL_EDNS_SIZE}")
    
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    request_count = 0
    last_report = time.time()
    
    try:
        while True:
            data, client_addr = server_sock.recvfrom(BUFFER_SIZE)
            executor.submit(process_request, server_sock, data, client_addr)
            
            request_count += 1
            current_time = time.time()
            if current_time - last_report > 10:
                print(f"[EDNS Proxy] Processed {request_count} requests")
                request_count = 0
                last_report = current_time
                
    except KeyboardInterrupt:
        print("\n[EDNS Proxy] Shutting down...")
    finally:
        executor.shutdown(wait=True)
        server_sock.close()
        print("[EDNS Proxy] Stopped")

if __name__ == "__main__":
    main()
'''

# ================= UTILITIES =================
def print_step(msg):
    print(f"\n\033[94m▶\033[0m {msg}")

def print_success(msg):
    print(f"  \033[92m✓\033[0m {msg}")

def print_error(msg):
    print(f"  \033[91m✗\033[0m {msg}")

def run_cmd(cmd, silent=True):
    """Run command quickly"""
    if silent:
        return subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)

# ================= MAIN INSTALLATION =================
def main():
    if os.geteuid() != 0:
        print_error("Must run as root")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("    ULTRA-FAST SLOWDNS + EDNS PROXY INSTALLER")
    print("="*60)
    
    # Get domain
    domain = input("\nEnter DNS hostname (e.g., dns.example.com): ").strip()
    if not domain:
        print_error("Domain is required!")
        sys.exit(1)
    
    start_time = time.time()
    print(f"\nInstalling with domain: \033[93m{domain}\033[0m")
    
    # ========== STEP 1: QUICK SYSTEM PREP ==========
    print_step("Quick system preparation...")
    
    # Only install what's missing
    packages = ["wget", "iptables", "iptables-persistent"]
    for pkg in packages:
        result = run_cmd(f"dpkg -l | grep -q '^{pkg}'")
        if result.returncode != 0:
            run_cmd(f"apt-get install -y {pkg} --no-install-recommends 2>/dev/null")
            print_success(f"Installed {pkg}")
    
    # Kernel tuning for performance
    print_step("Kernel tuning for high performance...")
    tunings = [
        "sysctl -w net.core.rmem_max=134217728",
        "sysctl -w net.core.wmem_max=134217728",
        "sysctl -w net.core.netdev_max_backlog=10000",
        "sysctl -w net.core.somaxconn=65535",
        "sysctl -w net.ipv4.udp_mem='8388608 12582912 16777216'",
    ]
    
    for tune in tunings:
        run_cmd(tune)
    print_success("Kernel optimized for high traffic")
    
    # ========== STEP 2: CONFIGURE SSH ==========
    print_step("Configuring SSH...")
    
    ssh_config = f"""Port {SSHD_PORT}
PermitRootLogin yes
PasswordAuthentication yes
UseDNS no
AllowTcpForwarding yes
GatewayPorts yes
ClientAliveInterval 30
ClientAliveCountMax 3
MaxSessions 100
"""
    
    with open("/etc/ssh/sshd_config", "w") as f:
        f.write(ssh_config)
    
    run_cmd("systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null")
    print_success(f"SSH configured on port {SSHD_PORT}")
    
    # ========== STEP 3: INSTALL SLOWDNS ==========
    print_step("Installing SlowDNS...")
    
    Path(SLOWDNS_DIR).mkdir(parents=True, exist_ok=True)
    
    # Download files with timeout
    files = [
        (SERVER_KEY_URL, f"{SLOWDNS_DIR}/server.key"),
        (SERVER_PUB_URL, f"{SLOWDNS_DIR}/server.pub"),
        (SERVER_BIN_URL, SLOWDNS_BIN),
    ]
    
    for url, dest in files:
        cmd = f"timeout 15 wget -q -O '{dest}' '{url}' || timeout 15 curl -s -o '{dest}' '{url}'"
        run_cmd(cmd)
        if os.path.exists(dest):
            print_success(f"Downloaded {os.path.basename(dest)}")
        else:
            print_error(f"Failed {os.path.basename(dest)}")
    
    os.chmod(SLOWDNS_BIN, 0o755)
    
    # ========== STEP 4: CREATE SLOWDNS SERVICE ==========
    print_step("Creating SlowDNS service...")
    
    slowdns_service = f"""[Unit]
Description=High-Performance SlowDNS Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory={SLOWDNS_DIR}
ExecStart={SLOWDNS_BIN} -udp :{SLOWDNS_PORT} -mtu {INTERNAL_EDNS_SIZE} -privkey-file {SLOWDNS_DIR}/server.key {domain} 127.0.0.1:{SSHD_PORT}
Restart=always
RestartSec=3

# Performance optimizations
LimitNOFILE=1048576
LimitNPROC=4096
OOMScoreAdjust=-100
Nice=-5

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/slowdns-server.service", "w") as f:
        f.write(slowdns_service)
    print_success(f"SlowDNS service created for {domain}")
    
    # ========== STEP 5: INSTALL EDNS PROXY ==========
    print_step("Installing High-Performance EDNS Proxy...")
    
    # Write EDNS proxy script
    with open(EDNS_PROXY_PATH, "w") as f:
        f.write(EDNS_PROXY_CODE)
    os.chmod(EDNS_PROXY_PATH, 0o755)
    print_success("EDNS proxy script created")
    
    # Create EDNS proxy service
    edns_service = f"""[Unit]
Description=High-Performance EDNS Proxy
After=network.target slowdns-server.service
Requires=slowdns-server.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {EDNS_PROXY_PATH}
Restart=always
RestartSec=2
User=root

# Maximum performance settings
LimitNOFILE=1048576
LimitNPROC=8192
LimitCORE=infinity
LimitMEMLOCK=infinity
OOMScoreAdjust=-100
Nice=-10
CPUSchedulingPolicy=rr
CPUSchedulingPriority=1
IOSchedulingClass=realtime
IOSchedulingPriority=0

# Resource limits
MemoryMax=512M
MemorySwapMax=0
CPUQuota=200%

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/edns-proxy.service", "w") as f:
        f.write(edns_service)
    print_success("EDNS proxy service created")
    
    # ========== STEP 6: FIREWALL CONFIGURATION ==========
    print_step("Configuring firewall...")
    
    # Clear and set rules
    run_cmd("iptables -F 2>/dev/null || true")
    run_cmd("iptables -t nat -F 2>/dev/null || true")
    
    # Allow our ports
    run_cmd(f"iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT")
    run_cmd(f"iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT")
    run_cmd(f"iptables -A INPUT -p udp --dport {EDNS_LISTEN_PORT} -j ACCEPT")
    
    # Allow established connections
    run_cmd("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    run_cmd("iptables -A INPUT -i lo -j ACCEPT")
    
    # Save rules
    run_cmd("iptables-save > /etc/iptables/rules.v4 2>/dev/null || true")
    run_cmd("systemctl enable netfilter-persistent 2>/dev/null || true")
    print_success("Firewall configured")
    
    # ========== STEP 7: START SERVICES ==========
    print_step("Starting services...")
    
    run_cmd("systemctl daemon-reload")
    
    # Start SlowDNS
    run_cmd("systemctl enable slowdns-server.service")
    run_cmd("systemctl start slowdns-server.service")
    print_success("SlowDNS service started")
    
    # Stop conflicting DNS services
    run_cmd("systemctl stop systemd-resolved 2>/dev/null || true")
    run_cmd("systemctl disable systemd-resolved 2>/dev/null || true")
    
    # Start EDNS proxy
    run_cmd("systemctl enable edns-proxy.service")
    run_cmd("systemctl start edns-proxy.service")
    print_success("EDNS proxy service started")
    
    # ========== STEP 8: VERIFICATION ==========
    print_step("Verifying installation...")
    
    time.sleep(3)  # Give services time to start
    
    print("\n\033[93mService Status:\033[0m")
    services = ["slowdns-server", "edns-proxy"]
    for svc in services:
        result = run_cmd(f"systemctl is-active {svc}")
        if result.returncode == 0:
            print_success(f"{svc:20} ACTIVE")
        else:
            print_error(f"{svc:20} INACTIVE")
    
    print("\n\033[93mListening Ports:\033[0m")
    ports = [
        (SSHD_PORT, "tcp", "SSH"),
        (SLOWDNS_PORT, "udp", "SlowDNS"),
        (EDNS_LISTEN_PORT, "udp", "EDNS Proxy"),
    ]
    
    for port, proto, name in ports:
        result = run_cmd(f"ss -lnp{proto[0]} | grep -q ':{port}'")
        if result.returncode == 0:
            print_success(f"{name:15} {proto.upper():4}:{port:5} ✓")
        else:
            print_error(f"{name:15} {proto.upper():4}:{port:5} ✗")
    
    # Show public key
    pubkey_path = f"{SLOWDNS_DIR}/server.pub"
    if os.path.exists(pubkey_path):
        print(f"\n\033[93mPUBLIC KEY (Copy for clients):\033[0m")
        print("\033[92m" + "="*60 + "\033[0m")
        with open(pubkey_path, "r") as f:
            print(f"\033[97m{f.read().strip()}\033[0m")
        print("\033[92m" + "="*60 + "\033[0m")
    
    # Final summary
    elapsed = time.time() - start_time
    
    print(f"\n\033[92m" + "="*60 + "\033[0m")
    print(f"\033[92m✅ COMPLETE STACK INSTALLED in {elapsed:.1f} seconds!\033[0m")
    print(f"\033[92m" + "="*60 + "\033[0m")
    
    print(f"\033[93mDomain:\033[0m        {domain}")
    print(f"\033[93mSSH Port:\033[0m      {SSHD_PORT}")
    print(f"\033[93mSlowDNS Port:\033[0m  {SLOWDNS_PORT}")
    print(f"\033[93mEDNS Proxy:\033[0m    {EDNS_LISTEN_PORT}")
    print(f"\033[93mEDNS Size:\033[0m     {EXTERNAL_EDNS_SIZE} → {INTERNAL_EDNS_SIZE}")
    print(f"\033[93mWorkers:\033[0m       {MAX_WORKERS}")
    
    print(f"\n\033[93mPerformance Features:\033[0m")
    print("  • Connection pooling (8 sockets)")
    print("  • Multi-threaded processing")
    print("  • 4MB socket buffers")
    print("  • Real-time scheduling")
    print("  • OOM protection")
    
    print(f"\n\033[93mTest Commands:\033[0m")
    print(f"  dig @$(curl -s ifconfig.me) test.{domain} TXT")
    print("  systemctl status edns-proxy")
    print("  ss -ulpn | grep ':53'")
    print(f"\033[92m" + "="*60 + "\033[0m")

if __name__ == "__main__":
    main()
