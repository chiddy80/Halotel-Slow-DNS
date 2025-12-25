#!/usr/bin/env python3
"""
FULL SLOWDNS + EDNS PROXY STACK - Debian 10 Compatible
- OpenSSH (auto-install if missing)
- SlowDNS server
- High-QPS EDNS Proxy (SO_REUSEPORT + anti-abuse)
- Kernel tuning
- Firewall
"""

import os
import subprocess
import sys
import time
import socket
import selectors
import struct
from pathlib import Path
from collections import defaultdict

# ================= CONFIG =================
SSHD_PORT = 22
SLOWDNS_PORT = 5300
EDNS_LISTEN_PORT = 53

EDNS_EXTERNAL = 512
EDNS_INTERNAL = 1232

WORKERS = os.cpu_count() or 2
INSTALL_DIR = "/opt/slowdns"
EDNS_PROXY_PATH = f"{INSTALL_DIR}/edns_proxy.py"
SLOWDNS_DIR = "/etc/slowdns"
SLOWDNS_BIN = f"{SLOWDNS_DIR}/sldns-server"

# URLs for GitHub resources
SERVER_KEY_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
SERVER_PUB_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
SERVER_BIN_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"

# ================= UTIL =================
def run(cmd, check=True, verbose=False):
    """Run shell command with error handling"""
    if verbose:
        print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error running: {cmd}")
        print(f"Error: {result.stderr}")
        # Don't exit for non-critical commands
    if verbose:
        print(f"Output: {result.stdout}")
    return result

def root_check():
    """Check if running as root"""
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)

def service_exists(name):
    """Check if a systemd service exists"""
    result = subprocess.run(f"systemctl list-unit-files | grep -q '^{name}.service'", shell=True)
    return result.returncode == 0

def fix_apt_sources():
    """Fix Debian 10 buster repositories"""
    print("[+] Fixing Debian 10 repositories")
    # Update sources.list for archive.debian.org
    sources_file = "/etc/apt/sources.list"
    if os.path.exists(sources_file):
        with open(sources_file, 'r') as f:
            content = f.read()
        
        # Replace deb.debian.org with archive.debian.org for buster
        new_content = content.replace('deb.debian.org/debian', 'archive.debian.org/debian')
        new_content = new_content.replace('security.debian.org/debian-security', 'archive.debian.org/debian-security')
        
        # Write back only if changes were made
        if new_content != content:
            with open(sources_file, 'w') as f:
                f.write(new_content)
            print("  Updated sources.list")
    run("apt-get update -qq", check=False, verbose=True)

# ================= EDNS PROXY CODE =================
EDNS_PROXY_CODE = '''#!/usr/bin/env python3
import socket, selectors, struct, time, os
from collections import defaultdict

LISTEN=("0.0.0.0",53)
UPSTREAM=("127.0.0.1",5300)
EXTERNAL=512
INTERNAL=1232
TIMEOUT=5
RATE=50
BURST=100

sel=selectors.DefaultSelector()
pending={}
clients=defaultdict(lambda:[BURST,0])

def allow(ip,now):
    t,l=clients[ip]
    t=min(BURST,t+(now-l)*RATE)
    if t<1:
        clients[ip]=[t,now]; return False
    clients[ip]=[t-1,now]; return True

def nid(): return os.urandom(2)

def patch(data,size):
    if len(data)<12: return data
    ar=struct.unpack("!H",data[10:12])[0]
    if ar==0: return data
    off=12
    def skip(b,i):
        while i<len(b):
            l=b[i]; i+=1
            if l==0: return i
            if l&0xC0: return i+1
            i+=l
        return i
    qd,an,ns=struct.unpack("!HHH",data[4:10])
    for _ in range(qd): off=skip(data,off)+4
    for _ in range(an+ns):
        off=skip(data,off)
        off+=10+struct.unpack("!H",data[off+8:off+10])[0]
    for _ in range(ar):
        n=skip(data,off)
        if struct.unpack("!H",data[n:n+2])[0]==41:
            b=bytearray(data)
            b[n+2:n+4]=struct.pack("!H",size)
            return bytes(b)
        off=n+10+struct.unpack("!H",data[n+8:n+10])[0]
    return data

ls=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
ls.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
ls.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
ls.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
ls.bind(LISTEN)
ls.setblocking(False)

us=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
us.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
us.setblocking(False)

sel.register(ls,selectors.EVENT_READ,"c")
sel.register(us,selectors.EVENT_READ,"u")

while True:
    now=time.time()
    for k,(_,_,t) in list(pending.items()):
        if now-t>TIMEOUT:
            pending.pop(k,None)
    for key,_ in sel.select(1):
        if key.data=="c":
            d,a=ls.recvfrom(4096)
            if not allow(a[0],now): continue
            cid=d[:2]; pid=nid()
            pending[pid]=(cid,a,now)
            us.sendto(patch(pid+d[2:],INTERNAL),UPSTREAM)
        else:
            d,_=us.recvfrom(4096)
            pid=d[:2]
            e=pending.pop(pid,None)
            if e:
                cid,a,_=e
                ls.sendto(patch(cid+d[2:],EXTERNAL),a)
'''

# ================= MAIN =================
def main():
    root_check()
    
    print("="*50)
    print("FULL SLOWDNS + EDNS PROXY STACK INSTALLER")
    print("Compatible with Debian 10 (buster)")
    print("="*50)

    print("[+] Preparing system")
    fix_apt_sources()
    
    # Install packages with error handling
    print("  Installing required packages...")
    result = run("apt-get install -y openssh-server wget iptables iptables-persistent", check=False, verbose=True)
    if result.returncode != 0:
        print("  Warning: Some packages may have failed to install")
    
    # Handle ufw gracefully - might not exist on minimal install
    print("  Disabling firewall services...")
    run("systemctl stop ufw 2>/dev/null || true", check=False)
    run("systemctl disable ufw 2>/dev/null || true", check=False)
    
    # Handle systemd-resolved gracefully
    run("systemctl stop systemd-resolved 2>/dev/null || true", check=False)
    run("systemctl disable systemd-resolved 2>/dev/null || true", check=False)

    # Fix for Python 3.7 compatibility - replace missing_ok=True
    print("  Configuring DNS resolver...")
    try:
        Path("/etc/resolv.conf").unlink()
    except FileNotFoundError:
        pass  # File doesn't exist, which is fine
    except Exception as e:
        print(f"  Warning: Could not unlink /etc/resolv.conf: {e}")
    
    # Create new resolv.conf
    try:
        with open("/etc/resolv.conf", "w") as f:
            f.write("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
        print("  Created /etc/resolv.conf")
    except Exception as e:
        print(f"  Error creating /etc/resolv.conf: {e}")

    print("[+] Kernel tuning")
    # Apply sysctl settings
    sysctl_settings = {
        "net.core.rmem_max": "134217728",
        "net.core.wmem_max": "134217728",
        "net.ipv6.conf.all.disable_ipv6": "1"
    }
    
    for key, value in sysctl_settings.items():
        cmd = f"sysctl -w {key}={value}"
        result = run(cmd, check=False)
        if result.returncode == 0:
            print(f"  Set {key} = {value}")
        else:
            print(f"  Warning: Failed to set {key}")

    print("[+] Configuring SSH")
    ssh_service = "ssh"
    
    # Backup original SSH config if it exists
    ssh_config = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_config):
        run(f"cp {ssh_config} {ssh_config}.backup", check=False)
        print("  Backed up original SSH config")
    
    # Write new SSH config
    try:
        with open(ssh_config, "w") as f:
            f.write(f"""Port {SSHD_PORT}
PermitRootLogin yes
PasswordAuthentication yes
UseDNS no
""")
        print("  Updated SSH configuration")
        
        # Restart SSH if service exists
        if service_exists(ssh_service):
            print("  Restarting SSH service...")
            run(f"systemctl restart {ssh_service}", check=False, verbose=True)
        else:
            print(f"  Warning: SSH service '{ssh_service}' not found")
    except Exception as e:
        print(f"  Error configuring SSH: {e}")

    print("[+] Installing SlowDNS")
    # Create directory
    try:
        Path(SLOWDNS_DIR).mkdir(parents=True, exist_ok=True)
        print(f"  Created directory: {SLOWDNS_DIR}")
    except Exception as e:
        print(f"  Error creating directory: {e}")
        return
    
    # Download files
    print("  Downloading SlowDNS files...")
    files_to_download = [
        (SERVER_KEY_URL, f"{SLOWDNS_DIR}/server.key"),
        (SERVER_PUB_URL, f"{SLOWDNS_DIR}/server.pub"),
        (SERVER_BIN_URL, SLOWDNS_BIN)
    ]
    
    for url, dest in files_to_download:
        result = run(f"wget -q -O '{dest}' '{url}'", check=False)
        if result.returncode == 0:
            print(f"    Downloaded: {dest}")
        else:
            print(f"    Error downloading {url}")
            # Try curl as fallback
            run(f"curl -s -o '{dest}' '{url}'", check=False, verbose=False)
    
    # Make binary executable
    if os.path.exists(SLOWDNS_BIN):
        run(f"chmod +x {SLOWDNS_BIN}", check=False)
        print(f"  Made {SLOWDNS_BIN} executable")
    else:
        print(f"  Warning: {SLOWDNS_BIN} not found after download")
    
    # Get nameserver from user
    nameserver = input("Enter DNS hostname (e.g., dns.example.com): ").strip()
    if not nameserver:
        print("  Error: DNS hostname is required")
        return
    
    print("[+] Creating systemd service for SlowDNS")
    service_content = f"""[Unit]
Description=SlowDNS Server
After=network.target {ssh_service}.service
[Service]
Type=simple
WorkingDirectory={SLOWDNS_DIR}
ExecStart={SLOWDNS_BIN} -udp :{SLOWDNS_PORT} -mtu 1232 -privkey-file {SLOWDNS_DIR}/server.key {nameserver} 127.0.0.1:{SSHD_PORT}
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open("/etc/systemd/system/server-sldns.service", "w") as f:
            f.write(service_content)
        print("  Created SlowDNS service file")
    except Exception as e:
        print(f"  Error creating service file: {e}")

    print("[+] Installing EDNS Proxy")
    try:
        Path(INSTALL_DIR).mkdir(parents=True, exist_ok=True)
        print(f"  Created directory: {INSTALL_DIR}")
    except Exception as e:
        print(f"  Error creating directory: {e}")
    
    # Write EDNS proxy code
    try:
        with open(EDNS_PROXY_PATH, "w") as f:
            f.write(EDNS_PROXY_CODE)
        run(f"chmod +x {EDNS_PROXY_PATH}", check=False)
        print(f"  Created EDNS proxy at {EDNS_PROXY_PATH}")
    except Exception as e:
        print(f"  Error creating EDNS proxy: {e}")
    
    # Create EDNS proxy service template
    proxy_service_content = f"""[Unit]
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 {EDNS_PROXY_PATH}
Restart=always
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open("/etc/systemd/system/edns-proxy@.service", "w") as f:
            f.write(proxy_service_content)
        print("  Created EDNS proxy service template")
    except Exception as e:
        print(f"  Error creating proxy service: {e}")

    print("[+] Configuring firewall")
    # Clear existing rules
    run("iptables -F", check=False)
    run("iptables -t nat -F", check=False)
    
    # Add new rules
    firewall_rules = [
        f"iptables -A INPUT -p udp --dport {EDNS_LISTEN_PORT} -j ACCEPT",
        f"iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT",
        f"iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT",
        "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -i lo -j ACCEPT",
        "iptables -A INPUT -j DROP"
    ]
    
    for rule in firewall_rules:
        result = run(rule, check=False)
        if result.returncode == 0:
            print(f"  Added rule: {rule}")
        else:
            print(f"  Warning: Failed to add rule: {rule}")
    
    # Save iptables rules
    print("  Saving iptables rules...")
    run("iptables-save > /etc/iptables/rules.v4", check=False)
    run("ip6tables-save > /etc/iptables/rules.v6", check=False)

    print("[+] Enabling services")
    run("systemctl daemon-reload", check=False)
    
    # Enable and start SlowDNS
    result = run("systemctl enable server-sldns", check=False)
    if result.returncode == 0:
        print("  Enabled SlowDNS service")
    else:
        print("  Warning: Failed to enable SlowDNS service")
    
    result = run("systemctl start server-sldns", check=False, verbose=True)
    if result.returncode == 0:
        print("  Started SlowDNS service")
    else:
        print("  Warning: Failed to start SlowDNS service")
        print(f"  Error: {result.stderr}")
    
    # Enable and start EDNS proxy workers
    print(f"  Starting {WORKERS} EDNS proxy worker(s)...")
    for i in range(1, WORKERS + 1):
        result = run(f"systemctl enable --now edns-proxy@{i}", check=False)
        if result.returncode == 0:
            print(f"    Started worker {i}/{WORKERS}")
        else:
            print(f"    Warning: Failed to start worker {i}")

    print("\n" + "="*50)
    print("✅ FULL STACK READY")
    print("="*50)
    print(f"SSH Port       : {SSHD_PORT}")
    print(f"SlowDNS Port   : {SLOWDNS_PORT}")
    print(f"DNS Proxy Port : {EDNS_LISTEN_PORT}")
    print(f"Workers        : {WORKERS}")
    print(f"SlowDNS Binary : {SLOWDNS_BIN}")
    print(f"Nameserver     : {nameserver}")
    print("\n" + "="*50)
    print("Post-installation checks:")
    print("="*50)
    
    # Check if services are running
    print("\nChecking services:")
    services_to_check = ["server-sldns"]
    for i in range(1, WORKERS + 1):
        services_to_check.append(f"edns-proxy@{i}")
    
    for service in services_to_check:
        result = run(f"systemctl is-active {service}", check=False)
        if result.returncode == 0:
            print(f"  ✓ {service} is running")
        else:
            print(f"  ✗ {service} is NOT running")
    
    # Check firewall rules
    print("\nChecking firewall rules:")
    result = run("iptables -L INPUT -n | grep -E '(ACCEPT|DROP)'", check=False)
    if result.returncode == 0 and result.stdout:
        print("  Firewall rules are configured")
    
    # Check if ports are listening
    print("\nChecking listening ports:")
    ports_to_check = [SSHD_PORT, SLOWDNS_PORT, EDNS_LISTEN_PORT]
    for port in ports_to_check:
        result = run(f"ss -tuln | grep :{port}", check=False)
        if result.returncode == 0:
            print(f"  ✓ Port {port} is listening")
        else:
            print(f"  ✗ Port {port} is NOT listening")
    
    print("\n" + "="*50)
    print("IMPORTANT: If you're on Debian 10, consider upgrading to a")
    print("supported version for security updates.")
    print("="*50)

if __name__ == "__main__":
    main()
