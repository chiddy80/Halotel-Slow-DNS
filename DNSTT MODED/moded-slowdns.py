#!/usr/bin/env python3
"""
COMPLETE SLOWDNS + EDNS PROXY - FULL SYSTEMD
Fixed for Debian 10 and proper service creation
"""

import os
import sys
import time
import socket
import struct
import selectors
import subprocess
from pathlib import Path
from collections import defaultdict

# ================= CONFIG =================
SSHD_PORT = 22
SLOWDNS_PORT = 5300
EDNS_LISTEN_PORT = 53

EDNS_EXTERNAL = 512
EDNS_INTERNAL = 1232

WORKERS = max(os.cpu_count() or 2, 2)  # Minimum 2 workers
INSTALL_DIR = "/opt/slowdns"
EDNS_PROXY_PATH = f"{INSTALL_DIR}/edns_proxy.py"
SLOWDNS_DIR = "/etc/slowdns"
SLOWDNS_BIN = f"{SLOWDNS_DIR}/dnstt-server"

# YOUR GitHub URLs
SERVER_KEY_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
SERVER_PUB_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
SERVER_BIN_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"

# ================= UTILITIES =================
def run(cmd, check=False, fatal=False):
    """Run command with error handling"""
    try:
        result = subprocess.run(
            cmd, shell=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, executable="/bin/bash"
        )
        if fatal and result.returncode != 0:
            print(f"[✗] Command failed: {cmd}")
            sys.exit(1)
        return result
    except Exception as e:
        if fatal:
            print(f"[✗] Exception: {e}")
            sys.exit(1)
        return subprocess.CompletedProcess(cmd, 1, "", str(e))

def print_step(msg):
    print(f"\n\033[94m▶\033[0m {msg}")

def print_success(msg):
    print(f"  \033[92m✓\033[0m {msg}")

def print_error(msg):
    print(f"  \033[91m✗\033[0m {msg}")

# ================= EDNS PROXY CODE =================
EDNS_PROXY_CODE = '''#!/usr/bin/env python3
import socket, selectors, struct, time, os, sys
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

try:
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
    
    print(f"[EDNS] Listening on {LISTEN[0]}:{LISTEN[1]}", flush=True)
    
    while True:
        now=time.time()
        for k,(_,_,t) in list(pending.items()):
            if now-t>TIMEOUT:
                pending.pop(k,None)
        for key,_ in sel.select(1):
            if key.data=="c":
                try:
                    d,a=ls.recvfrom(4096)
                    if not allow(a[0],now): continue
                    cid=d[:2]; pid=nid()
                    pending[pid]=(cid,a,now)
                    us.sendto(patch(pid+d[2:],INTERNAL),UPSTREAM)
                except Exception: pass
            else:
                try:
                    d,_=us.recvfrom(4096)
                    pid=d[:2]
                    e=pending.pop(pid,None)
                    if e:
                        cid,a,_=e
                        ls.sendto(patch(cid+d[2:],EXTERNAL),a)
                except Exception: pass
except Exception as e:
    print(f"[EDNS] Fatal: {e}", file=sys.stderr)
    sys.exit(1)
'''

# ================= MAIN INSTALLATION =================
def main():
    if os.geteuid() != 0:
        print_error("Must run as root")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("    SLOWDNS + EDNS PROXY INSTALLER")
    print("="*60)
    
    # Get domain interactively
    print("\n\033[93mEnter your DNS hostname (e.g., dns.yourdomain.com):\033[0m")
    try:
        nameserver = input("  → ").strip()
        if not nameserver:
            print_error("Domain is required!")
            sys.exit(1)
    except (EOFError, KeyboardInterrupt):
        print_error("Input cancelled")
        sys.exit(1)
    
    print(f"\nInstalling with domain: \033[92m{nameserver}\033[0m")
    
    # ========== STEP 1: SYSTEM PREPARATION ==========
    print_step("Preparing system...")
    
    # Update system
    run("apt-get update -qq", fatal=False)
    
    # Install required packages
    packages = ["openssh-server", "wget", "iptables", "iptables-persistent"]
    for pkg in packages:
        result = run(f"apt-get install -y {pkg} 2>/dev/null || true")
        if result.returncode == 0:
            print_success(f"Installed {pkg}")
    
    # Disable conflicting services
    for svc in ["ufw", "systemd-resolved"]:
        run(f"systemctl stop {svc} 2>/dev/null || true", fatal=False)
        run(f"systemctl disable {svc} 2>/dev/null || true", fatal=False)
    print_success("Disabled conflicting services")
    
    # ========== STEP 2: DNS CONFIG ==========
    print_step("Configuring DNS...")
    
    # Fix resolv.conf (Python 3.7 compatible)
    try:
        os.unlink("/etc/resolv.conf")
    except FileNotFoundError:
        pass
    
    with open("/etc/resolv.conf", "w") as f:
        f.write("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
    print_success("DNS configured")
    
    # ========== STEP 3: KERNEL TUNING ==========
    print_step("Kernel tuning...")
    run("sysctl -w net.core.rmem_max=134217728", fatal=False)
    run("sysctl -w net.core.wmem_max=134217728", fatal=False)
    print_success("Kernel tuned")
    
    # ========== STEP 4: SSH CONFIG ==========
    print_step(f"Configuring SSH on port {SSHD_PORT}...")
    
    ssh_config = f"""Port {SSHD_PORT}
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
    
    with open("/etc/ssh/sshd_config", "w") as f:
        f.write(ssh_config)
    
    run("systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null", fatal=False)
    print_success(f"SSH configured on port {SSHD_PORT}")
    
    # ========== STEP 5: SLOWDNS INSTALL ==========
    print_step("Installing SlowDNS...")
    
    # Create directory
    Path(SLOWDNS_DIR).mkdir(parents=True, exist_ok=True)
    print_success("Created SlowDNS directory")
    
    # Download files
    files = [
        (SERVER_KEY_URL, f"{SLOWDNS_DIR}/server.key"),
        (SERVER_PUB_URL, f"{SLOWDNS_DIR}/server.pub"),
        (SERVER_BIN_URL, SLOWDNS_BIN),
    ]
    
    for url, dest in files:
        # Try wget first
        result = run(f"wget -q -O '{dest}' '{url}'", fatal=False)
        if result.returncode != 0:
            # Try curl
            run(f"curl -s -o '{dest}' '{url}'", fatal=False)
        
        if os.path.exists(dest):
            print_success(f"Downloaded {os.path.basename(dest)}")
        else:
            print_error(f"Failed to download {os.path.basename(dest)}")
    
    # Make executable
    if os.path.exists(SLOWDNS_BIN):
        os.chmod(SLOWDNS_BIN, 0o755)
        print_success("Made dnstt-server executable")
    
    # ========== STEP 6: SLOWDNS SYSTEMD SERVICE ==========
    print_step("Creating SlowDNS systemd service...")
    
    slowdns_service = f"""[Unit]
Description=SlowDNS Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory={SLOWDNS_DIR}
ExecStart={SLOWDNS_BIN} -udp :{SLOWDNS_PORT} -mtu 1232 -privkey-file {SLOWDNS_DIR}/server.key {nameserver} 127.0.0.1:{SSHD_PORT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=slowdns
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/slowdns-server.service", "w") as f:
        f.write(slowdns_service)
    print_success("SlowDNS systemd service created")
    
    # ========== STEP 7: EDNS PROXY ==========
    print_step("Installing EDNS Proxy...")
    
    # Create directory
    Path(INSTALL_DIR).mkdir(parents=True, exist_ok=True)
    
    # Write EDNS proxy code
    with open(EDNS_PROXY_PATH, "w") as f:
        f.write(EDNS_PROXY_CODE)
    os.chmod(EDNS_PROXY_PATH, 0o755)
    print_success("EDNS proxy script created")
    
    # ========== STEP 8: EDNS PROXY SYSTEMD SERVICE ==========
    print_step("Creating EDNS Proxy systemd service...")
    
    edns_service = f"""[Unit]
Description=EDNS Proxy Worker %i
After=network.target
PartOf=edns-proxy.target
Wants=edns-proxy.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 {EDNS_PROXY_PATH}
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edns-proxy-%i
LimitNOFILE=1048576
CPUQuota={min(100//WORKERS, 50)}%
MemoryMax=512M

[Install]
WantedBy=edns-proxy.target
"""
    
    with open("/etc/systemd/system/edns-proxy@.service", "w") as f:
        f.write(edns_service)
    
    # Create target service
    target_service = """[Unit]
Description=EDNS Proxy Target
AllowIsolate=yes

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/edns-proxy.target", "w") as f:
        f.write(target_service)
    
    print_success("EDNS proxy systemd services created")
    
    # ========== STEP 9: FIREWALL ==========
    print_step("Configuring firewall...")
    
    # Clear existing rules
    run("iptables -F 2>/dev/null || true", fatal=False)
    run("iptables -t nat -F 2>/dev/null || true", fatal=False)
    
    # Allow SSH
    run(f"iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT", fatal=False)
    
    # Allow SlowDNS
    run(f"iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT", fatal=False)
    
    # Allow DNS (EDNS proxy)
    run(f"iptables -A INPUT -p udp --dport {EDNS_LISTEN_PORT} -j ACCEPT", fatal=False)
    
    # Allow established connections
    run("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT", fatal=False)
    
    # Allow loopback
    run("iptables -A INPUT -i lo -j ACCEPT", fatal=False)
    
    # Save rules
    run("iptables-save > /etc/iptables/rules.v4 2>/dev/null || true", fatal=False)
    run("systemctl enable netfilter-persistent 2>/dev/null || true", fatal=False)
    print_success("Firewall configured")
    
    # ========== STEP 10: ENABLE SERVICES ==========
    print_step("Enabling services...")
    
    # Reload systemd
    run("systemctl daemon-reload", fatal=False)
    
    # Enable and start SlowDNS
    run("systemctl enable slowdns-server.service", fatal=False)
    run("systemctl start slowdns-server.service", fatal=False)
    print_success("SlowDNS service started")
    
    # Enable target and workers
    run("systemctl enable edns-proxy.target", fatal=False)
    run("systemctl start edns-proxy.target", fatal=False)
    
    print(f"Starting {WORKERS} EDNS workers...")
    for i in range(1, WORKERS + 1):
        run(f"systemctl enable edns-proxy@{i}.service", fatal=False)
        run(f"systemctl start edns-proxy@{i}.service", fatal=False)
        print(f"  Worker {i}/{WORKERS} started")
    print_success(f"All {WORKERS} EDNS workers started")
    
    # ========== STEP 11: VERIFICATION ==========
    print_step("Verifying installation...")
    
    print("\n\033[93mService Status:\033[0m")
    services = ["slowdns-server"] + [f"edns-proxy@{i}" for i in range(1, WORKERS + 1)]
    
    for svc in services:
        result = run(f"systemctl is-active {svc}", fatal=False)
        if result.returncode == 0:
            print_success(f"{svc:25} ACTIVE")
        else:
            print_error(f"{svc:25} INACTIVE")
    
    print("\n\033[93mListening Ports:\033[0m")
    ports = [
        (SSHD_PORT, "tcp", "SSH"),
        (SLOWDNS_PORT, "udp", "SlowDNS"),
        (EDNS_LISTEN_PORT, "udp", "EDNS Proxy"),
    ]
    
    for port, proto, name in ports:
        result = run(f"ss -lnp{proto[0]} | grep -q ':{port}'", fatal=False)
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
    print(f"\n\033[92m" + "="*60 + "\033[0m")
    print(f"\033[92m✅ INSTALLATION COMPLETE!\033[0m")
    print(f"\033[92m" + "="*60 + "\033[0m")
    print(f"\033[93mDomain:\033[0m        {nameserver}")
    print(f"\033[93mSSH Port:\033[0m      {SSHD_PORT}")
    print(f"\033[93mSlowDNS Port:\033[0m  {SLOWDNS_PORT}")
    print(f"\033[93mEDNS Proxy:\033[0m    {EDNS_LISTEN_PORT}")
    print(f"\033[93mWorkers:\033[0m       {WORKERS}")
    print(f"\n\033[93mNext steps:\033[0m")
    print(f"1. Point NS record of {nameserver} to your server IP")
    print(f"2. Test: dig @$(curl -s ifconfig.me) test.{nameserver} TXT")
    print(f"3. Check logs: journalctl -u slowdns-server -f")
    print(f"4. Check EDNS: journalctl -u edns-proxy@1 -f")
    print(f"\033[92m" + "="*60 + "\033[0m")

if __name__ == "__main__":
    main()
