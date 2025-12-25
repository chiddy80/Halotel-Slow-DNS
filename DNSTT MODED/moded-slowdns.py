#!/usr/bin/env python3
"""
FULL SLOWDNS + EDNS PROXY STACK - Debian 10 Compatible
Fixed version for non-interactive install
"""

import os, subprocess, sys, time, socket, selectors, struct, shutil
from pathlib import Path
from collections import defaultdict

# ================= CONFIG =================
SSHD_PORT = 22
SLOWDNS_PORT = 5300
EDNS_LISTEN_PORT = 53
EDNS_EXTERNAL = 512
EDNS_INTERNAL = 1232
WORKERS = max(os.cpu_count() or 2, 1)
INSTALL_DIR = "/opt/slowdns"
EDNS_PROXY_PATH = f"{INSTALL_DIR}/edns_proxy.py"
SLOWDNS_DIR = "/etc/slowdns"
SLOWDNS_BIN = f"{SLOWDNS_DIR}/dnstt-server"

# GitHub raw URLs (URL encoded spaces)
SERVER_KEY_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
SERVER_PUB_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
SERVER_BIN_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"

# DNS Nameserver - CHANGE THIS TO YOUR DOMAIN
DNS_HOSTNAME = "YOUR_DOMAIN_HERE.com"  # <<< REPLACE WITH YOUR DOMAIN

# ================= UTIL =================
def run(cmd, check=False, capture=True, verbose=False):
    """Run shell command safely"""
    if verbose:
        print(f"[$] {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=False,
                               capture_output=capture, text=True,
                               executable="/bin/bash")
        if check and result.returncode != 0:
            print(f"[!] Command failed ({result.returncode}): {cmd}")
            if result.stderr:
                print(f"    Error: {result.stderr[:200]}")
        return result
    except Exception as e:
        print(f"[!] Exception running command: {e}")
        return subprocess.CompletedProcess(cmd, 1, "", str(e))

def root_check():
    if os.geteuid() != 0:
        print("[!] Must be root")
        sys.exit(1)

def service_exists(name):
    result = run(f"systemctl list-unit-files '{name}.service' 2>/dev/null | grep -q '^{name}'", capture=True)
    return result.returncode == 0

def fix_debian_sources():
    """Fix Debian 10 repositories"""
    src_file = "/etc/apt/sources.list"
    if not os.path.exists(src_file):
        return
    
    with open(src_file, 'r') as f:
        content = f.read()
    
    # Replace active repos with archive
    replacements = [
        ('http://deb.debian.org/debian', 'http://archive.debian.org/debian'),
        ('https://deb.debian.org/debian', 'http://archive.debian.org/debian'),
        ('http://security.debian.org', 'http://archive.debian.org/debian-security'),
        ('https://security.debian.org', 'http://archive.debian.org/debian-security'),
    ]
    
    for old, new in replacements:
        content = content.replace(old, new)
    
    with open(src_file, 'w') as f:
        f.write(content)
    
    print("[+] Updated sources.list for Debian archive")

# ================= EDNS PROXY =================
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

# ================= MAIN INSTALL =================
def main():
    root_check()
    
    print("="*60)
    print("SLOWDNS FULL STACK INSTALLER")
    print(f"Domain: {DNS_HOSTNAME}")
    print("="*60)
    
    # ========== STEP 1: SYSTEM PREP ==========
    print("\n[1] Preparing system...")
    fix_debian_sources()
    
    # Update packages
    result = run("apt-get update -qq", verbose=True)
    if result.returncode != 0:
        print("[!] apt update failed, trying without -qq")
        run("apt-get update", verbose=True)
    
    # Install required packages
    print("  Installing packages...")
    packages = ["openssh-server", "wget", "iptables", "iptables-persistent", "net-tools"]
    for pkg in packages:
        run(f"apt-get install -y {pkg} 2>/dev/null || apt-get install -y {pkg} --allow-unauthenticated", 
            verbose=True)
    
    # Disable conflicting services
    for svc in ["ufw", "systemd-resolved"]:
        run(f"systemctl stop {svc} 2>/dev/null || true", verbose=False)
        run(f"systemctl disable {svc} 2>/dev/null || true", verbose=False)
    
    # Fix resolv.conf (Python 3.7 compatible)
    print("  Configuring DNS...")
    try:
        os.unlink("/etc/resolv.conf")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"  [!] Could not unlink resolv.conf: {e}")
    
    with open("/etc/resolv.conf", "w") as f:
        f.write("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
    
    # ========== STEP 2: KERNEL TUNING ==========
    print("\n[2] Kernel tuning...")
    sysctl_cmds = [
        "sysctl -w net.core.rmem_max=134217728",
        "sysctl -w net.core.wmem_max=134217728",
        "sysctl -w net.ipv4.ip_local_port_range='1024 65000'",
        "sysctl -w net.ipv4.tcp_window_scaling=1",
        "sysctl -w net.ipv4.tcp_timestamps=1",
        "sysctl -w net.ipv4.tcp_sack=1",
    ]
    
    for cmd in sysctl_cmds:
        run(cmd, verbose=False)
    
    # Make sysctl persistent
    sysctl_conf = "/etc/sysctl.d/99-slowdns.conf"
    with open(sysctl_conf, "w") as f:
        f.write("""net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
""")
    
    # ========== STEP 3: SSH CONFIG ==========
    print("\n[3] Configuring SSH...")
    ssh_config = """Port 22
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AllowTcpForwarding yes
GatewayPorts yes
PermitTunnel yes
X11Forwarding no
PrintMotd no
UseDNS no
ClientAliveInterval 30
ClientAliveCountMax 3
MaxAuthTries 3
MaxSessions 10
"""
    
    # Backup original
    if os.path.exists("/etc/ssh/sshd_config"):
        shutil.copy2("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.backup")
    
    with open("/etc/ssh/sshd_config", "w") as f:
        f.write(ssh_config)
    
    # Restart SSH
    run("systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null", verbose=True)
    
    # ========== STEP 4: SLOWDNS INSTALL ==========
    print("\n[4] Installing SlowDNS...")
    
    # Create directory
    Path(SLOWDNS_DIR).mkdir(parents=True, exist_ok=True)
    
    # Download files with retry logic
    files = [
        (SERVER_KEY_URL, f"{SLOWDNS_DIR}/server.key"),
        (SERVER_PUB_URL, f"{SLOWDNS_DIR}/server.pub"),
        (SERVER_BIN_URL, SLOWDNS_BIN),
    ]
    
    for url, dest in files:
        print(f"  Downloading {os.path.basename(dest)}...")
        # Try wget first, then curl
        result = run(f"wget -q --timeout=30 --tries=3 -O '{dest}' '{url}'", verbose=False)
        if result.returncode != 0:
            result = run(f"curl -s --connect-timeout 30 --retry 3 -o '{dest}' '{url}'", verbose=False)
        
        if result.returncode == 0 and os.path.exists(dest):
            print(f"    ✓ {os.path.basename(dest)}")
        else:
            print(f"    ✗ Failed to download {os.path.basename(dest)}")
            # Create dummy files if download fails
            if "server.key" in dest:
                with open(dest, "wb") as f:
                    f.write(os.urandom(32))
            elif "server.pub" in dest:
                with open(dest, "w") as f:
                    f.write("dummy-public-key-for-testing")
            elif "dnstt-server" in dest:
                # Create a dummy binary
                with open(dest, "w") as f:
                    f.write("#!/bin/bash\necho 'SlowDNS server placeholder'\nsleep 1")
    
    # Make binary executable
    if os.path.exists(SLOWDNS_BIN):
        os.chmod(SLOWDNS_BIN, 0o755)
        print(f"  ✓ Made {SLOWDNS_BIN} executable")
    
    # ========== STEP 5: SLOWDNS SERVICE ==========
    print("\n[5] Creating SlowDNS service...")
    
    slowdns_service = f"""[Unit]
Description=SlowDNS Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory={SLOWDNS_DIR}
ExecStart={SLOWDNS_BIN} -udp :{SLOWDNS_PORT} -mtu {EDNS_INTERNAL} -privkey-file {SLOWDNS_DIR}/server.key {DNS_HOSTNAME} 127.0.0.1:{SSHD_PORT}
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
    
    print(f"  ✓ Service created for domain: {DNS_HOSTNAME}")
    
    # ========== STEP 6: EDNS PROXY ==========
    print("\n[6] Installing EDNS Proxy...")
    
    Path(INSTALL_DIR).mkdir(parents=True, exist_ok=True)
    
    # Write proxy code
    with open(EDNS_PROXY_PATH, "w") as f:
        f.write(EDNS_PROXY_CODE)
    os.chmod(EDNS_PROXY_PATH, 0o755)
    
    # Create service template
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
    
    print(f"  ✓ EDNS Proxy with {WORKERS} workers")
    
    # ========== STEP 7: FIREWALL ==========
    print("\n[7] Configuring firewall...")
    
    # Clear existing rules
    run("iptables -F 2>/dev/null || true", verbose=False)
    run("iptables -t nat -F 2>/dev/null || true", verbose=False)
    run("iptables -X 2>/dev/null || true", verbose=False)
    
    # Default policies
    run("iptables -P INPUT DROP", verbose=False)
    run("iptables -P FORWARD DROP", verbose=False)
    run("iptables -P OUTPUT ACCEPT", verbose=False)
    
    # Allow loopback
    run("iptables -A INPUT -i lo -j ACCEPT", verbose=False)
    
    # Allow established connections
    run("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT", verbose=False)
    
    # Allow ICMP (ping)
    run("iptables -A INPUT -p icmp -j ACCEPT", verbose=False)
    
    # Allow our ports
    ports = [
        (SSHD_PORT, "tcp", "SSH"),
        (SLOWDNS_PORT, "udp", "SlowDNS"),
        (EDNS_LISTEN_PORT, "udp", "DNS Proxy"),
    ]
    
    for port, proto, name in ports:
        run(f"iptables -A INPUT -p {proto} --dport {port} -j ACCEPT", verbose=False)
        print(f"  ✓ Allowed {name} on {proto.upper()}:{port}")
    
    # Save rules
    run("iptables-save > /etc/iptables/rules.v4 2>/dev/null || true", verbose=False)
    run("ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true", verbose=False)
    
    # Enable persistence
    run("systemctl enable netfilter-persistent 2>/dev/null || true", verbose=False)
    
    # ========== STEP 8: ENABLE SERVICES ==========
    print("\n[8] Enabling services...")
    
    # Reload systemd
    run("systemctl daemon-reload", verbose=True)
    
    # Enable and start slowdns
    run("systemctl enable slowdns-server.service", verbose=False)
    run("systemctl start slowdns-server.service", verbose=True)
    
    # Enable target
    run("systemctl enable edns-proxy.target", verbose=False)
    run("systemctl start edns-proxy.target", verbose=True)
    
    # Start workers
    print(f"  Starting {WORKERS} EDNS workers...")
    for i in range(1, WORKERS + 1):
        run(f"systemctl enable edns-proxy@{i}.service", verbose=False)
        run(f"systemctl start edns-proxy@{i}.service", verbose=False)
        print(f"    Worker {i}/{WORKERS}", end='\r')
    print()
    
    # ========== STEP 9: VERIFICATION ==========
    print("\n[9] Verification...")
    
    # Check services
    services = ["slowdns-server"] + [f"edns-proxy@{i}" for i in range(1, WORKERS + 1)]
    
    print("  Service Status:")
    for svc in services:
        result = run(f"systemctl is-active {svc}", capture=True)
        if result.returncode == 0:
            print(f"    ✓ {svc:25} ACTIVE")
        else:
            print(f"    ✗ {svc:25} INACTIVE")
            print(f"       Debug: systemctl status {svc}")
    
    # Check listening ports
    print("\n  Listening Ports:")
    for port, proto, name in ports:
        result = run(f"ss -lnp{proto[0]} | grep -q ':{port}'", capture=True)
        if result.returncode == 0:
            print(f"    ✓ {name:15} {proto.upper():4}:{port:5} ✓")
        else:
            print(f"    ✗ {name:15} {proto.upper():4}:{port:5} ✗")
    
    # Show public key
    pubkey_path = f"{SLOWDNS_DIR}/server.pub"
    if os.path.exists(pubkey_path):
        print(f"\n{'='*60}")
        print("PUBLIC KEY (Copy for clients):")
        print("="*60)
        with open(pubkey_path, "r") as f:
            key = f.read().strip()
            if key and "dummy" not in key:
                print(key)
            else:
                print("WARNING: Using dummy key. Replace with real key for production!")
        print("="*60)
    
    # Show summary
    print(f"\n{'='*60}")
    print("INSTALLATION COMPLETE")
    print("="*60)
    print(f"Domain:        {DNS_HOSTNAME}")
    print(f"SSH Port:      {SSHD_PORT}")
    print(f"SlowDNS Port:  {SLOWDNS_PORT}")
    print(f"DNS Proxy:     {EDNS_LISTEN_PORT} (EDNS)")
    print(f"Workers:       {WORKERS}")
    print(f"MTU External:  {EDNS_EXTERNAL}")
    print(f"MTU Internal:  {EDNS_INTERNAL}")
    print("="*60)
    print("\nNext steps:")
    print("1. Point your domain's NS record to this server")
    print("2. Test with: dig @$(curl -s ifconfig.me) test. YOUR_DOMAIN TXT")
    print("3. Check logs: journalctl -u slowdns-server -f")
    print("="*60)

if __name__ == "__main__":
    main()
