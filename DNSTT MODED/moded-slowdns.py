#!/usr/bin/env python3
"""
FULL SLOWDNS + EDNS PROXY STACK
- OpenSSH (auto-install if missing)
- SlowDNS server
- High-QPS EDNS Proxy (SO_REUSEPORT + anti-abuse)
- Kernel tuning
- Firewall
"""

import os, subprocess, sys, time, socket, selectors, struct
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

SERVER_KEY_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT MODED/server.key"
SERVER_PUB_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT/server.pub"
SERVER_BIN_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT MODED/dnstt-server"

# ================= UTIL =================
def run(cmd, check=True):
    subprocess.run(cmd, shell=True, check=check)

def root_check():
    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)

def service_exists(name):
    result = subprocess.run(f"systemctl list-units --type=service | grep -q {name}", shell=True)
    return result.returncode == 0

# ================= EDNS PROXY CODE =================
EDNS_PROXY_CODE = r'''
#!/usr/bin/env python3
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

    print("[+] Preparing system")
    run("apt-get update -qq", False)
    run("apt-get install -y openssh-server wget iptables", False)
    run("systemctl stop ufw || true", False)
    run("systemctl disable ufw || true", False)
    run("systemctl stop systemd-resolved || true", False)
    run("systemctl disable systemd-resolved || true", False)

    Path("/etc/resolv.conf").unlink(missing_ok=True)
    Path("/etc/resolv.conf").write_text("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")

    print("[+] Kernel tuning")
    run("sysctl -w net.core.rmem_max=134217728")
    run("sysctl -w net.core.wmem_max=134217728")
    run("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

    print("[+] Configuring SSH")
    ssh_service = "ssh"
    Path("/etc/ssh/sshd_config").write_text(f"""
Port {SSHD_PORT}
PermitRootLogin yes
PasswordAuthentication yes
UseDNS no
""")
    if service_exists(ssh_service):
        run(f"systemctl restart {ssh_service}")
    else:
        print(f"[!] SSH service '{ssh_service}' not found, skipping restart")

    print("[+] Installing SlowDNS")
    Path(SLOWDNS_DIR).mkdir(parents=True, exist_ok=True)
    run(f"wget -q -O {SLOWDNS_DIR}/server.key {SERVER_KEY_URL}")
    run(f"wget -q -O {SLOWDNS_DIR}/server.pub {SERVER_PUB_URL}")
    run(f"wget -q -O {SLOWDNS_BIN} {SERVER_BIN_URL}")
    run(f"chmod +x {SLOWDNS_BIN}")

    nameserver = input("Enter DNS hostname (e.g dns.example.com): ").strip()

    Path("/etc/systemd/system/server-sldns.service").write_text(f"""
[Unit]
After=network.target {ssh_service}.service
[Service]
ExecStart={SLOWDNS_BIN} -udp :{SLOWDNS_PORT} -mtu 1232 -privkey-file {SLOWDNS_DIR}/server.key {nameserver} 127.0.0.1:{SSHD_PORT}
Restart=always
[Install]
WantedBy=multi-user.target
""")

    print("[+] Installing EDNS Proxy")
    Path(INSTALL_DIR).mkdir(parents=True, exist_ok=True)
    Path(EDNS_PROXY_PATH).write_text(EDNS_PROXY_CODE)
    run(f"chmod +x {EDNS_PROXY_PATH}")

    Path("/etc/systemd/system/edns-proxy@.service").write_text(f"""
[Unit]
After=network.target
[Service]
ExecStart=/usr/bin/python3 {EDNS_PROXY_PATH}
Restart=always
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
""")

    print("[+] Firewall")
    run("iptables -F")
    run(f"iptables -A INPUT -p udp --dport {EDNS_LISTEN_PORT} -j ACCEPT")
    run(f"iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT")
    run(f"iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT")

    print("[+] Enabling services")
    run("systemctl daemon-reload")
    run("systemctl enable server-sldns")
    run("systemctl start server-sldns")

    for i in range(1, WORKERS + 1):
        run(f"systemctl enable --now edns-proxy@{i}")

    print("\n✅ FULL STACK READY")
    print(f"SSH      : {SSHD_PORT}")
    print(f"SlowDNS  : {SLOWDNS_PORT}")
    print(f"DNS Port : {EDNS_LISTEN_PORT} (EDNS Proxy)")

if __name__ == "__main__":
    main()
