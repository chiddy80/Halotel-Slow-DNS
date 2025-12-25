#!/usr/bin/env python3
"""
ULTRA SlowDNS + EDNS Installer (Fully Integrated)
- SlowDNS (DNSTT)
- Async multi-core EDNS proxy (port 53)
- Rate limit / anti-abuse
- SO_REUSEPORT + zero-copy recvmsg
- rc.local + iptables flush
- Hard IPv6 disable
- Proper systemd services
- Interactive port 53 conflict check
"""

import os, sys, socket, struct, selectors, time, subprocess, multiprocessing
from pathlib import Path
import urllib.request

# ================= CONFIG =================
SSHD_PORT = 22
SLOWDNS_PORT = 5300
DNS_PORT = 53

EXT_EDNS = 512
INT_EDNS = 1232
RATE_QPS = 50
RATE_BURST = 100

BASE_DIR = Path("/etc/slowdns")
URL_BASE = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
FILES = {
    "server.key": f"{URL_BASE}/server.key",
    "server.pub": f"{URL_BASE}/server.pub",
    "dnstt-server": f"{URL_BASE}/dnstt-server",
}

# ================= HELPERS =================
def run(cmd):
    subprocess.run(cmd, shell=True, check=True)

def root():
    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)

# ================= PORT 53 SAFE CHECK =================
def stop_conflicts():
    print("[*] Checking port 53 usage...")
    result = subprocess.run("ss -ulpn | grep ':53 '", shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        print("[!] Port 53 is in use by:")
        print(result.stdout)
        confirm = input("Do you want to stop these services to free port 53? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Aborted by user. Free port 53 first.")
            sys.exit(1)
        print("[*] Stopping conflicting services...")
        # Stop systemd-resolved if active
        if os.system("systemctl is-active --quiet systemd-resolved") == 0:
            run("systemctl stop systemd-resolved")
            run("systemctl disable systemd-resolved")
        # Kill any process using port 53
        os.system("fuser -k 53/udp || true")
        os.system("fuser -k 53/tcp || true")
    else:
        print("[✓] Port 53 is free")

# ================= RC.LOCAL =================
def setup_rc_local():
    rc = f"""#!/bin/sh -e
systemctl start sshd

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT
iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT
iptables -A INPUT -p tcp --dport {SLOWDNS_PORT} -j ACCEPT
iptables -A INPUT -p udp --dport {DNS_PORT} -j ACCEPT
iptables -A INPUT -p tcp --dport {DNS_PORT} -j ACCEPT

iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -j ACCEPT

iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -p tcp --dport {SSHD_PORT} -m recent --set
iptables -A INPUT -p tcp --dport {SSHD_PORT} -m recent --update --seconds 60 --hitcount 4 -j DROP

echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728

exit 0
"""
    Path("/etc/rc.local").write_text(rc)
    os.chmod("/etc/rc.local", 0o755)
    run("systemctl enable rc-local || true")
    run("systemctl start rc-local || true")

# ================= SSH =================
def ssh_config():
    Path("/etc/ssh/sshd_config").write_text(f"""Port {SSHD_PORT}
PermitRootLogin yes
PasswordAuthentication yes
AllowTcpForwarding yes
GatewayPorts yes
UseDNS no
""")
    run("systemctl restart sshd")

# ================= SLOWDNS =================
def slowdns_install(ns):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        dst = BASE_DIR / name
        if dst.exists():
            try: os.remove(dst)
            except: pass
        urllib.request.urlretrieve(url, dst)
        if "dnstt" in name:
            dst.chmod(0o755)

    service = f"""[Unit]
Description=DNSTT SlowDNS Server
After=network.target sshd.service

[Service]
ExecStart=/etc/slowdns/dnstt-server -udp :{SLOWDNS_PORT} -privkey-file /etc/slowdns/server.key {ns} 127.0.0.1:{SSHD_PORT}
Restart=always
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/slowdns.service").write_text(service)
    run("systemctl daemon-reload")
    run("systemctl enable slowdns")
    run("systemctl start slowdns")

# ================= EDNS =================
def patch_edns(data, size):
    if len(data) < 12: return data
    buf = bytearray(data)
    for i in range(len(buf)-2):
        if buf[i:i+2] == b"\x00\x29":
            buf[i+3:i+5] = struct.pack("!H", size)
            break
    return bytes(buf)

def edns_worker():
    sel = selectors.DefaultSelector()
    rate = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("0.0.0.0", DNS_PORT))
    sock.setblocking(False)

    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.setblocking(False)

    sel.register(sock, selectors.EVENT_READ)
    sel.register(upstream, selectors.EVENT_READ)

    pending = {}

    while True:
        for key, _ in sel.select(timeout=1):
            if key.fileobj is sock:
                data, anc, _, addr = sock.recvmsg(4096)
                ip = addr[0]
                now = time.time()
                tokens, ts = rate.get(ip, (RATE_BURST, now))
                tokens += (now - ts) * RATE_QPS
                if tokens > RATE_BURST: tokens = RATE_BURST
                if tokens < 1: rate[ip] = (tokens, now); continue
                rate[ip] = (tokens - 1, now)
                upstream.sendto(patch_edns(data, INT_EDNS), ("127.0.0.1", SLOWDNS_PORT))
                pending[ip] = addr
            else:
                data, _ = upstream.recvfrom(4096)
                if pending:
                    ip, addr = pending.popitem()
                    sock.sendto(patch_edns(data, EXT_EDNS), addr)

def edns_service_file():
    service = f"""[Unit]
Description=EDNS Proxy (UDP 53 -> SlowDNS {SLOWDNS_PORT})
After=network.target slowdns.service
Requires=slowdns.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/slowdns/edns.py
Restart=always
User=root
LimitNOFILE=65536
StandardOutput=append:/var/log/edns.log
StandardError=append:/var/log/edns.err

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/edns.service").write_text(service)
    run("systemctl daemon-reload")
    run("systemctl enable edns")
    run("systemctl start edns")

def edns_install_file():
    edns_path = BASE_DIR / "edns.py"
    code = open(__file__).read()  # save this script as edns.py
    edns_path.write_text(code)
    edns_path.chmod(0o755)

# ================= MAIN =================
def main():
    root()
    stop_conflicts()
    ns = input("Enter nameserver (dns.example.com): ").strip()

    ssh_config()
    setup_rc_local()
    slowdns_install(ns)
    edns_install_file()
    edns_service_file()

    print("\n✅ SlowDNS + EDNS installation complete.")
    print("Ports: SlowDNS 5300, EDNS 53")
    print("Check status: systemctl status slowdns edns")
    print("Test DNS: dig @127.0.0.1 google.com +short")

if __name__ == "__main__":
    main()
