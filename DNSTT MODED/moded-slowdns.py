#!/usr/bin/env python3
"""
ULTRA SlowDNS + EDNS Installer
- Legacy rc.local
- Global iptables flush
- Hard IPv6 disable
- Async EDNS Proxy
- Rate limit + anti-abuse
- SO_REUSEPORT multi-core
- Zero-copy recvmsg
"""

import os, sys, socket, struct, selectors, subprocess, urllib.request, time, multiprocessing
from pathlib import Path

# ================= CONFIG =================

SSHD_PORT = 22
SLOWDNS_PORT = 5300
DNS_PORT = 53

EXT_EDNS = 512
INT_EDNS = 1232

RATE_QPS = 50        # per IP
RATE_BURST = 100
ABUSE_TIMEOUT = 10  # seconds

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

# ================= LEGACY SYSTEM =================

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

def disable_ipv6():
    run("echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6")
    with open("/etc/sysctl.conf", "a") as f:
        f.write("\nnet.ipv6.conf.all.disable_ipv6=1\n")
        f.write("net.ipv6.conf.default.disable_ipv6=1\n")
    run("sysctl -p || true")

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
        urllib.request.urlretrieve(url, dst)
        if "dnstt" in name:
            dst.chmod(0o755)

    Path("/etc/systemd/system/slowdns.service").write_text(f"""[Unit]
Description=DNSTT SlowDNS
After=network.target sshd.service

[Service]
ExecStart=/etc/slowdns/dnstt-server -udp :{SLOWDNS_PORT} -privkey-file /etc/slowdns/server.key {ns} 127.0.0.1:{SSHD_PORT}
Restart=always

[Install]
WantedBy=multi-user.target
""")

    run("systemctl daemon-reload")
    run("systemctl enable slowdns")
    run("systemctl start slowdns")

# ================= EDNS CORE =================

def patch_edns(data, size):
    if len(data) < 12:
        return data
    buf = bytearray(data)
    for i in range(len(buf) - 2):
        if buf[i:i+2] == b"\x00\x29":
            buf[i+3:i+5] = struct.pack("!H", size)
            break
    return bytes(buf)

def edns_worker():
    sel = selectors.DefaultSelector()
    rate = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setblocking(False)
    sock.bind(("0.0.0.0", DNS_PORT))

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
                if tokens > RATE_BURST:
                    tokens = RATE_BURST

                if tokens < 1:
                    rate[ip] = (tokens, now)
                    continue

                rate[ip] = (tokens - 1, now)

                upstream.sendto(patch_edns(data, INT_EDNS), ("127.0.0.1", SLOWDNS_PORT))
                pending[ip] = addr

            else:
                data, _ = upstream.recvfrom(4096)
                if pending:
                    ip, addr = pending.popitem()
                    sock.sendto(patch_edns(data, EXT_EDNS), addr)

# ================= MAIN =================

def main():
    root()
    ns = input("Enter nameserver (dns.example.com): ").strip()

    ssh_config()
    disable_ipv6()
    setup_rc_local()
    slowdns_install(ns)

    print("Starting multi-core EDNS proxy")

    for _ in range(multiprocessing.cpu_count()):
        pid = os.fork()
        if pid == 0:
            edns_worker()
            sys.exit(0)

    os.wait()

if __name__ == "__main__":
    main()
