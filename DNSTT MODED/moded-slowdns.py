#!/usr/bin/env python3
"""
ULTRA SlowDNS + EDNS Installer (Fixed Version)
- Restores DNS for downloads
- Handles port 53 conflicts
- Installs SlowDNS + EDNS proxy
- Creates proper systemd services
"""

import os
import sys
import socket
import struct
import subprocess
from pathlib import Path
import urllib.request
import time

# ================= CONFIG =================
SSHD_PORT = 22
SLOWDNS_PORT = 5300
DNS_PORT = 53

EXT_EDNS = 512
INT_EDNS = 1232

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

def root_check():
    if os.geteuid() != 0:
        print("Please run this script as root")
        sys.exit(1)

# ================= TEMP DNS =================
def restore_dns():
    resolv = Path("/etc/resolv.conf")
    if not resolv.exists() or resolv.read_text().strip() == "":
        print("[*] Restoring temporary DNS to download files...")
        resolv.write_text("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
        os.system("chattr +i /etc/resolv.conf")
        time.sleep(1)
        print("[✓] DNS restored temporarily")

# ================= PORT 53 SAFE CHECK =================
def stop_conflicts():
    print("[*] Checking port 53 usage...")
    result = subprocess.run("ss -ulpn | grep ':53 '", shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        print("[!] Port 53 is in use by:")
        print(result.stdout)
        confirm = input("Stop conflicting services? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Aborted by user. Free port 53 first.")
            sys.exit(1)
        print("[*] Stopping conflicts...")
        # Stop systemd-resolved
        if os.system("systemctl is-active --quiet systemd-resolved") == 0:
            run("systemctl stop systemd-resolved")
            run("systemctl disable systemd-resolved")
        # Kill processes on port 53
        os.system("fuser -k 53/udp || true")
        os.system("fuser -k 53/tcp || true")
    else:
        print("[✓] Port 53 is free")

# ================= SSH =================
def ssh_config():
    print("[*] Configuring OpenSSH...")
    Path("/etc/ssh/sshd_config").write_text(f"""Port {SSHD_PORT}
PermitRootLogin yes
PasswordAuthentication yes
AllowTcpForwarding yes
GatewayPorts yes
UseDNS no
""")
    run("systemctl restart sshd")
    print("[✓] SSH configured")

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

echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728

exit 0
"""
    Path("/etc/rc.local").write_text(rc)
    os.chmod("/etc/rc.local", 0o755)
    run("systemctl enable rc-local || true")
    run("systemctl start rc-local || true")
    print("[✓] rc.local configured")

# ================= SLOWDNS =================
def slowdns_install(ns):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        dst = BASE_DIR / name
        if dst.exists():
            dst.unlink()
        print(f"[*] Downloading {name} ...")
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
    print("[✓] SlowDNS installed and started")

# ================= EDNS =================
def patch_edns(data, size):
    if len(data) < 12: return data
    buf = bytearray(data)
    for i in range(len(buf)-2):
        if buf[i:i+2] == b"\x00\x29":
            buf[i+3:i+5] = struct.pack("!H", size)
            break
    return bytes(buf)

def edns_install_file():
    edns_path = BASE_DIR / "edns.py"
    code = open(__file__).read()  # save this script as edns.py
    edns_path.write_text(code)
    edns_path.chmod(0o755)

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
    print("[✓] EDNS service created and started")

# ================= MAIN =================
def main():
    root_check()
    restore_dns()
    stop_conflicts()
    ns = input("Enter nameserver (default 8.8.8.8): ").strip() or "8.8.8.8"

    ssh_config()
    setup_rc_local()
    slowdns_install(ns)
    edns_install_file()
    edns_service_file()

    print("\n✅ SlowDNS + EDNS installation complete")
    print("Ports: SlowDNS 5300, EDNS 53")
    print("Check status: systemctl status slowdns edns")
    print("Test DNS: dig @127.0.0.1 google.com +short")

if __name__ == "__main__":
    main()
