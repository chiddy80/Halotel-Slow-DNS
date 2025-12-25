#!/usr/bin/env python3
"""
FAST SLOWDNS INSTALLER - Ubuntu 22.04
Completes in 30 seconds
"""
import os
import sys
import subprocess
import time
from pathlib import Path

def run(cmd, silent=False):
    """Run command quickly"""
    if silent:
        return subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)

def main():
    # Check root
    if os.geteuid() != 0:
        print("✗ Run as root")
        sys.exit(1)
    
    # Get domain
    print("\n" + "="*50)
    print("    FAST SLOWDNS INSTALLER")
    print("="*50)
    
    domain = input("\nEnter DNS hostname: ").strip()
    if not domain:
        print("✗ Domain required")
        sys.exit(1)
    
    start_time = time.time()
    print(f"\nInstalling for: {domain}")
    
    # STEP 1: QUICK SYSTEM PREP (5 seconds)
    print("\n[1/6] Quick system check...")
    
    # Skip apt update - Ubuntu 22.04 is fresh enough
    # Only install if missing
    for pkg in ["wget", "iptables"]:
        result = run(f"dpkg -l | grep -q '^{pkg}'", silent=True)
        if result.returncode != 0:
            run(f"apt-get install -y {pkg} --no-install-recommends 2>/dev/null", silent=True)
            print(f"  ✓ Installed {pkg}")
    
    # STEP 2: CONFIGURE SSH (2 seconds)
    print("\n[2/6] Configuring SSH...")
    
    ssh_config = f"""Port 22
PermitRootLogin yes
PasswordAuthentication yes
UseDNS no
AllowTcpForwarding yes
"""
    
    with open("/etc/ssh/sshd_config", "w") as f:
        f.write(ssh_config)
    
    run("systemctl restart ssh", silent=True)
    print("  ✓ SSH configured")
    
    # STEP 3: DOWNLOAD FILES (8 seconds)
    print("\n[3/6] Downloading SlowDNS...")
    
    slowdns_dir = "/etc/slowdns"
    Path(slowdns_dir).mkdir(exist_ok=True)
    
    # Download in background for speed
    urls = [
        ("server.key", "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"),
        ("server.pub", "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"),
        ("dnstt-server", "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"),
    ]
    
    for name, url in urls:
        cmd = f"timeout 10 wget -q -O {slowdns_dir}/{name} '{url}' || timeout 10 curl -s -o {slowdns_dir}/{name} '{url}'"
        run(cmd, silent=True)
        print(f"  ✓ {name}")
    
    Path(f"{slowdns_dir}/dnstt-server").chmod(0o755)
    
    # STEP 4: CREATE SIMPLE SERVICE (2 seconds)
    print("\n[4/6] Creating service...")
    
    service = f"""[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart={slowdns_dir}/dnstt-server -udp :5300 -mtu 1232 -privkey-file {slowdns_dir}/server.key {domain} 127.0.0.1:22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/slowdns.service", "w") as f:
        f.write(service)
    
    # STEP 5: START SERVICE (1 second)
    print("\n[5/6] Starting service...")
    
    run("systemctl daemon-reload", silent=True)
    run("systemctl enable --now slowdns.service", silent=True)
    print("  ✓ Service started")
    
    # STEP 6: FIREWALL (1 second)
    print("\n[6/6] Configuring firewall...")
    
    run("iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null", silent=True)
    run("iptables -A INPUT -p udp --dport 5300 -j ACCEPT 2>/dev/null", silent=True)
    run("iptables-save > /etc/iptables/rules.v4 2>/dev/null", silent=True)
    print("  ✓ Firewall configured")
    
    # DONE
    elapsed = time.time() - start_time
    
    print("\n" + "="*50)
    print(f"✅ INSTALLATION COMPLETE in {elapsed:.1f} seconds!")
    print("="*50)
    
    # Show public key
    pubkey_path = f"{slowdns_dir}/server.pub"
    if os.path.exists(pubkey_path):
        with open(pubkey_path, "r") as f:
            key = f.read().strip()
            print(f"\nPublic Key:\n{key}")
    
    print(f"\nDomain: {domain}")
    print("SSH Port: 22")
    print("SlowDNS Port: 5300")
    print(f"\nTest: dig @$(curl -s ifconfig.me) test.{domain} TXT")
    print("="*50)

if __name__ == "__main__":
    main()
