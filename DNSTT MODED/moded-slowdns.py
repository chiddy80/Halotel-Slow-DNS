#!/usr/bin/env python3
"""
OpenSSH + SlowDNS Installation Script
Python version of the bash script
"""

import os
import subprocess
import sys
import time
import shutil
from pathlib import Path

# ================= CONFIG =================
SSHD_PORT = 22
SLOWDNS_PORT = 5300

# Download URLs
SERVER_KEY_URL = "https://raw.githubusercontent.com/athumani2580/DNS/main/slowdns/server.key"
SERVER_KEY_ALT = "https://raw.githubusercontent.com/athumani2580/DNS/main/server.key"
SERVER_PUB_URL = "https://raw.githubusercontent.com/athumani2580/DNS/main/slowdns/server.pub"
SERVER_PUB_ALT = "https://raw.githubusercontent.com/athumani2580/DNS/main/server.pub"
SERVER_BIN_URL = "https://raw.githubusercontent.com/athumani2580/DNS/main/slowdns/sldns-server"
SERVER_BIN_ALT = "https://raw.githubusercontent.com/athumani2580/DNS/main/slowdns/sldns-server"

SLOWDNS_DIR = "/etc/slowdns"
SLOWDNS_BIN = f"{SLOWDNS_DIR}/sldns-server"

# ================= UTILITIES =================
def print_message(msg, prefix="[+]"):
    """Print colored message"""
    colors = {
        'green': '\033[92m',
        'yellow': '\033[93m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'red': '\033[91m',
        'nc': '\033[0m',
        'blue': '\033[94m'
    }
    print(f"{colors['cyan']}{prefix}{colors['nc']} {msg}")

def print_success(msg):
    print_message(msg, prefix="[✓]")

def print_error(msg):
    print_message(msg, prefix="[✗]")

def run_cmd(cmd, check=True, capture_output=True):
    """Run shell command"""
    try:
        result = subprocess.run(cmd, shell=True, check=check, 
                              capture_output=capture_output, text=True)
        return result
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {cmd}")
        print_error(f"Error: {e.stderr}")
        if check:
            raise
        return e

def root_check():
    """Check if running as root"""
    if os.geteuid() != 0:
        print_error("This script must be run as root")
        sys.exit(1)

def service_is_active(service_name):
    """Check if a systemd service is active"""
    result = run_cmd(f"systemctl is-active {service_name}", check=False)
    return result.returncode == 0

def download_file(url, destination, alt_url=None):
    """Download file with fallback URL"""
    try:
        print_message(f"Downloading {os.path.basename(destination)}...")
        
        # Try wget first
        cmd = f"wget -q -O '{destination}' '{url}'"
        result = run_cmd(cmd, check=False)
        
        if result.returncode != 0 and alt_url:
            print_message("Trying alternative URL...")
            cmd = f"wget -q -O '{destination}' '{alt_url}'"
            result = run_cmd(cmd, check=False)
        
        if result.returncode == 0:
            print_success(f"{os.path.basename(destination)} downloaded")
            return True
        else:
            # Try curl as last resort
            cmd = f"curl -s -o '{destination}' '{url}'"
            result = run_cmd(cmd, check=False)
            if result.returncode == 0:
                print_success(f"{os.path.basename(destination)} downloaded")
                return True
        
        print_error(f"Failed to download {os.path.basename(destination)}")
        return False
    except Exception as e:
        print_error(f"Download error: {e}")
        return False

# ================= MAIN INSTALLATION =================
def main():
    root_check()
    
    print("\n" + "="*60)
    print("OpenSSH + SlowDNS Installation")
    print("="*60)
    
    # ========== STEP 1: DISABLE UFW ==========
    print("\n[1] Disabling UFW...")
    run_cmd("ufw disable 2>/dev/null", check=False)
    if service_is_active("ufw"):
        run_cmd("systemctl stop ufw", check=False)
    run_cmd("systemctl disable ufw 2>/dev/null", check=False)
    print_success("UFW disabled")
    
    # ========== STEP 2: DISABLE systemd-resolved ==========
    print("\n[2] Disabling systemd-resolved...")
    if service_is_active("systemd-resolved"):
        run_cmd("systemctl stop systemd-resolved", check=False)
    run_cmd("systemctl disable systemd-resolved 2>/dev/null", check=False)
    print_success("systemd-resolved disabled")
    
    # ========== STEP 3: CONFIGURE DNS ==========
    print("\n[3] Configuring DNS...")
    resolv_conf = Path("/etc/resolv.conf")
    
    # Remove if it's a symlink
    if resolv_conf.is_symlink():
        try:
            resolv_conf.unlink()
        except:
            pass
    
    # Write new resolv.conf
    try:
        with open("/etc/resolv.conf", "w") as f:
            f.write("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
        
        # Try to make it immutable (may fail, that's OK)
        run_cmd("chattr +i /etc/resolv.conf 2>/dev/null", check=False)
        print_success("DNS configured")
    except Exception as e:
        print_error(f"Failed to configure DNS: {e}")
    
    # ========== STEP 4: CONFIGURE OPENSSH ==========
    print(f"\n[4] Configuring OpenSSH on port {SSHD_PORT}...")
    
    # Backup original config
    ssh_config = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_config):
        try:
            shutil.copy2(ssh_config, ssh_config + ".backup")
            print_success("Backed up original SSH config")
        except:
            pass
    
    # Create new SSH config
    ssh_config_content = f"""# OpenSSH Configuration - Standard Port 22
Port {SSHD_PORT}
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
    
    try:
        with open(ssh_config, "w") as f:
            f.write(ssh_config_content)
        
        # Restart SSH
        run_cmd("systemctl restart sshd", check=False)
        time.sleep(2)
        print_success(f"OpenSSH configured on port {SSHD_PORT}")
    except Exception as e:
        print_error(f"Failed to configure SSH: {e}")
    
    # ========== STEP 5: SETUP SLOWDNS ==========
    print("\n[5] Setting up SlowDNS...")
    
    # Create directory
    try:
        shutil.rmtree(SLOWDNS_DIR, ignore_errors=True)
        Path(SLOWDNS_DIR).mkdir(parents=True, exist_ok=True)
        print_success("SlowDNS directory created")
    except Exception as e:
        print_error(f"Failed to create directory: {e}")
        return
    
    # ========== STEP 6: DOWNLOAD FILES ==========
    print("\n[6] Downloading SlowDNS files...")
    
    files_to_download = [
        (SERVER_KEY_URL, f"{SLOWDNS_DIR}/server.key", SERVER_KEY_ALT),
        (SERVER_PUB_URL, f"{SLOWDNS_DIR}/server.pub", SERVER_PUB_ALT),
        (SERVER_BIN_URL, SLOWDNS_BIN, SERVER_BIN_ALT),
    ]
    
    for url, dest, alt_url in files_to_download:
        if not download_file(url, dest, alt_url):
            print_error(f"Critical: Could not download {os.path.basename(dest)}")
            return
    
    # Make binary executable
    try:
        os.chmod(SLOWDNS_BIN, 0o755)
        print_success("File permissions set")
    except Exception as e:
        print_error(f"Failed to set permissions: {e}")
    
    # ========== STEP 7: GET NAMESERVER ==========
    print("\n" + "="*60)
    print("[ NAMESERVER SETUP ]")
    print("="*60)
    
    nameserver = ""
    while not nameserver:
        try:
            nameserver = input("Enter nameserver (e.g., dns.example.com): ").strip()
            if not nameserver:
                print_error("Nameserver cannot be empty")
        except (EOFError, KeyboardInterrupt):
            print_error("\nInstallation cancelled")
            sys.exit(1)
    
    print(f"\n[7] Configuring with nameserver: {nameserver}")
    
    # ========== STEP 8: CREATE SLOWDNS SERVICE ==========
    print("\n[8] Creating SlowDNS service...")
    
    service_content = f"""[Unit]
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

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open("/etc/systemd/system/slowdns-server.service", "w") as f:
            f.write(service_content)
        
        # Enable and start service
        run_cmd("systemctl daemon-reload", check=False)
        run_cmd("systemctl enable slowdns-server.service", check=False)
        run_cmd("systemctl start slowdns-server.service", check=False)
        
        print_success("SlowDNS service created and started")
    except Exception as e:
        print_error(f"Failed to create service: {e}")
    
    # ========== STEP 9: FIREWALL CONFIGURATION ==========
    print("\n[9] Configuring firewall...")
    
    # Clear existing rules
    run_cmd("iptables -F 2>/dev/null", check=False)
    run_cmd("iptables -t nat -F 2>/dev/null", check=False)
    
    # Allow SSH
    run_cmd(f"iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT", check=False)
    
    # Allow SlowDNS
    run_cmd(f"iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT", check=False)
    
    # Allow established connections
    run_cmd("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT", check=False)
    
    # Allow loopback
    run_cmd("iptables -A INPUT -i lo -j ACCEPT", check=False)
    
    # Drop everything else
    run_cmd("iptables -P INPUT DROP", check=False)
    
    # Save rules
    run_cmd("iptables-save > /etc/iptables/rules.v4 2>/dev/null", check=False)
    run_cmd("systemctl enable netfilter-persistent 2>/dev/null", check=False)
    
    print_success("Firewall configured")
    
    # ========== STEP 10: VERIFICATION ==========
    print("\n[10] Verifying installation...")
    
    print("\nChecking services:")
    services = ["sshd", "slowdns-server"]
    for service in services:
        if service_is_active(service):
            print_success(f"{service} is running")
        else:
            print_error(f"{service} is NOT running")
    
    print("\nChecking ports:")
    ports = [(SSHD_PORT, "tcp"), (SLOWDNS_PORT, "udp")]
    for port, proto in ports:
        result = run_cmd(f"ss -lnp{proto[0]} | grep -q ':{port}'", check=False)
        if result.returncode == 0:
            print_success(f"Port {port}/{proto} is listening")
        else:
            print_error(f"Port {port}/{proto} is NOT listening")
    
    # Show public key
    pubkey_path = f"{SLOWDNS_DIR}/server.pub"
    if os.path.exists(pubkey_path):
        print("\n" + "="*60)
        print("PUBLIC KEY (Copy for clients):")
        print("="*60)
        with open(pubkey_path, "r") as f:
            print(f.read().strip())
        print("="*60)
    
    # Final summary
    print("\n" + "="*60)
    print("INSTALLATION COMPLETE")
    print("="*60)
    print(f"Nameserver:    {nameserver}")
    print(f"SSH Port:      {SSHD_PORT}")
    print(f"SlowDNS Port:  {SLOWDNS_PORT}")
    print(f"Public Key:    Saved in {pubkey_path}")
    print("\nNext steps:")
    print(f"1. Point NS record of {nameserver} to your server IP")
    print("2. Test with: dig @$(curl -s ifconfig.me) test.${nameserver} TXT")
    print("3. Check logs: journalctl -u slowdns-server -f")
    print("="*60)

if __name__ == "__main__":
    main()
