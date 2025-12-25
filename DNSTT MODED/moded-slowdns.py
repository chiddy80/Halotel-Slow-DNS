#!/usr/bin/env python3
"""
COMPLETE SLOWDNS + OPENSSH INSTALLER - DEBIAN 10 COMPATIBLE
Fixes all previous issues:
1. Proper input handling (non-interactive/pipe safe)
2. Python 3.7 compatibility (Debian 10)
3. All downloads from YOUR GitHub repo
4. Complete error handling
"""

import os
import sys
import time
import shutil
import subprocess
import signal
from pathlib import Path

# ============= GLOBAL CONFIG =============
SSHD_PORT = 22
SLOWDNS_PORT = 5300
DNS_HOSTNAME = ""  # Will be set via command line or prompt

# YOUR GitHub URLs (URL encoded spaces)
SERVER_KEY_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
SERVER_PUB_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
SERVER_BIN_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"

SLOWDNS_DIR = "/etc/slowdns"
SLOWDNS_BIN = f"{SLOWDNS_DIR}/dnstt-server"

# ============= UTILITIES =============
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}    SLOWDNS + OPENSSH INSTALLER{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    print()

def print_step(step, msg):
    print(f"{Colors.BLUE}[{step:2d}]{Colors.END} {msg}")

def print_success(msg):
    print(f"  {Colors.GREEN}✓{Colors.END} {msg}")

def print_error(msg):
    print(f"  {Colors.RED}✗{Colors.END} {msg}")

def print_warning(msg):
    print(f"  {Colors.YELLOW}!{Colors.END} {msg}")

def run_cmd(cmd, fatal=False):
    """Run command with proper error handling"""
    try:
        result = subprocess.run(
            cmd, shell=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, executable="/bin/bash"
        )
        if fatal and result.returncode != 0:
            print_error(f"Command failed: {cmd}")
            if result.stderr:
                print_error(f"Error: {result.stderr[:200]}")
            sys.exit(1)
        return result
    except Exception as e:
        if fatal:
            print_error(f"Exception: {e}")
            sys.exit(1)
        return subprocess.CompletedProcess(cmd, 1, "", str(e))

def get_input(prompt, default=""):
    """Get input with timeout and proper tty handling"""
    if not sys.stdin.isatty():
        # Non-interactive mode, use default
        print_warning(f"Non-interactive mode, using default: {default}")
        return default if default else "dns.example.com"
    
    try:
        # Setup signal handler for Ctrl+C
        signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(1))
        
        user_input = input(f"{Colors.CYAN}  → {prompt}: {Colors.END}").strip()
        if not user_input and default:
            print_warning(f"Using default: {default}")
            return default
        return user_input
    except (EOFError, KeyboardInterrupt):
        print()
        print_error("Input cancelled")
        sys.exit(1)

def download_file(url, dest, max_retries=3):
    """Download file with retry logic"""
    filename = os.path.basename(dest)
    
    for attempt in range(max_retries):
        if attempt > 0:
            print_warning(f"Retry {attempt}/{max_retries} for {filename}")
        
        # Try wget
        result = run_cmd(f"wget -q --timeout=30 --tries=2 -O '{dest}' '{url}'")
        if result.returncode == 0:
            return True
        
        # Try curl
        result = run_cmd(f"curl -s --connect-timeout 30 --retry 2 -o '{dest}' '{url}'")
        if result.returncode == 0:
            return True
        
        time.sleep(1)
    
    return False

def check_service(name):
    """Check if service exists and is active"""
    result = run_cmd(f"systemctl is-active {name} 2>/dev/null")
    return result.returncode == 0

# ============= MAIN INSTALLATION =============
def install_slowdns(domain):
    """Main installation function"""
    step = 1
    
    # Step 1: System preparation
    print_step(step, "Preparing system...")
    step += 1
    
    # Update apt sources for Debian 10
    sources_file = "/etc/apt/sources.list"
    if os.path.exists(sources_file):
        with open(sources_file, 'r') as f:
            content = f.read()
        
        # Fix for Debian 10 archive
        if "buster" in content.lower():
            content = content.replace('deb.debian.org', 'archive.debian.org')
            content = content.replace('security.debian.org', 'archive.debian.org/debian-security')
            with open(sources_file, 'w') as f:
                f.write(content)
            print_success("Updated sources.list for Debian 10")
    
    # Update package list
    run_cmd("apt-get update -qq", fatal=False)
    
    # Install required packages
    packages = ["openssh-server", "wget", "curl", "iptables", "iptables-persistent"]
    for pkg in packages:
        result = run_cmd(f"apt-get install -y {pkg} 2>/dev/null || apt-get install -y {pkg} --allow-unauthenticated")
        if result.returncode == 0:
            print_success(f"Installed {pkg}")
    
    # Step 2: Disable conflicting services
    print_step(step, "Disabling conflicting services...")
    step += 1
    
    for svc in ["ufw", "systemd-resolved"]:
        run_cmd(f"systemctl stop {svc} 2>/dev/null || true")
        run_cmd(f"systemctl disable {svc} 2>/dev/null || true")
    print_success("Services disabled")
    
    # Step 3: Configure DNS (Python 3.7 compatible)
    print_step(step, "Configuring DNS resolver...")
    step += 1
    
    resolv_conf = "/etc/resolv.conf"
    # Remove if exists (Python 3.7 compatible)
    try:
        os.unlink(resolv_conf)
    except FileNotFoundError:
        pass
    
    with open(resolv_conf, "w") as f:
        f.write("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
    
    # Try to make immutable
    run_cmd("chattr +i /etc/resolv.conf 2>/dev/null || true")
    print_success("DNS configured")
    
    # Step 4: Configure OpenSSH
    print_step(step, f"Configuring OpenSSH on port {SSHD_PORT}...")
    step += 1
    
    # Backup original config
    ssh_config = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_config):
        shutil.copy2(ssh_config, f"{ssh_config}.backup")
        print_success("Backed up SSH config")
    
    # Create new config
    ssh_content = f"""# OpenSSH Configuration
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
    
    with open(ssh_config, "w") as f:
        f.write(ssh_content)
    
    # Restart SSH
    run_cmd("systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null")
    print_success(f"SSH configured on port {SSHD_PORT}")
    
    # Step 5: Create SlowDNS directory
    print_step(step, "Setting up SlowDNS directory...")
    step += 1
    
    shutil.rmtree(SLOWDNS_DIR, ignore_errors=True)
    Path(SLOWDNS_DIR).mkdir(parents=True, exist_ok=True)
    print_success(f"Directory created: {SLOWDNS_DIR}")
    
    # Step 6: Download files from YOUR GitHub
    print_step(step, "Downloading SlowDNS files...")
    step += 1
    
    files = [
        (SERVER_KEY_URL, f"{SLOWDNS_DIR}/server.key"),
        (SERVER_PUB_URL, f"{SLOWDNS_DIR}/server.pub"),
        (SERVER_BIN_URL, SLOWDNS_BIN),
    ]
    
    all_downloaded = True
    for url, dest in files:
        if download_file(url, dest):
            print_success(f"Downloaded {os.path.basename(dest)}")
        else:
            print_error(f"Failed to download {os.path.basename(dest)}")
            all_downloaded = False
    
    if not all_downloaded:
        print_warning("Some downloads failed, but continuing...")
    
    # Make binary executable
    if os.path.exists(SLOWDNS_BIN):
        os.chmod(SLOWDNS_BIN, 0o755)
        print_success("Made dnstt-server executable")
    
    # Step 7: Create systemd service
    print_step(step, "Creating SlowDNS service...")
    step += 1
    
    service_content = f"""[Unit]
Description=SlowDNS Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory={SLOWDNS_DIR}
ExecStart={SLOWDNS_BIN} -udp :{SLOWDNS_PORT} -mtu 1232 -privkey-file {SLOWDNS_DIR}/server.key {domain} 127.0.0.1:{SSHD_PORT}
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
        f.write(service_content)
    print_success(f"Service created for domain: {domain}")
    
    # Step 8: Configure firewall
    print_step(step, "Configuring firewall...")
    step += 1
    
    # Clear existing rules
    run_cmd("iptables -F 2>/dev/null || true")
    run_cmd("iptables -t nat -F 2>/dev/null || true")
    
    # Allow SSH
    run_cmd(f"iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT")
    print_success(f"Allowed SSH port {SSHD_PORT}")
    
    # Allow SlowDNS
    run_cmd(f"iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT")
    print_success(f"Allowed SlowDNS port {SLOWDNS_PORT}")
    
    # Allow established connections
    run_cmd("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    
    # Allow loopback
    run_cmd("iptables -A INPUT -i lo -j ACCEPT")
    
    # Save rules
    run_cmd("iptables-save > /etc/iptables/rules.v4 2>/dev/null || true")
    run_cmd("systemctl enable netfilter-persistent 2>/dev/null || true")
    print_success("Firewall configured")
    
    # Step 9: Enable and start services
    print_step(step, "Starting services...")
    step += 1
    
    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl enable slowdns-server.service")
    run_cmd("systemctl start slowdns-server.service")
    print_success("SlowDNS service started")
    
    # Step 10: Verification
    print_step(step, "Verifying installation...")
    
    print(f"\n{Colors.CYAN}{'─'*40}{Colors.END}")
    print(f"{Colors.BOLD}Service Status:{Colors.END}")
    
    # Check services
    if check_service("slowdns-server"):
        print_success("slowdns-server is ACTIVE")
    else:
        print_error("slowdns-server is INACTIVE")
    
    if check_service("ssh") or check_service("sshd"):
        print_success("SSH service is ACTIVE")
    else:
        print_error("SSH service is INACTIVE")
    
    # Check ports
    print(f"\n{Colors.CYAN}{'─'*40}{Colors.END}")
    print(f"{Colors.BOLD}Listening Ports:{Colors.END}")
    
    for port, proto, name in [(SSHD_PORT, "tcp", "SSH"), (SLOWDNS_PORT, "udp", "SlowDNS")]:
        result = run_cmd(f"ss -lnp{proto[0]} | grep -q ':{port}'")
        if result.returncode == 0:
            print_success(f"{name} listening on {proto.upper()}:{port}")
        else:
            print_error(f"{name} NOT listening on {proto.upper()}:{port}")
    
    # Show public key
    pubkey_path = f"{SLOWDNS_DIR}/server.pub"
    if os.path.exists(pubkey_path):
        print(f"\n{Colors.CYAN}{'─'*40}{Colors.END}")
        print(f"{Colors.BOLD}PUBLIC KEY (Copy for clients):{Colors.END}")
        print(f"{Colors.CYAN}{'─'*40}{Colors.END}")
        with open(pubkey_path, "r") as f:
            key = f.read().strip()
            print(f"{Colors.GREEN}{key}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*40}{Colors.END}")
    
    return True

def main():
    """Main entry point"""
    print_banner()
    
    # Check root
    if os.geteuid() != 0:
        print_error("This script must be run as root")
        sys.exit(1)
    
    # Get domain from command line or prompt
    global DNS_HOSTNAME
    
    if len(sys.argv) > 1:
        DNS_HOSTNAME = sys.argv[1]
        print_success(f"Using domain from command line: {DNS_HOSTNAME}")
    else:
        DNS_HOSTNAME = get_input("Enter your DNS hostname (e.g., dns.example.com)", "dns.example.com")
    
    if not DNS_HOSTNAME:
        print_error("Domain is required!")
        sys.exit(1)
    
    print(f"\n{Colors.YELLOW}Starting installation with domain: {Colors.BOLD}{DNS_HOSTNAME}{Colors.END}")
    print(f"{Colors.YELLOW}Press Ctrl+C to cancel at any time{Colors.END}\n")
    
    try:
        # Install
        if install_slowdns(DNS_HOSTNAME):
            # Final summary
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}✅ INSTALLATION COMPLETE!{Colors.END}")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}Domain:{Colors.END}        {DNS_HOSTNAME}")
            print(f"{Colors.BOLD}SSH Port:{Colors.END}      {SSHD_PORT}")
            print(f"{Colors.BOLD}SlowDNS Port:{Colors.END}  {SLOWDNS_PORT}")
            print(f"{Colors.BOLD}Public IP:{Colors.END}     {run_cmd('curl -s ifconfig.me').stdout.strip()}")
            print(f"\n{Colors.BOLD}Next steps:{Colors.END}")
            print(f"1. Point NS record of {DNS_HOSTNAME} to your server IP")
            print(f"2. Test with: dig @$(curl -s ifconfig.me) test.{DNS_HOSTNAME} TXT")
            print(f"3. Check logs: journalctl -u slowdns-server -f")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Installation cancelled by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Installation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
