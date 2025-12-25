#!/usr/bin/env python3
"""
SLOWDNS + OPENSSH INSTALLER - ALWAYS INTERACTIVE
Force interactive mode even when piped
"""

import os
import sys
import time
import shutil
import subprocess
import tempfile
import select
import tty
import termios
from pathlib import Path

# ============= GLOBAL CONFIG =============
SSHD_PORT = 22
SLOWDNS_PORT = 5300

# YOUR GitHub URLs
SERVER_KEY_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
SERVER_PUB_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
SERVER_BIN_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"

SLOWDNS_DIR = "/etc/slowdns"
SLOWDNS_BIN = f"{SLOWDNS_DIR}/dnstt-server"

# ============= FORCE INTERACTIVE INPUT =============
def force_interactive_input():
    """Force interactive input even when piped"""
    # Try to open /dev/tty for direct terminal access
    try:
        tty_fd = os.open('/dev/tty', os.O_RDWR)
        old_settings = termios.tcgetattr(tty_fd)
        
        print("\n" + "="*60)
        print("    SLOWDNS + OPENSSH INSTALLER")
        print("="*60)
        print()
        
        # Ask for domain
        prompt = "Enter your DNS hostname (e.g., dns.yourdomain.com): "
        
        # Write to terminal
        os.write(tty_fd, prompt.encode())
        
        # Read from terminal
        domain = ""
        while True:
            char = os.read(tty_fd, 1).decode()
            if char == '\n' or char == '\r':
                break
            domain += char
            os.write(tty_fd, char.encode())
        
        os.write(tty_fd, b'\n')
        termios.tcsetattr(tty_fd, termios.TCSADRAIN, old_settings)
        os.close(tty_fd)
        
        return domain.strip()
    except:
        # Fallback: use command line argument or environment variable
        if len(sys.argv) > 1:
            return sys.argv[1]
        
        # Try to read from environment
        env_domain = os.getenv('SLOWDNS_DOMAIN')
        if env_domain:
            return env_domain
        
        # Last resort: ask via fallback
        print("\n" + "="*60)
        print("ERROR: Cannot get interactive input")
        print("="*60)
        print("\nPlease run the script in one of these ways:")
        print("1. Download and run: wget ... && python3 script.py")
        print("2. With domain argument: curl ... | python3 - 'your-domain.com'")
        print("3. Set environment: export SLOWDNS_DOMAIN='your-domain.com' && curl ... | python3")
        print("\nOr use this alternative install method:")
        print("wget https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/moded-slowdns.py -O install.py")
        print("python3 install.py")
        sys.exit(1)

# ============= UTILITIES =============
def print_success(msg):
    print(f"  \033[92m✓\033[0m {msg}")

def print_error(msg):
    print(f"  \033[91m✗\033[0m {msg}")

def print_step(msg):
    print(f"\n\033[94m▶\033[0m {msg}")

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode == 0, result.stdout, result.stderr

# ============= MAIN INSTALLATION =============
def main():
    # Get domain FIRST - before anything else
    domain = force_interactive_input()
    
    if not domain:
        print_error("Domain is required!")
        sys.exit(1)
    
    print(f"\nInstalling with domain: \033[93m{domain}\033[0m")
    
    # Check root
    if os.geteuid() != 0:
        print_error("Must run as root!")
        sys.exit(1)
    
    # Start installation
    print_step("1. Preparing system...")
    
    # Update packages
    run_cmd("apt-get update -qq")
    run_cmd("apt-get install -y openssh-server wget curl iptables iptables-persistent")
    print_success("System prepared")
    
    print_step("2. Configuring DNS...")
    
    # Fix resolv.conf (Python 3.7 compatible)
    try:
        os.unlink("/etc/resolv.conf")
    except:
        pass
    
    with open("/etc/resolv.conf", "w") as f:
        f.write("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
    print_success("DNS configured")
    
    print_step("3. Configuring SSH...")
    
    # SSH config
    ssh_config = f"""Port {SSHD_PORT}
PermitRootLogin yes
PasswordAuthentication yes
UseDNS no
AllowTcpForwarding yes
GatewayPorts yes
"""
    
    with open("/etc/ssh/sshd_config", "w") as f:
        f.write(ssh_config)
    
    run_cmd("systemctl restart ssh")
    print_success(f"SSH configured on port {SSHD_PORT}")
    
    print_step("4. Setting up SlowDNS...")
    
    # Create directory
    Path(SLOWDNS_DIR).mkdir(parents=True, exist_ok=True)
    
    # Download files
    files = [
        (SERVER_KEY_URL, f"{SLOWDNS_DIR}/server.key"),
        (SERVER_PUB_URL, f"{SLOWDNS_DIR}/server.pub"),
        (SERVER_BIN_URL, SLOWDNS_BIN),
    ]
    
    for url, dest in files:
        success, out, err = run_cmd(f"wget -q -O '{dest}' '{url}' || curl -s -o '{dest}' '{url}'")
        if success:
            print_success(f"Downloaded {os.path.basename(dest)}")
        else:
            print_error(f"Failed to download {os.path.basename(dest)}")
    
    # Make executable
    os.chmod(SLOWDNS_BIN, 0o755)
    
    print_step("5. Creating service...")
    
    # Create systemd service
    service_content = f"""[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart={SLOWDNS_BIN} -udp :{SLOWDNS_PORT} -mtu 1232 -privkey-file {SLOWDNS_DIR}/server.key {domain} 127.0.0.1:{SSHD_PORT}
Restart=always

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/slowdns-server.service", "w") as f:
        f.write(service_content)
    
    print_success(f"Service created for {domain}")
    
    print_step("6. Configuring firewall...")
    
    # Firewall rules
    run_cmd("iptables -F")
    run_cmd(f"iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT")
    run_cmd(f"iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT")
    run_cmd("iptables-save > /etc/iptables/rules.v4")
    print_success("Firewall configured")
    
    print_step("7. Starting services...")
    
    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl enable slowdns-server")
    run_cmd("systemctl start slowdns-server")
    print_success("Services started")
    
    # Show public key
    pubkey_path = f"{SLOWDNS_DIR}/server.pub"
    if os.path.exists(pubkey_path):
        print(f"\n{'='*60}")
        print("PUBLIC KEY (for clients):")
        print("="*60)
        with open(pubkey_path, "r") as f:
            print(f.read().strip())
        print("="*60)
    
    # Final
    print(f"\n\033[92m✅ INSTALLATION COMPLETE!\033[0m")
    print(f"\nDomain: {domain}")
    print(f"SSH Port: {SSHD_PORT}")
    print(f"SlowDNS Port: {SLOWDNS_PORT}")
    print(f"\nNow configure your domain's NS record to point to this server!")

if __name__ == "__main__":
    main()
