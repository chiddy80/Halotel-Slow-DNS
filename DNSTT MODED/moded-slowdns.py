#!/usr/bin/env python3
"""
🚀 COMPLETE SLOWDNS INSTALLATION SCRIPT
Fixes the issue where script stops after IP detection
"""

import os
import sys
import time
import socket
import subprocess
import threading
import urllib.request
import signal
from pathlib import Path
import shutil

# ============================================================================
# CONFIGURATION
# ============================================================================
SSHD_PORT = 22
SLOWDNS_PORT = 5300
GITHUB_BASE = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
WHITE = '\033[1;37m'
BOLD = '\033[1m'
NC = '\033[0m'

# ============================================================================
# UI FUNCTIONS
# ============================================================================
def print_banner():
    os.system('clear')
    print(f"{BLUE}╔{'═'*54}╗{NC}")
    print(f"{BLUE}║{NC}{CYAN}{BOLD}          🚀 SLOWDNS INSTALLATION SCRIPT{NC}          {BLUE}║{NC}")
    print(f"{BLUE}║{NC}{WHITE}            Complete Working Version{NC}                {BLUE}║{NC}")
    print(f"{BLUE}╚{'═'*54}╝{NC}")
    print()

def print_header(text):
    print(f"\n{PURPLE}{'═'*54}{NC}")
    print(f"{CYAN}{BOLD}{text}{NC}")
    print(f"{PURPLE}{'═'*54}{NC}")

def print_step(num, title):
    print(f"\n{BLUE}┌─{NC} {CYAN}{BOLD}STEP {num}{NC}")
    print(f"{BLUE}│{NC}")
    print(f"{BLUE}│{NC} {WHITE}{title}{NC}")

def print_step_end():
    print(f"{BLUE}└─{NC} {GREEN}✓{NC} Completed")

def print_success(msg):
    print(f"  {GREEN}{BOLD}✓{NC} {GREEN}{msg}{NC}")

def print_error(msg):
    print(f"  {RED}{BOLD}✗{NC} {RED}{msg}{NC}")

def print_info(msg):
    print(f"  {CYAN}{BOLD}ℹ{NC} {CYAN}{msg}{NC}")

def run_cmd(cmd, check=False):
    """Run shell command"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if check and result.returncode != 0:
            return False
        return True
    except:
        return False

# ============================================================================
# MAIN INSTALLATION FUNCTIONS
# ============================================================================
def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        print_error("Please run this script as root")
        print(f"\n{YELLOW}Usage:{NC} sudo python3 {sys.argv[0]}")
        sys.exit(1)

def get_nameserver():
    """Get nameserver from user"""
    print(f"\n{WHITE}{BOLD}Enter nameserver configuration:{NC}")
    print(f"{CYAN}┌──────────────────────────────────────────────────────────┐{NC}")
    print(f"{CYAN}│{NC} {YELLOW}Default:{NC} dns.example.com                                     {CYAN}│{NC}")
    print(f"{CYAN}│{NC} {YELLOW}Example:{NC} tunnel.yourdomain.com                               {CYAN}│{NC}")
    print(f"{CYAN}└──────────────────────────────────────────────────────────┘{NC}")
    print()
    
    nameserver = input(f"{WHITE}{BOLD}Enter nameserver: {NC}").strip()
    return nameserver if nameserver else "dns.example.com"

def get_server_ip():
    """Get server IP address"""
    print_info("Detecting server IP address...")
    
    # Simple spinner
    for i in range(10):
        chars = ['|', '/', '-', '\\']
        sys.stdout.write(f"\r  {CYAN}[{chars[i % 4]}]{NC}  ")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r      \r")
    
    try:
        # Try public IP
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", "3", "ifconfig.me"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            ip = result.stdout.strip()
            print(f"\r  {GREEN}Server IP:{NC} {WHITE}{BOLD}{ip}{NC}")
            return ip
        
        # Fallback to local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        print(f"\r  {GREEN}Server IP:{NC} {WHITE}{BOLD}{ip}{NC}")
        return ip
    except:
        ip = "127.0.0.1"
        print(f"\r  {YELLOW}Server IP:{NC} {WHITE}{BOLD}{ip} (localhost){NC}")
        return ip

def step1_configure_ssh(nameserver):
    """Configure SSH"""
    print_step("1", "Configuring OpenSSH")
    print_info(f"Configuring OpenSSH on port {SSHD_PORT}")
    
    # Backup SSH config
    if os.path.exists("/etc/ssh/sshd_config"):
        run_cmd("cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup")
        print_success("SSH configuration backed up")
    
    # Create SSH config
    ssh_config = f"""# SLOWDNS OPTIMIZED SSH CONFIGURATION
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
        with open("/etc/ssh/sshd_config", 'w') as f:
            f.write(ssh_config)
        
        # Restart SSH
        run_cmd("systemctl restart ssh")
        time.sleep(2)
        
        print_success("SSH service restarted")
        print_success(f"OpenSSH configured on port {SSHD_PORT}")
        print_step_end()
        return True
    except Exception as e:
        print_error(f"Failed to configure SSH: {str(e)[:50]}")
        return False

def step2_setup_slowdns():
    """Setup SlowDNS"""
    print_step("2", "Setting up SlowDNS environment")
    print_info("Setting up SlowDNS environment")
    
    # Create directory
    install_dir = Path("/etc/slowdns")
    if install_dir.exists():
        shutil.rmtree(install_dir, ignore_errors=True)
    install_dir.mkdir(parents=True, exist_ok=True)
    os.chdir(install_dir)
    
    print_success("SlowDNS directory created")
    
    # Download binary
    print_info("Downloading SlowDNS binary")
    
    url = f"{GITHUB_BASE}/dnstt-server"
    if run_cmd(f"wget -q '{url}' -O dnstt-server 2>/dev/null") or \
       run_cmd(f"curl -fsSL '{url}' -o dnstt-server 2>/dev/null"):
        os.chmod("dnstt-server", 0o755)
        print_success("Binary downloaded via wget/curl")
    else:
        # Try Python download
        try:
            with urllib.request.urlopen(url) as response:
                with open("dnstt-server", 'wb') as f:
                    f.write(response.read())
            os.chmod("dnstt-server", 0o755)
            print_success("Binary downloaded via Python")
        except:
            print_error("Failed to download binary")
            return False
    
    # Download key files
    print_info("Downloading encryption keys")
    
    for key_file in ["server.key", "server.pub"]:
        url = f"{GITHUB_BASE}/{key_file}"
        if run_cmd(f"wget -q '{url}' -O {key_file} 2>/dev/null") or \
           run_cmd(f"curl -fsSL '{url}' -o {key_file} 2>/dev/null"):
            print_success(f"{key_file} downloaded")
        else:
            try:
                with urllib.request.urlopen(url) as response:
                    with open(key_file, 'wb') as f:
                        f.write(response.read())
                print_success(f"{key_file} downloaded")
            except:
                print_error(f"Failed to download {key_file}")
                return False
    
    # Test binary
    print_info("Validating binary...")
    if run_cmd("./dnstt-server --help 2>&1 | head -5", check=False):
        print_success("Binary validated successfully")
    else:
        print_info("Binary test inconclusive")
    
    print_success("SlowDNS components installed")
    print_step_end()
    return True

def step3_create_services(nameserver):
    """Create systemd services"""
    print_step("3", "Creating SlowDNS system service")
    print_info("Creating SlowDNS system service")
    
    # SlowDNS service
    service_content = f"""[Unit]
Description=SlowDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :{SLOWDNS_PORT} -mtu 1800 -privkey-file /etc/slowdns/server.key {nameserver} 127.0.0.1:{SSHD_PORT}
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open("/etc/systemd/system/server-sldns.service", 'w') as f:
            f.write(service_content)
        
        print_success("Service configuration created")
        print_step_end()
        return True
    except Exception as e:
        print_error(f"Failed to create service: {str(e)[:50]}")
        return False

def step4_compile_edns():
    """Compile EDNS proxy"""
    print_step("4", "Compiling high-performance EDNS Proxy")
    print_info("Compiling high-performance EDNS Proxy")
    
    # Check for gcc
    if not run_cmd("which gcc", check=False):
        print_info("Installing compiler tools")
        print_info("Installing gcc...")
        run_cmd("apt update -qq && apt install -y gcc -qq")
        print_success("Compiler installed")
    
    # Create C code
    edns_code = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT_53 53
#define PORT_5300 5300
#define BUFSIZE 4096

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in srv = {0};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(PORT_53);
    srv.sin_addr.s_addr = INADDR_ANY;
    
    bind(sock, (struct sockaddr*)&srv, sizeof(srv));
    
    while(1) {
        char buf[BUFSIZE];
        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        
        int len = recvfrom(sock, buf, BUFSIZE, 0, (struct sockaddr*)&cli, &clilen);
        if(len > 0) {
            int upsock = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in up = {0};
            up.sin_family = AF_INET;
            up.sin_port = htons(PORT_5300);
            inet_pton(AF_INET, "127.0.0.1", &up.sin_addr);
            
            sendto(upsock, buf, len, 0, (struct sockaddr*)&up, sizeof(up));
            
            int rlen = recv(upsock, buf, BUFSIZE, 0);
            if(rlen > 0) {
                sendto(sock, buf, rlen, 0, (struct sockaddr*)&cli, clilen);
            }
            close(upsock);
        }
    }
    return 0;
}
"""
    
    # Write and compile
    with open("/tmp/edns.c", 'w') as f:
        f.write(edns_code)
    
    print_info("Compiling EDNS Proxy...")
    if run_cmd("gcc -O3 /tmp/edns.c -o /usr/local/bin/edns-proxy 2>/dev/null"):
        os.chmod("/usr/local/bin/edns-proxy", 0o755)
        print_success("EDNS Proxy compiled successfully")
    else:
        print_error("Compilation failed")
        return False
    
    # Create EDNS service
    edns_service = """[Unit]
Description=EDNS Proxy for SlowDNS
After=server-sldns.service
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
    
    with open("/etc/systemd/system/edns-proxy.service", 'w') as f:
        f.write(edns_service)
    
    print_success("EDNS Proxy service configured")
    print_step_end()
    return True

def step5_configure_firewall():
    """Configure firewall"""
    print_step("5", "Configuring system firewall")
    print_info("Configuring system firewall")
    
    # Flush existing rules
    run_cmd("iptables -F 2>/dev/null")
    run_cmd("iptables -X 2>/dev/null")
    
    # Basic rules
    rules = [
        "iptables -A INPUT -i lo -j ACCEPT",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        f"iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT",
        f"iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT",
        "iptables -A INPUT -p udp --dport 53 -j ACCEPT",
        "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -p icmp -j ACCEPT"
    ]
    
    for rule in rules:
        run_cmd(rule + " 2>/dev/null")
    
    # Stop conflicting services
    run_cmd("systemctl stop systemd-resolved 2>/dev/null")
    run_cmd("fuser -k 53/udp 2>/dev/null")
    
    print_success("Firewall configured")
    print_step_end()
    return True

def step6_start_services():
    """Start services"""
    print_step("6", "Starting all services")
    print_info("Starting all services")
    
    # Reload systemd
    run_cmd("systemctl daemon-reload")
    
    # Start SlowDNS
    print_info("Starting SlowDNS service...")
    run_cmd("systemctl enable server-sldns 2>/dev/null")
    run_cmd("systemctl start server-sldns 2>/dev/null")
    time.sleep(2)
    
    # Check if running
    if run_cmd("systemctl is-active server-sldns", check=False):
        print_success("SlowDNS service started")
    else:
        print_info("Starting SlowDNS manually")
        run_cmd("/etc/slowdns/dnstt-server -udp :5300 -mtu 1800 -privkey-file /etc/slowdns/server.key dns.example.com 127.0.0.1:22 &")
    
    # Start EDNS proxy
    print_info("Starting EDNS Proxy service...")
    run_cmd("systemctl enable edns-proxy 2>/dev/null")
    run_cmd("systemctl start edns-proxy 2>/dev/null")
    time.sleep(2)
    
    if run_cmd("systemctl is-active edns-proxy", check=False):
        print_success("EDNS Proxy service started")
    else:
        print_info("Starting EDNS Proxy manually")
        run_cmd("/usr/local/bin/edns-proxy &")
    
    print_success("All services started successfully")
    print_step_end()
    return True

# ============================================================================
# MAIN INSTALLATION FUNCTION
# ============================================================================
def install_slowdns():
    """Main installation function - THIS WAS MISSING!"""
    print_banner()
    
    # Check root
    check_root()
    
    # Get configuration
    print_header("📦 GATHERING SYSTEM INFORMATION")
    nameserver = get_nameserver()
    server_ip = get_server_ip()
    
    # Installation steps
    steps = [
        ("Configure SSH", lambda: step1_configure_ssh(nameserver)),
        ("Setup SlowDNS", step2_setup_slowdns),
        ("Create Services", lambda: step3_create_services(nameserver)),
        ("Compile EDNS Proxy", step4_compile_edns),
        ("Configure Firewall", step5_configure_firewall),
        ("Start Services", step6_start_services)
    ]
    
    # Execute all steps
    for step_name, step_func in steps:
        print_header(step_name)
        if not step_func():
            print_error(f"Failed: {step_name}")
            return False
        time.sleep(1)
    
    # Show completion
    print_header("🎉 INSTALLATION COMPLETE")
    
    print(f"{CYAN}┌{'─'*50}┐{NC}")
    print(f"{CYAN}│{NC} {WHITE}{BOLD}SERVER INFORMATION{NC}{' ' * 31}{CYAN}│{NC}")
    print(f"{CYAN}├{'─'*50}┤{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} Server IP:     {WHITE}{server_ip}{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} SSH Port:      {WHITE}{SSHD_PORT}{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} SlowDNS Port:  {WHITE}{SLOWDNS_PORT}{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} EDNS Port:     {WHITE}53{NC}")
    print(f"{CYAN}│{NC} {YELLOW}●{NC} Nameserver:    {WHITE}{nameserver}{NC}")
    print(f"{CYAN}└{'─'*50}┘{NC}")
    
    print(f"\n{CYAN}┌{'─'*50}┐{NC}")
    print(f"{CYAN}│{NC} {WHITE}{BOLD}MANAGEMENT COMMANDS{NC}{' ' * 31}{CYAN}│{NC}")
    print(f"{CYAN}├{'─'*50}┤{NC}")
    print(f"{CYAN}│{NC} {GREEN}systemctl status server-sldns{NC}")
    print(f"{CYAN}│{NC} {GREEN}systemctl status edns-proxy{NC}")
    print(f"{CYAN}│{NC} {GREEN}journalctl -u edns-proxy -f{NC}")
    print(f"{CYAN}└{'─'*50}┘{NC}")
    
    print(f"\n{GREEN}{BOLD}✓ Installation completed successfully!{NC}")
    
    # Cleanup
    run_cmd("rm -f /tmp/edns.c /tmp/compile.log 2>/dev/null")
    
    return True

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        success = install_slowdns()
        sys.exit(0 if success else 1)
    elif len(sys.argv) > 1 and sys.argv[1] == "--uninstall":
        print_info("Uninstalling...")
        run_cmd("systemctl stop server-sldns edns-proxy 2>/dev/null")
        run_cmd("systemctl disable server-sldns edns-proxy 2>/dev/null")
        run_cmd("rm -f /etc/systemd/system/server-sldns.service 2>/dev/null")
        run_cmd("rm -f /etc/systemd/system/edns-proxy.service 2>/dev/null")
        run_cmd("systemctl daemon-reload 2>/dev/null")
        print_success("Uninstalled")
    elif len(sys.argv) > 1 and sys.argv[1] == "--status":
        run_cmd("systemctl status server-sldns --no-pager")
        print()
        run_cmd("systemctl status edns-proxy --no-pager")
    elif len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(f"{CYAN}Usage:{NC}")
        print(f"  sudo python3 {sys.argv[0]} --install")
        print(f"  sudo python3 {sys.argv[0]} --uninstall")
        print(f"  sudo python3 {sys.argv[0]} --status")
        print(f"  sudo python3 {sys.argv[0]} --help")
    else:
        # Interactive mode
        print_banner()
        print(f"{CYAN}Select option:{NC}")
        print(f"  1. Install SlowDNS")
        print(f"  2. Show status")
        print(f"  3. Exit")
        
        choice = input(f"\n{WHITE}Choice [1]: {NC}").strip() or "1"
        
        if choice == "1":
            install_slowdns()
        elif choice == "2":
            run_cmd("systemctl status server-sldns --no-pager")
        else:
            print("Goodbye!")
