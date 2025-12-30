#!/usr/bin/env python3
"""
COMPLETE SLOWDNS INSTALLATION & SERVER SCRIPT
Replaces the bash script with full functionality
"""

import os
import sys
import time
import socket
import subprocess
import configparser
import urllib.request
import threading
import logging
from pathlib import Path
import shutil
import signal
import atexit

# ============================================================================
# CONFIGURATION
# ============================================================================
class SlowDNSConfig:
    def __init__(self):
        # Default configuration
        self.config = {
            'network': {
                'ssh_port': '22',
                'slowdns_port': '5300', 
                'dns_port': '53',
                'bind_address': '0.0.0.0',
                'mtu': '1400'
            },
            'server': {
                'nameserver': 'dns.example.com'
            }
        }
    
    def get(self, section, key, default=None):
        if section in self.config and key in self.config[section]:
            return self.config[section][key]
        return default
    
    def set(self, section, key, value):
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value

# ============================================================================
# INSTALLATION MANAGER
# ============================================================================
class SlowDNSInstaller:
    def __init__(self):
        self.config = SlowDNSConfig()
        self.base_url = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
        self.install_dir = Path("/etc/slowdns")
        self.log_dir = Path("/var/log/slowdns")
        self.systemd_dir = Path("/etc/systemd/system")
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging for installation"""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_dir / "install.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def print_banner(self):
        """Print installation banner"""
        banner = """
╔══════════════════════════════════════════════════════╗
║           SLOWDNS MODERN INSTALLATION                ║
║           Python Edition - Full Features             ║
╚══════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def check_root(self):
        """Check if running as root"""
        if os.geteuid() != 0:
            self.logger.error("This script must be run as root!")
            print("❌ Please run with: sudo python3 moded-slowdns.py --install")
            sys.exit(1)
    
    def get_nameserver(self):
        """Get nameserver from user"""
        print("\n" + "="*60)
        print("📡 Enter your nameserver configuration")
        print("="*60)
        print("Default: dns.example.com")
        print("Example: tunnel.yourdomain.com")
        print("="*60)
        
        nameserver = input("\nEnter nameserver: ").strip()
        if not nameserver:
            nameserver = "dns.example.com"
        
        self.config.set('server', 'nameserver', nameserver)
        return nameserver
    
    def detect_server_ip(self):
        """Detect server IP address"""
        try:
            # Try multiple methods to get public IP
            import requests
            ip = requests.get('https://api.ipify.org', timeout=5).text
            if ip:
                self.logger.info(f"Detected server IP: {ip}")
                return ip
        except:
            pass
        
        # Fallback to local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            self.logger.info(f"Using local IP: {ip}")
            return ip
        except:
            return "127.0.0.1"
    
    # ============================================================================
    # STEP 1: CONFIGURE OPENSSH
    # ============================================================================
    def configure_ssh(self):
        """Configure OpenSSH server"""
        self.logger.info("Configuring OpenSSH...")
        ssh_port = self.config.get('network', 'ssh_port', '22')
        
        try:
            # Backup SSH config
            ssh_config = Path("/etc/ssh/sshd_config")
            if ssh_config.exists():
                backup = Path("/etc/ssh/sshd_config.backup")
                shutil.copy2(ssh_config, backup)
                self.logger.info("SSH configuration backed up")
            
            # Create optimized SSH config
            ssh_content = f"""# ============================================================================
# SLOWDNS OPTIMIZED SSH CONFIGURATION
# ============================================================================
Port {ssh_port}
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
            
            with open(ssh_config, 'w') as f:
                f.write(ssh_content)
            
            # Restart SSH service
            subprocess.run(["systemctl", "restart", "ssh"], 
                          capture_output=True, check=False)
            
            self.logger.info(f"OpenSSH configured on port {ssh_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure SSH: {e}")
            return False
    
    # ============================================================================
    # STEP 2: DOWNLOAD SLOWDNS COMPONENTS
    # ============================================================================
    def download_components(self):
        """Download SlowDNS binaries and keys"""
        self.logger.info("Downloading SlowDNS components...")
        
        # Create installation directory
        self.install_dir.mkdir(parents=True, exist_ok=True)
        os.chdir(self.install_dir)
        
        components = [
            ("dnstt-server", "dnstt-server"),
            ("server.key", "server.key"),
            ("server.pub", "server.pub")
        ]
        
        for url_name, filename in components:
            try:
                url = f"{self.base_url}/{url_name}"
                self.logger.info(f"Downloading {filename}...")
                
                # Download file
                response = urllib.request.urlopen(url)
                with open(filename, 'wb') as f:
                    f.write(response.read())
                
                # Make binary executable
                if filename == "dnstt-server":
                    os.chmod(filename, 0o755)
                
                self.logger.info(f"✓ Downloaded {filename}")
                
            except Exception as e:
                self.logger.error(f"Failed to download {filename}: {e}")
                return False
        
        return True
    
    # ============================================================================
    # STEP 3: CREATE SYSTEMD SERVICES
    # ============================================================================
    def create_services(self, nameserver):
        """Create systemd services for SlowDNS and EDNS proxy"""
        self.logger.info("Creating systemd services...")
        
        slowdns_port = self.config.get('network', 'slowdns_port', '5300')
        ssh_port = self.config.get('network', 'ssh_port', '22')
        mtu = self.config.get('network', 'mtu', '1400')
        
        # 1. SlowDNS Server Service
        slowdns_service = """[Unit]
Description=SlowDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :{port} -mtu {mtu} -privkey-file /etc/slowdns/server.key {nameserver} 127.0.0.1:{ssh_port}
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
""".format(port=slowdns_port, mtu=mtu, nameserver=nameserver, ssh_port=ssh_port)
        
        with open(self.systemd_dir / "slowdns-server.service", 'w') as f:
            f.write(slowdns_service)
        
        # 2. EDNS Proxy Service (Compiled C version like original)
        edns_service = """[Unit]
Description=EDNS Proxy for SlowDNS
After=slowdns-server.service
Requires=slowdns-server.service

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
        
        with open(self.systemd_dir / "edns-proxy.service", 'w') as f:
            f.write(edns_service)
        
        self.logger.info("✓ Systemd services created")
        return True
    
    # ============================================================================
    # STEP 4: COMPILE AND SETUP EDNS PROXY
    # ============================================================================
    def setup_edns_proxy(self):
        """Compile and setup EDNS proxy"""
        self.logger.info("Setting up EDNS proxy...")
        
        # Create C source code for EDNS proxy
        edns_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096

int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        offset += 5;
    }
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0 && offset + 4 < len) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            if(type == 41) {
                buf[offset+3] = new_size >> 8;
                buf[offset+4] = new_size & 0xFF;
                return len;
            }
        }
        offset++;
    }
    return len;
}

int main() {
    printf("[EDNS Proxy] Starting DNS proxy...\\n");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("[ERROR] socket");
        return 1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[ERROR] bind");
        close(sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port 53\\n");
    
    while(1) {
        unsigned char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                         (struct sockaddr*)&client_addr, &client_len);
        if(len > 0) {
            patch_edns(buffer, len, 1800);
            
            int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if(up_sock >= 0) {
                struct sockaddr_in up_addr;
                memset(&up_addr, 0, sizeof(up_addr));
                up_addr.sin_family = AF_INET;
                up_addr.sin_port = htons(SLOWDNS_PORT);
                inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                
                sendto(up_sock, buffer, len, 0,
                       (struct sockaddr*)&up_addr, sizeof(up_addr));
                
                int resp_len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                if(resp_len > 0) {
                    patch_edns(buffer, resp_len, 512);
                    sendto(sock, buffer, resp_len, 0,
                           (struct sockaddr*)&client_addr, client_len);
                }
                close(up_sock);
            }
        }
    }
    return 0;
}
"""
        
        try:
            # Write C source code
            with open("/tmp/edns.c", 'w') as f:
                f.write(edns_c_code)
            
            # Check if gcc is installed
            if subprocess.run(["which", "gcc"], capture_output=True).returncode != 0:
                self.logger.info("Installing gcc compiler...")
                subprocess.run(["apt", "update", "-qq"], capture_output=True)
                subprocess.run(["apt", "install", "-y", "gcc", "-qq"], capture_output=True)
            
            # Compile EDNS proxy
            self.logger.info("Compiling EDNS proxy...")
            result = subprocess.run(
                ["gcc", "-O3", "/tmp/edns.c", "-o", "/usr/local/bin/edns-proxy"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                os.chmod("/usr/local/bin/edns-proxy", 0o755)
                self.logger.info("✓ EDNS proxy compiled successfully")
                return True
            else:
                self.logger.error(f"Compilation failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to setup EDNS proxy: {e}")
            return False
    
    # ============================================================================
    # STEP 5: CONFIGURE FIREWALL
    # ============================================================================
    def configure_firewall(self):
        """Configure firewall rules"""
        self.logger.info("Configuring firewall...")
        
        ssh_port = self.config.get('network', 'ssh_port', '22')
        slowdns_port = self.config.get('network', 'slowdns_port', '5300')
        
        try:
            # Flush existing rules
            subprocess.run(["iptables", "-F"], capture_output=True)
            subprocess.run(["iptables", "-X"], capture_output=True)
            subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
            
            # Set default policies
            subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], capture_output=True)
            subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], capture_output=True)
            
            # Essential rules
            rules = [
                ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-m", "state", "--state", 
                 "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", ssh_port, "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "udp", "--dport", slowdns_port, "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"]
            ]
            
            for rule in rules:
                subprocess.run(rule, capture_output=True)
            
            # Disable IPv6
            with open("/proc/sys/net/ipv6/conf/all/disable_ipv6", 'w') as f:
                f.write("1")
            
            # Stop conflicting DNS services
            subprocess.run(["systemctl", "stop", "systemd-resolved"], 
                          capture_output=True, check=False)
            subprocess.run(["fuser", "-k", "53/udp"], 
                          capture_output=True, check=False)
            
            self.logger.info("✓ Firewall configured")
            return True
            
        except Exception as e:
            self.logger.error(f"Firewall configuration warning: {e}")
            return True  # Continue even if firewall fails
    
    # ============================================================================
    # STEP 6: START SERVICES
    # ============================================================================
    def start_services(self):
        """Start and enable all services"""
        self.logger.info("Starting services...")
        
        try:
            # Reload systemd
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            
            # Start SlowDNS service
            subprocess.run(["systemctl", "enable", "slowdns-server"], 
                          capture_output=True, check=False)
            subprocess.run(["systemctl", "start", "slowdns-server"], 
                          capture_output=True, check=False)
            
            # Start EDNS proxy service
            subprocess.run(["systemctl", "enable", "edns-proxy"], 
                          capture_output=True, check=False)
            subprocess.run(["systemctl", "start", "edns-proxy"], 
                          capture_output=True, check=False)
            
            # Check if services are running
            time.sleep(3)
            
            slowdns_status = subprocess.run(
                ["systemctl", "is-active", "slowdns-server"],
                capture_output=True,
                text=True
            )
            
            edns_status = subprocess.run(
                ["systemctl", "is-active", "edns-proxy"],
                capture_output=True,
                text=True
            )
            
            if slowdns_status.returncode == 0:
                self.logger.info("✓ SlowDNS service started")
            else:
                self.logger.warning("SlowDNS service may have issues")
            
            if edns_status.returncode == 0:
                self.logger.info("✓ EDNS proxy service started")
            else:
                self.logger.warning("EDNS proxy service may have issues")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start services: {e}")
            return False
    
    # ============================================================================
    # MAIN INSTALLATION
    # ============================================================================
    def install(self):
        """Main installation method"""
        self.print_banner()
        self.check_root()
        
        print("🚀 Starting SlowDNS Installation...")
        print("="*60)
        
        # Get configuration
        nameserver = self.get_nameserver()
        server_ip = self.detect_server_ip()
        
        steps = [
            ("📡 Configuring OpenSSH", self.configure_ssh),
            ("📦 Downloading components", self.download_components),
            ("⚙️ Creating services", lambda: self.create_services(nameserver)),
            ("🔧 Setting up EDNS proxy", self.setup_edns_proxy),
            ("🔥 Configuring firewall", self.configure_firewall),
            ("🚀 Starting services", self.start_services)
        ]
        
        # Execute all steps
        for step_name, step_func in steps:
            print(f"\n{step_name}...")
            if step_func():
                print(f"  ✓ {step_name.split()[1]} completed")
            else:
                print(f"  ✗ {step_name.split()[1]} failed")
                return False
            time.sleep(1)
        
        # Show installation summary
        self.show_summary(nameserver, server_ip)
        return True
    
    def show_summary(self, nameserver, server_ip):
        """Show installation summary"""
        print("\n" + "="*60)
        print("🎉 INSTALLATION COMPLETE!")
        print("="*60)
        print(f"Server IP:     {server_ip}")
        print(f"SSH Port:      {self.config.get('network', 'ssh_port', '22')}")
        print(f"SlowDNS Port:  {self.config.get('network', 'slowdns_port', '5300')}")
        print(f"DNS Port:      53")
        print(f"Nameserver:    {nameserver}")
        print("="*60)
        
        print("\n📋 Quick Commands:")
        print(f"  Test DNS: dig @{server_ip} {nameserver}")
        print(f"  Check status: systemctl status slowdns-server")
        print(f"  View logs: journalctl -u slowdns-server -f")
        
        print("\n⚙️ Management:")
        print("  Restart: systemctl restart slowdns-server edns-proxy")
        print("  Stop: systemctl stop slowdns-server edns-proxy")
        print("  Start: systemctl start slowdns-server edns-proxy")
        
        print("\n" + "="*60)
        print("✅ SlowDNS is now running with all features!")
        print("="*60)
    
    # ============================================================================
    # UNINSTALL METHOD
    # ============================================================================
    def uninstall(self):
        """Uninstall SlowDNS"""
        self.check_root()
        
        print("\n" + "="*60)
        print("🗑️  SLOWDNS UNINSTALLATION")
        print("="*60)
        
        confirm = input("Are you sure you want to uninstall SlowDNS? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Uninstallation cancelled.")
            return
        
        try:
            # Stop and disable services
            subprocess.run(["systemctl", "stop", "slowdns-server", "edns-proxy"], 
                          capture_output=True)
            subprocess.run(["systemctl", "disable", "slowdns-server", "edns-proxy"], 
                          capture_output=True)
            
            # Remove services
            service_files = ["slowdns-server.service", "edns-proxy.service"]
            for service in service_files:
                service_path = self.systemd_dir / service
                if service_path.exists():
                    service_path.unlink()
            
            # Remove binaries
            if Path("/usr/local/bin/edns-proxy").exists():
                Path("/usr/local/bin/edns-proxy").unlink()
            
            # Remove directories (optional - keep configs)
            # shutil.rmtree(self.install_dir, ignore_errors=True)
            # shutil.rmtree(self.log_dir, ignore_errors=True)
            
            # Reload systemd
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            
            print("✓ SlowDNS uninstalled successfully")
            
        except Exception as e:
            print(f"✗ Uninstallation error: {e}")

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================
def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  sudo python3 moded-slowdns.py --install    # Install SlowDNS")
        print("  sudo python3 moded-slowdns.py --uninstall  # Uninstall SlowDNS")
        print("  sudo python3 moded-slowdns.py --status     # Check status")
        sys.exit(1)
    
    installer = SlowDNSInstaller()
    
    if sys.argv[1] == "--install":
        if installer.install():
            sys.exit(0)
        else:
            sys.exit(1)
    elif sys.argv[1] == "--uninstall":
        installer.uninstall()
    elif sys.argv[1] == "--status":
        # Check service status
        subprocess.run(["systemctl", "status", "slowdns-server", "--no-pager"])
    else:
        print(f"Unknown option: {sys.argv[1]}")
        sys.exit(1)

# ============================================================================
# RUN AS SCRIPT
# ============================================================================
if __name__ == "__main__":
    main()
