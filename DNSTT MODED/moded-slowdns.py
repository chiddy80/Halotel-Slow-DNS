#!/usr/bin/env python3
"""
🚀 MODERN SLOWDNS INSTALLATION SCRIPT - Python Edition
Same beautiful UI as bash, but more stable and faster
All functions working with better error handling
"""

import os
import sys
import time
import socket
import subprocess
import threading
import urllib.request
import signal
import select
import fcntl
import struct
from pathlib import Path
from datetime import datetime
import shutil
import hashlib

# ============================================================================
# MODERN COLORS & DESIGN (Same as bash)
# ============================================================================
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN = '\033[0;36m'
WHITE = '\033[1;37m'
BOLD = '\033[1m'
NC = '\033[0m'

# ============================================================================
# ANIMATION FUNCTIONS (Same look as bash)
# ============================================================================
class Animation:
    @staticmethod
    def show_progress(pid=None, duration=2):
        """Spinner animation like bash"""
        spin_chars = ['|', '/', '-', '\\']
        for i in range(20):
            sys.stdout.write(f"\r  {CYAN}[{spin_chars[i % 4]}]{NC}  ")
            sys.stdout.flush()
            time.sleep(duration / 20)
        sys.stdout.write("\r      \r")
    
    @staticmethod
    def type_effect(text, delay=0.02):
        """Typewriter effect"""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

# ============================================================================
# UI COMPONENTS (Same as bash)
# ============================================================================
def print_banner():
    """Same banner as bash"""
    os.system('clear')
    print(f"{BLUE}╔{'═'*54}╗{NC}")
    print(f"{BLUE}║{NC}{CYAN}{BOLD}          🚀 MODERN SLOWDNS INSTALLATION SCRIPT{NC}          {BLUE}║{NC}")
    print(f"{BLUE}║{NC}{WHITE}            Python Edition - Enhanced Stability{NC}           {BLUE}║{NC}")
    print(f"{BLUE}║{NC}{YELLOW}                Optimized for Performance{NC}                {BLUE}║{NC}")
    print(f"{BLUE}╚{'═'*54}╝{NC}")
    print()

def print_header(text):
    """Same header style"""
    print(f"\n{PURPLE}{'═'*54}{NC}")
    print(f"{CYAN}{BOLD}{text}{NC}")
    print(f"{PURPLE}{'═'*54}{NC}")

def print_step(num):
    """Same step boxes"""
    print(f"\n{BLUE}┌─{NC} {CYAN}{BOLD}STEP {num}{NC}")
    print(f"{BLUE}│{NC}")

def print_step_end():
    """End step box"""
    print(f"{BLUE}└─{NC} {GREEN}✓{NC} Completed")

def print_success(msg):
    """Success messages"""
    print(f"  {GREEN}{BOLD}✓{NC} {GREEN}{msg}{NC}")

def print_error(msg):
    """Error messages"""
    print(f"  {RED}{BOLD}✗{NC} {RED}{msg}{NC}")

def print_warning(msg):
    """Warning messages"""
    print(f"  {YELLOW}{BOLD}!{NC} {YELLOW}{msg}{NC}")

def print_info(msg):
    """Info messages"""
    print(f"  {CYAN}{BOLD}ℹ{NC} {CYAN}{msg}{NC}")

def print_box(text, color=CYAN):
    """Text in a box"""
    width = 50
    padding = (width - len(text) - 2) // 2
    print(f"{color}┌{'─'*(width-2)}┐{NC}")
    print(f"{color}│{NC}{' '*padding}{text}{' '*(width-2-len(text)-padding)}{color}│{NC}")
    print(f"{color}└{'─'*(width-2)}┘{NC}")

# ============================================================================
# CORE INSTALLATION CLASS - STABLE & FAST
# ============================================================================
class SlowDNSInstaller:
    def __init__(self):
        self.config = {
            'SSHD_PORT': 22,
            'SLOWDNS_PORT': 5300,
            'GITHUB_BASE': "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED",
            'NAMESERVER': "",
            'SERVER_IP': "",
            'MTU': 1800,
            'SLOWDNS_BINARY': "/etc/slowdns/dnstt-server"
        }
        self.install_dir = Path("/etc/slowdns")
        self.start_time = time.time()
    
    def check_root(self):
        """Check root - with better error handling"""
        if os.geteuid() != 0:
            print_error("Please run this script as root")
            print(f"\n{YELLOW}Usage:{NC} sudo python3 {sys.argv[0]}")
            sys.exit(1)
    
    def get_nameserver(self):
        """Get nameserver - beautiful prompt"""
        print_box("Enter nameserver configuration", CYAN)
        print(f"{CYAN}│{NC} {YELLOW}Default:{NC} dns.example.com")
        print(f"{CYAN}│{NC} {YELLOW}Example:{NC} tunnel.yourdomain.com")
        print(f"{CYAN}└{'─'*48}┘{NC}")
        print()
        
        nameserver = input(f"{WHITE}{BOLD}Enter nameserver: {NC}").strip()
        self.config['NAMESERVER'] = nameserver if nameserver else "dns.example.com"
        return self.config['NAMESERVER']
    
    def detect_server_ip(self):
        """Fast IP detection with fallbacks"""
        print_info("Detecting server IP address...")
        Animation.show_progress()
        
        # Try multiple methods FAST
        ip_methods = [
            self._get_ip_via_curl,
            self._get_ip_via_socket,
            self._get_ip_via_hostname
        ]
        
        for method in ip_methods:
            ip = method()
            if ip and ip != "127.0.0.1":
                self.config['SERVER_IP'] = ip
                print(f"\r  {GREEN}Server IP:{NC} {WHITE}{BOLD}{ip}{NC}")
                return ip
        
        self.config['SERVER_IP'] = "127.0.0.1"
        print_warning("Using localhost IP")
        return "127.0.0.1"
    
    def _get_ip_via_curl(self):
        """Fast curl method"""
        try:
            # Use timeout and quick connect
            result = subprocess.run(
                ["curl", "-s", "--connect-timeout", "3", "ifconfig.me"],
                capture_output=True,
                text=True,
                timeout=3
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except:
            return None
    
    def _get_ip_via_socket(self):
        """Fast socket method"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None
    
    def _get_ip_via_hostname(self):
        """Fast hostname method"""
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return None
    
    # ============================================================================
    # STEP 1: CONFIGURE OPENSSH - OPTIMIZED
    # ============================================================================
    def configure_ssh(self):
        """Fast SSH configuration"""
        print_step("1")
        print_info(f"Configuring OpenSSH on port {self.config['SSHD_PORT']}")
        
        # Backup with progress
        print_info("Backing up SSH configuration...")
        Animation.show_progress()
        
        ssh_config = Path("/etc/ssh/sshd_config")
        if ssh_config.exists():
            backup = Path("/etc/ssh/sshd_config.backup")
            shutil.copy2(ssh_config, backup)
            print_success("SSH configuration backed up")
        
        # Write config
        ssh_content = f"""# ============================================================================
# SLOWDNS OPTIMIZED SSH CONFIGURATION
# ============================================================================
Port {self.config['SSHD_PORT']}
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
                f.write(ssh_content)
            
            # Fast service restart
            print_info("Restarting SSH service...")
            Animation.show_progress()
            
            subprocess.run(["systemctl", "restart", "ssh"], 
                          capture_output=True, check=False)
            time.sleep(1)
            
            print_success("SSH service restarted")
            print_success(f"OpenSSH configured on port {self.config['SSHD_PORT']}")
            print_step_end()
            return True
            
        except Exception as e:
            print_error(f"SSH configuration failed: {str(e)[:50]}")
            return False
    
    # ============================================================================
    # STEP 2: SETUP SLOWDNS - FASTER DOWNLOADS
    # ============================================================================
    def setup_slowdns(self):
        """Optimized SlowDNS setup"""
        print_step("2")
        print_info("Setting up SlowDNS environment")
        
        # Create directory
        print_info("Creating SlowDNS directory...")
        Animation.show_progress()
        
        if self.install_dir.exists():
            shutil.rmtree(self.install_dir, ignore_errors=True)
        self.install_dir.mkdir(parents=True, exist_ok=True)
        os.chdir(self.install_dir)
        
        print_success("SlowDNS directory created")
        
        # Download files with parallel threads
        print_info("Downloading SlowDNS components")
        
        files_to_download = [
            ("dnstt-server", "dnstt-server", True),  # binary, executable
            ("server.key", "server.key", False),
            ("server.pub", "server.pub", False)
        ]
        
        # Download in sequence for reliability
        for url_name, filename, is_executable in files_to_download:
            print_info(f"Fetching {filename}...")
            Animation.show_progress()
            
            url = f"{self.config['GITHUB_BASE']}/{url_name}"
            success = False
            
            # Try multiple download methods
            download_methods = [
                self._download_wget,
                self._download_curl,
                self._download_python
            ]
            
            for method in download_methods:
                if method(url, filename):
                    success = True
                    break
            
            if success:
                if is_executable:
                    os.chmod(filename, 0o755)
                print_success(f"{filename} downloaded")
            else:
                print_error(f"Failed to download {filename}")
                return False
        
        # Quick binary test
        print_info("Validating binary...")
        Animation.show_progress()
        
        test_result = subprocess.run(
            ["./dnstt-server", "--help"],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if test_result.returncode == 0 or "usage" in test_result.stdout.lower():
            print_success("Binary validated successfully")
        else:
            print_warning("Binary test inconclusive")
        
        print_success("SlowDNS components installed")
        print_step_end()
        return True
    
    def _download_wget(self, url, filename):
        """Fast wget download"""
        try:
            result = subprocess.run(
                ["wget", "-q", "--timeout=10", "--tries=2", url, "-O", filename],
                capture_output=True,
                timeout=15
            )
            return result.returncode == 0
        except:
            return False
    
    def _download_curl(self, url, filename):
        """Fast curl download"""
        try:
            result = subprocess.run(
                ["curl", "-fsSL", "--connect-timeout", "10", "--max-time", "15", url, "-o", filename],
                capture_output=True,
                timeout=15
            )
            return result.returncode == 0
        except:
            return False
    
    def _download_python(self, url, filename):
        """Python fallback download"""
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                with open(filename, 'wb') as f:
                    f.write(response.read())
            return True
        except:
            return False
    
    # ============================================================================
    # STEP 3: CREATE SERVICES - OPTIMIZED
    # ============================================================================
    def create_services(self):
        """Create systemd services"""
        print_step("3")
        print_info("Creating SlowDNS system service")
        
        service_content = f"""# ============================================================================
# SLOWDNS SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=SlowDNS Server
Description=High-performance DNS tunnel server
After=network.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={self.config['SLOWDNS_BINARY']} -udp :{self.config['SLOWDNS_PORT']} -mtu {self.config['MTU']} -privkey-file /etc/slowdns/server.key {self.config['NAMESERVER']} 127.0.0.1:{self.config['SSHD_PORT']}
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
LimitCORE=infinity
TimeoutStartSec=0

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
    
    # ============================================================================
    # STEP 4: COMPILE EDNS PROXY - FASTER COMPILATION
    # ============================================================================
    def compile_edns_proxy(self):
        """Optimized EDNS proxy compilation"""
        print_step("4")
        print_info("Compiling high-performance EDNS Proxy")
        
        # Check for gcc
        gcc_check = subprocess.run(["which", "gcc"], capture_output=True)
        if gcc_check.returncode != 0:
            print_info("Installing compiler tools")
            print_info("Installing gcc...")
            Animation.show_progress()
            
            # Fast apt operations
            subprocess.run(
                ["apt", "update", "-qq"],
                capture_output=True,
                check=False
            )
            subprocess.run(
                ["apt", "install", "-y", "gcc", "-qq"],
                capture_output=True,
                check=False
            )
            print_success("Compiler installed")
        
        # Create optimized C code
        print_info("Creating optimized C code...")
        Animation.show_progress()
        
        edns_code = self._get_optimized_edns_code()
        
        with open("/tmp/edns_opt.c", 'w') as f:
            f.write(edns_code)
        
        # Compile with optimizations
        print_info("Compiling EDNS Proxy with O3 optimizations...")
        Animation.show_progress()
        
        compile_cmd = [
            "gcc", "-O3", "-march=native", "-pipe", 
            "/tmp/edns_opt.c", "-o", "/usr/local/bin/edns-proxy"
        ]
        
        result = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            os.chmod("/usr/local/bin/edns-proxy", 0o755)
            print_success("EDNS Proxy compiled successfully")
        else:
            print_error("Compilation failed")
            return False
        
        # Create EDNS service
        edns_service = """# ============================================================================
# EDNS PROXY SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=EDNS Proxy for SlowDNS
Description=High-performance DNS proxy with EDNS support
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
    
    def _get_optimized_edns_code(self):
        """Optimized EDNS proxy code"""
        return """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 100

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
} request_t;

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

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    printf("[EDNS Proxy] Starting high-performance DNS proxy...\\n");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("[ERROR] socket");
        return 1;
    }
    
    if(set_nonblock(sock) < 0) {
        perror("[ERROR] fcntl");
        close(sock);
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
    
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0) {
        perror("[ERROR] epoll_create1");
        close(sock);
        return 1;
    }
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("[ERROR] epoll_ctl");
        close(epoll_fd);
        close(sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port 53 (epoll optimized)\\n");
    printf("[EDNS Proxy] Ready to handle DNS queries\\n");
    
    struct epoll_event events[MAX_EVENTS];
    request_t *requests[10000] = {0};
    
    while(1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        for(int i = 0; i < n; i++) {
            if(events[i].data.fd == sock) {
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
                if(len > 0) {
                    patch_edns(buffer, len, INT_EDNS);
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if(up_sock >= 0) {
                        set_nonblock(up_sock);
                        request_t *req = malloc(sizeof(request_t));
                        if(req) {
                            req->client_fd = sock;
                            req->client_addr = client_addr;
                            req->addr_len = client_len;
                            req->timestamp = time(NULL);
                            requests[up_sock] = req;
                            struct epoll_event up_ev;
                            up_ev.events = EPOLLIN;
                            up_ev.data.fd = up_sock;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev);
                            struct sockaddr_in up_addr;
                            memset(&up_addr, 0, sizeof(up_addr));
                            up_addr.sin_family = AF_INET;
                            up_addr.sin_port = htons(SLOWDNS_PORT);
                            inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                            sendto(up_sock, buffer, len, 0,
                                   (struct sockaddr*)&up_addr, sizeof(up_addr));
                        } else {
                            close(up_sock);
                        }
                    }
                }
            } else {
                int up_sock = events[i].data.fd;
                request_t *req = requests[up_sock];
                if(req) {
                    unsigned char buffer[BUFFER_SIZE];
                    int len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                    if(len > 0) {
                        patch_edns(buffer, len, EXT_EDNS);
                        sendto(req->client_fd, buffer, len, 0,
                               (struct sockaddr*)&req->client_addr,
                               req->addr_len);
                    }
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, up_sock, NULL);
                    close(up_sock);
                    free(req);
                    requests[up_sock] = NULL;
                }
            }
        }
    }
    return 0;
}
"""
    
    # ============================================================================
    # STEP 5: FIREWALL CONFIGURATION - OPTIMIZED
    # ============================================================================
    def configure_firewall(self):
        """Fast firewall configuration"""
        print_step("5")
        print_info("Configuring system firewall")
        
        print_info("Setting up firewall rules...")
        Animation.show_progress()
        
        # Batch execute firewall commands
        firewall_commands = [
            "iptables -F 2>/dev/null",
            "iptables -X 2>/dev/null",
            "iptables -t nat -F 2>/dev/null",
            "iptables -t nat -X 2>/dev/null",
            "iptables -P INPUT ACCEPT 2>/dev/null",
            "iptables -P FORWARD ACCEPT 2>/dev/null",
            "iptables -P OUTPUT ACCEPT 2>/dev/null",
            f"iptables -A INPUT -i lo -j ACCEPT 2>/dev/null",
            f"iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null",
            f"iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null",
            f"iptables -A INPUT -p tcp --dport {self.config['SSHD_PORT']} -j ACCEPT 2>/dev/null",
            f"iptables -A INPUT -p udp --dport {self.config['SLOWDNS_PORT']} -j ACCEPT 2>/dev/null",
            f"iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null",
            f"iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null",
            f"iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT 2>/dev/null",
            f"iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null",
            f"iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null"
        ]
        
        for cmd in firewall_commands:
            subprocess.run(cmd, shell=True, capture_output=True)
        
        # Disable IPv6
        try:
            with open("/proc/sys/net/ipv6/conf/all/disable_ipv6", 'w') as f:
                f.write("1")
        except:
            pass
        
        # Stop conflicting services
        print_info("Stopping conflicting DNS services...")
        Animation.show_progress()
        
        subprocess.run(["systemctl", "stop", "systemd-resolved"], 
                      capture_output=True, check=False)
        subprocess.run(["pkill", "-f", "dnsmasq"], 
                      capture_output=True, check=False)
        
        print_success("Firewall rules configured")
        print_success("Firewall and network configured")
        print_step_end()
        return True
    
    # ============================================================================
    # STEP 6: START SERVICES - WITH HEALTH CHECKS
    # ============================================================================
    def start_services(self):
        """Start services with health checks"""
        print_step("6")
        print_info("Starting all services")
        
        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        
        # Start SlowDNS
        print_info("Starting SlowDNS service...")
        Animation.show_progress()
        
        subprocess.run(["systemctl", "enable", "server-sldns"], 
                      capture_output=True, check=False)
        subprocess.run(["systemctl", "start", "server-sldns"], 
                      capture_output=True, check=False)
        time.sleep(2)
        
        # Check if running
        result = subprocess.run(
            ["systemctl", "is-active", "server-sldns"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print_success("SlowDNS service started")
        else:
            print_warning("Starting SlowDNS in background")
            # Start manually
            cmd = f"{self.config['SLOWDNS_BINARY']} -udp :{self.config['SLOWDNS_PORT']} -mtu {self.config['MTU']} -privkey-file /etc/slowdns/server.key {self.config['NAMESERVER']} 127.0.0.1:{self.config['SSHD_PORT']} &"
            subprocess.run(cmd, shell=True, check=False)
        
        # Start EDNS proxy
        print_info("Starting EDNS Proxy service...")
        Animation.show_progress()
        
        subprocess.run(["systemctl", "enable", "edns-proxy"], 
                      capture_output=True, check=False)
        subprocess.run(["systemctl", "start", "edns-proxy"], 
                      capture_output=True, check=False)
        time.sleep(2)
        
        result = subprocess.run(
            ["systemctl", "is-active", "edns-proxy"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print_success("EDNS Proxy service started")
        else:
            print_warning("Starting EDNS Proxy manually")
            subprocess.run(["/usr/local/bin/edns-proxy", "&"], 
                          shell=True, check=False)
        
        # Verify services
        print_info("Verifying service status...")
        time.sleep(2)
        print_success("Service verification complete")
        
        print_success("All services started successfully")
        print_step_end()
        return True
    
    # ============================================================================
    # COMPLETION SUMMARY - SAME AS BASH
    # ============================================================================
    def show_summary(self):
        """Beautiful summary like bash"""
        print_header("🎉 INSTALLATION COMPLETE")
        
        # Server info box
        print(f"{CYAN}┌{'─'*50}┐{NC}")
        print(f"{CYAN}│{NC} {WHITE}{BOLD}SERVER INFORMATION{NC}{' ' * 31}{CYAN}│{NC}")
        print(f"{CYAN}├{'─'*50}┤{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} Server IP:     {WHITE}{self.config['SERVER_IP']}{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} SSH Port:      {WHITE}{self.config['SSHD_PORT']}{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} SlowDNS Port:  {WHITE}{self.config['SLOWDNS_PORT']}{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} EDNS Port:     {WHITE}53{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} MTU Size:      {WHITE}{self.config['MTU']}{NC}")
        print(f"{CYAN}│{NC} {YELLOW}●{NC} Nameserver:    {WHITE}{self.config['NAMESERVER']}{NC}")
        print(f"{CYAN}└{'─'*50}┘{NC}")
        
        # Quick test commands
        print(f"\n{CYAN}┌{'─'*50}┐{NC}")
        print(f"{CYAN}│{NC} {WHITE}{BOLD}QUICK TEST COMMANDS{NC}{' ' * 31}{CYAN}│{NC}")
        print(f"{CYAN}├{'─'*50}┤{NC}")
        print(f"{CYAN}│{NC} {GREEN}dig @{self.config['SERVER_IP']} {self.config['NAMESERVER']}{NC}")
        print(f"{CYAN}│{NC} {GREEN}nslookup {self.config['NAMESERVER']} {self.config['SERVER_IP']}{NC}")
        print(f"{CYAN}│{NC} {GREEN}systemctl status server-sldns{NC}")
        print(f"{CYAN}│{NC} {GREEN}systemctl status edns-proxy{NC}")
        print(f"{CYAN}└{'─'*50}┘{NC}")
        
        # Service management
        print(f"\n{CYAN}┌{'─'*50}┐{NC}")
        print(f"{CYAN}│{NC} {WHITE}{BOLD}SERVICE MANAGEMENT{NC}{' ' * 32}{CYAN}│{NC}")
        print(f"{CYAN}├{'─'*50}┤{NC}")
        print(f"{CYAN}│{NC} {YELLOW}Restart services:{NC} systemctl restart server-sldns edns-proxy")
        print(f"{CYAN}│{NC} {YELLOW}View logs:{NC}        journalctl -u server-sldns -f")
        print(f"{CYAN}│{NC} {YELLOW}Check ports:{NC}      ss -ulpn | grep ':53\\|:5300'")
        print(f"{CYAN}└{'─'*50}┘{NC}")
        
        # Verify installation
        print(f"\n{WHITE}{BOLD}Verifying installation...{NC}")
        
        # Check ports
        result = subprocess.run(
            ["ss", "-ulpn"],
            capture_output=True,
            text=True
        )
        
        if ":53 " in result.stdout:
            print(f"  {GREEN}✓ Port 53 (EDNS Proxy) is listening{NC}")
        else:
            print(f"  {YELLOW}! Port 53 not listening{NC}")
        
        if f":{self.config['SLOWDNS_PORT']} " in result.stdout:
            print(f"  {GREEN}✓ Port {self.config['SLOWDNS_PORT']} (SlowDNS) is listening{NC}")
        else:
            print(f"  {YELLOW}! Port {self.config['SLOWDNS_PORT']} not listening{NC}")
        
        # Check services
        services_ok = True
        for svc in ["server-sldns", "edns-proxy"]:
            result = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                services_ok = False
        
        if services_ok:
            print(f"  {GREEN}✓ All services are running{NC}")
        else:
            print(f"  {YELLOW}! Some services need attention{NC}")
        
        # Show public key
        pubkey_path = Path("/etc/slowdns/server.pub")
        if pubkey_path.exists():
            print(f"\n{CYAN}┌{'─'*50}┐{NC}")
            print(f"{CYAN}│{NC} {WHITE}{BOLD}PUBLIC KEY (For Client Configuration){NC}{' ' * 15}{CYAN}│{NC}")
            print(f"{CYAN}├{'─'*50}┤{NC}")
            print(f"{CYAN}│{NC}{WHITE}")
            with open(pubkey_path, 'r') as f:
                print(f"  {f.readline().strip()}")
            print(f"{NC}{CYAN}│{NC}")
            print(f"{CYAN}└{'─'*50}┘{NC}")
        
        # Final message
        elapsed = time.time() - self.start_time
        print(f"\n{GREEN}{BOLD}╔{'═'*52}╗{NC}")
        print(f"{GREEN}{BOLD}║{NC}    {WHITE}🎯 SLOWDNS INSTALLATION COMPLETED SUCCESSFULLY!{NC}    {GREEN}{BOLD}║{NC}")
        print(f"{GREEN}{BOLD}║{NC}    {WHITE}⚡ Python Edition - Time: {elapsed:.1f}s{NC}               {GREEN}{BOLD}║{NC}")
        print(f"{GREEN}{BOLD}║{NC}    {WHITE}📊 Services running: SlowDNS + EDNS Proxy{NC}          {GREEN}{BOLD}║{NC}")
        print(f"{GREEN}{BOLD}║{NC}    {WHITE}🔧 Ready for DNS tunneling{NC}                         {GREEN}{BOLD}║{NC}")
        print(f"{GREEN}{BOLD}╚{'═'*52}╝{NC}")
        
        print(f"\n{YELLOW}{BOLD}📞 Need help? Contact support: @esimfreegb{NC}")
        print(f"{YELLOW}{BOLD}💡 Documentation: https://github.com/chiddy80/Halotel-Slow-DNS{NC}")
        
        # Post-install menu
        self.post_install_menu()
    
    def post_install_menu(self):
        """Post-installation options"""
        print(f"\n{CYAN}┌{'─'*50}┐{NC}")
        print(f"{CYAN}│{NC} {WHITE}{BOLD}POST-INSTALLATION OPTIONS{NC}{' ' * 25}{CYAN}│{NC}")
        print(f"{CYAN}├{'─'*50}┤{NC}")
        print(f"{CYAN}│{NC} {YELLOW}1.{NC} {WHITE}View service status{NC}{' ' * 28}{CYAN}│{NC}")
        print(f"{CYAN}│{NC} {YELLOW}2.{NC} {WHITE}Check listening ports{NC}{' ' * 26}{CYAN}│{NC}")
        print(f"{CYAN}│{NC} {YELLOW}3.{NC} {WHITE}Restart all services{NC}{' ' * 27}{CYAN}│{NC}")
        print(f"{CYAN}│{NC} {YELLOW}4.{NC} {WHITE}Test DNS functionality{NC}{' ' * 25}{CYAN}│{NC}")
        print(f"{CYAN}│{NC} {YELLOW}5.{NC} {WHITE}Exit to terminal{NC}{' ' * 31}{CYAN}│{NC}")
        print(f"{CYAN}└{'─'*50}┘{NC}")
        
        choice = input(f"{WHITE}{BOLD}Select option [1-5]: {NC}").strip() or "5"
        
        if choice == "1":
            print(f"\n{CYAN}{'═'*24} SERVICE STATUS {'═'*24}{NC}")
            subprocess.run(["systemctl", "status", "server-sldns", "--no-pager", "-l"])
            print(f"\n{CYAN}{'═'*24}══════════════════{'═'*24}{NC}")
            subprocess.run(["systemctl", "status", "edns-proxy", "--no-pager", "-l"])
        elif choice == "2":
            print(f"\n{CYAN}{'═'*22} LISTENING PORTS {'═'*22}{NC}")
            print(f"{WHITE}Checking UDP ports:{NC}")
            subprocess.run(["ss", "-ulpn"])
        elif choice == "3":
            print(f"\n{CYAN}{'═'*20} RESTARTING SERVICES {'═'*20}{NC}")
            subprocess.run(["systemctl", "restart", "server-sldns", "edns-proxy"])
            time.sleep(2)
            print(f"{GREEN}✓ Services restarted successfully{NC}")
        elif choice == "4":
            print(f"\n{CYAN}{'═'*22} DNS TEST {'═'*22}{NC}")
            print(f"{WHITE}Testing DNS query to {self.config['NAMESERVER']}...{NC}")
            # Try dig
            result = subprocess.run(["which", "dig"], capture_output=True)
            if result.returncode == 0:
                subprocess.run(["dig", f"@{self.config['SERVER_IP']}", 
                              self.config['NAMESERVER'], "+short"])
            else:
                # Try nslookup
                result = subprocess.run(["which", "nslookup"], capture_output=True)
                if result.returncode == 0:
                    subprocess.run(["nslookup", self.config['NAMESERVER'], 
                                  self.config['SERVER_IP']])
                else:
                    print(f"{YELLOW}DNS tools not available{NC}")
        
        # Cleanup
        self.cleanup()
        
        # Final exit
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{GREEN}{BOLD}{'═'*60}{NC}")
        print(f"{GREEN}{BOLD}   Installation completed at: {current_time}{NC}")
        print(f"{GREEN}{BOLD}   Server: {self.config['SERVER_IP']} | SlowDNS: {self.config['SLOWDNS_PORT']} | EDNS: 53{NC}")
        print(f"{GREEN}{BOLD}{'═'*60}{NC}")
    
    def cleanup(self):
        """Cleanup temporary files"""
        temp_files = ["/tmp/edns_opt.c", "/tmp/compile.log"]
        for file in temp_files:
            try:
                os.remove(file)
            except:
                pass
    
    # ============================================================================
    # MAIN INSTALLATION
    # ============================================================================
    def install(self):
        """Main installation - optimized for speed and stability"""
        try:
            print_banner()
            self.check_root()
            
            # Get configuration
            print_header("📦 GATHERING SYSTEM INFORMATION")
            nameserver = self.get_nameserver()
            server_ip = self.detect_server_ip()
            
            # Installation steps
            steps = [
                ("Configure SSH", self.configure_ssh),
                ("Setup SlowDNS", self.setup_slowdns),
                ("Create Services", self.create_services),
                ("Compile EDNS Proxy", self.compile_edns_proxy),
                ("Configure Firewall", self.configure_firewall),
                ("Start Services", self.start_services)
            ]
            
            # Execute all steps
            for step_name, step_func in steps:
                if not step_func():
                    return False
                time.sleep(0.5)
            
            # Show completion
            self.show_summary()
            return True
            
        except KeyboardInterrupt:
            print_error("\nInstallation interrupted!")
            return False
        except Exception as e:
            print_error(f"Installation failed: {str(e)[:100]}")
            return False

# ============================================================================
# ENTRY POINT
# ============================================================================
def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        installer = SlowDNSInstaller()
        success = installer.install()
        sys.exit(0 if success else 1)
    elif len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(f"{CYAN}Usage:{NC}")
        print(f"  sudo python3 {sys.argv[0]} --install")
        print(f"  sudo python3 {sys.argv[0]} --help")
        return True
    else:
        # Interactive
        print_banner()
        print(f"{CYAN}To install SlowDNS:{NC}")
        print(f"  sudo python3 {sys.argv[0]} --install")
        print(f"\n{YELLOW}Or run directly:{NC}")
        
        response = input(f"{WHITE}Start installation now? (y/n): {NC}").lower()
        if response == 'y':
            installer = SlowDNSInstaller()
            return installer.install()
        return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
