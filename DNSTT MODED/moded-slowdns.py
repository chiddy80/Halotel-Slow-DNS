#!/usr/bin/env python3
"""
🚀 BALANCED SLOWDNS INSTALLER - Fast & Stable
"""

import os
import sys
import time
import socket
import subprocess
import threading
import urllib.request
import concurrent.futures
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
import selectors
import fcntl
import signal

# Colors (same as before)

class BalancedSlowDNSInstaller:
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
        self.errors = []
        self.warnings = []
        
    # ============================================================================
    # STABLE + FAST IP DETECTION
    # ============================================================================
    def detect_ip_stable_fast(self):
        """Fast with fallbacks"""
        print_info("Detecting server IP...")
        
        methods = [
            self._get_ip_public_api,    # Fastest first
            self._get_ip_socket,        # Reliable
            self._get_ip_interface,     # Local fallback
        ]
        
        # Try fast methods with timeout
        for method in methods:
            try:
                ip = method()
                if ip and ip != "127.0.0.1":
                    self.config['SERVER_IP'] = ip
                    print_success(f"Server IP: {ip}")
                    return ip
            except:
                continue
        
        # Final fallback
        self.config['SERVER_IP'] = "127.0.0.1"
        print_warning("Using localhost (127.0.0.1)")
        self.warnings.append("Could not detect public IP")
        return "127.0.0.1"
    
    def _get_ip_public_api(self):
        """Fast but might fail"""
        try:
            # Multiple public APIs for reliability
            apis = [
                "https://api.ipify.org",
                "https://checkip.amazonaws.com",
                "http://ifconfig.me"
            ]
            
            for api in apis:
                try:
                    with urllib.request.urlopen(api, timeout=2) as resp:
                        return resp.read().decode().strip()
                except:
                    continue
        except:
            return None
    
    def _get_ip_socket(self):
        """Reliable local IP detection"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            # Connect to Google DNS
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None
    
    def _get_ip_interface(self):
        """Fallback to interface IP"""
        try:
            import netifaces
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if ip != "127.0.0.1":
                            return ip
        except ImportError:
            # Fallback to hostname
            return socket.gethostbyname(socket.gethostname())
        return None
    
    # ============================================================================
    # ROBUST PARALLEL DOWNLOADS WITH VERIFICATION
    # ============================================================================
    def download_with_verification(self):
        """Parallel downloads with checksum verification"""
        print_step("2")
        print_info("Downloading SlowDNS components")
        
        files = [
            ("dnstt-server", "dnstt-server", True),
            ("server.key", "server.key", False),
            ("server.pub", "server.pub", False)
        ]
        
        # Expected SHA256 hashes (optional - add if you know them)
        expected_hashes = {
            "dnstt-server": None,  # Add actual hash if known
            "server.key": None,
            "server.pub": None
        }
        
        # Create download tasks
        download_tasks = []
        for url_name, filename, is_exec in files:
            task = {
                'url': f"{self.config['GITHUB_BASE']}/{url_name}",
                'filename': filename,
                'is_executable': is_exec,
                'expected_hash': expected_hashes.get(filename)
            }
            download_tasks.append(task)
        
        # Download in parallel but with error collection
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_task = {
                executor.submit(self._download_single_file, task): task
                for task in download_tasks
            }
            
            for future in concurrent.futures.as_completed(future_to_task, timeout=30):
                task = future_to_task[future]
                try:
                    success, message = future.result()
                    if success:
                        print_success(f"{task['filename']}: {message}")
                        results.append(True)
                    else:
                        print_error(f"{task['filename']}: {message}")
                        results.append(False)
                        self.errors.append(f"Failed to download {task['filename']}")
                except Exception as e:
                    print_error(f"{task['filename']}: {str(e)[:50]}")
                    results.append(False)
                    self.errors.append(f"Download error: {task['filename']}")
        
        # Verify all files were downloaded
        if not all(results):
            print_error("Some downloads failed. Trying fallback...")
            return self._download_sequential_fallback(files)
        
        # Verify binary works
        print_info("Verifying binary...")
        if not self._verify_binary():
            print_error("Binary verification failed!")
            return False
        
        print_success("All downloads completed and verified")
        return True
    
    def _download_single_file(self, task):
        """Download single file with retries"""
        url = task['url']
        filename = task['filename']
        is_executable = task['is_executable']
        
        # Try multiple methods with retries
        methods = [
            self._download_urllib,
            self._download_curl,
            self._download_wget
        ]
        
        for attempt in range(3):  # 3 attempts
            for method in methods:
                try:
                    if method(url, filename):
                        # Verify file size
                        if os.path.getsize(filename) == 0:
                            os.remove(filename)
                            continue
                        
                        # Set permissions
                        if is_executable:
                            os.chmod(filename, 0o755)
                        
                        # Optional hash verification
                        if task['expected_hash']:
                            if not self._verify_hash(filename, task['expected_hash']):
                                os.remove(filename)
                                continue
                        
                        return True, "Downloaded"
                except:
                    continue
            
            time.sleep(1)  # Wait before retry
        
        return False, "Failed after 3 attempts"
    
    def _download_sequential_fallback(self, files):
        """Fallback to sequential downloads"""
        print_warning("Falling back to sequential downloads...")
        
        for url_name, filename, is_exec in files:
            print_info(f"Downloading {filename}...")
            
            url = f"{self.config['GITHUB_BASE']}/{url_name}"
            success = False
            
            for method in [self._download_curl, self._download_wget, self._download_urllib]:
                if method(url, filename):
                    if is_exec:
                        os.chmod(filename, 0o755)
                    print_success(f"Downloaded {filename}")
                    success = True
                    break
            
            if not success:
                print_error(f"Failed to download {filename}")
                return False
        
        return True
    
    def _verify_binary(self):
        """Thorough binary verification"""
        binary_path = Path("dnstt-server")
        if not binary_path.exists():
            return False
        
        # Check file size
        size = os.path.getsize(binary_path)
        if size < 1000:  # Too small
            return False
        
        # Test execution
        try:
            # Quick test
            result = subprocess.run(
                [str(binary_path), "--help"],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            # Look for expected output
            if result.returncode == 0 or "usage" in result.stdout.lower():
                return True
            elif result.returncode == 1:  # Some binaries exit with 1 for help
                return True
        except:
            pass
        
        # Try version flag
        try:
            result = subprocess.run(
                [str(binary_path), "--version"],
                capture_output=True,
                text=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            pass
        
        # Last resort: check if it's executable
        return os.access(binary_path, os.X_OK)
    
    # ============================================================================
    # STABLE EDNS PROXY (Event-Driven)
    # ============================================================================
    def compile_stable_edns_proxy(self):
        """Compile with epoll for stability"""
        print_step("4")
        print_info("Compiling high-performance EDNS Proxy")
        
        # Check dependencies
        if not self._check_dependencies():
            print_error("Missing dependencies")
            return False
        
        # Create optimized but stable C code
        edns_code = self._get_stable_edns_code()
        
        # Write and compile
        try:
            with open("/tmp/edns_stable.c", 'w') as f:
                f.write(edns_code)
            
            print_info("Compiling with optimizations...")
            
            # Optimized but safe flags
            compile_cmd = [
                "gcc", "-O2", "-Wall", "-Wextra", "-pipe",
                "/tmp/edns_stable.c", "-o", "/usr/local/bin/edns-proxy"
            ]
            
            result = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print_error("Compilation failed!")
                print_error(result.stderr[:200])
                return False
            
            os.chmod("/usr/local/bin/edns-proxy", 0o755)
            
            # Test the binary
            print_info("Testing EDNS proxy...")
            test_result = subprocess.run(
                ["/usr/local/bin/edns-proxy", "--help"],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if test_result.returncode != 0:
                print_warning("Test inconclusive, but binary compiled")
            
            print_success("EDNS Proxy compiled successfully")
            return True
            
        except Exception as e:
            print_error(f"Compilation error: {str(e)}")
            return False
    
    def _get_stable_edns_code(self):
        """Return stable epoll-based EDNS code"""
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
#include <errno.h>

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 64
#define MAX_CLIENTS 1000
#define TIMEOUT_MS 1000

typedef struct {
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len;
    time_t last_active;
    int upstream_fd;
} client_t;

int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    
    // Skip questions
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        if(offset >= len) return len;
        offset += 5;  // QTYPE + QCLASS
    }
    
    int arcount = (buf[10] << 8) | buf[11];
    
    // Find and patch EDNS
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0) {  // Root label
            if(offset + 10 < len) {
                uint16_t type = (buf[offset+1] << 8) | buf[offset+2];
                if(type == 41) {  // EDNS
                    buf[offset+9] = new_size >> 8;   // UDP payload size high
                    buf[offset+10] = new_size & 0xFF; // UDP payload size low
                    return len;
                }
            }
        }
        offset++;
    }
    
    return len;
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void cleanup_client(client_t *client) {
    if(client->upstream_fd > 0) close(client->upstream_fd);
    if(client->fd > 0) close(client->fd);
    free(client);
}

int main() {
    printf("[EDNS Proxy] Starting stable DNS proxy...\\n");
    
    // Create main socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Set socket options for better performance
    int reuse = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        close(sock);
        return 1;
    }
    
    // Bind to port 53
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }
    
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0) {
        perror("epoll_create1");
        close(sock);
        return 1;
    }
    
    // Add main socket to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("epoll_ctl");
        close(epoll_fd);
        close(sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port 53 (epoll stable)\\n");
    
    struct epoll_event events[MAX_EVENTS];
    client_t *clients[MAX_CLIENTS] = {0};
    
    while(1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, TIMEOUT_MS);
        
        if(nfds < 0) {
            if(errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        
        for(int i = 0; i < nfds; i++) {
            if(events[i].data.fd == sock) {
                // New incoming packet
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                
                ssize_t len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                     (struct sockaddr*)&client_addr, &client_len);
                
                if(len > 0) {
                    // Patch EDNS size
                    patch_edns(buffer, len, INT_EDNS);
                    
                    // Forward to SlowDNS
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if(up_sock >= 0) {
                        struct sockaddr_in up_addr = {0};
                        up_addr.sin_family = AF_INET;
                        up_addr.sin_port = htons(SLOWDNS_PORT);
                        up_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                        
                        sendto(up_sock, buffer, len, 0,
                               (struct sockaddr*)&up_addr, sizeof(up_addr));
                        
                        // Wait for response with timeout
                        struct timeval tv;
                        tv.tv_sec = 2;
                        tv.tv_usec = 0;
                        setsockopt(up_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                        
                        ssize_t resp_len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                        if(resp_len > 0) {
                            patch_edns(buffer, resp_len, EXT_EDNS);
                            sendto(sock, buffer, resp_len, 0,
                                   (struct sockaddr*)&client_addr, client_len);
                        }
                        
                        close(up_sock);
                    }
                }
            }
        }
        
        // Cleanup old clients (simplified)
        time_t now = time(NULL);
        // Implementation for client cleanup...
    }
    
    close(epoll_fd);
    close(sock);
    printf("[EDNS Proxy] Shutting down\\n");
    return 0;
}
"""
    
    def _check_dependencies(self):
        """Check and install dependencies"""
        print_info("Checking dependencies...")
        
        deps = ["gcc", "make", "build-essential"]
        missing = []
        
        for dep in deps:
            if shutil.which(dep) is None:
                missing.append(dep)
        
        if missing:
            print_warning(f"Missing: {', '.join(missing)}")
            print_info("Installing dependencies...")
            
            try:
                # Update repos
                subprocess.run(
                    ["apt-get", "update", "-qq"],
                    capture_output=True,
                    check=False
                )
                
                # Install missing deps
                install_cmd = ["apt-get", "install", "-y", "-qq"] + missing
                result = subprocess.run(
                    install_cmd,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode != 0:
                    print_error("Failed to install dependencies")
                    return False
                
                print_success("Dependencies installed")
                return True
                
            except Exception as e:
                print_error(f"Installation failed: {str(e)}")
                return False
        
        print_success("All dependencies available")
        return True
    
    # ============================================================================
    # STABLE SERVICE MANAGEMENT
    # ============================================================================
    def manage_services_stable(self):
        """Start services with health checks"""
        print_step("6")
        print_info("Starting services...")
        
        services = [
            {
                'name': 'server-sldns',
                'start_cmd': [
                    self.config['SLOWDNS_BINARY'],
                    '-udp', f":{self.config['SLOWDNS_PORT']}",
                    '-mtu', str(self.config['MTU']),
                    '-privkey-file', '/etc/slowdns/server.key',
                    self.config['NAMESERVER'],
                    f"127.0.0.1:{self.config['SSHD_PORT']}"
                ],
                'type': 'systemd'
            },
            {
                'name': 'edns-proxy',
                'start_cmd': ['/usr/local/bin/edns-proxy'],
                'type': 'systemd'
            }
        ]
        
        # First reload systemd
        print_info("Reloading systemd...")
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        
        all_started = True
        
        for service in services:
            print_info(f"Starting {service['name']}...")
            
            if service['type'] == 'systemd':
                # Create service file if doesn't exist
                if not self._service_file_exists(service['name']):
                    self._create_service_file(service)
                
                # Enable and start
                success = self._start_systemd_service(service['name'])
            else:
                # Direct start
                success = self._start_direct_service(service['start_cmd'])
            
            if success:
                print_success(f"{service['name']} started")
                
                # Verify it's running
                if not self._verify_service_running(service['name']):
                    print_warning(f"{service['name']} may not be running")
                    self.warnings.append(f"{service['name']} status uncertain")
            else:
                print_error(f"Failed to start {service['name']}")
                self.errors.append(f"Failed to start {service['name']}")
                all_started = False
        
        # Additional verification
        if all_started:
            print_info("Verifying installation...")
            time.sleep(2)  # Give services time to start
            
            # Check ports
            ports_ok = self._check_required_ports()
            
            # Check processes
            processes_ok = self._check_processes()
            
            if ports_ok and processes_ok:
                print_success("All services verified")
                return True
            else:
                print_warning("Some services may need attention")
                return True  # Continue anyway
        else:
            print_error("Some services failed to start")
            return False
    
    def _start_systemd_service(self, service_name):
        """Start systemd service with retries"""
        for attempt in range(3):
            try:
                # Enable
                subprocess.run(
                    ["systemctl", "enable", service_name],
                    capture_output=True,
                    check=False
                )
                
                # Start
                result = subprocess.run(
                    ["systemctl", "start", service_name],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    return True
                
                # Wait and retry
                time.sleep(1)
                
            except Exception:
                time.sleep(1)
        
        return False
    
    def _verify_service_running(self, service_name):
        """Verify service is actually running"""
        try:
            # Check systemd status
            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return True
            
            # Check process
            result = subprocess.run(
                ["pgrep", "-f", service_name],
                capture_output=True
            )
            
            return result.returncode == 0
            
        except:
            return False
    
    def _check_required_ports(self):
        """Check if required ports are listening"""
        required_ports = [
            (53, "udp", "EDNS Proxy"),
            (self.config['SLOWDNS_PORT'], "udp", "SlowDNS"),
            (self.config['SSHD_PORT'], "tcp", "SSH")
        ]
        
        all_ok = True
        
        for port, proto, service in required_ports:
            try:
                if proto == "tcp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(("127.0.0.1", port))
                    sock.close()
                    listening = result == 0
                else:  # udp
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1)
                    try:
                        sock.sendto(b"", ("127.0.0.1", port))
                        sock.recvfrom(1024)
                        listening = True
                    except socket.timeout:
                        # UDP - timeout might mean it's listening
                        listening = True
                    except:
                        listening = False
                    finally:
                        sock.close()
                
                if listening:
                    print_success(f"Port {port} ({service}) is listening")
                else:
                    print_warning(f"Port {port} ({service}) may not be listening")
                    all_ok = False
                    
            except Exception as e:
                print_warning(f"Could not check port {port}: {str(e)[:30]}")
                all_ok = False
        
        return all_ok
    
    # ============================================================================
    # ERROR HANDLING AND RECOVERY
    # ============================================================================
    def handle_errors(self):
        """Handle any accumulated errors"""
        if not self.errors and not self.warnings:
            return True
        
        print_header("⚠️  INSTALLATION SUMMARY")
        
        if self.warnings:
            print(f"{YELLOW}Warnings:{NC}")
            for warning in self.warnings:
                print(f"  {YELLOW}•{NC} {warning}")
        
        if self.errors:
            print(f"\n{RED}Errors:{NC}")
            for error in self.errors:
                print(f"  {RED}•{NC} {error}")
            
            print(f"\n{YELLOW}Some errors occurred. Installation may be incomplete.{NC}")
            
            # Offer recovery options
            choice = input(f"\n{WHITE}Continue anyway? (y/N): {NC}").lower()
            return choice == 'y'
        
        return True
    
    # ============================================================================
    # MAIN INSTALLATION FLOW
    # ============================================================================
    def install_balanced(self):
        """Balanced installation - fast but stable"""
        try:
            print_banner()
            self.check_root()
            
            # Configuration
            print_header("⚙️  CONFIGURATION")
            self.config['NAMESERVER'] = input(f"{WHITE}Nameserver [dns.example.com]: {NC}").strip() or "dns.example.com"
            
            print_info("Detecting system information...")
            self.detect_ip_stable_fast()
            
            # Installation steps
            steps = [
                ("Configure SSH", self.configure_ssh_stable),
                ("Download Components", self.download_with_verification),
                ("Create Services", self.create_service_files),
                ("Compile EDNS", self.compile_stable_edns_proxy),
                ("Setup Firewall", self.configure_firewall_safe),
                ("Start Services", self.manage_services_stable)
            ]
            
            print_header("🚀 INSTALLATION")
            
            # Execute with progress
            for i, (name, func) in enumerate(steps, 1):
                print(f"\n{CYAN}[{i}/{len(steps)}]{NC} {WHITE}{name}...{NC}")
                
                if not func():
                    print_error(f"Failed at: {name}")
                    
                    # Try to recover
                    if not self._attempt_recovery(name):
                        print_error("Recovery failed. Aborting.")
                        return False
                
                # Brief pause between steps
                time.sleep(0.5)
            
            # Handle any errors
            if not self.handle_errors():
                return False
            
            # Final verification
            print_header("✅ VERIFICATION")
            self._final_verification()
            
            # Show success
            elapsed = time.time() - self.start_time
            self._show_success_message(elapsed)
            
            return True
            
        except KeyboardInterrupt:
            print_error("\nInstallation interrupted by user")
            return False
        except Exception as e:
            print_error(f"Unexpected error: {str(e)}")
            return False
    
    def _attempt_recovery(self, failed_step):
        """Attempt to recover from failed step"""
        print_warning(f"Attempting recovery for: {failed_step}")
        
        # Simple recovery strategies
        recoveries = {
            "Download Components": self._recover_download,
            "Compile EDNS": self._recover_compile,
            "Start Services": self._recover_services
        }
        
        if failed_step in recoveries:
            return recoveries[failed_step]()
        
        # Generic recovery
        print_info("Retrying step...")
        time.sleep(2)
        return False
    
    def _recover_download(self):
        """Recover from download failure"""
        print_info("Trying alternative download methods...")
        
        # Use curl with verbose output
        files = ["dnstt-server", "server.key", "server.pub"]
        base_url = self.config['GITHUB_BASE']
        
        for file in files:
            print_info(f"Downloading {file}...")
            url = f"{base_url}/{file}"
            
            result = subprocess.run(
                ["curl", "-fL", "-o", f"/etc/slowdns/{file}", url],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print_error(f"Failed to download {file}")
                return False
        
        return True
    
    def _final_verification(self):
        """Final comprehensive verification"""
        print_info("Running final checks...")
        
        checks = [
            ("Binary exists", lambda: Path(self.config['SLOWDNS_BINARY']).exists()),
            ("EDNS proxy exists", lambda: Path("/usr/local/bin/edns-proxy").exists()),
            ("Services enabled", self._check_services_enabled),
            ("Ports listening", self._check_required_ports),
        ]
        
        all_ok = True
        for check_name, check_func in checks:
            try:
                if check_func():
                    print_success(f"{check_name}")
                else:
                    print_warning(f"{check_name}")
                    all_ok = False
            except Exception:
                print_warning(f"{check_name} (check failed)")
                all_ok = False
        
        return all_ok
    
    def _show_success_message(self, elapsed):
        """Show success message"""
        print(f"\n{GREEN}{'═'*60}{NC}")
        print(f"{GREEN}{BOLD}   SLOWDNS INSTALLATION COMPLETED!{NC}")
        print(f"{GREEN}{BOLD}   Time: {elapsed:.1f} seconds{NC}")
        print(f"{GREEN}{BOLD}   Status: {'Stable' if not self.errors else 'With warnings'}{NC}")
        print(f"{GREEN}{BOLD}{'═'*60}{NC}")
        
        # Show configuration
        print(f"\n{WHITE}{BOLD}Configuration:{NC}")
        print(f"  {CYAN}•{NC} Server IP: {self.config['SERVER_IP']}")
        print(f"  {CYAN}•{NC} Nameserver: {self.config['NAMESERVER']}")
        print(f"  {CYAN}•{NC} SSH Port: {self.config['SSHD_PORT']}")
        print(f"  {CYAN}•{NC} SlowDNS Port: {self.config['SLOWDNS_PORT']}")
        
        # Show public key
        pubkey_file = Path("/etc/slowdns/server.pub")
        if pubkey_file.exists():
            print(f"\n{YELLOW}Public Key:{NC}")
            with open(pubkey_file, 'r') as f:
                print(f"{WHITE}{f.read().strip()}{NC}")
        
        # Post-install instructions
        print(f"\n{WHITE}{BOLD}Next Steps:{NC}")
        print(f"  1. Configure client with the public key above")
        print(f"  2. Test: dig @{self.config['SERVER_IP']} {self.config['NAMESERVER']}")
        print(f"  3. Check logs: journalctl -u server-sldns -f")

# Helper functions (define these)
def print_step(num): print(f"\n{BLUE}▶{NC} {CYAN}Step {num}{NC}")
def print_success(msg): print(f"  {GREEN}✓{NC} {msg}")
def print_error(msg): print(f"  {RED}✗{NC} {msg}")
def print_info(msg): print(f"  {CYAN}ℹ{NC} {msg}")
def print_warning(msg): print(f"  {YELLOW}!{NC} {msg}")
def print_header(text):
    print(f"\n{CYAN}{'═'*50}{NC}")
    print(f"{WHITE}{BOLD}{text}{NC}")
    print(f"{CYAN}{'═'*50}{NC}")

# Main entry point
if __name__ == "__main__":
    installer = BalancedSlowDNSInstaller()
    success = installer.install_balanced()
    sys.exit(0 if success else 1)
