#!/usr/bin/env python3
"""
EDNS Proxy for SlowDNS - Complete with DNS Configuration
"""

import socket
import struct
import threading
import time
import sys
import os
import subprocess
import signal

# Colors for output (same as your bash script)
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN = '\033[0;36m'
WHITE = '\033[1;37m'
NC = '\033[0m'

# Configuration
EXTERNAL_EDNS_SIZE = 512
INTERNAL_EDNS_SIZE = 1232
LISTEN_PORT = 53
UPSTREAM_PORT = 5300

def print_title():
    """Clear and show title like bash script."""
    os.system('clear')
    print(f"\n{CYAN}────────────────────────────────────────────────────────────────{NC}")
    print(f"{WHITE}   S L O W D N S   O P E N S S H   +   E D N S   P R O X Y{NC}")
    print(f"{CYAN}────────────────────────────────────────────────────────────────{NC}")
    print(f"{YELLOW}   Complete Installation Script{NC}")
    print(f"{CYAN}────────────────────────────────────────────────────────────────{NC}\n")

def print_msg(msg):
    """Equivalent to print() in bash."""
    print(f"{BLUE}[*]{NC} {msg}")

def print_success(msg):
    """Equivalent to print_success() in bash."""
    print(f"{GREEN}[✓]{NC} {msg}")

def print_error(msg):
    """Equivalent to print_error() in bash."""
    print(f"{RED}[✗]{NC} {msg}")

def print_warning(msg):
    """Equivalent to print_warning() in bash."""
    print(f"{YELLOW}[!]{NC} {msg}")

def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        print_error("Please run as root: sudo python3 script.py")
        sys.exit(1)

def configure_dns():
    """Configure DNS settings like in your bash script."""
    print_msg("Configuring DNS...")
    
    try:
        # Check if /etc/resolv.conf is a symlink
        if os.path.islink('/etc/resolv.conf'):
            os.remove('/etc/resolv.conf')
            print_msg("Removed symlink /etc/resolv.conf")
        
        # Write new DNS configuration
        with open('/etc/resolv.conf', 'w') as f:
            f.write("nameserver 8.8.8.8\n")
            f.write("nameserver 8.8.4.4\n")
        
        # Make it immutable like in bash script
        try:
            subprocess.run(['chattr', '+i', '/etc/resolv.conf'], 
                         capture_output=True, stderr=subprocess.DEVNULL)
        except:
            pass  # chattr might not be available
        
        print_success("DNS configured")
        return True
        
    except Exception as e:
        print_error(f"Failed to configure DNS: {e}")
        return False

def disable_systemd_resolved():
    """Disable systemd-resolved service."""
    print_msg("Disabling systemd-resolved...")
    
    try:
        # Check if service is active
        result = subprocess.run(['systemctl', 'is-active', 'systemd-resolved'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            subprocess.run(['systemctl', 'stop', 'systemd-resolved'])
            print_msg("Stopped systemd-resolved")
        
        # Disable it
        subprocess.run(['systemctl', 'disable', 'systemd-resolved'], 
                      capture_output=True, stderr=subprocess.DEVNULL)
        
        print_success("systemd-resolved disabled")
        return True
        
    except Exception as e:
        print_error(f"Failed to disable systemd-resolved: {e}")
        return False

def disable_ufw():
    """Disable UFW firewall."""
    print_msg("Disabling UFW...")
    
    try:
        # Check if UFW is installed and active
        result = subprocess.run(['systemctl', 'is-active', 'ufw'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            subprocess.run(['ufw', 'disable'], capture_output=True, stderr=subprocess.DEVNULL)
            subprocess.run(['systemctl', 'stop', 'ufw'])
            print_msg("Stopped UFW")
        
        subprocess.run(['systemctl', 'disable', 'ufw'], 
                      capture_output=True, stderr=subprocess.DEVNULL)
        
        print_success("UFW disabled")
        return True
        
    except Exception as e:
        print_warning(f"UFW not available: {e}")
        return False

def disable_ipv6():
    """Disable IPv6 like in bash script."""
    print_msg("Disabling IPv6...")
    
    try:
        # Write to proc
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'w') as f:
            f.write('1\n')
        
        # Update sysctl
        commands = [
            "sysctl -w net.ipv6.conf.all.disable_ipv6=1",
            "sysctl -w net.ipv6.conf.default.disable_ipv6=1",
            "echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf",
            "echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.conf",
            "sysctl -p"
        ]
        
        for cmd in commands:
            os.system(f"{cmd} > /dev/null 2>&1")
        
        print_success("IPv6 disabled")
        return True
        
    except Exception as e:
        print_warning(f"Failed to disable IPv6: {e}")
        return False

def check_slowdns():
    """Check if SlowDNS is running on port 5300."""
    print_msg(f"Checking if SlowDNS is running on port {UPSTREAM_PORT}...")
    
    try:
        # Use ss command like in bash script
        result = subprocess.run(['ss', '-ulpn'], capture_output=True, text=True)
        if f":{UPSTREAM_PORT}" in result.stdout:
            print_success(f"SlowDNS found running on port {UPSTREAM_PORT}")
            return True
        else:
            print_error(f"SlowDNS not found on port {UPSTREAM_PORT}")
            print(f"\n{YELLOW}Note: This EDNS Proxy requires SlowDNS to be running first.{NC}")
            print(f"{YELLOW}Please install and start SlowDNS before running this script.{NC}\n")
            return False
    except:
        print_error("Failed to check SlowDNS")
        return False

def safe_stop_dns():
    """
    SAFE: Stop DNS services without killing the script
    Exact translation from your bash function
    """
    print_msg("Stopping existing DNS services on port 53...")
    
    # 1. Stop systemd-resolved if running
    try:
        result = subprocess.run(['systemctl', 'is-active', 'systemd-resolved'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print_msg("Stopping systemd-resolved...")
            subprocess.run(['systemctl', 'stop', 'systemd-resolved'])
            time.sleep(1)
    except:
        pass
    
    # 2. Disable systemd-resolved from starting on boot
    subprocess.run(['systemctl', 'disable', 'systemd-resolved'], 
                  capture_output=True, stderr=subprocess.DEVNULL)
    
    # 3. Check what's on port 53 without killing
    print_msg("Checking what's using port 53...")
    
    try:
        result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
        port_users = []
        for line in result.stdout.split('\n'):
            if ':53 ' in line:
                port_users.append(line.strip())
                if len(port_users) >= 5:
                    break
        
        if port_users:
            print_warning("Port 53 is currently in use by:")
            for line in port_users:
                print(f"  {line}")
            
            # Ask user for confirmation
            print("")
            reply = input("Continue and stop these services? (y/n): ").strip().lower()
            if reply not in ['y', 'yes']:
                print_error("Installation aborted by user")
                sys.exit(1)
            
            # Gracefully stop services by service name
            print_msg("Stopping services gracefully...")
            
            # Check and stop dnsmasq
            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service'], 
                                      capture_output=True, text=True)
                if 'dnsmasq' in result.stdout:
                    subprocess.run(['systemctl', 'stop', 'dnsmasq'], 
                                 capture_output=True, stderr=subprocess.DEVNULL)
            except:
                pass
            
            # Check and stop bind9
            try:
                if 'bind9' in result.stdout:
                    subprocess.run(['systemctl', 'stop', 'bind9'], 
                                 capture_output=True, stderr=subprocess.DEVNULL)
            except:
                pass
            
            # Check and stop named
            try:
                if 'named' in result.stdout:
                    subprocess.run(['systemctl', 'stop', 'named'], 
                                 capture_output=True, stderr=subprocess.DEVNULL)
            except:
                pass
            
            time.sleep(2)
            
            # Check if still in use
            result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
            if ':53 ' in result.stdout:
                print_msg("Freeing port 53 using fuser...")
                subprocess.run(['fuser', '-k', '53/udp'], 
                             capture_output=True, stderr=subprocess.DEVNULL)
                subprocess.run(['fuser', '-k', '53/tcp'], 
                             capture_output=True, stderr=subprocess.DEVNULL)
                time.sleep(2)
    
    except Exception as e:
        print_error(f"Error checking port 53: {e}")
    
    print_success("Port 53 prepared for EDNS Proxy")

def install_python3():
    """Install Python3 if not present."""
    print_msg("Checking for Python3...")
    
    # Check if python3 is installed
    try:
        subprocess.run(['python3', '--version'], capture_output=True, check=True)
        print_success("Python3 already installed")
        return True
    except:
        print_msg("Python3 not found, installing...")
        try:
            subprocess.run(['apt-get', 'update'], 
                         capture_output=True, stderr=subprocess.DEVNULL)
            subprocess.run(['apt-get', 'install', '-y', 'python3'], 
                         capture_output=True, stderr=subprocess.DEVNULL)
            print_success("Python3 installed")
            return True
        except:
            print_error("Failed to install Python3")
            return False

def create_edns_proxy_script():
    """Create EDNS Proxy Python script."""
    print_msg("Creating EDNS Proxy Python script...")
    
    script_content = '''#!/usr/bin/env python3
"""
EDNS Proxy for SlowDNS (smart parser)
- Listens on UDP :53 (public)
- Forwards to 127.0.0.1:5300 (SlowDNS server) with bigger EDNS size
- Outside sees 512, inside server sees 1232
"""

import socket
import threading
import struct
import sys
import os

# Public listen
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53

# Internal SlowDNS server address
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 5300

# EDNS sizes
EXTERNAL_EDNS_SIZE = 512    # what we show to clients
INTERNAL_EDNS_SIZE = 1232   # what we tell SlowDNS internally


def patch_edns_udp_size(data: bytes, new_size: int) -> bytes:
    """
    Parse DNS message properly and patch EDNS (OPT RR) UDP payload size.
    If no EDNS / cannot parse properly → return data as is.
    """
    if len(data) < 12:
        return data

    try:
        # Header: ID(2), FLAGS(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
        qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
    except struct.error:
        return data

    offset = 12

    def skip_name(buf, off):
        """Skip DNS name (supporting compression)."""
        while True:
            if off >= len(buf):
                return len(buf)
            l = buf[off]
            off += 1
            if l == 0:
                break
            if l & 0xC0 == 0xC0:
                # compression pointer, one more byte
                if off >= len(buf):
                    return len(buf)
                off += 1
                break
            off += l
        return off

    # Skip Questions
    for _ in range(qdcount):
        offset = skip_name(data, offset)
        if offset + 4 > len(data):
            return data
        offset += 4  # QTYPE + QCLASS

    def skip_rrs(count, buf, off):
        """Skip Resource Records (Answer + Authority)."""
        for _ in range(count):
            off = skip_name(buf, off)
            if off + 10 > len(buf):
                return len(buf)
            # TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", buf[off:off+10])
            off += 10
            if off + rdlen > len(buf):
                return len(buf)
            off += rdlen
        return off

    # Skip Answer + Authority
    offset = skip_rrs(ancount, data, offset)
    offset = skip_rrs(nscount, data, offset)

    # Additional section → EDNS OPT RR is here
    new_data = bytearray(data)
    for _ in range(arcount):
        rr_name_start = offset
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            return data
        rtype = struct.unpack("!H", data[offset:offset+2])[0]

        if rtype == 41:  # OPT RR (EDNS)
            # UDP payload size is 2 bytes after TYPE
            size_bytes = struct.pack("!H", new_size)
            new_data[offset+2:offset+4] = size_bytes
            return bytes(new_data)

        # Skip CLASS(2) + TTL(4) + RDLEN(2) + RDATA
        _, _, rdlen = struct.unpack("!H I H", data[offset+2:offset+10])
        offset += 10 + rdlen

    return data


def handle_request(server_sock: socket.socket, data: bytes, client_addr):
    """
    - patch EDNS size to INTERNAL_EDNS_SIZE for request
    - send to upstream (SlowDNS:5300)
    - receive response, patch EDNS size to EXTERNAL_EDNS_SIZE
    - return to client
    """
    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.settimeout(5.0)

    try:
        upstream_data = patch_edns_udp_size(data, INTERNAL_EDNS_SIZE)
        upstream_sock.sendto(upstream_data, (UPSTREAM_HOST, UPSTREAM_PORT))

        resp, _ = upstream_sock.recvfrom(4096)
        resp_patched = patch_edns_udp_size(resp, EXTERNAL_EDNS_SIZE)

        server_sock.sendto(resp_patched, client_addr)
    except socket.timeout:
        # client will resend, no need to kill proxy
        pass
    except Exception as e:
        # Log error but don't crash
        pass
    finally:
        upstream_sock.close()


def main():
    """Main function for EDNS Proxy."""
    # Check if we're root
    if os.geteuid() != 0:
        print("Error: This script must be run as root")
        sys.exit(1)
    
    # Create socket
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind((LISTEN_HOST, LISTEN_PORT))
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    except OSError as e:
        print(f"Error: Cannot bind to port {LISTEN_PORT}: {e}")
        print("Try: sudo python3 edns-proxy.py")
        sys.exit(1)
    
    print(f"[EDNS Proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[EDNS Proxy] Forwarding to {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    print(f"[EDNS Proxy] EDNS: {EXTERNAL_EDNS_SIZE} ↔ {INTERNAL_EDNS_SIZE}")
    print("[EDNS Proxy] Press Ctrl+C to stop")
    
    try:
        while True:
            data, client_addr = server_sock.recvfrom(4096)
            t = threading.Thread(
                target=handle_request,
                args=(server_sock, data, client_addr),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[EDNS Proxy] Stopping...")
    finally:
        server_sock.close()
        print("[EDNS Proxy] Stopped")


if __name__ == "__main__":
    main()
'''
    
    try:
        with open('/usr/local/bin/edns-proxy.py', 'w') as f:
            f.write(script_content)
        os.chmod('/usr/local/bin/edns-proxy.py', 0o755)
        print_success("EDNS Proxy Python script created")
        return True
    except Exception as e:
        print_error(f"Failed to create script: {e}")
        return False

def create_systemd_service():
    """Create systemd service for EDNS Proxy."""
    print_msg("Creating EDNS Proxy systemd service...")
    
    service_content = f"""[Unit]
Description=EDNS Proxy for SlowDNS (512 ↔ {INTERNAL_EDNS_SIZE})
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/edns-proxy.py
Restart=always
RestartSec=3
User=root
LimitNOFILE=65536
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open('/etc/systemd/system/edns-proxy.service', 'w') as f:
            f.write(service_content)
        
        # Reload systemd and enable service
        subprocess.run(['systemctl', 'daemon-reload'])
        subprocess.run(['systemctl', 'enable', 'edns-proxy.service'], 
                      capture_output=True, stderr=subprocess.DEVNULL)
        
        print_success("EDNS Proxy systemd service created")
        return True
    except Exception as e:
        print_error(f"Failed to create systemd service: {e}")
        return False

def setup_firewall_rules():
    """Setup iptables rules for DNS."""
    print_msg("Setting up firewall rules...")
    
    rules = [
        "iptables -F",
        "iptables -t nat -F",
        "iptables -A INPUT -p udp --dport 53 -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 53 -j ACCEPT",
        "iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53",
        "iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53"
    ]
    
    try:
        for rule in rules:
            subprocess.run(rule.split(), capture_output=True, stderr=subprocess.DEVNULL)
        print_success("Firewall rules configured")
        return True
    except:
        print_warning("Failed to configure firewall rules (iptables not available?)")
        return True

def create_test_commands():
    """Create test commands like in bash script."""
    print_msg("Creating test commands...")
    
    # Create status script
    status_script = '''#!/bin/bash
echo "=== EDNS Proxy Status ==="
echo ""
echo "Service Status:"
systemctl status edns-proxy --no-pager | grep "Active:" | sed 's/^/  /'
echo ""
echo "Port Status:"
echo "  Port 53 (EDNS Proxy):"
ss -ulpn | grep ":53" | sed 's/^/    /'
echo "  Port 5300 (SlowDNS):"
ss -ulpn | grep ":5300" | sed 's/^/    /'
'''
    
    # Create test script
    test_script = '''#!/bin/bash
echo "Testing EDNS Proxy..."
echo "Running: dig @127.0.0.1 google.com +short"
dig @127.0.0.1 google.com +short
'''
    
    try:
        with open('/usr/local/bin/edns-status', 'w') as f:
            f.write(status_script)
        os.chmod('/usr/local/bin/edns-status', 0o755)
        
        with open('/usr/local/bin/test-edns', 'w') as f:
            f.write(test_script)
        os.chmod('/usr/local/bin/test-edns', 0o755)
        
        print_success("Test commands created")
        return True
    except:
        print_warning("Failed to create test commands")
        return True

def main():
    """Main installation function."""
    # Show title
    print_title()
    
    # Check root
    check_root()
    
    print_msg("Starting Complete SlowDNS + EDNS Proxy Installation...")
    print("")
    
    # Step 1: Disable services
    disable_ufw()
    disable_systemd_resolved()
    
    # Step 2: Configure DNS
    configure_dns()
    
    # Step 3: Check SlowDNS
    if not check_slowdns():
        print_warning("SlowDNS not found. Please install SlowDNS first.")
        print_warning("Continuing with EDNS Proxy setup...")
    
    # Step 4: Install Python3
    if not install_python3():
        sys.exit(1)
    
    # Step 5: Stop DNS services
    safe_stop_dns()
    
    # Step 6: Disable IPv6
    disable_ipv6()
    
    # Step 7: Create EDNS Proxy script
    if not create_edns_proxy_script():
        sys.exit(1)
    
        # Step 8: Create systemd service
    create_systemd_service()
    
    # Step 9: Setup firewall
    setup_firewall_rules()
    
    # Step 10: Create test commands
    create_test_commands()
    
    # Step 11: Start EDNS Proxy service
    print_msg("Starting EDNS Proxy service...")
    try:
        subprocess.run(['systemctl', 'daemon-reload'])
        subprocess.run(['systemctl', 'start', 'edns-proxy.service'])
        
        # Check if service started successfully
        time.sleep(3)
        result = subprocess.run(['systemctl', 'is-active', 'edns-proxy.service'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print_success("EDNS Proxy service started")
        else:
            print_warning("EDNS Proxy service might not be running")
            print_warning("Try starting manually: sudo systemctl start edns-proxy")
    except Exception as e:
        print_error(f"Failed to start service: {e}")
    
    # Step 12: Test the installation
    print_msg("Testing EDNS Proxy installation...")
    
    # Test 1: Check if port 53 is listening
    try:
        result = subprocess.run(['ss', '-ulpn'], capture_output=True, text=True)
        if ':53 ' in result.stdout:
            print_success("Port 53 is listening")
        else:
            print_warning("Port 53 not listening")
    except:
        pass
    
    # Test 2: Check service status
    try:
        result = subprocess.run(['systemctl', 'status', 'edns-proxy.service', '--no-pager'], 
                              capture_output=True, text=True)
        if 'Active: active' in result.stdout:
            print_success("EDNS Proxy service is active")
        else:
            print_warning("Check service status with: sudo systemctl status edns-proxy")
    except:
        pass
    
    # Final message
    print(f"\n{GREEN}────────────────────────────────────────────────────────────────{NC}")
    print_success("COMPLETE INSTALLATION FINISHED!")
    print(f"{GREEN}────────────────────────────────────────────────────────────────{NC}")
    
    print(f"\n{YELLOW}=== Summary ==={NC}")
    print(f"{GREEN}✓{NC} DNS configured (8.8.8.8, 8.8.4.4)")
    print(f"{GREEN}✓{NC} systemd-resolved disabled")
    print(f"{GREEN}✓{NC} UFW disabled")
    print(f"{GREEN}✓{NC} IPv6 disabled")
    print(f"{GREEN}✓{NC} EDNS Proxy installed")
    print(f"{GREEN}✓{NC} Systemd service created")
    print(f"{GREEN}✓{NC} Firewall rules configured")
    print(f"{GREEN}✓{NC} Test commands installed")
    
    print(f"\n{YELLOW}=== Quick Commands ==={NC}")
    print(f"{CYAN}Service Management:{NC}")
    print("  sudo systemctl start edns-proxy     # Start EDNS Proxy")
    print("  sudo systemctl stop edns-proxy      # Stop EDNS Proxy")
    print("  sudo systemctl restart edns-proxy   # Restart EDNS Proxy")
    print("  sudo systemctl status edns-proxy    # Check status")
    print("  sudo systemctl enable edns-proxy    # Enable auto-start")
    print("  sudo systemctl disable edns-proxy   # Disable auto-start")
    
    print(f"\n{CYAN}Testing:{NC}")
    print("  edns-status                         # Check EDNS Proxy status")
    print("  test-edns                           # Test DNS resolution")
    print("  dig @127.0.0.1 google.com           # Manual DNS test")
    print("  dig @127.0.0.1 google.com +short    # Short DNS test")
    
    print(f"\n{CYAN}Troubleshooting:{NC}")
    print("  sudo journalctl -u edns-proxy -f    # View logs in real-time")
    print("  sudo ss -ulpn | grep :53            # Check port 53 usage")
    print("  sudo python3 /usr/local/bin/edns-proxy.py  # Run manually")
    
    print(f"\n{YELLOW}=== Immediate Actions ==={NC}")
    print("1. Test DNS resolution:")
    print("   $ dig @127.0.0.1 google.com")
    print("")
    print("2. Enable auto-start on boot:")
    print("   $ sudo systemctl enable edns-proxy")
    print("")
    print("3. Check service status:")
    print("   $ sudo systemctl status edns-proxy")
    
    print(f"\n{YELLOW}=== If DNS is not working ==={NC}")
    print("1. Check if SlowDNS is running:")
    print("   $ sudo ss -ulpn | grep :5300")
    print("")
    print("2. Restart EDNS Proxy:")
    print("   $ sudo systemctl restart edns-proxy")
    print("")
    print("3. Check for port 53 conflicts:")
    print("   $ sudo ss -tulpn | grep :53")
    print("")
    print("4. Kill processes on port 53:")
    print("   $ sudo fuser -k 53/udp")
    print("   $ sudo fuser -k 53/tcp")
    
    print(f"\n{YELLOW}=== Manual Start (if service fails) ==={NC}")
    print("Run EDNS Proxy manually:")
    print("  sudo python3 /usr/local/bin/edns-proxy.py")
    print("")
    print("Or run in background:")
    print("  nohup sudo python3 /usr/local/bin/edns-proxy.py > /tmp/edns.log 2>&1 &")
    
    print(f"\n{GREEN}────────────────────────────────────────────────────────────────{NC}")
    print_success("Installation complete! You can now use SlowDNS with EDNS support.")
    print(f"{GREEN}────────────────────────────────────────────────────────────────{NC}")
    print("")
    
    # Ask if user wants to start service now
    try:
        print(f"{YELLOW}Do you want to start EDNS Proxy now and enable auto-start?{NC}")
        reply = input("(y/n, default=y): ").strip().lower()
        if reply in ['', 'y', 'yes']:
            print_msg("Starting EDNS Proxy...")
            subprocess.run(['systemctl', 'start', 'edns-proxy.service'])
            subprocess.run(['systemctl', 'enable', 'edns-proxy.service'])
            print_success("EDNS Proxy started and enabled!")
            
            # Quick test
            print_msg("Performing quick test...")
            time.sleep(2)
            try:
                result = subprocess.run(['dig', '@127.0.0.1', 'google.com', '+short', '+time=2', '+tries=1'], 
                                      capture_output=True, text=True)
                if result.stdout.strip():
                    print_success("DNS test successful!")
                else:
                    print_warning("DNS test returned no results (might need a moment)")
            except:
                print_warning("Could not run DNS test")
    except KeyboardInterrupt:
        print("\n")
    except:
        pass

if __name__ == "__main__":
    main()
