#!/usr/bin/env python3
"""
EDNS Proxy for SlowDNS - Fixed Version
"""

import socket
import struct
import threading
import time
import sys
import os
import subprocess

# Colors for output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

# Configuration
EXTERNAL_EDNS_SIZE = 512
INTERNAL_EDNS_SIZE = 1232
LISTEN_PORT = 53
UPSTREAM_PORT = 5300

def print_msg(msg):
    print(f"{BLUE}[*]{NC} {msg}")

def print_success(msg):
    print(f"{GREEN}[✓]{NC} {msg}")

def print_error(msg):
    print(f"{RED}[✗]{NC} {msg}")

def print_warning(msg):
    print(f"{YELLOW}[!]{NC} {msg}")

def check_root():
    if os.geteuid() != 0:
        print_error("Please run as root: sudo python3 script.py")
        sys.exit(1)

def check_slowdns():
    print_msg(f"Checking if SlowDNS is running on port {UPSTREAM_PORT}...")
    
    # Simple check without subprocess errors
    try:
        # Try to connect to the port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b"test", ("127.0.0.1", UPSTREAM_PORT))
        sock.close()
        print_success(f"SlowDNS found running on port {UPSTREAM_PORT}")
        return True
    except:
        print_warning(f"SlowDNS not found on port {UPSTREAM_PORT}")
        print(f"\n{YELLOW}Note: This EDNS Proxy requires SlowDNS to be running first.{NC}")
        print(f"{YELLOW}Please install and start SlowDNS before running this script.{NC}\n")
        return False

def safe_stop_dns():
    print_msg("Stopping existing DNS services on port 53...")
    
    # Stop systemd-resolved if running
    try:
        result = subprocess.run(['systemctl', 'is-active', 'systemd-resolved'], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print_msg("Stopping systemd-resolved...")
            subprocess.run(['systemctl', 'stop', 'systemd-resolved'])
            time.sleep(1)
    except:
        pass
    
    # Disable systemd-resolved - FIXED: no capture_output
    try:
        subprocess.run(['systemctl', 'disable', 'systemd-resolved'])
    except:
        pass
    
    # Check what's on port 53
    print_msg("Checking what's using port 53...")
    
    try:
        result = subprocess.run(['ss', '-tulpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        port_users = []
        for line in result.stdout.decode().split('\n'):
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
            
            # Stop services
            print_msg("Stopping services...")
            
            # Stop common DNS services
            services = ['dnsmasq', 'bind9', 'named']
            for service in services:
                try:
                    subprocess.run(['systemctl', 'stop', service])
                except:
                    pass
            
            time.sleep(2)
            
            # If still in use, use fuser
            result = subprocess.run(['ss', '-tulpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if ':53 ' in result.stdout.decode():
                print_msg("Freeing port 53 using fuser...")
                subprocess.run(['fuser', '-k', '53/udp'])
                subprocess.run(['fuser', '-k', '53/tcp'])
                time.sleep(2)
    
    except Exception as e:
        print_error(f"Error checking port 53: {e}")
    
    print_success("Port 53 prepared for EDNS Proxy")

def configure_dns():
    print_msg("Configuring DNS...")
    
    try:
        # Remove symlink if exists
        if os.path.islink('/etc/resolv.conf'):
            os.remove('/etc/resolv.conf')
        
        # Write new DNS config
        with open('/etc/resolv.conf', 'w') as f:
            f.write("nameserver 8.8.8.8\n")
            f.write("nameserver 8.8.4.4\n")
        
        print_success("DNS configured")
        return True
    except Exception as e:
        print_error(f"Failed to configure DNS: {e}")
        return False

def disable_services():
    print_msg("Disabling services...")
    
    # Disable UFW
    try:
        subprocess.run(['ufw', 'disable'])
        subprocess.run(['systemctl', 'stop', 'ufw'])
        subprocess.run(['systemctl', 'disable', 'ufw'])
        print_success("UFW disabled")
    except:
        pass
    
    # Disable IPv6
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'w') as f:
            f.write('1\n')
        print_success("IPv6 disabled")
    except:
        pass

def create_edns_proxy():
    print_msg("Creating EDNS Proxy script...")
    
    script = '''#!/usr/bin/env python3
import socket, threading, struct

EXTERNAL = 512
INTERNAL = 1232

def patch_edns(data, new_size):
    if len(data) < 12:
        return data
    try:
        qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
    except:
        return data
    
    offset = 12
    
    # Skip questions
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            offset += 1
        offset += 5
    
    # Skip answers and authority
    for _ in range(ancount + nscount):
        while offset < len(data) and data[offset] != 0:
            offset += 1
        if offset + 11 >= len(data):
            return data
        rdlen = struct.unpack("!H", data[offset+9:offset+11])[0]
        offset += 11 + rdlen
    
    # Find and patch EDNS
    for _ in range(arcount):
        while offset < len(data) and data[offset] != 0:
            offset += 1
        if offset + 11 >= len(data):
            return data
        
        rtype = struct.unpack("!H", data[offset+1:offset+3])[0]
        if rtype == 41:
            new_data = bytearray(data)
            new_data[offset+3:offset+5] = struct.pack("!H", new_size)
            return bytes(new_data)
        
        rdlen = struct.unpack("!H", data[offset+9:offset+11])[0]
        offset += 11 + rdlen
    
    return data

def handle(sock, data, addr):
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.settimeout(3)
    
    try:
        # To SlowDNS with bigger EDNS
        query = patch_edns(data, INTERNAL)
        upstream.sendto(query, ("127.0.0.1", 5300))
        
        # From SlowDNS
        response, _ = upstream.recvfrom(4096)
        response = patch_edns(response, EXTERNAL)
        sock.sendto(response, addr)
    except:
        pass
    finally:
        upstream.close()

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    
    print("[EDNS Proxy] Listening on port 53")
    print("[EDNS Proxy] Forwarding to 127.0.0.1:5300")
    print("[EDNS Proxy] EDNS: 512 -> 1232")
    
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            threading.Thread(target=handle, args=(sock, data, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[EDNS Proxy] Stopping")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
'''
    
    try:
        with open('/usr/local/bin/edns-proxy.py', 'w') as f:
            f.write(script)
        os.chmod('/usr/local/bin/edns-proxy.py', 0o755)
        print_success("EDNS Proxy script created")
        return True
    except Exception as e:
        print_error(f"Failed to create script: {e}")
        return False

def create_systemd_service():
    print_msg("Creating systemd service...")
    
    service = '''[Unit]
Description=EDNS Proxy for SlowDNS
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/edns-proxy.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
'''
    
    try:
        with open('/etc/systemd/system/edns-proxy.service', 'w') as f:
            f.write(service)
        
        subprocess.run(['systemctl', 'daemon-reload'])
        subprocess.run(['systemctl', 'enable', 'edns-proxy.service'])
        
        print_success("Systemd service created")
        return True
    except Exception as e:
        print_error(f"Failed to create service: {e}")
        return False

def start_service():
    print_msg("Starting EDNS Proxy service...")
    
    try:
        subprocess.run(['systemctl', 'start', 'edns-proxy.service'])
        time.sleep(2)
        
        # Check status
        result = subprocess.run(['systemctl', 'is-active', 'edns-proxy.service'], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print_success("EDNS Proxy service started")
        else:
            print_warning("Service might not be running")
    except Exception as e:
        print_error(f"Failed to start service: {e}")

def main():
    print("\n" + "="*60)
    print("            EDNS Proxy for SlowDNS Installation")
    print("="*60 + "\n")
    
    # Check root
    check_root()
    
    print_msg("Starting installation...")
    
    # Check SlowDNS
    slowdns_running = check_slowdns()
    if not slowdns_running:
        print_warning("SlowDNS not found. Continuing setup anyway...")
    
    # Configure system
    configure_dns()
    disable_services()
    
    # Stop DNS services
    safe_stop_dns()
    
    # Create proxy
    if not create_edns_proxy():
        sys.exit(1)
    
    # Create service
    create_systemd_service()
    
    # Start service
    start_service()
    
    # Final message
    print(f"\n{GREEN}="*60)
    print_success("INSTALLATION COMPLETE!")
    print(f"{GREEN}="*60)
    
    print(f"\n{YELLOW}Commands:{NC}")
    print("  sudo systemctl status edns-proxy")
    print("  sudo systemctl restart edns-proxy")
    print("  dig @127.0.0.1 google.com")
    
    if not slowdns_running:
        print(f"\n{YELLOW}Warning:{NC} SlowDNS is not running!")
        print("Start SlowDNS first for EDNS Proxy to work.")
    
    print()

if __name__ == "__main__":
    main()
