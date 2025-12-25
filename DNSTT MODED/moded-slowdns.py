#!/usr/bin/env python3
"""
Complete SlowDNS + EDNS Proxy Installation Script
Using chiddy80 GitHub files
"""

import os
import sys
import subprocess
import time
import socket
import struct
import asyncio
import urllib.request
import shutil
from typing import Optional

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
NC = '\033[0m'

# Configuration
SSHD_PORT = 22
SLOWDNS_PORT = 5300
EXTERNAL_EDNS_SIZE = 512
INTERNAL_EDNS_SIZE = 1800

# YOUR GitHub files
SLOWDNS_FILES = {
    'server.key': [
        'https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key'
    ],
    'server.pub': [
        'https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub'
    ],
    'dnstt-client': [  # <-- WRONG FILENAME, CHANGE THIS KEY AND URL
        'https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-client'
    ]
}
def print_success(msg):
    print(f"{GREEN}[✓]{NC} {msg}")

def print_error(msg):
    print(f"{RED}[✗]{NC} {msg}")

def print_warning(msg):
    print(f"{YELLOW}[!]{NC} {msg}")

def run_cmd(cmd, capture=False):
    """Run shell command."""
    try:
        if capture:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0, result.stdout.strip()
        else:
            subprocess.run(cmd, shell=True, check=False)
            return True, ""
    except Exception as e:
        return False, str(e)

def download_file(url, dest):
    """Download file from URL."""
    try:
        print(f"Downloading {url}...")
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        print_error(f"Failed to download {url}: {e}")
        return False

def get_server_ip():
    """Get server IP address."""
    try:
        # Try external IP first
        ip = urllib.request.urlopen('https://ifconfig.me').read().decode().strip()
        if ip:
            return ip
    except:
        pass
    
    # Fallback to local IP
    try:
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        if result.stdout:
            return result.stdout.split()[0]
    except:
        pass
    
    return "127.0.0.1"

def configure_openssh():
    """Configure OpenSSH server."""
    print_warning("Configuring OpenSSH...")
    
    # Backup original config
    run_cmd("cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup 2>/dev/null")
    
    # Create new config
    sshd_config = f"""# OpenSSH Configuration
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
        with open('/etc/ssh/sshd_config', 'w') as f:
            f.write(sshd_config)
        
        run_cmd("systemctl restart sshd")
        time.sleep(2)
        print_success(f"OpenSSH configured on port {SSHD_PORT}")
        return True
    except Exception as e:
        print_error(f"Failed to configure SSH: {e}")
        return False

def setup_slowdns():
    """Setup SlowDNS (dnstt-client)."""
    print_warning("Setting up SlowDNS (dnstt-client)...")
    
    # Create directory
    os.makedirs('/etc/slowdns', exist_ok=True)
    
    # Download files
    for filename, urls in SLOWDNS_FILES.items():
        dest = f"/etc/slowdns/{filename}"
        success = False
        
        for url in urls:
            if download_file(url, dest):
                success = True
                print_success(f"{filename} downloaded")
                break
        
        if not success:
            print_error(f"Failed to download {filename}")
            return False
    
    # Make dnstt-client executable
    os.chmod('/etc/slowdns/dnstt-client', 0o755)
    print_success("File permissions set")
    
    return True

def create_slowdns_service(nameserver):
    """Create systemd service for SlowDNS."""
    print_warning("Creating SlowDNS service...")
    
    service_content = f"""[Unit]
Description=SlowDNS Server (dnstt-client)
After=network.target sshd.service

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-client -udp :{SLOWDNS_PORT} -mtu {INTERNAL_EDNS_SIZE} -privkey-file /etc/slowdns/server.key {nameserver} 127.0.0.1:{SSHD_PORT}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open('/etc/systemd/system/server-sldns.service', 'w') as f:
            f.write(service_content)
        print_success("SlowDNS service created")
        return True
    except Exception as e:
        print_error(f"Failed to create service: {e}")
        return False

def setup_firewall():
    """Setup iptables firewall rules."""
    print_warning("Setting up firewall...")
    
    rules = f"""#!/bin/sh -e
systemctl start sshd
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport {SSHD_PORT} -j ACCEPT
iptables -A INPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT
iptables -A INPUT -p tcp --dport {SLOWDNS_PORT} -j ACCEPT
iptables -A OUTPUT -p udp --dport {SLOWDNS_PORT} -j ACCEPT
iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -p tcp --dport {SSHD_PORT} -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport {SSHD_PORT} -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.core.rmem_max=134217728 > /dev/null 2>&1
sysctl -w net.core.wmem_max=134217728 > /dev/null 2>&1
exit 0
"""
    
    try:
        with open('/etc/rc.local', 'w') as f:
            f.write(rules)
        os.chmod('/etc/rc.local', 0o755)
        
        run_cmd("systemctl enable rc-local 2>/dev/null")
        run_cmd("systemctl start rc-local.service 2>/dev/null")
        print_success("Firewall configured")
        return True
    except Exception as e:
        print_error(f"Failed to setup firewall: {e}")
        return False

def disable_ipv6():
    """Disable IPv6."""
    print_warning("Disabling IPv6...")
    
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'w') as f:
            f.write('1\n')
        
        # Update sysctl
        run_cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        run_cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        
        with open('/etc/sysctl.conf', 'a') as f:
            f.write("net.ipv6.conf.all.disable_ipv6 = 1\n")
            f.write("net.ipv6.conf.default.disable_ipv6 = 1\n")
        
        run_cmd("sysctl -p")
        print_success("IPv6 disabled")
        return True
    except Exception as e:
        print_error(f"Failed to disable IPv6: {e}")
        return False

def start_slowdns(nameserver):
    """Start SlowDNS service."""
    print_warning("Starting SlowDNS service...")
    
    # Kill any existing process
    run_cmd("pkill dnstt-client 2>/dev/null")
    
    # Reload systemd
    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl enable server-sldns 2>/dev/null")
    
    # Start service
    success, output = run_cmd("systemctl start server-sldns", capture=True)
    
    time.sleep(3)
    
    # Check if running
    success, output = run_cmd("systemctl is-active server-sldns", capture=True)
    if success and "active" in output.lower():
        print_success("SlowDNS service started")
        
        # Test if listening
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b"\x00", ("127.0.0.1", SLOWDNS_PORT))
            sock.close()
            print_success(f"SlowDNS listening on port {SLOWDNS_PORT}")
        except:
            print_warning("SlowDNS not responding on test")
        
        return True
    else:
        print_error("SlowDNS service failed to start")
        
        # Try direct start
        print_warning("Trying direct start...")
        cmd = f"/etc/slowdns/dnstt-client -udp :{SLOWDNS_PORT} -mtu {INTERNAL_EDNS_SIZE} -privkey-file /etc/slowdns/server.key {nameserver} 127.0.0.1:{SSHD_PORT} &"
        run_cmd(cmd)
        time.sleep(2)
        
        success, output = run_cmd("pgrep dnstt-client", capture=True)
        if success and output:
            print_success("SlowDNS started directly")
            return True
        else:
            print_error("Failed to start SlowDNS")
            return False

# ========================= EDNS PROXY FUNCTIONS =========================

def patch_edns_size(data, new_size):
    """Patch EDNS UDP payload size in DNS packet."""
    if len(data) < 12:
        return data
    
    try:
        qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
    except:
        return data
    
    pos = 12
    
    # Skip questions
    for _ in range(qd):
        while pos < len(data) and data[pos] != 0:
            pos += 1
        pos += 5
    
    # Skip answers + authority
    for _ in range(an + ns):
        while pos < len(data) and data[pos] != 0:
            pos += 1
        if pos + 11 >= len(data):
            return data
        rdlen = struct.unpack("!H", data[pos+9:pos+11])[0]
        pos += 11 + rdlen
    
    # Find EDNS OPT
    for _ in range(ar):
        while pos < len(data) and data[pos] != 0:
            pos += 1
        if pos + 11 >= len(data):
            return data
        
        rtype = struct.unpack("!H", data[pos+1:pos+3])[0]
        if rtype == 41:  # OPT RR
            new = bytearray(data)
            new[pos+3:pos+5] = struct.pack("!H", new_size)
            return bytes(new)
        
        rdlen = struct.unpack("!H", data[pos+9:pos+11])[0]
        pos += 11 + rdlen
    
    return data

async def edns_proxy_main():
    """Main EDNS Proxy function."""
    print_warning("Starting EDNS Proxy...")
    
    # Check root
    if os.geteuid() != 0:
        print_error("EDNS Proxy requires root")
        return False
    
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024*1024)
    
    try:
        sock.bind(("0.0.0.0", 53))
    except OSError as e:
        if "Address already in use" in str(e):
            print_error("Port 53 is in use")
            print_warning("Try: sudo fuser -k 53/udp 53/tcp")
        else:
            print_error(f"Cannot bind to port 53: {e}")
        return False
    
    sock.setblocking(False)
    loop = asyncio.get_event_loop()
    
    print_success(f"EDNS Proxy: {EXTERNAL_EDNS_SIZE}↔{INTERNAL_EDNS_SIZE}")
    
    try:
        while True:
            try:
                data, addr = await loop.sock_recvfrom(sock, 65507)
                
                # Forward to SlowDNS
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", SLOWDNS_PORT,
                    proto=socket.SOCK_DGRAM
                )
                
                # Patch EDNS for SlowDNS
                query = patch_edns_size(data, INTERNAL_EDNS_SIZE)
                writer.write(query)
                await writer.drain()
                
                try:
                    response = await asyncio.wait_for(reader.read(4096), 2.0)
                    # Patch EDNS for client
                    response = patch_edns_size(response, EXTERNAL_EDNS_SIZE)
                    await loop.sock_sendto(sock, response, addr)
                except:
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()
                    
            except KeyboardInterrupt:
                break
            except Exception:
                continue
    
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    
    return True

def create_edns_proxy_service():
    """Create EDNS Proxy as systemd service."""
    print_warning("Creating EDNS Proxy service...")
    
    # Create the proxy script
    proxy_script = f'''#!/usr/bin/env python3
import socket, struct, asyncio, os, sys

EXTERNAL = {EXTERNAL_EDNS_SIZE}
INTERNAL = {INTERNAL_EDNS_SIZE}

def patch(data, new_size):
    if len(data) < 12:
        return data
    try:
        qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
    except:
        return data
    
    pos = 12
    for _ in range(qd):
        while pos < len(data) and data[pos] != 0:
            pos += 1
        pos += 5
    
    for _ in range(an + ns):
        while pos < len(data) and data[pos] != 0:
            pos += 1
        if pos + 11 >= len(data):
            return data
        rdlen = struct.unpack("!H", data[pos+9:pos+11])[0]
        pos += 11 + rdlen
    
    for _ in range(ar):
        while pos < len(data) and data[pos] != 0:
            pos += 1
        if pos + 11 >= len(data):
            return data
        
        rtype = struct.unpack("!H", data[pos+1:pos+3])[0]
        if rtype == 41:
            new = bytearray(data)
            new[pos+3:pos+5] = struct.pack("!H", new_size)
            return bytes(new)
        
        rdlen = struct.unpack("!H", data[pos+9:pos+11])[0]
        pos += 11 + rdlen
    
    return data

async def main():
    if os.geteuid() != 0:
        print("Run with sudo", file=sys.stderr)
        return
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(("0.0.0.0", 53))
        print(f"EDNS Proxy: {{EXTERNAL}}↔{{INTERNAL}}", file=sys.stderr)
    except OSError as e:
        print(f"Port 53 error: {{e}}", file=sys.stderr)
        return
    
    sock.setblocking(False)
    loop = asyncio.get_event_loop()
    
    while True:
        try:
            data, addr = await loop.sock_recvfrom(sock, 65507)
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", {SLOWDNS_PORT}, proto=socket.SOCK_DGRAM
            )
            
            query = patch(data, INTERNAL)
            writer.write(query)
            await writer.drain()
            
            try:
                response = await asyncio.wait_for(reader.read(4096), 2.0)
                response = patch(response, EXTERNAL)
                await loop.sock_sendto(sock, response, addr)
            except:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
                
        except KeyboardInterrupt:
            break
        except Exception:
            continue
    
    sock.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
'''
    
    try:
        # Save proxy script
        with open('/usr/local/bin/edns-proxy.py', 'w') as f:
            f.write(proxy_script)
        os.chmod('/usr/local/bin/edns-proxy.py', 0o755)
        print_success("EDNS Proxy script created")
        
        # Create service file
        service_content = f"""[Unit]
Description=EDNS Proxy for SlowDNS ({EXTERNAL_EDNS_SIZE}↔{INTERNAL_EDNS_SIZE})
After=network.target server-sldns.service
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/edns-proxy.py
Restart=always
RestartSec=3
User=root
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
        
        with open('/etc/systemd/system/edns-proxy.service', 'w') as f:
            f.write(service_content)
        
        run_cmd("systemctl daemon-reload")
        run_cmd("systemctl enable edns-proxy.service 2>/dev/null")
        run_cmd("systemctl start edns-proxy.service")
        
        time.sleep(2)
        
        # Check if running
        success, output = run_cmd("systemctl is-active edns-proxy.service", capture=True)
        if success and "active" in output.lower():
            print_success("EDNS Proxy service started")
            return True
        else:
            print_error("EDNS Proxy service failed")
            return False
        
    except Exception as e:
        print_error(f"Failed to create EDNS Proxy: {e}")
        return False

# ========================= MAIN INSTALLATION =========================

def main():
    """Main installation function."""
    print("\n" + "="*60)
    print("        COMPLETE SLOWDNS + EDNS PROXY INSTALLATION")
    print("="*60)
    
    # Check root
    if os.geteuid() != 0:
        print_error("Run as root: sudo python3 script.py")
        sys.exit(1)
    
    # Get server IP
    server_ip = get_server_ip()
    print(f"Server IP: {server_ip}")
    
    # Get nameserver
    print("\n" + "="*60)
    nameserver = input("Enter nameserver (e.g., dns.example.com): ").strip()
    if not nameserver:
        print_error("Nameserver is required!")
        sys.exit(1)
    
    print("\n" + "="*60)
    print_warning("Starting installation...")
    
    # Step 1: Configure OpenSSH
    if not configure_openssh():
        sys.exit(1)
    
    # Step 2: Setup SlowDNS
    if not setup_slowdns():
        sys.exit(1)
    
    # Step 3: Create SlowDNS service
    if not create_slowdns_service(nameserver):
        sys.exit(1)
    
    # Step 4: Setup firewall
    if not setup_firewall():
        print_warning("Continuing despite firewall error...")
    
    # Step 5: Disable IPv6
    if not disable_ipv6():
        print_warning("Continuing despite IPv6 error...")
    
    # Step 6: Start SlowDNS
    if not start_slowdns(nameserver):
        print_warning("SlowDNS may not be running")
    
    # Step 7: Create EDNS Proxy service
    if not create_edns_proxy_service():
        print_warning("EDNS Proxy installation failed")
        print_warning("You can still use SlowDNS on port 5300")
    
    # Final output
    print("\n" + "="*60)
    print_success("INSTALLATION COMPLETE!")
    print("="*60)
    print(f"SSH Port:        {SSHD_PORT}")
    print(f"SlowDNS Port:    {SLOWDNS_PORT}")
    print(f"MTU:             {INTERNAL_EDNS_SIZE}")
    print(f"Nameserver:      {nameserver}")
    print(f"Server IP:       {server_ip}")
    print("="*60)
    print("\nCommands:")
    print("  sudo systemctl status server-sldns    # Check SlowDNS")
    print("  sudo systemctl status edns-proxy      # Check EDNS Proxy")
    print("  dig @127.0.0.1 google.com             # Test DNS")
    print("  dig @127.0.0.1 -p 5300 google.com     # Test SlowDNS directly")
    print("\nLogs:")
    print("  sudo journalctl -u server-sldns -f")
    print("  sudo journalctl -u edns-proxy -f")
    print("="*60)

if __name__ == "__main__":
    main()
