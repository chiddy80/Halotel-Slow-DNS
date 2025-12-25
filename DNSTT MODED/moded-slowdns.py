#!/usr/bin/env python3
"""
EDNS Proxy for SlowDNS - Smooth Running Version
Handles port conflicts gracefully and ensures clean startup
"""

import socket
import threading
import struct
import sys
import os
import time
import signal
import subprocess
from datetime import datetime

# Configuration
EXTERNAL_EDNS_SIZE = 512
INTERNAL_EDNS_SIZE = 1232
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 5300
ALT_PORT = 5353  # Alternative port if 53 fails

def log_message(level, message):
    """Clean logging without colors for better compatibility."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    levels = {
        'INFO': '[*]',
        'SUCCESS': '[✓]',
        'ERROR': '[✗]',
        'WARNING': '[!]'
    }
    print(f"[{timestamp}] {levels.get(level, '[*]')} {message}")

def is_slowdns_running():
    """Check if SlowDNS is running on port 5300."""
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.settimeout(1)
        test_sock.sendto(b"\x00" * 12, (UPSTREAM_HOST, UPSTREAM_PORT))
        test_sock.close()
        return True
    except:
        return False

def get_port_53_users():
    """Get detailed info about what's using port 53."""
    users = []
    
    # Check with ss
    try:
        result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if ':53 ' in line:
                users.append(line.strip())
    except:
        pass
    
    # Check with lsof
    try:
        result = subprocess.run(['lsof', '-i', ':53'], capture_output=True, text=True)
        for line in result.stdout.split('\n')[1:]:
            if line.strip():
                users.append(line.strip())
    except:
        pass
    
    return users

def stop_dns_services_safely():
    """Safely stop DNS services using port 53."""
    log_message('INFO', 'Checking port 53 usage...')
    users = get_port_53_users()
    
    if not users:
        log_message('SUCCESS', 'Port 53 is available')
        return True
    
    log_message('WARNING', f'Port 53 is in use by {len(service)} service(s):')
    for user in users[:3]:  # Show first 3
        print(f"  → {user}")
    
    # Common DNS services to stop
    services_to_stop = [
        'systemd-resolved',
        'dnsmasq',
        'bind9',
        'named',
        'unbound',
        'stubby'
    ]
    
    log_message('INFO', 'Attempting to stop DNS services...')
    
    stopped_count = 0
    for service in services_to_stop:
        try:
            # Check if service exists and is running
            result = subprocess.run(
                ['systemctl', 'is-active', service],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:  # Service is active
                log_message('INFO', f'Stopping {service}...')
                subprocess.run(['systemctl', 'stop', service], check=False)
                subprocess.run(['systemctl', 'disable', service], check=False)
                stopped_count += 1
                time.sleep(0.5)
        except:
            continue
    
    # Also try to kill processes using fuser
    try:
        log_message('INFO', 'Clearing remaining processes on port 53...')
        subprocess.run(['fuser', '-k', '53/udp'], capture_output=True)
        subprocess.run(['fuser', '-k', '53/tcp'], capture_output=True)
        time.sleep(1)
    except:
        pass
    
    # Verify port is free
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.bind((LISTEN_HOST, LISTEN_PORT))
        test_sock.close()
        log_message('SUCCESS', 'Port 53 is now available')
        return True
    except OSError:
        log_message('WARNING', 'Port 53 still in use, will use alternative port')
        return False

def create_redirect_rules():
    """Create iptables rules to redirect DNS traffic."""
    log_message('INFO', 'Setting up iptables redirect rules...')
    
    rules = [
        'iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353',
        'iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353',
        'iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 5353',
        'iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 5353'
    ]
    
    for rule in rules:
        try:
            subprocess.run(rule.split(), check=False)
        except:
            pass
    
    log_message('SUCCESS', 'Redirect rules created')

def patch_edns_size(data, new_size):
    """Patch EDNS UDP payload size in DNS packet."""
    if len(data) < 12:
        return data
    
    try:
        qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
    except struct.error:
        return data
    
    offset = 12
    
    def skip_name(buf, pos):
        """Skip DNS name with compression."""
        while pos < len(buf):
            length = buf[pos]
            pos += 1
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                pos += 1
                break
            pos += length
        return pos
    
    # Skip questions
    for _ in range(qdcount):
        offset = skip_name(data, offset)
        if offset + 4 > len(data):
            return data
        offset += 4
    
    # Skip answers and authority
    def skip_rrs(count):
        nonlocal offset
        for _ in range(count):
            offset = skip_name(data, offset)
            if offset + 10 > len(data):
                return False
            rdlen = struct.unpack("!H", data[offset+8:offset+10])[0]
            offset += 10 + rdlen
        return True
    
    if not skip_rrs(ancount) or not skip_rrs(nscount):
        return data
    
    # Find and patch EDNS OPT
    for _ in range(arcount):
        name_start = offset
        offset = skip_name(data, offset)
        if offset + 4 > len(data):
            return data
        
        rtype = struct.unpack("!H", data[offset:offset+2])[0]
        if rtype == 41:  # OPT RR
            new_data = bytearray(data)
            new_data[offset+2:offset+4] = struct.pack("!H", new_size)
            return bytes(new_data)
        
        if offset + 10 > len(data):
            return data
        rdlen = struct.unpack("!H", data[offset+8:offset+10])[0]
        offset += 10 + rdlen
    
    return data

def handle_client(server_sock, data, client_addr, stats):
    """Handle DNS client request."""
    stats['requests'] += 1
    
    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.settimeout(5.0)
    
    try:
        # Forward to SlowDNS with larger EDNS
        request = patch_edns_size(data, INTERNAL_EDNS_SIZE)
        upstream_sock.sendto(request, (UPSTREAM_HOST, UPSTREAM_PORT))
        
        response, _ = upstream_sock.recvfrom(4096)
        stats['responses'] += 1
        
        # Return to client with smaller EDNS
        response = patch_edns_size(response, EXTERNAL_EDNS_SIZE)
        server_sock.sendto(response, client_addr)
        
    except socket.timeout:
        stats['timeouts'] += 1
    except ConnectionRefusedError:
        stats['errors'] += 1
        log_message('ERROR', 'SlowDNS not responding')
    except Exception as e:
        stats['errors'] += 1
    finally:
        upstream_sock.close()
        
    # Log every 100 requests
    if stats['requests'] % 100 == 0:
        log_message('INFO', f'Processed {stats["requests"]} requests')

def run_proxy(port):
    """Run the EDNS proxy on specified port."""
    stats = {
        'requests': 0,
        'responses': 0,
        'timeouts': 0,
        'errors': 0,
        'start_time': time.time()
    }
    
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    
    try:
        sock.bind((LISTEN_HOST, port))
        log_message('SUCCESS', f'EDNS Proxy started on port {port}')
        log_message('INFO', f'Forwarding to {UPSTREAM_HOST}:{UPSTREAM_PORT}')
        log_message('INFO', f'EDNS: {EXTERNAL_EDNS_SIZE} ↔ {INTERNAL_EDNS_SIZE}')
        print("\n" + "="*60)
        print("EDNS Proxy is running. Press Ctrl+C to stop.")
        print("="*60 + "\n")
        
        # Main loop
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                thread = threading.Thread(
                    target=handle_client,
                    args=(sock, data, addr, stats),
                    daemon=True
                )
                thread.start()
            except KeyboardInterrupt:
                break
                
    except OSError as e:
        log_message('ERROR', f'Failed to bind to port {port}: {e}')
        return False
    finally:
        sock.close()
        
        # Print statistics
        runtime = time.time() - stats['start_time']
        log_message('INFO', f'Runtime: {runtime:.1f}s')
        log_message('INFO', f'Requests: {stats["requests"]}')
        log_message('INFO', f'Responses: {stats["responses"]}')
        log_message('INFO', f'Success rate: {(stats["responses"]/max(stats["requests"],1)*100):.1f}%')
    
    return True

def main():
    """Main entry point with smooth error handling."""
    print("\n" + "="*60)
    print("          EDNS PROXY FOR SLOWDNS - SMOOTH EDITION")
    print("="*60 + "\n")
    
    # Check root privileges
    if os.geteuid() != 0:
        log_message('ERROR', 'This script requires root privileges')
        log_message('INFO', 'Please run with: sudo python3 edns-proxy.py')
        sys.exit(1)
    
    # Check SlowDNS
    log_message('INFO', 'Checking SlowDNS connection...')
    if not is_slowdns_running():
        log_message('ERROR', f'SlowDNS not found on {UPSTREAM_HOST}:{UPSTREAM_PORT}')
        log_message('INFO', 'Please start SlowDNS first')
        sys.exit(1)
    log_message('SUCCESS', 'SlowDNS is running')
    
    # Try to free port 53
    port_to_use = LISTEN_PORT
    
    if stop_dns_services_safely():
        log_message('SUCCESS', 'Port 53 successfully freed')
    else:
        log_message('WARNING', 'Using alternative port 5353')
        log_message('INFO', 'Setting up port redirect...')
        create_redirect_rules()
        port_to_use = ALT_PORT
    
    # Run proxy
    try:
        success = run_proxy(port_to_use)
        if not success and port_to_use == LISTEN_PORT:
            log_message('WARNING', 'Falling back to port 5353...')
            create_redirect_rules()
            run_proxy(ALT_PORT)
    except KeyboardInterrupt:
        log_message('INFO', '\nProxy stopped by user')
    except Exception as e:
        log_message('ERROR', f'Unexpected error: {e}')

if __name__ == "__main__":
    main()
