#!/usr/bin/env python3
"""
EDNS Proxy for SlowDNS - Clean & Reliable
"""

import socket
import threading
import struct
import sys
import os
import time
import subprocess

# Configuration
EXTERNAL_EDNS_SIZE = 512
INTERNAL_EDNS_SIZE = 1232
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 5300

def print_status(msg):
    print(f"[*] {msg}")

def print_success(msg):
    print(f"[✓] {msg}")

def print_error(msg):
    print(f"[✗] {msg}")

def print_warning(msg):
    print(f"[!] {msg}")

def check_slowdns():
    """Check if SlowDNS is running."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b"\x00" * 12, (UPSTREAM_HOST, UPSTREAM_PORT))
        sock.close()
        return True
    except:
        return False

def free_port_53():
    """Stop services using port 53."""
    print_status("Checking port 53...")
    
    # Check if port 53 is in use
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.bind((LISTEN_HOST, LISTEN_PORT))
        test_sock.close()
        print_success("Port 53 is available")
        return True
    except OSError:
        print_warning("Port 53 is in use")
    
    # Stop common DNS services
    services = ['systemd-resolved', 'dnsmasq', 'bind9', 'named']
    
    for service in services:
        try:
            # Check if service exists
            result = subprocess.run(
                ['systemctl', 'list-unit-files', f'{service}.service'],
                capture_output=True,
                text=True
            )
            
            if 'enabled' in result.stdout or 'disabled' in result.stdout:
                print_status(f"Stopping {service}...")
                subprocess.run(['systemctl', 'stop', service], capture_output=True)
                subprocess.run(['systemctl', 'disable', service], capture_output=True)
        except:
            continue
    
    # Kill any remaining processes on port 53
    try:
        subprocess.run(['fuser', '-k', '53/udp'], capture_output=True)
        subprocess.run(['fuser', '-k', '53/tcp'], capture_output=True)
        time.sleep(2)
    except:
        pass
    
    # Verify port is free
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.bind((LISTEN_HOST, LISTEN_PORT))
        test_sock.close()
        print_success("Port 53 is now free")
        return True
    except OSError:
        print_error("Cannot free port 53")
        return False

def patch_edns(data, new_size):
    """Patch EDNS size in DNS packet."""
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
        if offset + 5 >= len(data):
            return data
        offset += 5
    
    # Skip answers and authority
    for _ in range(ancount + nscount):
        while offset < len(data) and data[offset] != 0:
            offset += 1
        if offset + 11 >= len(data):
            return data
        rdlen = struct.unpack("!H", data[offset+9:offset+11])[0]
        offset += 11 + rdlen
    
    # Find and patch EDNS OPT
    for _ in range(arcount):
        while offset < len(data) and data[offset] != 0:
            offset += 1
        if offset + 11 >= len(data):
            return data
        
        rtype = struct.unpack("!H", data[offset+1:offset+3])[0]
        if rtype == 41:  # OPT
            new_data = bytearray(data)
            new_data[offset+3:offset+5] = struct.pack("!H", new_size)
            return bytes(new_data)
        
        rdlen = struct.unpack("!H", data[offset+9:offset+11])[0]
        offset += 11 + rdlen
    
    return data

def handle_query(sock, data, addr, stats):
    """Handle DNS query."""
    stats['requests'] += 1
    
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.settimeout(3.0)
    
    try:
        # Forward to SlowDNS
        query = patch_edns(data, INTERNAL_EDNS_SIZE)
        upstream.sendto(query, (UPSTREAM_HOST, UPSTREAM_PORT))
        
        # Get response
        response, _ = upstream.recvfrom(4096)
        response = patch_edns(response, EXTERNAL_EDNS_SIZE)
        sock.sendto(response, addr)
        
        stats['responses'] += 1
        
        # Log every 50 requests
        if stats['requests'] % 50 == 0:
            print_status(f"Processed {stats['requests']} requests")
            
    except socket.timeout:
        stats['timeouts'] += 1
    except ConnectionRefusedError:
        stats['errors'] += 1
        if stats['errors'] == 1:  # Only show once
            print_error("SlowDNS not responding")
    except:
        stats['errors'] += 1
    finally:
        upstream.close()

def run_edns_proxy():
    """Run the EDNS proxy."""
    # Display banner
    print("\n" + "="*60)
    print("              EDNS PROXY FOR SLOWDNS")
    print("="*60)
    print(f"External EDNS: {EXTERNAL_EDNS_SIZE}")
    print(f"Internal EDNS: {INTERNAL_EDNS_SIZE}")
    print(f"Listen Port:   {LISTEN_PORT}")
    print(f"SlowDNS Port:  {UPSTREAM_PORT}")
    print("="*60 + "\n")
    
    # Check root
    if os.geteuid() != 0:
        print_error("Must run as root")
        print("Use: sudo python3 edns-proxy.py")
        sys.exit(1)
    
    # Check SlowDNS
    print_status("Checking SlowDNS...")
    if not check_slowdns():
        print_error(f"SlowDNS not running on {UPSTREAM_HOST}:{UPSTREAM_PORT}")
        sys.exit(1)
    print_success("SlowDNS is running")
    
    # Free port 53
    if not free_port_53():
        print_error("Cannot continue without port 53")
        sys.exit(1)
    
    # Create socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((LISTEN_HOST, LISTEN_PORT))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    except OSError as e:
        print_error(f"Cannot bind to port {LISTEN_PORT}: {e}")
        sys.exit(1)
    
    print_success(f"EDNS Proxy started on port {LISTEN_PORT}")
    print_status("Press Ctrl+C to stop\n")
    
    # Statistics
    stats = {
        'requests': 0,
        'responses': 0,
        'timeouts': 0,
        'errors': 0,
        'start_time': time.time()
    }
    
    # Main loop
    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                thread = threading.Thread(
                    target=handle_query,
                    args=(sock, data, addr, stats),
                    daemon=True
                )
                thread.start()
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        
        # Show statistics
        runtime = time.time() - stats['start_time']
        print("\n" + "="*60)
        print("Statistics:")
        print(f"  Runtime:      {runtime:.1f} seconds")
        print(f"  Requests:     {stats['requests']}")
        print(f"  Responses:    {stats['responses']}")
        print(f"  Success Rate: {(stats['responses']/max(stats['requests'],1)*100):.1f}%")
        print(f"  Timeouts:     {stats['timeouts']}")
        print(f"  Errors:       {stats['errors']}")
        print("="*60)
        print_success("EDNS Proxy stopped")

def main():
    """Main entry point with error handling."""
    try:
        run_edns_proxy()
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
