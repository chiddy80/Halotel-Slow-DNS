#!/usr/bin/env python3
"""
EDNS Proxy for SlowDNS - Unified Script
- Works directly with SlowDNS on port 5300
- Converts EDNS sizes (512 ↔ 1232)
- No separate setup needed
"""

import socket
import threading
import struct
import sys
import os
import signal
import time
from datetime import datetime

# Configuration
EXTERNAL_EDNS_SIZE = 512      # What clients see
INTERNAL_EDNS_SIZE = 1232     # What SlowDNS sees
LISTEN_PORT = 53              # Public DNS port
UPSTREAM_PORT = 5300          # SlowDNS port
UPSTREAM_HOST = "127.0.0.1"   # SlowDNS address
LISTEN_HOST = "0.0.0.0"       # Listen on all interfaces

# Colors for terminal output
COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "ENDC": "\033[0m",
    "BOLD": "\033[1m"
}

def color_text(text, color):
    """Add color to text for terminal output."""
    return f"{COLORS.get(color.upper(), '')}{text}{COLORS['ENDC']}"

def print_status(message):
    """Print status messages with timestamp."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{color_text(f'[{timestamp}]', 'CYAN')} {color_text('[EDNS Proxy]', 'GREEN')} {message}")

def print_error(message):
    """Print error messages."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{color_text(f'[{timestamp}]', 'CYAN')} {color_text('[ERROR]', 'RED')} {message}")

def print_warning(message):
    """Print warning messages."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{color_text(f'[{timestamp}]', 'CYAN')} {color_text('[WARNING]', 'YELLOW')} {message}")

def patch_edns_udp_size(data: bytes, new_size: int) -> bytes:
    """
    Parse DNS message and patch EDNS OPT RR UDP payload size.
    Returns modified data or original if no EDNS found.
    """
    if len(data) < 12:
        return data
    
    try:
        # Parse DNS header
        qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
    except struct.error:
        return data
    
    offset = 12
    
    def skip_name(buf, off):
        """Skip DNS name with compression support."""
        while True:
            if off >= len(buf):
                return len(buf)
            length = buf[off]
            off += 1
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                # Compression pointer
                if off >= len(buf):
                    return len(buf)
                off += 1
                break
            off += length
        return off
    
    # Skip Questions section
    for _ in range(qdcount):
        offset = skip_name(data, offset)
        if offset + 4 > len(data):
            return data
        offset += 4  # QTYPE + QCLASS
    
    def skip_rrs(count, buf, off):
        """Skip Resource Records."""
        for _ in range(count):
            off = skip_name(buf, off)
            if off + 10 > len(buf):
                return len(buf)
            # TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2)
            rtype, _, _, rdlen = struct.unpack("!HHIH", buf[off:off+10])
            off += 10
            if off + rdlen > len(buf):
                return len(buf)
            off += rdlen
        return off
    
    # Skip Answer and Authority sections
    offset = skip_rrs(ancount, data, offset)
    offset = skip_rrs(nscount, data, offset)
    
    # Check Additional section for EDNS OPT RR
    new_data = bytearray(data)
    for _ in range(arcount):
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            return data
        
        rtype = struct.unpack("!H", data[offset:offset+2])[0]
        
        if rtype == 41:  # OPT RR (EDNS)
            # Patch UDP payload size (bytes at offset+2 and offset+3)
            size_bytes = struct.pack("!H", new_size)
            new_data[offset+2:offset+4] = size_bytes
            return bytes(new_data)
        
        # Skip this RR
        _, _, rdlen = struct.unpack("!H I H", data[offset+2:offset+10])
        offset += 10 + rdlen
    
    return data

def handle_client_request(server_sock, data, client_addr, client_ip, stats):
    """
    Handle a single DNS request from a client.
    """
    stats["requests"] += 1
    
    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.settimeout(5.0)
    
    try:
        # Forward to SlowDNS with larger EDNS size
        request_data = patch_edns_udp_size(data, INTERNAL_EDNS_SIZE)
        upstream_sock.sendto(request_data, (UPSTREAM_HOST, UPSTREAM_PORT))
        
        # Get response from SlowDNS
        response, _ = upstream_sock.recvfrom(4096)
        stats["responses"] += 1
        
        # Return to client with smaller EDNS size
        response_data = patch_edns_udp_size(response, EXTERNAL_EDNS_SIZE)
        server_sock.sendto(response_data, client_addr)
        
        # Log successful request
        if stats["requests"] % 100 == 0:
            print_status(f"Processed {stats['requests']} requests")
    
    except socket.timeout:
        stats["timeouts"] += 1
        print_warning(f"Timeout from {client_ip}")
    
    except ConnectionRefusedError:
        stats["errors"] += 1
        print_error(f"Cannot connect to SlowDNS on {UPSTREAM_HOST}:{UPSTREAM_PORT}")
        print_error("Make sure SlowDNS is running!")
    
    except Exception as e:
        stats["errors"] += 1
        print_error(f"Error handling request from {client_ip}: {str(e)}")
    
    finally:
        upstream_sock.close()

def check_slowdns():
    """Check if SlowDNS is running on port 5300."""
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.settimeout(2.0)
        test_sock.sendto(b"\x00" * 12, (UPSTREAM_HOST, UPSTREAM_PORT))
        test_sock.close()
        return True
    except:
        return False

def free_port_53():
    """Try to free port 53 if it's in use."""
    try:
        # Try to bind to port 53 to check if it's free
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.bind((LISTEN_HOST, LISTEN_PORT))
        test_sock.close()
        return True
    except OSError as e:
        print_warning(f"Port 53 is in use: {e}")
        
        if os.geteuid() != 0:
            print_error("Must run as root to use port 53!")
            return False
        
        # Try to kill processes on port 53
        try:
            print_warning("Attempting to free port 53...")
            os.system("fuser -k 53/udp 2>/dev/null")
            os.system("fuser -k 53/tcp 2>/dev/null")
            time.sleep(2)
            return True
        except:
            print_error("Failed to free port 53")
            return False

def print_banner():
    """Print startup banner."""
    os.system("clear" if os.name == "posix" else "cls")
    
    banner = f"""
{color_text('═' * 60, 'CYAN')}
{color_text(' ' * 20 + 'EDNS PROXY FOR SLOWDNS', 'WHITE')}
{color_text('═' * 60, 'CYAN')}
{color_text('• External EDNS Size:', 'YELLOW')} {EXTERNAL_EDNS_SIZE}
{color_text('• Internal EDNS Size:', 'YELLOW')} {INTERNAL_EDNS_SIZE}
{color_text('• Listening Port:', 'YELLOW')} {LISTEN_PORT}
{color_text('• SlowDNS Port:', 'YELLOW')} {UPSTREAM_PORT}
{color_text('═' * 60, 'CYAN')}
"""
    print(banner)

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    print_status("Shutting down EDNS Proxy...")
    sys.exit(0)

def run_edns_proxy():
    """Main function to run the EDNS Proxy."""
    signal.signal(signal.SIGINT, signal_handler)
    
    print_banner()
    
    # Check if we're root (needed for port 53)
    if os.geteuid() != 0:
        print_error("This script must be run as root!")
        print_error("Use: sudo python3 edns-proxy.py")
        sys.exit(1)
    
    # Check if SlowDNS is running
    print_status("Checking SlowDNS connection...")
    if not check_slowdns():
        print_error(f"SlowDNS not found on {UPSTREAM_HOST}:{UPSTREAM_PORT}")
        print_error("Please start SlowDNS first!")
        sys.exit(1)
    print_success("SlowDNS is running")
    
    # Try to free port 53
    if not free_port_53():
        print_error("Cannot bind to port 53. Trying alternative port 5353...")
        global LISTEN_PORT
        LISTEN_PORT = 5353
    
    # Create UDP socket
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind((LISTEN_HOST, LISTEN_PORT))
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    except OSError as e:
        print_error(f"Cannot bind to port {LISTEN_PORT}: {e}")
        sys.exit(1)
    
    # Statistics
    stats = {
        "requests": 0,
        "responses": 0,
        "timeouts": 0,
        "errors": 0,
        "start_time": time.time()
    }
    
    print_success(f"EDNS Proxy started on port {LISTEN_PORT}")
    print_success(f"Forwarding to {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    print_success(f"EDNS: {EXTERNAL_EDNS_SIZE} ↔ {INTERNAL_EDNS_SIZE}")
    print_status("Press Ctrl+C to stop\n")
    
    # Main loop
    try:
        while True:
            try:
                # Receive DNS query
                data, client_addr = server_sock.recvfrom(4096)
                client_ip = client_addr[0]
                
                # Handle in separate thread
                thread = threading.Thread(
                    target=handle_client_request,
                    args=(server_sock, data, client_addr, client_ip, stats),
                    daemon=True
                )
                thread.start()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print_error(f"Main loop error: {e}")
                time.sleep(1)
                
    except KeyboardInterrupt:
        print_status("\nShutting down...")
    
    finally:
        server_sock.close()
        
        # Print statistics
        runtime = time.time() - stats["start_time"]
        print_status(f"Runtime: {runtime:.1f} seconds")
        print_status(f"Requests handled: {stats['requests']}")
        print_status(f"Responses sent: {stats['responses']}")
        print_status(f"Timeouts: {stats['timeouts']}")
        print_status(f"Errors: {stats['errors']}")
        print_success("EDNS Proxy stopped")

def print_success(message):
    """Print success messages."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{color_text(f'[{timestamp}]', 'CYAN')} {color_text('[SUCCESS]', 'GREEN')} {message}")

if __name__ == "__main__":
    run_edns_proxy()
