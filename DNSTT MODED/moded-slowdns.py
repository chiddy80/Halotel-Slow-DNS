#!/usr/bin/env python3
"""
EDNS Proxy for SlowDNS - Complete DNS Integration
"""

import socket
import struct
import threading
import time
import sys
import os
import select
from typing import Optional, Tuple

# ========================= CONFIGURATION =========================
EXTERNAL_EDNS_SIZE = 512      # What clients see (standard DNS)
INTERNAL_EDNS_SIZE = 1232     # What SlowDNS sees (bypass MTU)
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 5300

# Fallback DNS servers if SlowDNS fails
FALLBACK_DNS_SERVERS = [
    ("8.8.8.8", 53),      # Google DNS
    ("1.1.1.1", 53),      # Cloudflare DNS
    ("8.8.4.4", 53)       # Google DNS secondary
]

# ========================= DNS PARSING ==========================

class DNSParser:
    """DNS packet parser and manipulator."""
    
    @staticmethod
    def parse_header(data: bytes) -> Optional[Tuple]:
        """Parse DNS header."""
        if len(data) < 12:
            return None
        
        try:
            header = struct.unpack("!HHHHHH", data[:12])
            return {
                'id': header[0],
                'flags': header[1],
                'qdcount': header[2],
                'ancount': header[3],
                'nscount': header[4],
                'arcount': header[5]
            }
        except:
            return None
    
    @staticmethod
    def skip_name(data: bytes, offset: int) -> int:
        """Skip DNS name with compression."""
        orig_offset = offset
        max_offset = len(data) - 1
        
        while offset <= max_offset:
            length = data[offset]
            offset += 1
            
            if length == 0:
                break
            elif length & 0xC0 == 0xC0:  # Compression pointer
                if offset <= max_offset:
                    offset += 1
                break
            else:
                offset += min(length, max_offset - offset + 1)
        
        return offset
    
    @staticmethod
    def patch_edns_size(data: bytes, new_size: int) -> bytes:
        """Patch EDNS UDP payload size in DNS packet."""
        if len(data) < 12:
            return data
        
        try:
            # Parse header
            qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
        except struct.error:
            return data
        
        offset = 12
        
        # Skip questions
        for _ in range(qdcount):
            offset = DNSParser.skip_name(data, offset)
            if offset + 4 > len(data):
                return data
            offset += 4  # QTYPE + QCLASS
        
        # Skip answers and authority
        def skip_rrs(count: int) -> bool:
            nonlocal offset
            for _ in range(count):
                offset = DNSParser.skip_name(data, offset)
                if offset + 10 > len(data):
                    return False
                rdlen = struct.unpack("!H", data[offset+8:offset+10])[0]
                offset += 10 + rdlen
            return True
        
        if not skip_rrs(ancount) or not skip_rrs(nscount):
            return data
        
        # Find and patch EDNS OPT record
        new_data = bytearray(data)
        for _ in range(arcount):
            offset = DNSParser.skip_name(data, offset)
            if offset + 4 > len(data):
                return bytes(new_data)
            
            rtype = struct.unpack("!H", new_data[offset:offset+2])[0]
            if rtype == 41:  # OPT RR
                # Patch UDP payload size
                new_data[offset+2:offset+4] = struct.pack("!H", new_size)
                return bytes(new_data)
            
            if offset + 10 > len(data):
                return bytes(new_data)
            rdlen = struct.unpack("!H", new_data[offset+8:offset+10])[0]
            offset += 10 + rdlen
        
        return bytes(new_data)
    
    @staticmethod
    def is_valid_dns_packet(data: bytes) -> bool:
        """Check if data looks like a valid DNS packet."""
        if len(data) < 12:
            return False
        
        try:
            # Check DNS header
            flags = struct.unpack("!H", data[2:4])[0]
            # Basic validation: QR bit should be 0 for query, 1 for response
            qr = (flags >> 15) & 0x1
            opcode = (flags >> 11) & 0xF
            
            # Valid DNS opcodes: 0=Query, 1=IQuery, 2=Status, 4=Notify, 5=Update
            valid_opcodes = {0, 1, 2, 4, 5}
            return opcode in valid_opcodes
        except:
            return False

# ========================= DNS HANDLER ==========================

class DNSHandler:
    """Handle DNS queries with fallback support."""
    
    def __init__(self):
        self.stats = {
            'requests': 0,
            'slowdns_success': 0,
            'fallback_success': 0,
            'timeouts': 0,
            'errors': 0
        }
    
    def forward_to_upstream(self, data: bytes, host: str, port: int, timeout: float = 3.0) -> Optional[bytes]:
        """Forward DNS query to upstream server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Patch EDNS size based on destination
            if port == UPSTREAM_PORT:
                # To SlowDNS: use larger EDNS
                query = DNSParser.patch_edns_size(data, INTERNAL_EDNS_SIZE)
            else:
                # To regular DNS: keep standard EDNS
                query = data
            
            sock.sendto(query, (host, port))
            
            # Wait for response with select for better timeout handling
            ready = select.select([sock], [], [], timeout)
            if ready[0]:
                response, _ = sock.recvfrom(4096)
                
                # Patch response EDNS size if coming from SlowDNS
                if port == UPSTREAM_PORT:
                    response = DNSParser.patch_edns_size(response, EXTERNAL_EDNS_SIZE)
                
                return response
            else:
                return None
                
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            return None
        finally:
            try:
                sock.close()
            except:
                pass
    
    def handle_query(self, server_sock: socket.socket, data: bytes, client_addr: Tuple[str, int]) -> None:
        """Handle a DNS query with SlowDNS primary + fallback."""
        self.stats['requests'] += 1
        
        # Validate DNS packet
        if not DNSParser.is_valid_dns_packet(data):
            return
        
        response = None
        
        # Try SlowDNS first
        response = self.forward_to_upstream(data, UPSTREAM_HOST, UPSTREAM_PORT, 2.0)
        
        if response and len(response) >= 12:
            self.stats['slowdns_success'] += 1
        else:
            # SlowDNS failed, try fallback DNS servers
            for dns_server, dns_port in FALLBACK_DNS_SERVERS:
                response = self.forward_to_upstream(data, dns_server, dns_port, 1.0)
                if response and len(response) >= 12:
                    self.stats['fallback_success'] += 1
                    break
        
        # Send response back to client
        if response and len(response) >= 12:
            try:
                server_sock.sendto(response, client_addr)
            except:
                self.stats['errors'] += 1
        else:
            self.stats['timeouts'] += 1
    
    def print_stats(self, interval: int = 100):
        """Print statistics every N requests."""
        if self.stats['requests'] % interval == 0:
            total = self.stats['requests']
            slowdns_rate = (self.stats['slowdns_success'] / max(total, 1)) * 100
            fallback_rate = (self.stats['fallback_success'] / max(total, 1)) * 100
            
            print(f"\n[STATS] Requests: {total}")
            print(f"        SlowDNS: {self.stats['slowdns_success']} ({slowdns_rate:.1f}%)")
            print(f"        Fallback: {self.stats['fallback_success']} ({fallback_rate:.1f}%)")
            print(f"        Timeouts: {self.stats['timeouts']}")
            print(f"        Errors: {self.stats['errors']}")

# ========================= MAIN PROXY ==========================

class EDNSProxy:
    """Main EDNS Proxy server."""
    
    def __init__(self):
        self.handler = DNSHandler()
        self.running = False
        self.server_sock = None
    
    def setup_socket(self) -> bool:
        """Setup UDP socket for DNS."""
        try:
            # Check if we're root (needed for port 53)
            if os.geteuid() != 0:
                print("ERROR: Must run as root (use sudo)")
                return False
            
            # Create socket
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Set socket options
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)  # 1MB buffer
            
            # Bind to port
            self.server_sock.bind((LISTEN_HOST, LISTEN_PORT))
            
            return True
            
        except OSError as e:
            if "Address already in use" in str(e):
                print("ERROR: Port 53 is already in use")
                print("Try these commands:")
                print("  sudo fuser -k 53/udp")
                print("  sudo fuser -k 53/tcp")
                print("  sudo systemctl stop systemd-resolved")
            else:
                print(f"ERROR: Cannot bind to port {LISTEN_PORT}: {e}")
            return False
    
    def check_slowdns(self) -> bool:
        """Check if SlowDNS is reachable."""
        print("[*] Checking SlowDNS connectivity...")
        
        # Create a simple DNS query
        query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # Header
        query += b"\x06google\x03com\x00"  # Query: google.com
        query += b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
        
        response = self.handler.forward_to_upstream(query, UPSTREAM_HOST, UPSTREAM_PORT, 2.0)
        
        if response:
            print("[✓] SlowDNS is responding")
            return True
        else:
            print("[!] SlowDNS not responding (will use fallback DNS)")
            return False
    
    def run(self):
        """Run the EDNS Proxy."""
        print("="*60)
        print("          EDNS PROXY FOR SLOWDNS")
        print("="*60)
        print(f"Listen:    {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"Upstream:  {UPSTREAM_HOST}:{UPSTREAM_PORT}")
        print(f"EDNS:      {EXTERNAL_EDNS_SIZE} ↔ {INTERNAL_EDNS_SIZE}")
        print("="*60)
        print("[*] Starting EDNS Proxy...")
        
        # Setup socket
        if not self.setup_socket():
            return
        
        # Check SlowDNS
        self.check_slowdns()
        
        print("\n[*] Proxy is running. Press Ctrl+C to stop.")
        print("[*] Statistics will show every 100 requests.\n")
        
        self.running = True
        last_stats_time = time.time()
        
        try:
            while self.running:
                try:
                    # Set timeout to allow keyboard interrupt
                    self.server_sock.settimeout(1.0)
                    
                    # Wait for data
                    ready = select.select([self.server_sock], [], [], 1.0)
                    if ready[0]:
                        data, addr = self.server_sock.recvfrom(4096)
                        
                        # Handle in thread pool
                        thread = threading.Thread(
                            target=self.handler.handle_query,
                            args=(self.server_sock, data, addr),
                            daemon=True
                        )
                        thread.start()
                    
                    # Print stats periodically
                    current_time = time.time()
                    if current_time - last_stats_time >= 30:  # Every 30 seconds
                        if self.handler.stats['requests'] > 0:
                            self.handler.print_stats(1)  # Force print
                        last_stats_time = current_time
                    
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    print("\n[*] Stopping proxy...")
                    self.running = False
                except Exception as e:
                    print(f"[ERROR] {e}")
                    
        finally:
            # Cleanup
            if self.server_sock:
                self.server_sock.close()
            
            # Final statistics
            print("\n" + "="*60)
            print("FINAL STATISTICS:")
            print("="*60)
            self.handler.print_stats(1)
            print("="*60)
            print("[✓] EDNS Proxy stopped")

# ========================= ENTRY POINT ==========================

def main():
    """Main entry point."""
    proxy = EDNSProxy()
    proxy.run()

if __name__ == "__main__":
    main()
