#!/usr/bin/env python3
"""
EDNS Proxy for SlowDNS with EDNS 1800
Listens on port 53, forwards to SlowDNS on port 5300
Converts EDNS 512 -> 1800
"""

import socket
import struct
import asyncio
import sys
import os
import time
from typing import Optional

# Configuration - Match your settings exactly
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 5300
EXTERNAL_EDNS_SIZE = 512    # What clients see
INTERNAL_EDNS_SIZE = 1800   # What SlowDNS sees

def patch_edns_size(data: bytes, new_size: int) -> bytes:
    """
    Patch EDNS UDP payload size in DNS packet.
    Optimized for speed and reliability.
    """
    if len(data) < 12:
        return data
    
    try:
        # Parse DNS header
        qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
    except struct.error:
        return data
    
    offset = 12
    
    # Skip questions efficiently
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0 == 0xC0:  # Compression pointer
                offset += 1
                break
            offset += length
        offset += 4  # QTYPE + QCLASS
        
        if offset > len(data):
            return data
    
    # Skip answers and authority sections
    def skip_rrs(count: int) -> bool:
        nonlocal offset
        for _ in range(count):
            # Skip name
            while offset < len(data):
                length = data[offset]
                offset += 1
                if length == 0:
                    break
                if length & 0xC0 == 0xC0:
                    offset += 1
                    break
                offset += length
            
            if offset + 10 > len(data):
                return False
            
            # Skip TYPE, CLASS, TTL, RDLEN
            rdlen = struct.unpack("!H", data[offset+8:offset+10])[0]
            offset += 10 + rdlen
            
            if offset > len(data):
                return False
        return True
    
    if not skip_rrs(ancount) or not skip_rrs(nscount):
        return data
    
    # Find and patch EDNS OPT record in additional section
    for _ in range(arcount):
        # Skip name (should be root for OPT)
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                offset += 1
                break
            offset += length
        
        if offset + 4 > len(data):
            return data
        
        # Check if this is an OPT record
        rtype = struct.unpack("!H", data[offset:offset+2])[0]
        if rtype == 41:  # OPT RR
            new_data = bytearray(data)
            new_data[offset+2:offset+4] = struct.pack("!H", new_size)
            return bytes(new_data)
        
        if offset + 10 > len(data):
            return data
        
        # Skip this RR and continue
        rdlen = struct.unpack("!H", data[offset+8:offset+10])[0]
        offset += 10 + rdlen
    
    return data

async def forward_to_slowdns(data: bytes) -> Optional[bytes]:
    """
    Forward DNS query to SlowDNS with proper EDNS patching.
    """
    try:
        # Create UDP connection to SlowDNS
        reader, writer = await asyncio.open_connection(
            UPSTREAM_HOST, UPSTREAM_PORT,
            proto=socket.SOCK_DGRAM
        )
        
        # Patch EDNS size for SlowDNS (512 -> 1800)
        query = patch_edns_size(data, INTERNAL_EDNS_SIZE)
        
        # Send request
        writer.write(query)
        await writer.drain()
        
        # Wait for response with timeout
        response = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        
        # Patch EDNS size for client (1800 -> 512)
        response = patch_edns_size(response, EXTERNAL_EDNS_SIZE)
        
        writer.close()
        await writer.wait_closed()
        
        return response
        
    except asyncio.TimeoutError:
        return None
    except ConnectionRefusedError:
        return None
    except Exception:
        return None

async def dns_server():
    """
    Main DNS server using asyncio for high performance.
    """
    # Check root privileges
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Set socket options for better performance
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)  # 1MB buffer
    
    try:
        sock.bind((LISTEN_HOST, LISTEN_PORT))
    except OSError as e:
        if "Address already in use" in str(e):
            print("ERROR: Port 53 is already in use")
            print("Try: sudo fuser -k 53/udp 53/tcp")
        else:
            print(f"ERROR: Cannot bind to port {LISTEN_PORT}: {e}")
        sys.exit(1)
    
    sock.setblocking(False)
    loop = asyncio.get_event_loop()
    
    # Print startup banner
    print("\n" + "="*60)
    print("           EDNS PROXY FOR SLOWDNS")
    print("="*60)
    print(f"External EDNS: {EXTERNAL_EDNS_SIZE}")
    print(f"Internal EDNS: {INTERNAL_EDNS_SIZE}")
    print(f"Listen Port:   {LISTEN_PORT}")
    print(f"SlowDNS Port:  {UPSTREAM_PORT}")
    print("="*60)
    print("[*] Proxy is running. Press Ctrl+C to stop")
    print("="*60 + "\n")
    
    # Statistics
    stats = {
        'requests': 0,
        'responses': 0,
        'errors': 0,
        'start_time': time.time()
    }
    
    try:
        while True:
            try:
                # Wait for DNS query
                data, addr = await loop.sock_recvfrom(sock, 65507)  # Max UDP size
                stats['requests'] += 1
                
                # Process the request asynchronously
                async def handle_request():
                    response = await forward_to_slowdns(data)
                    if response:
                        # Send response back to client
                        await loop.sock_sendto(sock, response, addr)
                        stats['responses'] += 1
                    else:
                        stats['errors'] += 1
                
                # Fire and forget for maximum concurrency
                asyncio.create_task(handle_request())
                
                # Print stats every 100 requests
                if stats['requests'] % 100 == 0:
                    elapsed = time.time() - stats['start_time']
                    rps = stats['requests'] / elapsed if elapsed > 0 else 0
                    success_rate = (stats['responses'] / max(stats['requests'], 1)) * 100
                    print(f"[STATS] Req: {stats['requests']}, "
                          f"Res: {stats['responses']} ({success_rate:.1f}%), "
                          f"RPS: {rps:.1f}")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                stats['errors'] += 1
    
    except KeyboardInterrupt:
        print("\n[*] Stopping proxy...")
    finally:
        sock.close()
        
        # Print final statistics
        elapsed = time.time() - stats['start_time']
        rps = stats['requests'] / elapsed if elapsed > 0 else 0
        success_rate = (stats['responses'] / max(stats['requests'], 1)) * 100
        
        print("\n" + "="*60)
        print("FINAL STATISTICS:")
        print("="*60)
        print(f"Runtime:      {elapsed:.1f} seconds")
        print(f"Requests:     {stats['requests']}")
        print(f"Responses:    {stats['responses']} ({success_rate:.1f}%)")
        print(f"Errors:       {stats['errors']}")
        print(f"Avg RPS:      {rps:.1f}")
        print("="*60)
        print("[✓] EDNS Proxy stopped")

def main():
    """Main entry point."""
    try:
        asyncio.run(dns_server())
    except KeyboardInterrupt:
        print("\n[✓] Proxy stopped by user")

if __name__ == "__main__":
    main()
