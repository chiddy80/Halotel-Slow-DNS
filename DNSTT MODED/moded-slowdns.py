#!/usr/bin/env python3
"""
Modern SlowDNS Server with Enhanced Streaming Performance
Optimized for stability, speed, and reliability
"""

import os
import sys
import time
import signal
import socket
import struct
import threading
import logging
import asyncio
import subprocess
import configparser
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, List
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import psutil
import selectors
from enum import Enum

# ============================================================================
# CONFIGURATION
# ============================================================================
@dataclass
class Config:
    """Configuration for SlowDNS Server"""
    # Network settings
    ssh_port: int = 22
    slowdns_port: int = 5300
    dns_port: int = 53
    bind_address: str = "0.0.0.0"
    mtu: int = 1400  # Better for streaming
    buffer_size: int = 4096
    
    # Performance settings
    max_connections: int = 1000
    connection_timeout: int = 30
    worker_threads: int = 4
    max_retries: int = 3
    retry_delay: float = 1.0
    
    # Streaming optimization
    enable_tcp_fallback: bool = True
    enable_compression: bool = True
    packet_loss_threshold: float = 0.05  # 5% packet loss
    min_bandwidth_mbps: float = 1.0
    
    # Memory management
    max_memory_mb: int = 100
    max_packets_per_second: int = 10000
    
    # Security
    enable_rate_limit: bool = True
    max_requests_per_ip: int = 100
    block_duration: int = 300  # seconds
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "/var/log/slowdns/server.log"


class DNSPacketType(Enum):
    """DNS Packet Types"""
    QUERY = 0
    RESPONSE = 1
    EDNS = 41


class StreamQuality(Enum):
    """Streaming quality levels"""
    LOW = 1      # Low bandwidth optimization
    MEDIUM = 2   # Balanced streaming
    HIGH = 3     # High quality streaming
    ULTRA = 4    # Maximum performance


# ============================================================================
# LOGGING SETUP
# ============================================================================
def setup_logging(config: Config):
    """Configure logging system"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format=log_format,
        handlers=[
            logging.FileHandler(config.log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


# ============================================================================
# PERFORMANCE MONITOR
# ============================================================================
class PerformanceMonitor:
    """Monitor system and network performance"""
    
    def __init__(self):
        self.metrics = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'errors': 0,
            'latency_ms': 0,
            'packet_loss': 0.0,
            'bandwidth_mbps': 0.0
        }
        self.lock = threading.Lock()
        self.start_time = time.time()
    
    def update_metrics(self, sent: int = 0, received: int = 0, 
                       latency: float = 0, error: bool = False):
        """Update performance metrics"""
        with self.lock:
            if sent:
                self.metrics['packets_sent'] += 1
                self.metrics['bytes_sent'] += sent
            if received:
                self.metrics['packets_received'] += 1
                self.metrics['bytes_received'] += received
            if latency:
                self.metrics['latency_ms'] = (
                    0.9 * self.metrics['latency_ms'] + 0.1 * latency
                )
            if error:
                self.metrics['errors'] += 1
            
            # Calculate packet loss
            total = self.metrics['packets_sent']
            if total > 100:
                expected = total
                actual = self.metrics['packets_received']
                self.metrics['packet_loss'] = (
                    max(0, expected - actual) / expected
                )
            
            # Calculate bandwidth
            elapsed = time.time() - self.start_time
            if elapsed > 1:
                self.metrics['bandwidth_mbps'] = (
                    (self.metrics['bytes_sent'] + self.metrics['bytes_received']) 
                    * 8 / elapsed / 1_000_000
                )
    
    def get_optimal_mtu(self) -> int:
        """Dynamically determine optimal MTU"""
        base_mtu = 1400
        packet_loss = self.metrics['packet_loss']
        
        if packet_loss > 0.1:  # High packet loss
            return 512
        elif packet_loss > 0.05:  # Medium packet loss
            return 1024
        elif self.metrics['latency_ms'] > 100:  # High latency
            return 1280
        else:
            return base_mtu
    
    def get_stream_quality(self) -> StreamQuality:
        """Determine optimal streaming quality"""
        bandwidth = self.metrics['bandwidth_mbps']
        latency = self.metrics['latency_ms']
        
        if bandwidth < 2 or latency > 200:
            return StreamQuality.LOW
        elif bandwidth < 5 or latency > 100:
            return StreamQuality.MEDIUM
        elif bandwidth < 10:
            return StreamQuality.HIGH
        else:
            return StreamQuality.ULTRA
    
    def get_report(self) -> Dict:
        """Get performance report"""
        with self.lock:
            return self.metrics.copy()


# ============================================================================
# CONNECTION POOL
# ============================================================================
class ConnectionPool:
    """Manage reusable socket connections"""
    
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self.pool: Dict[Tuple, List[socket.socket]] = {}
        self.lock = threading.Lock()
        self.active_connections = 0
    
    def get_connection(self, address: Tuple[str, int]) -> socket.socket:
        """Get a connection from pool or create new"""
        with self.lock:
            # Check pool for available connection
            if address in self.pool and self.pool[address]:
                sock = self.pool[address].pop()
                if self._is_socket_alive(sock):
                    return sock
            
            # Create new connection
            if self.active_connections < self.max_size:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5.0)
                self.active_connections += 1
                return sock
            
            # Pool exhausted, reuse oldest
            for addr, socks in self.pool.items():
                if socks:
                    sock = socks.pop(0)
                    if self._is_socket_alive(sock):
                        return sock
            
            # Create one anyway if all else fails
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            return sock
    
    def return_connection(self, address: Tuple[str, int], sock: socket.socket):
        """Return connection to pool"""
        with self.lock:
            if address not in self.pool:
                self.pool[address] = []
            
            if len(self.pool[address]) < 10:  # Max 10 per address
                self.pool[address].append(sock)
            else:
                sock.close()
                self.active_connections -= 1
    
    def _is_socket_alive(self, sock: socket.socket) -> bool:
        """Check if socket is still usable"""
        try:
            # Try a non-blocking test
            sock.setblocking(False)
            ready = selectors.DefaultSelector()
            ready.register(sock, selectors.EVENT_READ)
            events = ready.select(timeout=0.1)
            ready.close()
            sock.setblocking(True)
            return True
        except:
            return False
    
    def cleanup(self):
        """Clean up all connections"""
        with self.lock:
            for address, socks in self.pool.items():
                for sock in socks:
                    try:
                        sock.close()
                    except:
                        pass
                self.pool[address].clear()
            self.active_connections = 0


# ============================================================================
# DNS PACKET HANDLER
# ============================================================================
class DNSPacketHandler:
    """Handle DNS packet parsing and manipulation"""
    
    @staticmethod
    def parse_dns_header(data: bytes) -> Dict:
        """Parse DNS packet header"""
        if len(data) < 12:
            return {}
        
        header = struct.unpack('!6H', data[:12])
        return {
            'id': header[0],
            'flags': header[1],
            'qdcount': header[2],
            'ancount': header[3],
            'nscount': header[4],
            'arcount': header[5],
            'qr': (header[1] >> 15) & 1,
            'opcode': (header[1] >> 11) & 0xF,
            'aa': (header[1] >> 10) & 1,
            'tc': (header[1] >> 9) & 1,
            'rd': (header[1] >> 8) & 1,
            'ra': (header[1] >> 7) & 1,
            'z': (header[1] >> 4) & 0x7,
            'rcode': header[1] & 0xF
        }
    
    @staticmethod
    def patch_edns(data: bytes, new_size: int) -> bytes:
        """Patch EDNS OPT record with new buffer size"""
        if len(data) < 12:
            return data
        
        data = bytearray(data)
        offset = 12
        
        # Skip question section
        qdcount = struct.unpack('!H', data[4:6])[0]
        for _ in range(qdcount):
            while offset < len(data) and data[offset]:
                offset += 1
            offset += 5  # Skip null byte and QTYPE/QCLASS
        
        # Search for EDNS OPT record in additional section
        arcount = struct.unpack('!H', data[10:12])[0]
        for _ in range(arcount):
            if offset >= len(data):
                break
            
            if data[offset] == 0:  # Root label
                if offset + 4 < len(data):
                    rtype = struct.unpack('!H', data[offset+1:offset+3])[0]
                    if rtype == 41:  # OPT record
                        # Update UDP payload size
                        data[offset+3] = (new_size >> 8) & 0xFF
                        data[offset+4] = new_size & 0xFF
                        break
                offset += 11  # Skip OPT record
            else:
                # Skip regular record
                offset += 1
        
        return bytes(data)
    
    @staticmethod
    def extract_domain(data: bytes, offset: int = 12) -> Tuple[str, int]:
        """Extract domain name from DNS packet"""
        domain_parts = []
        original_offset = offset
        
        try:
            while offset < len(data) and data[offset] != 0:
                length = data[offset]
                if length & 0xC0:  # Compression pointer
                    ptr = struct.unpack('!H', data[offset:offset+2])[0]
                    offset += 2
                    ptr &= 0x3FFF
                    subdomain, _ = DNSPacketHandler.extract_domain(data, ptr)
                    domain_parts.append(subdomain)
                    break
                else:
                    offset += 1
                    if offset + length <= len(data):
                        domain_parts.append(data[offset:offset+length].decode('utf-8', errors='ignore'))
                        offset += length
                    else:
                        break
            offset += 1  # Skip null byte
        except:
            pass
        
        domain = '.'.join(domain_parts) if domain_parts else ''
        return domain, offset


# ============================================================================
# RATE LIMITER
# ============================================================================
class RateLimiter:
    """Rate limiting to prevent abuse"""
    
    def __init__(self, max_requests: int = 100, window: int = 60):
        self.max_requests = max_requests
        self.window = window
        self.requests: Dict[str, List[float]] = {}
        self.blocked: Dict[str, float] = {}
        self.lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> bool:
        """Check if IP is allowed to make request"""
        with self.lock:
            current_time = time.time()
            
            # Check if IP is blocked
            if ip in self.blocked:
                if current_time - self.blocked[ip] < 300:  # 5 minute block
                    return False
                else:
                    del self.blocked[ip]
            
            # Clean old requests
            if ip in self.requests:
                self.requests[ip] = [
                    t for t in self.requests[ip]
                    if current_time - t < self.window
                ]
            
            # Check rate limit
            if ip not in self.requests:
                self.requests[ip] = []
            
            if len(self.requests[ip]) >= self.max_requests:
                self.blocked[ip] = current_time
                return False
            
            self.requests[ip].append(current_time)
            return True
    
    def cleanup_old_entries(self):
        """Clean up old entries periodically"""
        with self.lock:
            current_time = time.time()
            
            # Clean old requests
            for ip in list(self.requests.keys()):
                self.requests[ip] = [
                    t for t in self.requests[ip]
                    if current_time - t < self.window * 2
                ]
                if not self.requests[ip]:
                    del self.requests[ip]
            
            # Clean old blocks
            for ip in list(self.blocked.keys()):
                if current_time - self.blocked[ip] > 300:
                    del self.blocked[ip]


# ============================================================================
# SLOWDNS SERVER
# ============================================================================
class SlowDNSServer:
    """Main SlowDNS Server Implementation"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logging(config)
        self.monitor = PerformanceMonitor()
        self.connection_pool = ConnectionPool(config.max_connections)
        self.rate_limiter = RateLimiter(
            config.max_requests_per_ip,
            config.block_duration
        )
        
        # Socket for receiving DNS queries
        self.udp_socket = None
        self.running = False
        self.worker_pool = ThreadPoolExecutor(max_workers=config.worker_threads)
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'active_connections': 0
        }
    
    def start(self):
        """Start the SlowDNS server"""
        self.logger.info("Starting SlowDNS Server...")
        
        try:
            # Create UDP socket for DNS
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Increase buffer sizes for better performance
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            
            self.udp_socket.bind((self.config.bind_address, self.config.dns_port))
            self.logger.info(f"DNS server listening on {self.config.bind_address}:{self.config.dns_port}")
            
            self.running = True
            
            # Start cleanup thread
            threading.Thread(target=self._cleanup_thread, daemon=True).start()
            
            # Start monitoring thread
            threading.Thread(target=self._monitoring_thread, daemon=True).start()
            
            # Main receive loop
            self._receive_loop()
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            self.stop()
            raise
    
    def _receive_loop(self):
        """Main receive loop for DNS queries"""
        self.logger.info("Entering receive loop...")
        
        while self.running:
            try:
                # Receive DNS query
                data, addr = self.udp_socket.recvfrom(self.config.buffer_size)
                client_ip = addr[0]
                
                # Update statistics
                self.stats['total_queries'] += 1
                self.stats['active_connections'] = self.connection_pool.active_connections
                
                # Rate limiting
                if self.config.enable_rate_limit:
                    if not self.rate_limiter.is_allowed(client_ip):
                        self.logger.warning(f"Rate limit exceeded for {client_ip}")
                        continue
                
                # Process query in thread pool for better concurrency
                self.worker_pool.submit(self._process_query, data, addr)
                
            except socket.timeout:
                continue
            except OSError as e:
                if self.running:
                    self.logger.error(f"Socket error: {e}")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in receive loop: {e}")
                continue
    
    def _process_query(self, data: bytes, client_addr: Tuple[str, int]):
        """Process a DNS query"""
        start_time = time.time()
        
        try:
            # Parse DNS header
            header = DNSPacketHandler.parse_dns_header(data)
            if not header:
                self.logger.warning("Invalid DNS packet received")
                return
            
            # Extract domain for logging
            domain, _ = DNSPacketHandler.extract_domain(data)
            
            # Patch EDNS with dynamic MTU based on network conditions
            optimal_mtu = self.monitor.get_optimal_mtu()
            modified_data = DNSPacketHandler.patch_edns(data, optimal_mtu)
            
            # Forward to SlowDNS backend
            response = self._forward_to_slowdns(modified_data, client_addr)
            
            if response:
                # Patch response EDNS with external MTU
                response_data = DNSPacketHandler.patch_edns(response, 512)
                
                # Send response back to client
                self.udp_socket.sendto(response_data, client_addr)
                
                # Update performance metrics
                latency = (time.time() - start_time) * 1000
                self.monitor.update_metrics(
                    sent=len(modified_data),
                    received=len(response),
                    latency=latency
                )
                
                self.stats['successful_queries'] += 1
                
                # Log successful query (at debug level to reduce noise)
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(f"Query: {domain} | Latency: {latency:.1f}ms | MTU: {optimal_mtu}")
            else:
                self.stats['failed_queries'] += 1
                self.monitor.update_metrics(error=True)
                
        except Exception as e:
            self.logger.error(f"Error processing query from {client_addr[0]}: {e}")
            self.stats['failed_queries'] += 1
            self.monitor.update_metrics(error=True)
    
    def _forward_to_slowdns(self, data: bytes, client_addr: Tuple[str, int]) -> Optional[bytes]:
        """Forward query to SlowDNS backend"""
        max_retries = self.config.max_retries
        
        for attempt in range(max_retries):
            try:
                # Get connection from pool
                sock = self.connection_pool.get_connection(
                    ('127.0.0.1', self.config.slowdns_port)
                )
                
                # Set timeout based on attempt
                sock.settimeout(self.config.connection_timeout / (attempt + 1))
                
                # Send to SlowDNS
                sock.sendto(data, ('127.0.0.1', self.config.slowdns_port))
                
                # Receive response
                response, _ = sock.recvfrom(self.config.buffer_size)
                
                # Return connection to pool
                self.connection_pool.return_connection(
                    ('127.0.0.1', self.config.slowdns_port),
                    sock
                )
                
                return response
                
            except socket.timeout:
                self.logger.warning(f"Timeout connecting to SlowDNS (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                continue
            except Exception as e:
                self.logger.error(f"Error forwarding to SlowDNS: {e}")
                break
        
        return None
    
    def _cleanup_thread(self):
        """Periodic cleanup thread"""
        while self.running:
            time.sleep(60)  # Run every minute
            
            try:
                # Cleanup rate limiter
                self.rate_limiter.cleanup_old_entries()
                
                # Cleanup connection pool
                self.connection_pool.cleanup()
                
                # Log statistics
                self.logger.info(
                    f"Stats - Queries: {self.stats['total_queries']}, "
                    f"Success: {self.stats['successful_queries']}, "
                    f"Failed: {self.stats['failed_queries']}, "
                    f"Active: {self.stats['active_connections']}"
                )
                
                # Report performance
                perf = self.monitor.get_report()
                quality = self.monitor.get_stream_quality()
                self.logger.info(
                    f"Performance - BW: {perf['bandwidth_mbps']:.2f}Mbps, "
                    f"Loss: {perf['packet_loss']:.2%}, "
                    f"Latency: {perf['latency_ms']:.1f}ms, "
                    f"Quality: {quality.name}"
                )
                
            except Exception as e:
                self.logger.error(f"Error in cleanup thread: {e}")
    
    def _monitoring_thread(self):
        """Monitor system resources"""
        while self.running:
            time.sleep(30)
            
            try:
                # Check memory usage
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                
                if memory_mb > self.config.max_memory_mb:
                    self.logger.warning(
                        f"High memory usage: {memory_mb:.1f}MB > {self.config.max_memory_mb}MB"
                    )
                
                # Check bandwidth
                perf = self.monitor.get_report()
                if perf['bandwidth_mbps'] < self.config.min_bandwidth_mbps:
                    self.logger.warning(
                        f"Low bandwidth: {perf['bandwidth_mbps']:.2f}Mbps"
                    )
                
                # Adjust MTU based on conditions
                optimal_mtu = self.monitor.get_optimal_mtu()
                if optimal_mtu != self.config.mtu:
                    self.logger.info(f"Adjusting MTU from {self.config.mtu} to {optimal_mtu}")
                    self.config.mtu = optimal_mtu
                
            except Exception as e:
                self.logger.error(f"Error in monitoring thread: {e}")
    
    def stop(self):
        """Stop the SlowDNS server"""
        self.logger.info("Stopping SlowDNS Server...")
        self.running = False
        
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except:
                pass
        
        self.worker_pool.shutdown(wait=True)
        self.connection_pool.cleanup()
        
        self.logger.info("Server stopped")


# ============================================================================
# INSTALLATION MANAGER
# ============================================================================
class InstallationManager:
    """Manage SlowDNS installation and configuration"""
    
    def __init__(self):
        self.config_dir = Path("/etc/slowdns")
        self.binary_path = self.config_dir / "dnstt-server"
        self.systemd_dir = Path("/etc/systemd/system")
        
    def install_slowdns(self, nameserver: str = "dns.example.com"):
        """Install SlowDNS server components"""
        print("🚀 Starting Modern SlowDNS Installation...")
        
        # Create directories
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Download and configure components
        self._download_components()
        self._configure_services(nameserver)
        self._configure_firewall()
        self._start_services()
        
        print("✅ Installation completed successfully!")
        self._show_summary(nameserver)
    
    def _download_components(self):
        """Download required components"""
        print("📦 Downloading SlowDNS components...")
        
        # URLs for components
        base_url = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
        
        try:
            import urllib.request
            
            # Download binary
            urllib.request.urlretrieve(
                f"{base_url}/dnstt-server",
                str(self.binary_path)
            )
            self.binary_path.chmod(0o755)
            print("  ✓ Downloaded dnstt-server")
            
            # Download keys
            urllib.request.urlretrieve(
                f"{base_url}/server.key",
                str(self.config_dir / "server.key")
            )
            urllib.request.urlretrieve(
                f"{base_url}/server.pub",
                str(self.config_dir / "server.pub"
            ))
            print("  ✓ Downloaded encryption keys")
            
        except Exception as e:
            print(f"  ✗ Download failed: {e}")
            raise
    
    def _configure_services(self, nameserver: str):
        """Configure systemd services"""
        print("⚙️  Configuring services...")
        
        # SlowDNS service
        slowdns_service = self.systemd_dir / "slowdns-server.service"
        with open(slowdns_service, 'w') as f:
            f.write(f"""[Unit]
Description=SlowDNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={self.binary_path} -udp :5300 -mtu 1400 -privkey-file /etc/slowdns/server.key {nameserver} 127.0.0.1:22
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
""")
        
        # Python EDNS Proxy service
        edns_service = self.systemd_dir / "edns-proxy.service"
        with open(edns_service, 'w') as f:
            f.write(f"""[Unit]
Description=EDNS Proxy for SlowDNS
After=slowdns-server.service
Requires=slowdns-server.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/slowdns/edns_proxy.py
WorkingDirectory=/opt/slowdns
Restart=always
RestartSec=3
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
""")
        
        print("  ✓ Service files created")
    
    def _configure_firewall(self):
        """Configure firewall rules"""
        print("🔥 Configuring firewall...")
        
        try:
            subprocess.run(["iptables", "-F"], check=False)
            subprocess.run(["iptables", "-X"], check=False)
            
            # Essential rules
            rules = [
                ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "udp", "--dport", "5300", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"],
                ["iptables", "-P", "INPUT", "DROP"],
                ["iptables", "-P", "FORWARD", "DROP"],
                ["iptables", "-P", "OUTPUT", "ACCEPT"]
            ]
            
            for rule in rules:
                subprocess.run(rule, check=False)
            
            print("  ✓ Firewall rules configured")
            
        except Exception as e:
            print(f"  ⚠️  Firewall configuration warning: {e}")
    
    def _start_services(self):
        """Start and enable services"""
        print("🚀 Starting services...")
        
        try:
            # Stop conflicting services
            subprocess.run(["systemctl", "stop", "systemd-resolved"], check=False)
            subprocess.run(["pkill", "-f", "dnsmasq"], check=False)
            
            # Reload systemd
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            
            # Enable and start services
            services = ["slowdns-server", "edns-proxy"]
            for service in services:
                subprocess.run(["systemctl", "enable", service], check=True)
                subprocess.run(["systemctl", "start", service], check=True)
            
            print("  ✓ Services started successfully")
            
        except Exception as e:
            print(f"  ✗ Service startup failed: {e}")
            raise
    
    def _show_summary(self, nameserver: str):
        """Show installation summary"""
        import socket
        
        ip = socket.gethostbyname(socket.gethostname())
        
        print("\n" + "="*60)
        print("📊 INSTALLATION SUMMARY")
        print("="*60)
        print(f"Server IP:        {ip}")
        print(f"SSH Port:         22")
        print(f"SlowDNS Port:     5300")
        print(f"DNS Port:         53")
        print(f"Nameserver:       {nameserver}")
        print(f"MTU:              1400 (adaptive)")
        print("="*60)
        print("\n📋 Service Status:")
        subprocess.run(["systemctl", "status", "slowdns-server", "--no-pager"])
        print("\n🔧 Test Commands:")
        print(f"  dig @{ip} {nameserver}")
        print(f"  nslookup {nameserver} {ip}")
        print("\n")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
def main():
    """Main entry point"""
    
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║           MODERN SLOWDNS INSTALLATION                ║
    ║        Optimized for Streaming & Stability          ║
    ╚══════════════════════════════════════════════════════╝
    """)
    
    # Check root privileges
    if os.geteuid() != 0:
        print("❌ Please run as root!")
        sys.exit(1)
    
    # Get nameserver
    nameserver = input("Enter nameserver [dns.example.com]: ").strip()
    if not nameserver:
        nameserver = "dns.example.com"
    
    # Ask for operation mode
    print("\nSelect operation mode:")
    print("1. Full installation (recommended)")
    print("2. Start Python proxy only")
    print("3. Configure existing installation")
    
    choice = input("\nYour choice [1]: ").strip() or "1"
    
    if choice == "1":
        # Full installation
        installer = InstallationManager()
        installer.install_slowdns(nameserver)
        
        # Also create Python proxy script
        proxy_script = Path("/opt/slowdns/edns_proxy.py")
        proxy_script.parent.mkdir(parents=True, exist_ok=True)
        
        with open(proxy_script, 'w') as f:
            f.write(__file__)
        
        print(f"✅ Python proxy installed at {proxy_script}")
        
    elif choice == "2":
        # Start Python proxy only
        config = Config()
        server = SlowDNSServer(config)
        
        def signal_handler(signum, frame):
            print("\n🛑 Shutting down...")
            server.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        print("🚀 Starting Python EDNS Proxy...")
        server.start()
        
    elif choice == "3":
        # Reconfigure existing installation
        installer = InstallationManager()
        installer._configure_services(nameserver)
        installer._start_services()
        print("✅ Configuration updated!")
    
    else:
        print("❌ Invalid choice!")


if __name__ == "__main__":
    main()
