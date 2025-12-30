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
import json
from dataclasses import dataclass, field, asdict
from typing import Optional, Tuple, Dict, List, Set
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from pathlib import Path
import psutil
import selectors
from enum import Enum
import random
import hashlib
import zlib
from datetime import datetime, timedelta
import secrets
import urllib.request
import ssl

# ============================================================================
# CONFIGURATION SYSTEM
# ============================================================================
class ConfigManager:
    """Configuration management with defaults and validation"""
    
    DEFAULTS = {
        'network': {
            'ssh_port': '22',
            'slowdns_port': '5300',
            'dns_port': '53',
            'bind_address': '0.0.0.0',
            'mtu': '1400',
            'buffer_size': '4096',
            'enable_ipv6': 'false',
            'dns_timeout': '5'
        },
        'performance': {
            'worker_threads': '4',
            'max_connections': '1000',
            'connection_timeout': '30',
            'max_retries': '3',
            'retry_delay': '1.0',
            'enable_connection_pool': 'true',
            'pool_size': '100',
            'enable_load_balancing': 'true'
        },
        'streaming': {
            'enable_tcp_fallback': 'true',
            'enable_compression': 'true',
            'packet_loss_threshold': '0.05',
            'min_bandwidth_mbps': '1.0',
            'adaptive_bitrate': 'true',
            'max_bitrate_mbps': '10',
            'min_bitrate_mbps': '0.5',
            'buffer_size_ms': '2000',
            'enable_fec': 'false',  # Forward Error Correction
            'fec_percentage': '20'
        },
        'security': {
            'enable_rate_limit': 'true',
            'max_requests_per_ip': '100',
            'block_duration': '300',
            'enable_ip_whitelist': 'false',
            'enable_dnssec': 'false',
            'enable_query_filtering': 'true',
            'allowed_domains': '',
            'blocked_domains': ''
        },
        'monitoring': {
            'log_level': 'INFO',
            'log_file': '/var/log/slowdns/server.log',
            'enable_metrics': 'true',
            'metrics_port': '9090',
            'enable_health_checks': 'true',
            'health_check_interval': '30',
            'enable_performance_logging': 'true'
        },
        'optimization': {
            'enable_packet_prioritization': 'true',
            'udp_buffer_multiplier': '2',
            'tcp_keepalive': 'true',
            'tcp_keepalive_idle': '60',
            'tcp_keepalive_interval': '10',
            'tcp_keepalive_count': '3',
            'enable_mtu_discovery': 'true',
            'enable_tcp_nodelay': 'true'
        }
    }
    
    @staticmethod
    def load_config(config_path: str = "/etc/slowdns/config.ini") -> configparser.ConfigParser:
        """Load configuration from file with defaults"""
        config = configparser.ConfigParser()
        
        # Set defaults
        for section, options in ConfigManager.DEFAULTS.items():
            config[section] = options
        
        # Load user config if exists
        if os.path.exists(config_path):
            config.read(config_path)
        
        return config
    
    @staticmethod
    def save_config(config: configparser.ConfigParser, config_path: str = "/etc/slowdns/config.ini"):
        """Save configuration to file"""
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            config.write(f)
    
    @staticmethod
    def create_default_config():
        """Create default configuration file"""
        config = configparser.ConfigParser()
        for section, options in ConfigManager.DEFAULTS.items():
            config[section] = options
        
        ConfigManager.save_config(config)
        return config


@dataclass
class ServerConfig:
    """Structured server configuration"""
    # Network
    ssh_port: int = 22
    slowdns_port: int = 5300
    dns_port: int = 53
    bind_address: str = "0.0.0.0"
    mtu: int = 1400
    buffer_size: int = 4096
    enable_ipv6: bool = False
    dns_timeout: int = 5
    
    # Performance
    worker_threads: int = 4
    max_connections: int = 1000
    connection_timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    enable_connection_pool: bool = True
    pool_size: int = 100
    enable_load_balancing: bool = True
    
    # Streaming
    enable_tcp_fallback: bool = True
    enable_compression: bool = True
    packet_loss_threshold: float = 0.05
    min_bandwidth_mbps: float = 1.0
    adaptive_bitrate: bool = True
    max_bitrate_mbps: float = 10.0
    min_bitrate_mbps: float = 0.5
    buffer_size_ms: int = 2000
    enable_fec: bool = False
    fec_percentage: int = 20
    
    # Security
    enable_rate_limit: bool = True
    max_requests_per_ip: int = 100
    block_duration: int = 300
    enable_ip_whitelist: bool = False
    enable_dnssec: bool = False
    enable_query_filtering: bool = True
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    
    # Monitoring
    log_level: str = "INFO"
    log_file: str = "/var/log/slowdns/server.log"
    enable_metrics: bool = True
    metrics_port: int = 9090
    enable_health_checks: bool = True
    health_check_interval: int = 30
    enable_performance_logging: bool = True
    
    # Optimization
    enable_packet_prioritization: bool = True
    udp_buffer_multiplier: int = 2
    tcp_keepalive: bool = True
    tcp_keepalive_idle: int = 60
    tcp_keepalive_interval: int = 10
    tcp_keepalive_count: int = 3
    enable_mtu_discovery: bool = True
    enable_tcp_nodelay: bool = True
    
    @classmethod
    def from_configparser(cls, config: configparser.ConfigParser) -> 'ServerConfig':
        """Create ServerConfig from ConfigParser"""
        kwargs = {}
        
        for field_name in cls.__dataclass_fields__:
            section = None
            config_name = field_name
            
            # Map fields to sections
            if field_name in ['ssh_port', 'slowdns_port', 'dns_port', 'bind_address', 
                            'mtu', 'buffer_size', 'enable_ipv6', 'dns_timeout']:
                section = 'network'
            elif field_name in ['worker_threads', 'max_connections', 'connection_timeout',
                              'max_retries', 'retry_delay', 'enable_connection_pool',
                              'pool_size', 'enable_load_balancing']:
                section = 'performance'
            elif field_name in ['enable_tcp_fallback', 'enable_compression', 'packet_loss_threshold',
                              'min_bandwidth_mbps', 'adaptive_bitrate', 'max_bitrate_mbps',
                              'min_bitrate_mbps', 'buffer_size_ms', 'enable_fec', 'fec_percentage']:
                section = 'streaming'
            elif field_name in ['enable_rate_limit', 'max_requests_per_ip', 'block_duration',
                              'enable_ip_whitelist', 'enable_dnssec', 'enable_query_filtering',
                              'allowed_domains', 'blocked_domains']:
                section = 'security'
            elif field_name in ['log_level', 'log_file', 'enable_metrics', 'metrics_port',
                              'enable_health_checks', 'health_check_interval', 'enable_performance_logging']:
                section = 'monitoring'
            elif field_name in ['enable_packet_prioritization', 'udp_buffer_multiplier',
                              'tcp_keepalive', 'tcp_keepalive_idle', 'tcp_keepalive_interval',
                              'tcp_keepalive_count', 'enable_mtu_discovery', 'enable_tcp_nodelay']:
                section = 'optimization'
            
            if section and config.has_option(section, config_name):
                value = config.get(section, config_name)
                field_type = cls.__dataclass_fields__[field_name].type
                
                try:
                    # Convert string to appropriate type
                    if field_type == bool:
                        kwargs[field_name] = value.lower() in ('true', 'yes', '1', 'on')
                    elif field_type == int:
                        kwargs[field_name] = int(value)
                    elif field_type == float:
                        kwargs[field_name] = float(value)
                    elif field_name in ['allowed_domains', 'blocked_domains']:
                        kwargs[field_name] = [d.strip() for d in value.split(',') if d.strip()]
                    else:
                        kwargs[field_name] = value
                except (ValueError, TypeError):
                    # Keep default value if conversion fails
                    pass
        
        return cls(**kwargs)


# ============================================================================
# STREAMING OPTIMIZATIONS
# ============================================================================
class StreamQuality(Enum):
    """Streaming quality levels with optimization parameters"""
    LOW = {
        'bitrate': 500,  # Kbps
        'buffer': 5000,  # ms
        'compression': 'none',
        'fec': False,
        'mtu': 512
    }
    MEDIUM = {
        'bitrate': 2000,
        'buffer': 2000,
        'compression': 'fast',
        'fec': True,
        'mtu': 1024
    }
    HIGH = {
        'bitrate': 5000,
        'buffer': 1000,
        'compression': 'balanced',
        'fec': True,
        'mtu': 1400
    }
    ULTRA = {
        'bitrate': 10000,
        'buffer': 500,
        'compression': 'maximum',
        'fec': True,
        'mtu': 1500
    }


class StreamingOptimizer:
    """Optimize streaming performance based on network conditions"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.quality_history: List[StreamQuality] = []
        self.network_stats = {
            'bandwidth_mbps': 0.0,
            'latency_ms': 0.0,
            'jitter_ms': 0.0,
            'packet_loss': 0.0,
            'throughput_mbps': 0.0
        }
        self.last_update = time.time()
        self.compression_enabled = config.enable_compression
        self.compression_level = 6  # Default compression level
    
    def update_network_stats(self, bandwidth: float, latency: float, 
                           jitter: float, packet_loss: float):
        """Update network statistics"""
        self.network_stats.update({
            'bandwidth_mbps': bandwidth,
            'latency_ms': latency,
            'jitter_ms': jitter,
            'packet_loss': packet_loss
        })
        self.last_update = time.time()
    
    def get_optimal_quality(self) -> StreamQuality:
        """Determine optimal streaming quality based on network conditions"""
        bandwidth = self.network_stats['bandwidth_mbps']
        latency = self.network_stats['latency_ms']
        packet_loss = self.network_stats['packet_loss']
        
        # Quality selection algorithm
        if bandwidth < 1 or latency > 300 or packet_loss > 0.2:
            quality = StreamQuality.LOW
        elif bandwidth < 3 or latency > 150 or packet_loss > 0.1:
            quality = StreamQuality.MEDIUM
        elif bandwidth < 8 or latency > 80 or packet_loss > 0.05:
            quality = StreamQuality.HIGH
        else:
            quality = StreamQuality.ULTRA
        
        # Smooth quality transitions
        self.quality_history.append(quality)
        if len(self.quality_history) > 10:
            self.quality_history.pop(0)
        
        # Use mode of recent history to prevent rapid fluctuations
        if len(self.quality_history) >= 5:
            from collections import Counter
            most_common = Counter(self.quality_history).most_common(1)[0][0]
            if most_common != quality:
                # Only upgrade quality, don't downgrade rapidly
                if self._quality_value(most_common) > self._quality_value(quality):
                    quality = most_common
        
        return quality
    
    def _quality_value(self, quality: StreamQuality) -> int:
        """Get numeric value for quality comparison"""
        return {
            StreamQuality.LOW: 1,
            StreamQuality.MEDIUM: 2,
            StreamQuality.HIGH: 3,
            StreamQuality.ULTRA: 4
        }[quality]
    
    def optimize_packet(self, data: bytes, quality: StreamQuality) -> bytes:
        """Optimize packet for streaming"""
        optimized = data
        
        # Compression based on quality
        if self.compression_enabled:
            quality_params = quality.value
            if quality_params['compression'] != 'none':
                optimized = self._compress_packet(optimized, quality_params['compression'])
        
        # Add FEC if enabled
        if self.config.enable_fec and quality.value['fec']:
            optimized = self._add_fec(optimized)
        
        return optimized
    
    def _compress_packet(self, data: bytes, mode: str) -> bytes:
        """Compress packet data"""
        if len(data) < 100:  # Don't compress small packets
            return data
        
        try:
            # Adjust compression level based on mode
            level = {
                'fast': 1,
                'balanced': 6,
                'maximum': 9
            }.get(mode, 6)
            
            compressed = zlib.compress(data, level)
            
            # Only use compression if it actually reduces size
            if len(compressed) < len(data) * 0.9:  # At least 10% reduction
                # Add compression header (1 byte for mode)
                header = bytes([{'fast': 1, 'balanced': 2, 'maximum': 3}[mode]])
                return header + compressed
            else:
                return b'\x00' + data  # No compression header
        except:
            return b'\x00' + data  # Fallback: no compression
    
    def _add_fec(self, data: bytes) -> bytes:
        """Add Forward Error Correction"""
        # Simple XOR-based FEC for demonstration
        # In production, use Reed-Solomon or similar
        fec_percentage = self.config.fec_percentage
        fec_size = max(1, len(data) * fec_percentage // 100)
        
        # Generate simple parity bytes
        fec_data = bytearray()
        for i in range(fec_size):
            parity = 0
            for j in range(i, len(data), fec_size):
                parity ^= data[j]
            fec_data.append(parity)
        
        # Add FEC header (2 bytes: FEC indicator + percentage)
        header = struct.pack('!BB', 0xFE, fec_percentage)
        return header + data + bytes(fec_data)
    
    def adjust_mtu(self, current_mtu: int) -> int:
        """Dynamically adjust MTU based on network conditions"""
        packet_loss = self.network_stats['packet_loss']
        latency = self.network_stats['latency_ms']
        
        # MTU adjustment algorithm
        if packet_loss > 0.15:  # High packet loss
            new_mtu = min(576, current_mtu - 100)
        elif packet_loss > 0.08:  # Medium packet loss
            new_mtu = min(1024, current_mtu - 50)
        elif latency > 200:  # High latency
            new_mtu = min(1280, current_mtu)
        elif self.network_stats['bandwidth_mbps'] > 20:  # High bandwidth
            new_mtu = min(1500, current_mtu + 50)
        else:
            new_mtu = current_mtu
        
        # Ensure MTU is within reasonable bounds
        return max(576, min(1500, new_mtu))


# ============================================================================
# CONNECTION MANAGER WITH LOAD BALANCING
# ============================================================================
class LoadBalancedConnection:
    """Connection with load balancing capabilities"""
    
    def __init__(self, address: Tuple[str, int], weight: int = 1):
        self.address = address
        self.weight = weight
        self.active_connections = 0
        self.failed_attempts = 0
        self.last_used = 0
        self.response_time = 0.0
        self.success_rate = 1.0
        self.lock = threading.Lock()
    
    def update_stats(self, success: bool, response_time: float):
        """Update connection statistics"""
        with self.lock:
            if success:
                self.success_rate = 0.9 * self.success_rate + 0.1
                self.response_time = 0.9 * self.response_time + 0.1 * response_time
                self.failed_attempts = 0
            else:
                self.success_rate = 0.9 * self.success_rate
                self.failed_attempts += 1


class LoadBalancer:
    """Load balancer for multiple backend connections"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.connections: List[LoadBalancedConnection] = []
        self.connection_pool: Dict[Tuple, List[socket.socket]] = {}
        self.lock = threading.Lock()
        self.strategy = "weighted_round_robin"  # or "least_connections", "fastest_response"
        
    def add_backend(self, address: Tuple[str, int], weight: int = 1):
        """Add a backend server"""
        with self.lock:
            conn = LoadBalancedConnection(address, weight)
            self.connections.append(conn)
    
    def get_connection(self) -> Optional[Tuple[str, int]]:
        """Get optimal backend connection based on strategy"""
        with self.lock:
            if not self.connections:
                return None
            
            # Filter out unhealthy connections
            healthy_conns = [
                c for c in self.connections
                if c.failed_attempts < 3 and c.success_rate > 0.5
            ]
            
            if not healthy_conns:
                # Fall back to any connection
                healthy_conns = self.connections
            
            if self.strategy == "least_connections":
                return min(healthy_conns, key=lambda c: c.active_connections).address
            elif self.strategy == "fastest_response":
                return min(healthy_conns, key=lambda c: c.response_time).address
            else:  # weighted_round_robin
                # Weighted selection based on success rate and weight
                total_weight = sum(c.weight * c.success_rate for c in healthy_conns)
                if total_weight == 0:
                    return healthy_conns[0].address
                
                r = random.uniform(0, total_weight)
                current = 0
                for conn in healthy_conns:
                    current += conn.weight * conn.success_rate
                    if r <= current:
                        return conn.address
            
            return healthy_conns[0].address
    
    def get_socket(self, address: Tuple[str, int]) -> socket.socket:
        """Get socket from pool or create new"""
        with self.lock:
            if address not in self.connection_pool:
                self.connection_pool[address] = []
            
            pool = self.connection_pool[address]
            if pool:
                sock = pool.pop()
                if self._is_socket_alive(sock):
                    return sock
            
            # Create new socket with optimizations
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Apply optimizations
            if self.config.tcp_keepalive and hasattr(socket, 'SO_KEEPALIVE'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 
                                  self.config.tcp_keepalive_idle)
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL,
                                  self.config.tcp_keepalive_interval)
                if hasattr(socket, 'TCP_KEEPCNT'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,
                                  self.config.tcp_keepalive_count)
            
            # Increase buffer sizes
            buffer_size = self.config.buffer_size * self.config.udp_buffer_multiplier
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)
            
            sock.settimeout(self.config.connection_timeout)
            return sock
    
    def return_socket(self, address: Tuple[str, int], sock: socket.socket):
        """Return socket to pool"""
        with self.lock:
            if address not in self.connection_pool:
                self.connection_pool[address] = []
            
            pool = self.connection_pool[address]
            if len(pool) < 10:  # Max 10 sockets per address in pool
                pool.append(sock)
            else:
                sock.close()
    
    def _is_socket_alive(self, sock: socket.socket) -> bool:
        """Check if socket is still usable"""
        try:
            # Quick non-blocking test
            sock.setblocking(False)
            ready, _, _ = selectors.select([sock], [], [], 0.01)
            sock.setblocking(True)
            return True
        except:
            return False
    
    def cleanup(self):
        """Cleanup all connections"""
        with self.lock:
            for address, pool in self.connection_pool.items():
                for sock in pool:
                    try:
                        sock.close()
                    except:
                        pass
                pool.clear()
            self.connection_pool.clear()


# ============================================================================
# DNS PACKET HANDLER WITH ENHANCEMENTS
# ============================================================================
class EnhancedDNSPacketHandler:
    """Enhanced DNS packet handling with streaming optimizations"""
    
    @staticmethod
    def parse_dns_packet(data: bytes) -> Dict:
        """Parse DNS packet with detailed information"""
        if len(data) < 12:
            return {}
        
        try:
            header = struct.unpack('!6H', data[:12])
            result = {
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
                'rcode': header[1] & 0xF,
                'questions': [],
                'answers': [],
                'authority': [],
                'additional': []
            }
            
            offset = 12
            
            # Parse questions
            for _ in range(result['qdcount']):
                qname, offset = EnhancedDNSPacketHandler._parse_name(data, offset)
                if offset + 4 > len(data):
                    break
                qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
                offset += 4
                result['questions'].append({
                    'name': qname,
                    'type': qtype,
                    'class': qclass
                })
            
            # Parse answers, authority, additional (simplified)
            for section in ['answers', 'authority', 'additional']:
                count = result['answers' if section == 'answers' else 
                              'authority' if section == 'authority' else 'arcount']
                for _ in range(count):
                    if offset >= len(data):
                        break
                    name, offset = EnhancedDNSPacketHandler._parse_name(data, offset)
                    if offset + 10 > len(data):
                        break
                    rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', 
                                                                 data[offset:offset+10])
                    offset += 10
                    rdata = data[offset:offset+rdlength] if offset + rdlength <= len(data) else b''
                    offset += rdlength
                    
                    result[section].append({
                        'name': name,
                        'type': rtype,
                        'class': rclass,
                        'ttl': ttl,
                        'data': rdata
                    })
            
            return result
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def _parse_name(data: bytes, offset: int) -> Tuple[str, int]:
        """Parse DNS name with compression handling"""
        parts = []
        original_offset = offset
        
        try:
            while offset < len(data) and data[offset] != 0:
                length = data[offset]
                if length & 0xC0:  # Compression pointer
                    if offset + 2 > len(data):
                        break
                    ptr = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
                    offset += 2
                    name, _ = EnhancedDNSPacketHandler._parse_name(data, ptr)
                    parts.append(name)
                    break
                else:
                    offset += 1
                    if offset + length <= len(data):
                        parts.append(data[offset:offset+length].decode('utf-8', errors='ignore'))
                        offset += length
                    else:
                        break
            offset += 1  # Skip null terminator
        except:
            pass
        
        return '.'.join(parts), offset
    
    @staticmethod
    def patch_edns(data: bytes, new_size: int, enable_dnssec: bool = False) -> bytes:
        """Patch EDNS OPT record with streaming optimizations"""
        if len(data) < 12:
            return data
        
        data = bytearray(data)
        offset = 12
        
        # Skip question section
        qdcount = struct.unpack('!H', data[4:6])[0]
        for _ in range(qdcount):
            while offset < len(data) and data[offset]:
                offset += 1
            offset += 5
        
        # Update EDNS if exists, or add if not
        arcount = struct.unpack('!H', data[10:12])[0]
        edns_found = False
        
        for i in range(arcount):
            if offset >= len(data):
                break
            
            if data[offset] == 0:  # Root label
                if offset + 4 < len(data):
                    rtype = struct.unpack('!H', data[offset+1:offset+3])[0]
                    if rtype == 41:  # OPT record
                        # Update UDP payload size
                        data[offset+3] = (new_size >> 8) & 0xFF
                        data[offset+4] = new_size & 0xFF
                        
                        # Set DNSSEC OK bit if enabled
                        if enable_dnssec and offset + 5 < len(data):
                            data[offset+5] |= 0x80
                        
                        edns_found = True
                        break
                offset += 11  # Skip OPT record
            else:
                # Skip regular record
                offset += 1
        
        # Add EDNS OPT record if not found
        if not edns_found:
            # Convert arcount to int, increment, and update
            arcount_val = struct.unpack('!H', data[10:12])[0] + 1
            data[10:12] = struct.pack('!H', arcount_val)
            
            # Append OPT record
            opt_record = struct.pack('!BBHHIH', 
                                   0,           # Root label
                                   0, 41,       # TYPE OPT
                                   new_size,    # UDP payload size
                                   0,           # Extended RCODE
                                   0,           # EDNS version
                                   (1 << 15) if enable_dnssec else 0)  # Flags (DO bit)
            data.extend(opt_record)
        
        return bytes(data)
    
    @staticmethod
    def is_streaming_query(packet: Dict) -> bool:
        """Check if query is likely for streaming"""
        # Check for common streaming-related patterns
        streaming_keywords = ['video', 'stream', 'livestream', 'cdn', 'hls', 'dash', 'm3u8']
        
        for question in packet.get('questions', []):
            domain = question.get('name', '').lower()
            for keyword in streaming_keywords:
                if keyword in domain:
                    return True
        
        # Check query type (A/AAAA records are common for streaming)
        for question in packet.get('questions', []):
            qtype = question.get('type', 0)
            if qtype in [1, 28]:  # A or AAAA record
                return True
        
        return False


# ============================================================================
# MAIN SLOWDNS SERVER
# ============================================================================
class SlowDNSServer:
    """Main SlowDNS Server with streaming optimizations"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.optimizer = StreamingOptimizer(config)
        self.load_balancer = LoadBalancer(config)
        self.load_balancer.add_backend(('127.0.0.1', config.slowdns_port))
        
        # Initialize rate limiter
        from collections import defaultdict
        self.rate_limiter = RateLimiter(
            max_requests=config.max_requests_per_ip,
            window=config.block_duration
        )
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'streaming_queries': 0,
            'compressed_bytes': 0,
            'original_bytes': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_response_time_ms': 0
        }
        
        # Cache for frequent queries
        self.cache = DNSCache(max_size=1000, ttl=300)
        
        # Worker pool
        self.worker_pool = ThreadPoolExecutor(max_workers=config.worker_threads)
        
        # Server state
        self.udp_socket = None
        self.running = False
        self.start_time = time.time()
        
    def _setup_logging(self):
        """Configure logging"""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        
        # Create log directory
        log_dir = os.path.dirname(self.config.log_file)
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler() if self.config.enable_performance_logging else 
                logging.NullHandler()
            ]
        )
    
    def start(self):
        """Start the server"""
        self.logger.info("🚀 Starting Enhanced SlowDNS Server...")
        self.logger.info(f"📊 Configuration: {json.dumps(asdict(self.config), indent=2)}")
        
        try:
            # Create UDP socket
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Optimize socket buffers
            buffer_size = self.config.buffer_size * self.config.udp_buffer_multiplier
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)
            
            # Bind to address
            self.udp_socket.bind((self.config.bind_address, self.config.dns_port))
            self.logger.info(f"📡 Listening on {self.config.bind_address}:{self.config.dns_port}")
            
            self.running = True
            
            # Start background threads
            threading.Thread(target=self._monitoring_thread, daemon=True).start()
            threading.Thread(target=self._cleanup_thread, daemon=True).start()
            
            if self.config.enable_metrics:
                threading.Thread(target=self._metrics_server, daemon=True).start()
            
            # Main receive loop
            self._receive_loop()
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start server: {e}")
            self.stop()
            raise
    
    def _receive_loop(self):
        """Main receive loop"""
        self.logger.info("🎯 Entering receive loop...")
        
        while self.running:
            try:
                # Receive DNS query with timeout
                self.udp_socket.settimeout(1.0)
                data, addr = self.udp_socket.recvfrom(self.config.buffer_size)
                
                if not data:
                    continue
                
                client_ip = addr[0]
                
                # Update statistics
                self.stats['total_queries'] += 1
                self.stats['original_bytes'] += len(data)
                
                # Rate limiting
                if self.config.enable_rate_limit:
                    if not self.rate_limiter.is_allowed(client_ip):
                        self.logger.warning(f"⚠️ Rate limit exceeded for {client_ip}")
                        continue
                
                # Process query asynchronously
                self.worker_pool.submit(self._process_query_async, data, addr)
                
            except socket.timeout:
                continue
            except OSError as e:
                if self.running:
                    self.logger.error(f"🔌 Socket error: {e}")
                break
            except Exception as e:
                self.logger.error(f"💥 Unexpected error: {e}")
                continue
    
    def _process_query_async(self, data: bytes, client_addr: Tuple[str, int]):
        """Process query asynchronously"""
        start_time = time.time()
        
        try:
            # Check cache first
            cache_key = hashlib.md5(data).hexdigest()
            cached_response = self.cache.get(cache_key)
            
            if cached_response:
                self.stats['cache_hits'] += 1
                self.udp_socket.sendto(cached_response, client_addr)
                return
            
            self.stats['cache_misses'] += 1
            
            # Parse DNS packet
            packet_info = EnhancedDNSPacketHandler.parse_dns_packet(data)
            
            # Check if streaming query
            is_streaming = EnhancedDNSPacketHandler.is_streaming_query(packet_info)
            if is_streaming:
                self.stats['streaming_queries'] += 1
            
            # Get optimal MTU and quality
            optimal_mtu = self.optimizer.adjust_mtu(self.config.mtu)
            quality = self.optimizer.get_optimal_quality()
            
            # Patch EDNS with optimized settings
            patched_data = EnhancedDNSPacketHandler.patch_edns(
                data, optimal_mtu, self.config.enable_dnssec
            )
            
            # Forward to backend
            response = self._forward_to_backend(patched_data, client_addr, 
                                              is_streaming, quality)
            
            if response:
                # Optimize response for streaming if needed
                if is_streaming:
                    response = self.optimizer.optimize_packet(response, quality)
                    self.stats['compressed_bytes'] += len(response)
                
                # Cache the response
                self.cache.set(cache_key, response)
                
                # Send response back
                self.udp_socket.sendto(response, client_addr)
                
                # Update statistics
                response_time = (time.time() - start_time) * 1000
                self.stats['successful_queries'] += 1
                self.stats['avg_response_time_ms'] = (
                    0.9 * self.stats['avg_response_time_ms'] + 0.1 * response_time
                )
                
                # Log successful query (verbose)
                if self.logger.isEnabledFor(logging.DEBUG):
                    domain = packet_info.get('questions', [{}])[0].get('name', 'unknown')
                    self.logger.debug(
                        f"✅ Query: {domain[:30]}... | "
                        f"Time: {response_time:.1f}ms | "
                        f"MTU: {optimal_mtu} | "
                        f"Quality: {quality.name}"
                    )
            else:
                self.stats['failed_queries'] += 1
                self.logger.warning(f"❌ Failed to process query from {client_addr[0]}")
                
        except Exception as e:
            self.stats['failed_queries'] += 1
            self.logger.error(f"💥 Error processing query: {e}")
    
    def _forward_to_backend(self, data: bytes, client_addr: Tuple[str, int],
                          is_streaming: bool, quality: StreamQuality) -> Optional[bytes]:
        """Forward query to backend with retries"""
        max_retries = self.config.max_retries if not is_streaming else self.config.max_retries + 1
        
        for attempt in range(max_retries):
            try:
                # Get backend address using load balancer
                backend_addr = self.load_balancer.get_connection()
                if not backend_addr:
                    self.logger.error("No available backend servers")
                    return None
                
                # Get socket from pool
                sock = self.load_balancer.get_socket(backend_addr)
                
                # Adjust timeout for streaming
                timeout = self.config.connection_timeout
                if is_streaming:
                    timeout = min(timeout * 2, 30)  # Longer timeout for streaming
                
                sock.settimeout(timeout)
                
                # Send to backend
                start_time = time.time()
                sock.sendto(data, backend_addr)
                
                # Receive response
                response, _ = sock.recvfrom(self.config.buffer_size)
                response_time = (time.time() - start_time) * 1000
                
                # Return socket to pool
                self.load_balancer.return_socket(backend_addr, sock)
                
                # Update connection statistics
                self.load_balancer.connections[0].update_stats(True, response_time)
                
                # Update network statistics for optimizer
                self.optimizer.update_network_stats(
                    bandwidth=10.0,  # TODO: Calculate actual bandwidth
                    latency=response_time,
                    jitter=0.0,  # TODO: Calculate jitter
                    packet_loss=0.0  # TODO: Track packet loss
                )
                
                return response
                
            except socket.timeout:
                self.logger.warning(f"⏰ Timeout connecting to backend (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                continue
            except Exception as e:
                self.logger.error(f"🔌 Error forwarding to backend: {e}")
                break
        
        return None
    
    def _monitoring_thread(self):
        """Monitor system and service health"""
        while self.running:
            time.sleep(self.config.health_check_interval)
            
            try:
                # Check system resources
                cpu_percent = psutil.cpu_percent()
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Check service health
                health_status = self._check_health()
                
                # Log health status
                self.logger.info(
                    f"🏥 Health Check | "
                    f"CPU: {cpu_percent:.1f}% | "
                    f"Memory: {memory.percent:.1f}% | "
                    f"Disk: {disk.percent:.1f}% | "
                    f"Queries: {self.stats['total_queries']} | "
                    f"Success Rate: {self.stats['successful_queries'] / max(1, self.stats['total_queries']) * 100:.1f}%"
                )
                
                # Take action if unhealthy
                if not health_status['healthy']:
                    self.logger.warning(f"🚨 Unhealthy: {health_status['issues']}")
                    self._recover_from_failure()
                
            except Exception as e:
                self.logger.error(f"⚠️ Monitoring error: {e}")
    
    def _check_health(self) -> Dict:
        """Check service health"""
        issues = []
        
        # Check socket
        if not self.udp_socket:
            issues.append("No UDP socket")
        
        # Check backend connectivity
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_sock.settimeout(1)
            test_sock.sendto(b'test', ('127.0.0.1', self.config.slowdns_port))
            test_sock.close()
        except:
            issues.append("Backend unreachable")
        
        # Check memory usage
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        if memory_mb > self.config.max_connections:
            issues.append(f"High memory usage: {memory_mb:.1f}MB")
        
        return {
            'healthy': len(issues) == 0,
            'issues': issues,
            'uptime': time.time() - self.start_time,
            'timestamp': datetime.now().isoformat()
        }
    
    def _recover_from_failure(self):
        """Attempt to recover from failure"""
        self.logger.info("🔄 Attempting recovery...")
        
        try:
            # Restart UDP socket
            if self.udp_socket:
                self.udp_socket.close()
            
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.bind((self.config.bind_address, self.config.dns_port))
            
            # Clear connection pool
            self.load_balancer.cleanup()
            
            # Reset rate limiter
            self.rate_limiter.cleanup_old_entries()
            
            self.logger.info("✅ Recovery successful")
            
        except Exception as e:
            self.logger.error(f"❌ Recovery failed: {e}")
    
    def _cleanup_thread(self):
        """Periodic cleanup tasks"""
        while self.running:
            time.sleep(60)  # Run every minute
            
            try:
                # Cleanup rate limiter
                self.rate_limiter.cleanup_old_entries()
                
                # Cleanup cache
                self.cache.cleanup()
                
                # Cleanup connection pool
                self.load_balancer.cleanup()
                
                # Log statistics
                self._log_statistics()
                
            except Exception as e:
                self.logger.error(f"⚠️ Cleanup error: {e}")
    
    def _log_statistics(self):
        """Log performance statistics"""
        if self.stats['total_queries'] > 0:
            success_rate = self.stats['successful_queries'] / self.stats['total_queries'] * 100
            compression_ratio = (self.stats['compressed_bytes'] / max(1, self.stats['original_bytes'])) * 100
            
            self.logger.info(
                f"📈 Statistics | "
                f"Queries: {self.stats['total_queries']} | "
                f"Success: {success_rate:.1f}% | "
                f"Streaming: {self.stats['streaming_queries']} | "
                f"Cache: {self.stats['cache_hits']}/{self.stats['cache_misses']} | "
                f"Compression: {compression_ratio:.1f}% | "
                f"Avg Time: {self.stats['avg_response_time_ms']:.1f}ms"
            )
    
    def _metrics_server(self):
        """Simple metrics server for monitoring"""
        if self.config.metrics_port <= 0:
            return
        
        try:
            metrics_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            metrics_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            metrics_sock.bind(('127.0.0.1', self.config.metrics_port))
            metrics_sock.listen(5)
            metrics_sock.settimeout(1)
            
            self.logger.info(f"📊 Metrics server listening on 127.0.0.1:{self.config.metrics_port}")
            
            while self.running:
                try:
                    client, addr = metrics_sock.accept()
                    threading.Thread(target=self._handle_metrics_client, 
                                   args=(client, addr)).start()
                except socket.timeout:
                    continue
                    
        except Exception as e:
            self.logger.error(f"❌ Metrics server error: {e}")
    
    def _handle_metrics_client(self, client: socket.socket, addr: Tuple[str, int]):
        """Handle metrics client request"""
        try:
            # Simple HTTP response with metrics
            metrics = {
                'status': 'running' if self.running else 'stopped',
                'uptime': time.time() - self.start_time,
                'statistics': self.stats,
                'health': self._check_health(),
                'config': {
                    'mtu': self.config.mtu,
                    'compression': self.config.enable_compression,
                    'streaming_optimized': True
                }
            }
            
            response = f"HTTP/1.1 200 OK\r\n"
            response += f"Content-Type: application/json\r\n"
            response += f"Content-Length: {len(json.dumps(metrics, indent=2))}\r\n"
            response += f"\r\n"
            response += json.dumps(metrics, indent=2)
            
            client.send(response.encode())
            client.close()
            
        except Exception as e:
            self.logger.error(f"❌ Metrics client error: {e}")
            try:
                client.close()
            except:
                pass
    
    def stop(self):
        """Stop the server gracefully"""
        self.logger.info("🛑 Stopping SlowDNS Server...")
        self.running = False
        
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except:
                pass
        
        self.worker_pool.shutdown(wait=True)
        self.load_balancer.cleanup()
        self.cache.clear()
        
        # Log final statistics
        uptime = time.time() - self.start_time
        self.logger.info(
            f"📊 Final Statistics | "
            f"Uptime: {uptime:.1f}s | "
            f"Total Queries: {self.stats['total_queries']} | "
            f"Success Rate: {self.stats['successful_queries'] / max(1, self.stats['total_queries']) * 100:.1f}%"
        )
        
        self.logger.info("👋 Server stopped")


# ============================================================================
# SUPPORTING CLASSES
# ============================================================================
class RateLimiter:
    """Rate limiting implementation"""
    
    def __init__(self, max_requests: int = 100, window: int = 60):
        self.max_requests = max_requests
        self.window = window
        self.requests: Dict[str, List[float]] = {}
        self.blocked: Dict[str, float] = {}
        self.lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> bool:
        """Check if IP is allowed"""
        with self.lock:
            current_time = time.time()
            
            # Check if blocked
            if ip in self.blocked:
                if current_time - self.blocked[ip] < 300:
                    return False
                del self.blocked[ip]
            
            # Clean old requests
            if ip in self.requests:
                self.requests[ip] = [
                    t for t in self.requests[ip]
                    if current_time - t < self.window
                ]
            
            # Check rate
            if ip not in self.requests:
                self.requests[ip] = []
            
            if len(self.requests[ip]) >= self.max_requests:
                self.blocked[ip] = current_time
                return False
            
            self.requests[ip].append(current_time)
            return True
    
    def cleanup_old_entries(self):
        """Clean old entries"""
        with self.lock:
            current_time = time.time()
            
            # Clean requests
            for ip in list(self.requests.keys()):
                self.requests[ip] = [
                    t for t in self.requests[ip]
                    if current_time - t < self.window * 2
                ]
                if not self.requests[ip]:
                    del self.requests[ip]
            
            # Clean blocked
            for ip in list(self.blocked.keys()):
                if current_time - self.blocked[ip] > 300:
                    del self.blocked[ip]


class DNSCache:
    """DNS response cache"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = ttl
        self.cache: Dict[str, Tuple[bytes, float]] = {}
        self.lock = threading.Lock()
    
    def get(self, key: str) -> Optional[bytes]:
        """Get cached response"""
        with self.lock:
            if key in self.cache:
                data, expiry = self.cache[key]
                if time.time() < expiry:
                    return data
                del self.cache[key]
        return None
    
    def set(self, key: str, data: bytes, ttl: int = None):
        """Cache response"""
        with self.lock:
            if len(self.cache) >= self.max_size:
                # Remove oldest entries
                oldest = sorted(self.cache.items(), key=lambda x: x[1][1])[:self.max_size // 10]
                for k, _ in oldest:
                    del self.cache[k]
            
            expiry = time.time() + (ttl or self.default_ttl)
            self.cache[key] = (data, expiry)
    
    def cleanup(self):
        """Clean expired entries"""
        with self.lock:
            current_time = time.time()
            expired = [k for k, (_, expiry) in self.cache.items() 
                      if current_time >= expiry]
            for k in expired:
                del self.cache[k]
    
    def clear(self):
        """Clear cache"""
        with self.lock:
            self.cache.clear()


# ============================================================================
# INSTALLATION AND MANAGEMENT
# ============================================================================
class SlowDNSManager:
    """Manage SlowDNS installation and configuration"""
    
    def __init__(self):
        self.config_dir = Path("/etc/slowdns")
        self.install_dir = Path("/opt/slowdns")
        self.log_dir = Path("/var/log/slowdns")
        self.systemd_dir = Path("/etc/systemd/system")
        
        # Ensure directories exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.install_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def install(self, nameserver: str = "dns.example.com", update: bool = False):
        """Install or update SlowDNS"""
        print("🚀 Starting SlowDNS Installation...")
        print("=" * 60)
        
        try:
            # Create configuration
            self._create_configuration(nameserver)
            
            # Download components
            self._download_components()
            
            # Setup Python proxy
            self._setup_python_proxy()
            
            # Configure services
            self._configure_services(nameserver)
            
            # Configure firewall
            self._configure_firewall()
            
            # Start services
            self._start_services()
            
            print("=" * 60)
            print("✅ Installation completed successfully!")
            
            # Show summary
            self._show_summary(nameserver)
            
        except Exception as e:
            print(f"❌ Installation failed: {e}")
            raise
    
    def _create_configuration(self, nameserver: str):
        """Create configuration files"""
        print("📝 Creating configuration...")
        
        # Create config.ini
        config = ConfigManager.create_default_config()
        
        # Update with nameserver
        if not config.has_section('general'):
            config.add_section('general')
        config.set('general', 'nameserver', nameserver)
        
        ConfigManager.save_config(config, self.config_dir / "config.ini")
        print("  ✓ Configuration file created")
        
        # Create environment file
        env_file = self.config_dir / "environment"
        with open(env_file, 'w') as f:
            f.write(f"NAMESERVER={nameserver}\n")
            f.write(f"CONFIG_FILE={self.config_dir}/config.ini\n")
            f.write(f"LOG_DIR={self.log_dir}\n")
        print("  ✓ Environment file created")
    
    def _download_components(self):
        """Download required components"""
        print("📦 Downloading components...")
        
        base_url = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
        
        try:
            # Create SSL context for secure download
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Download dnstt-server
            binary_path = self.config_dir / "dnstt-server"
            with urllib.request.urlopen(
                f"{base_url}/dnstt-server",
                context=ssl_context,
                timeout=30
            ) as response:
                with open(binary_path, 'wb') as f:
                    f.write(response.read())
            
            binary_path.chmod(0o755)
            print("  ✓ Downloaded dnstt-server")
            
            # Download keys
            for key_file in ["server.key", "server.pub"]:
                key_path = self.config_dir / key_file
                with urllib.request.urlopen(
                    f"{base_url}/{key_file}",
                    context=ssl_context,
                    timeout=30
                ) as response:
                    with open(key_path, 'wb') as f:
                        f.write(response.read())
                print(f"  ✓ Downloaded {key_file}")
                
        except Exception as e:
            print(f"  ⚠️  Download warning: {e}")
            print("  ℹ️  Using existing files if available")
    
    def _setup_python_proxy(self):
        """Setup Python EDNS proxy"""
        print("🐍 Setting up Python proxy...")
        
        # Copy this script to install directory
        script_path = self.install_dir / "slowdns_server.py"
        with open(script_path, 'w') as f:
            f.write(__file__)
        
        # Make executable
        script_path.chmod(0o755)
        print("  ✓ Python proxy script installed")
        
        # Create wrapper script
        wrapper_path = self.install_dir / "start_proxy.py"
        with open(wrapper_path, 'w') as f:
            f.write("""#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from slowdns_server import main

if __name__ == "__main__":
    main()
""")
        wrapper_path.chmod(0o755)
        print("  ✓ Wrapper script created")
    
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
EnvironmentFile=/etc/slowdns/environment
ExecStart=/etc/slowdns/dnstt-server -udp :5300 \\
  -mtu 1400 \\
  -privkey-file /etc/slowdns/server.key \\
  {nameserver} 127.0.0.1:22
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
WorkingDirectory=/etc/slowdns

[Install]
WantedBy=multi-user.target
""")
        
        # Python proxy service
        proxy_service = self.systemd_dir / "slowdns-proxy.service"
        with open(proxy_service, 'w') as f:
            f.write(f"""[Unit]
Description=SlowDNS EDNS Proxy
After=slowdns-server.service
Requires=slowdns-server.service

[Service]
Type=simple
EnvironmentFile=/etc/slowdns/environment
ExecStart=/usr/bin/python3 /opt/slowdns/start_proxy.py --proxy-only
WorkingDirectory=/opt/slowdns
Restart=always
RestartSec=3
User=root
Environment=PYTHONUNBUFFERED=1
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
""")
        
        print("  ✓ Service files created")
    
    def _configure_firewall(self):
        """Configure firewall rules"""
        print("🔥 Configuring firewall...")
        
        try:
            # Flush existing rules
            subprocess.run(["iptables", "-F"], check=False, capture_output=True)
            subprocess.run(["iptables", "-X"], check=False, capture_output=True)
            
            # Default policies
            subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=False)
            subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=False)
            
            # Essential rules
            rules = [
                ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-m", "state", "--state", 
                 "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "udp", "--dport", "5300", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"]
            ]
            
            for rule in rules:
                subprocess.run(rule, check=False, capture_output=True)
            
            # Save rules
            subprocess.run(["iptables-save", ">", "/etc/iptables/rules.v4"], 
                         shell=True, check=False)
            
            print("  ✓ Firewall rules configured")
            
        except Exception as e:
            print(f"  ⚠️  Firewall configuration warning: {e}")
    
    def _start_services(self):
        """Start and enable services"""
        print("🚀 Starting services...")
        
        try:
            # Stop conflicting services
            subprocess.run(["systemctl", "stop", "systemd-resolved"], 
                         check=False, capture_output=True)
            subprocess.run(["systemctl", "disable", "systemd-resolved"],
                         check=False, capture_output=True)
            
            # Reload systemd
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            
            # Enable and start services
            services = ["slowdns-server", "slowdns-proxy"]
            for service in services:
                subprocess.run(["systemctl", "enable", service], check=True)
                subprocess.run(["systemctl", "start", service], check=True)
                time.sleep(2)
                
                # Check status
                result = subprocess.run(["systemctl", "is-active", service],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"  ✓ {service} started successfully")
                else:
                    print(f"  ⚠️  {service} may have issues: {result.stderr}")
            
            print("  ✓ All services started")
            
        except Exception as e:
            print(f"  ❌ Service startup failed: {e}")
            raise
    
    def _show_summary(self, nameserver: str):
        """Show installation summary"""
        import socket
        
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except:
            ip = "127.0.0.1"
        
        print("\n" + "="*60)
        print("📊 INSTALLATION SUMMARY")
        print("="*60)
        print(f"Server IP:        {ip}")
        print(f"SSH Port:         22")
        print(f"SlowDNS Port:     5300")
        print(f"DNS Port:         53")
        print(f"Nameserver:       {nameserver}")
        print(f"MTU:              1400 (adaptive)")
        print(f"Config:           /etc/slowdns/config.ini")
        print(f"Logs:             /var/log/slowdns/")
        print("="*60)
        
        print("\n📋 Service Status:")
        subprocess.run(["systemctl", "status", "slowdns-server", "--no-pager", "-l"])
        
        print("\n🔧 Test Commands:")
        print(f"  dig @{ip} {nameserver}")
        print(f"  nslookup {nameserver} {ip}")
        print(f"  curl http://{ip}:9090/metrics")
        
        print("\n⚙️  Management Commands:")
        print("  sudo systemctl restart slowdns-server")
        print("  sudo systemctl restart slowdns-proxy")
        print("  sudo journalctl -u slowdns-proxy -f")
        print("  sudo tail -f /var/log/slowdns/server.log")
        
        print("\n📈 Performance Monitoring:")
        print("  Access metrics: http://localhost:9090")
        print("  View real-time stats: journalctl -u slowdns-proxy -f")
        
        print("="*60)
        print("🎉 Installation Complete! Services are running.")
        print("="*60)


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================
def main():
    """Main entry point"""
    
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║           ENHANCED SLOWDNS INSTALLATION              ║
    ║     Optimized for Streaming & Maximum Performance    ║
    ╚══════════════════════════════════════════════════════╝
    """)
    
    # Check root privileges
    if os.geteuid() != 0:
        print("❌ Please run as root (use sudo)!")
        sys.exit(1)
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="SlowDNS Server Manager")
    parser.add_argument("--install", action="store_true", help="Install SlowDNS")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall SlowDNS")
    parser.add_argument("--start", action="store_true", help="Start SlowDNS proxy")
    parser.add_argument("--stop", action="store_true", help="Stop SlowDNS proxy")
    parser.add_argument("--status", action="store_true", help="Show status")
    parser.add_argument("--proxy-only", action="store_true", 
                       help="Run Python proxy only (no installation)")
    parser.add_argument("--nameserver", default="dns.example.com",
                       help="Nameserver domain (default: dns.example.com)")
    parser.add_argument("--config", default="/etc/slowdns/config.ini",
                       help="Configuration file path")
    
    args = parser.parse_args()
    
    if args.proxy_only:
        # Run Python proxy only
        print("🚀 Starting Enhanced SlowDNS Proxy...")
        
        # Load configuration
        config_parser = ConfigManager.load_config(args.config)
        config = ServerConfig.from_configparser(config_parser)
        
        # Create and start server
        server = SlowDNSServer(config)
        
        def signal_handler(signum, frame):
            print("\n🛑 Shutting down gracefully...")
            server.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            server.start()
        except KeyboardInterrupt:
            print("\n👋 Interrupted by user")
            server.stop()
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
            
    elif args.install:
        # Full installation
        manager = SlowDNSManager()
        manager.install(args.nameserver)
        
    elif args.uninstall:
        print("🗑️  Uninstalling SlowDNS...")
        # TODO: Implement uninstall
        print("⚠️  Uninstall not yet implemented")
        
    elif args.start:
        print("▶️  Starting services...")
        subprocess.run(["systemctl", "start", "slowdns-server", "slowdns-proxy"])
        
    elif args.stop:
        print("⏹️  Stopping services...")
        subprocess.run(["systemctl", "stop", "slowdns-server", "slowdns-proxy"])
        
    elif args.status:
        print("📊 Service Status:")
        subprocess.run(["systemctl", "status", "slowdns-server", "slowdns-proxy"])
        
    else:
        # Interactive mode
        print("\nSelect operation:")
        print("1. Install SlowDNS (recommended)")
        print("2. Start Python proxy only")
        print("3. Show service status")
        print("4. Exit")
        
        choice = input("\nYour choice [1]: ").strip() or "1"
        
        if choice == "1":
            nameserver = input(f"Enter nameserver [{args.nameserver}]: ").strip() or args.nameserver
            manager = SlowDNSManager()
            manager.install(nameserver)
        elif choice == "2":
            args.proxy_only = True
            main()  # Restart with proxy-only
        elif choice == "3":
            args.status = True
            main()  # Restart with status
        else:
            print("👋 Goodbye!")
            sys.exit(0)


if __name__ == "__main__":
    main()
