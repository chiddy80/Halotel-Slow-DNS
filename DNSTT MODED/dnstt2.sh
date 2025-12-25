#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
EXTERNAL_EDNS_SIZE=512
INTERNAL_EDNS_SIZE=1800
EDNS_PROXY_PORT=53
SLOWDNS_PORT=5300

# Functions
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root: sudo bash $0${NC}"
        exit 1
    fi
}

# Check if SlowDNS is running
check_slowdns() {
    print_warning "Checking if SlowDNS is running on port $SLOWDNS_PORT..."
    if ss -ulpn | grep -q ":$SLOWDNS_PORT"; then
        print_success "SlowDNS found running on port $SLOWDNS_PORT"
        return 0
    else
        print_error "SlowDNS not found on port $SLOWDNS_PORT"
        echo ""
        echo -e "${YELLOW}Note: This EDNS Proxy requires SlowDNS to be running first.${NC}"
        echo -e "${YELLOW}Please install and start SlowDNS before running this script.${NC}"
        echo ""
        exit 1
    fi
}

# SAFE: Stop DNS services without killing the script
safe_stop_dns() {
    print_warning "Stopping existing DNS services on port 53..."
    
    # Stop systemd-resolved
    systemctl stop systemd-resolved
    
    # Free port 53
    fuser -k 53/udp
    
    print_success "Port 53 prepared for EDNS Proxy"
}

# Check prerequisites
check_root
check_slowdns

# Install Python3 if not present
print_warning "Checking for Python3..."
if ! command -v python3 &> /dev/null; then
    print_warning "Python3 not found, installing..."
    apt-get update > /dev/null 2>&1
    apt-get install -y python3 > /dev/null 2>&1
    print_success "Python3 installed"
else
    print_success "Python3 already installed"
fi

# Create EDNS Proxy Python script
print_warning "Creating EDNS Proxy Python script..."
cat > /usr/local/bin/edns-proxy.py << 'EOF'
#!/usr/bin/env python3
import socket
import threading
import struct

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 5300
EXTERNAL_EDNS_SIZE = 512
INTERNAL_EDNS_SIZE = 1800

def patch_edns_udp_size(data: bytes, new_size: int) -> bytes:
    if len(data) < 12:
        return data
    try:
        qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
    except struct.error:
        return data
    
    offset = 12
    def skip_name(buf, off):
        while True:
            if off >= len(buf):
                return len(buf)
            l = buf[off]
            off += 1
            if l == 0:
                break
            if l & 0xC0 == 0xC0:
                if off >= len(buf):
                    return len(buf)
                off += 1
                break
            off += l
        return off
    
    for _ in range(qdcount):
        offset = skip_name(data, offset)
        if offset + 4 > len(data):
            return data
        offset += 4
    
    def skip_rrs(count, buf, off):
        for _ in range(count):
            off = skip_name(buf, off)
            if off + 10 > len(buf):
                return len(buf)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", buf[off:off+10])
            off += 10
            if off + rdlen > len(buf):
                return len(buf)
            off += rdlen
        return off
    
    offset = skip_rrs(ancount, data, offset)
    offset = skip_rrs(nscount, data, offset)
    
    new_data = bytearray(data)
    for _ in range(arcount):
        rr_name_start = offset
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            return data
        rtype = struct.unpack("!H", data[offset:offset+2])[0]
        if rtype == 41:
            size_bytes = struct.pack("!H", new_size)
            new_data[offset+2:offset+4] = size_bytes
            return bytes(new_data)
        _, _, rdlen = struct.unpack("!H I H", data[offset+2:offset+10])
        offset += 10 + rdlen
    return data

def handle_request(server_sock: socket.socket, data: bytes, client_addr):
    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.settimeout(5.0)
    try:
        upstream_data = patch_edns_udp_size(data, INTERNAL_EDNS_SIZE)
        upstream_sock.sendto(upstream_data, (UPSTREAM_HOST, UPSTREAM_PORT))
        resp, _ = upstream_sock.recvfrom(4096)
        resp_patched = patch_edns_udp_size(resp, EXTERNAL_EDNS_SIZE)
        server_sock.sendto(resp_patched, client_addr)
    except:
        pass
    finally:
        upstream_sock.close()

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    while True:
        data, client_addr = server_sock.recvfrom(4096)
        t = threading.Thread(
            target=handle_request,
            args=(server_sock, data, client_addr),
            daemon=True,
        )
        t.start()

if __name__ == "__main__":
    main()
EOF

chmod +x /usr/local/bin/edns-proxy.py
print_success "EDNS Proxy Python script created"

# Create systemd service for EDNS Proxy
print_warning "Creating EDNS Proxy service..."
cat > /etc/systemd/system/edns-proxy.service << EOF
[Unit]
Description=EDNS Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/edns-proxy.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

print_success "EDNS Proxy service created"

# SAFELY stop DNS services
safe_stop_dns

# Start EDNS Proxy service
print_warning "Starting EDNS Proxy service..."
systemctl daemon-reload
systemctl enable edns-proxy.service > /dev/null 2>&1
systemctl restart edns-proxy
sleep 2

# Test EDNS Proxy
print_warning "Testing EDNS Proxy..."
if ss -ulpn | grep -q ":$EDNS_PROXY_PORT"; then
    print_success "EDNS Proxy listening on port $EDNS_PROXY_PORT"
else
    print_error "EDNS Proxy failed to start"
fi

# Add the requested commands
systemctl stop systemd-resolved
fuser -k 53/udp
systemctl restart edns-proxy

echo ""
print_success "EDNS Proxy Installation Completed"
