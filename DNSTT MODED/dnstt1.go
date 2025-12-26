#!/bin/bash
# EDNS Proxy Installer - C/epoll (Fixed)

# Check root
[ "$EUID" -ne 0 ] && echo "Run: sudo bash $0" && exit 1

# Check SlowDNS
! ss -ulpn 2>/dev/null | grep -q ":5300" && echo "Start SlowDNS first" && exit 1

# Stop DNS
systemctl stop systemd-resolved 2>/dev/null
fuser -k 53/udp 2>/dev/null

# Install gcc
! command -v gcc &>/dev/null && apt update && apt install -y gcc

# Create proper C code with epoll for both sockets
cat > /tmp/edns.c <<'EOF'
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define EXT_EDNS 512
#define INT_EDNS 1800

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
} request_t;

// Simple EDNS patching
int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    
    // Find OPT record (type 41) in additional section
    int offset = 12;
    
    // Skip questions
    int qdcount = (buf[4] << 8) | buf[5];
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        offset += 5; // null byte + qtype + qclass
    }
    
    // Find OPT (EDNS) record
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0) { // root label
            if(offset + 4 < len) {
                int type = (buf[offset+1] << 8) | buf[offset+2];
                if(type == 41) { // OPT record
                    buf[offset+3] = new_size >> 8;
                    buf[offset+4] = new_size & 0xFF;
                    break;
                }
            }
        }
        offset++;
    }
    return len;
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    // Create UDP socket for clients
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    set_nonblock(sock);
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = INADDR_ANY
    };
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    // Create epoll
    int epoll_fd = epoll_create1(0);
    struct epoll_event ev = {EPOLLIN, .fd = sock};
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
    
    struct epoll_event events[100];
    request_t *requests[10000] = {0};
    
    printf("EDNS Proxy running (C/epoll)\n");
    
    while(1) {
        int n = epoll_wait(epoll_fd, events, 100, -1);
        
        for(int i = 0; i < n; i++) {
            if(events[i].data.fd == sock) {
                // New client request
                unsigned char buf[4096];
                request_t *req = malloc(sizeof(request_t));
                req->addr_len = sizeof(req->client_addr);
                
                int len = recvfrom(sock, buf, 4096, 0, 
                                 (struct sockaddr*)&req->client_addr, 
                                 &req->addr_len);
                
                if(len > 0) {
                    // Patch EDNS for upstream
                    patch_edns(buf, len, INT_EDNS);
                    
                    // Create upstream socket
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    set_nonblock(up_sock);
                    
                    // Store request context
                    req->client_fd = sock;
                    requests[up_sock] = req;
                    
                    // Add to epoll
                    struct epoll_event up_ev = {EPOLLIN, .fd = up_sock};
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev);
                    
                    // Send to SlowDNS
                    struct sockaddr_in up_addr = {
                        .sin_family = AF_INET,
                        .sin_port = htons(5300)
                    };
                    inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                    sendto(up_sock, buf, len, 0, 
                           (struct sockaddr*)&up_addr, sizeof(up_addr));
                } else {
                    free(req);
                }
            } else {
                // Upstream response
                int up_sock = events[i].data.fd;
                request_t *req = requests[up_sock];
                
                if(req) {
                    unsigned char buf[4096];
                    int len = recv(up_sock, buf, 4096, 0);
                    
                    if(len > 0) {
                        // Patch EDNS for client
                        patch_edns(buf, len, EXT_EDNS);
                        
                        // Send back to client
                        sendto(req->client_fd, buf, len, 0,
                               (struct sockaddr*)&req->client_addr,
                               req->addr_len);
                    }
                    
                    // Cleanup
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, up_sock, NULL);
                    close(up_sock);
                    free(req);
                    requests[up_sock] = NULL;
                }
            }
        }
    }
}
EOF

# Compile with optimization
gcc -O3 -Wall /tmp/edns.c -o /usr/local/bin/edns-proxy

# Create service
cat > /etc/systemd/system/edns-proxy.service <<EOF
[Unit]
Description=EDNS Proxy (C/epoll)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl daemon-reload
systemctl enable edns-proxy --now

echo "EDNS Proxy installed and running"
echo "Test with: dig @127.0.0.1 google.com"
