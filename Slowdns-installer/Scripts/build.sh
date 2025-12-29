#!/bin/bash
# Build script for SlowDNS Rust installer

set -e

echo "🚀 Building SlowDNS Rust Installer..."

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# Create project structure
mkdir -p resources/banners
mkdir -p resources/service_templates

# Copy C source
echo "// EDNS Proxy source code" > resources/edns_proxy.c
cat >> resources/edns_proxy.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 100

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
} request_t;

int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        offset += 5;
    }
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0 && offset + 4 < len) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            if(type == 41) {
                buf[offset+3] = new_size >> 8;
                buf[offset+4] = new_size & 0xFF;
                return len;
            }
        }
        offset++;
    }
    return len;
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    printf("[EDNS Proxy] Starting high-performance DNS proxy...\n");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("[ERROR] socket");
        return 1;
    }
    
    if(set_nonblock(sock) < 0) {
        perror("[ERROR] fcntl");
        close(sock);
        return 1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[ERROR] bind");
        close(sock);
        return 1;
    }
    
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0) {
        perror("[ERROR] epoll_create1");
        close(sock);
        return 1;
    }
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("[ERROR] epoll_ctl");
        close(epoll_fd);
        close(sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port 53 (epoll optimized)\n");
    printf("[EDNS Proxy] Ready to handle DNS queries\n");
    
    struct epoll_event events[MAX_EVENTS];
    request_t *requests[10000] = {0};
    
    while(1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        for(int i = 0; i < n; i++) {
            if(events[i].data.fd == sock) {
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
                if(len > 0) {
                    patch_edns(buffer, len, INT_EDNS);
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if(up_sock >= 0) {
                        set_nonblock(up_sock);
                        request_t *req = malloc(sizeof(request_t));
                        if(req) {
                            req->client_fd = sock;
                            req->client_addr = client_addr;
                            req->addr_len = client_len;
                            req->timestamp = time(NULL);
                            requests[up_sock] = req;
                            struct epoll_event up_ev;
                            up_ev.events = EPOLLIN;
                            up_ev.data.fd = up_sock;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev);
                            struct sockaddr_in up_addr;
                            memset(&up_addr, 0, sizeof(up_addr));
                            up_addr.sin_family = AF_INET;
                            up_addr.sin_port = htons(SLOWDNS_PORT);
                            inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                            sendto(up_sock, buffer, len, 0,
                                   (struct sockaddr*)&up_addr, sizeof(up_addr));
                        } else {
                            close(up_sock);
                        }
                    }
                }
            } else {
                int up_sock = events[i].data.fd;
                request_t *req = requests[up_sock];
                if(req) {
                    unsigned char buffer[BUFFER_SIZE];
                    int len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                    if(len > 0) {
                        patch_edns(buffer, len, EXT_EDNS);
                        sendto(req->client_fd, buffer, len, 0,
                               (struct sockaddr*)&req->client_addr,
                               req->addr_len);
                    }
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, up_sock, NULL);
                    close(up_sock);
                    free(req);
                    requests[up_sock] = NULL;
                }
            }
        }
    }
    return 0;
}
EOF

# Build release version
echo "Building release version..."
cargo build --release

echo "✅ Build complete!"
echo "Binary location: ./target/release/slowdns-installer"
echo ""
echo "To install: sudo ./target/release/slowdns-installer"
