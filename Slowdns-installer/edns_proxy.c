#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LISTEN_PORT 53
#define UPSTREAM_PORT 5300
#define EXT_EDNS 512
#define INT_EDNS 1800
#define BUF 4096
#define MAX_EVENTS 1024

volatile int running = 1;

typedef struct {
    struct sockaddr_in client;
    socklen_t len;
    time_t ts;
} session_t;

static int make_nonblock(int fd) {
    int f = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

static void sig(int x) { running = 0; }

static void patch_edns(unsigned char *b, int n, int size) {
    if (n < 12) return;
    int ar = (b[10]<<8)|b[11];
    int off = n - 11;
    for (int i=0;i<ar;i++) {
        if (off+4<n && b[off]==0 && b[off+1]==0 && b[off+2]==41) {
            b[off+3]=size>>8;
            b[off+4]=size&255;
            return;
        }
    }
}

int main() {
    signal(SIGINT,sig); signal(SIGTERM,sig);

    int dns = socket(AF_INET,SOCK_DGRAM,0);
    make_nonblock(dns);

    struct sockaddr_in a={0};
    a.sin_family=AF_INET;
    a.sin_port=htons(LISTEN_PORT);
    a.sin_addr.s_addr=INADDR_ANY;
    bind(dns,(void*)&a,sizeof(a));

    int ep=epoll_create1(0);
    struct epoll_event ev={.events=EPOLLIN,.data.fd=dns};
    epoll_ctl(ep,EPOLL_CTL_ADD,dns,&ev);

    struct epoll_event evs[MAX_EVENTS];

    while(running) {
        int n=epoll_wait(ep,evs,MAX_EVENTS,1000);
        for(int i=0;i<n;i++){
            if(evs[i].data.fd==dns){
                unsigned char buf[BUF];
                struct sockaddr_in cli; socklen_t l=sizeof(cli);
                int r=recvfrom(dns,buf,BUF,0,(void*)&cli,&l);
                if(r>0){
                    patch_edns(buf,r,INT_EDNS);
                    int up=socket(AF_INET,SOCK_DGRAM,0);
                    make_nonblock(up);

                    session_t *s=malloc(sizeof(session_t));
                    *s=(session_t){cli,l,time(NULL)};

                    struct epoll_event ue={.events=EPOLLIN,.data.ptr=s};
                    epoll_ctl(ep,EPOLL_CTL_ADD,up,&ue);

                    struct sockaddr_in u={0};
                    u.sin_family=AF_INET;
                    u.sin_port=htons(UPSTREAM_PORT);
                    inet_pton(AF_INET,"127.0.0.1",&u.sin_addr);
                    sendto(up,buf,r,0,(void*)&u,sizeof(u));
                }
            } else {
                session_t *s=evs[i].data.ptr;
                unsigned char buf[BUF];
                int fd=((struct epoll_event*)&evs[i])->data.fd;
                int r=recv(fd,buf,BUF,0);
                if(r>0){
                    patch_edns(buf,r,EXT_EDNS);
                    sendto(dns,buf,r,0,(void*)&s->client,s->len);
                }
                close(fd);
                free(s);
            }
        }
    }
}
