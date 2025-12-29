#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

#define LISTEN_PORT 53
#define UPSTREAM_PORT 5300
#define BUFFER_SIZE 4096
#define MAX_EVENTS 1024
#define MAX_SESSIONS 65535
#define EXT_EDNS 512
#define INT_EDNS 1800

volatile sig_atomic_t running = 1;

typedef struct {
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
} session_t;

static session_t *sessions[MAX_SESSIONS];

void on_signal(int s) { running = 0; }

int set_nonblock(int fd) {
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

/* Correct OPT record patch */
void patch_edns(unsigned char *buf, int len, int size) {
    if (len < 12) return;

    int qd = (buf[4]<<8)|buf[5];
    int an = (buf[6]<<8)|buf[7];
    int ns = (buf[8]<<8)|buf[9];
    int ar = (buf[10]<<8)|buf[11];

    int off = 12;
    for(int i=0;i<qd;i++){
        while(off<len && buf[off]) off+=buf[off]+1;
        off+=5;
    }
    for(int i=0;i<an+ns;i++){
        off+=10;
        off+= (buf[off-2]<<8)|buf[off-1];
    }

    for(int i=0;i<ar;i++){
        if(off+11>len) return;
        if(buf[off]==0 && ((buf[off+1]<<8)|buf[off+2])==41){
            buf[off+3]=(size>>8)&0xff;
            buf[off+4]=size&0xff;
            return;
        }
        off+=11+((buf[off+9]<<8)|buf[off+10]);
    }
}

int main() {
    signal(SIGINT,on_signal);
    signal(SIGTERM,on_signal);

    int listen_fd=socket(AF_INET,SOCK_DGRAM,0);
    int up_fd=socket(AF_INET,SOCK_DGRAM,0);

    set_nonblock(listen_fd);
    set_nonblock(up_fd);

    struct sockaddr_in addr={0},up={0};
    addr.sin_family=AF_INET;
    addr.sin_port=htons(LISTEN_PORT);
    addr.sin_addr.s_addr=INADDR_ANY;
    bind(listen_fd,(void*)&addr,sizeof(addr));

    up.sin_family=AF_INET;
    up.sin_port=htons(UPSTREAM_PORT);
    inet_pton(AF_INET,"127.0.0.1",&up.sin_addr);

    int ep=epoll_create1(0);
    struct epoll_event ev={.events=EPOLLIN,.data.fd=listen_fd};
    epoll_ctl(ep,EPOLL_CTL_ADD,listen_fd,&ev);
    ev.data.fd=up_fd;
    epoll_ctl(ep,EPOLL_CTL_ADD,up_fd,&ev);

    struct epoll_event events[MAX_EVENTS];
    unsigned char buf[BUFFER_SIZE];

    printf("[EDNS] Proxy listening on :53 → 127.0.0.1:%d\n",UPSTREAM_PORT);

    while(running){
        int n=epoll_wait(ep,events,MAX_EVENTS,1000);
        for(int i=0;i<n;i++){
            if(events[i].data.fd==listen_fd){
                struct sockaddr_in cli; socklen_t l=sizeof(cli);
                int len=recvfrom(listen_fd,buf,BUFFER_SIZE,0,(void*)&cli,&l);
                if(len>0){
                    patch_edns(buf,len,INT_EDNS);
                    sendto(up_fd,buf,len,0,(void*)&up,sizeof(up));

                    uint16_t id=(buf[0]<<8)|buf[1];
                    session_t *s=malloc(sizeof(session_t));
                    s->client_addr=cli; s->addr_len=l; s->timestamp=time(0);
                    sessions[id]=s;
                }
            } else {
                int len=recv(up_fd,buf,BUFFER_SIZE,0);
                if(len>0){
                    uint16_t id=(buf[0]<<8)|buf[1];
                    session_t *s=sessions[id];
                    if(s){
                        patch_edns(buf,len,EXT_EDNS);
                        sendto(listen_fd,buf,len,0,(void*)&s->client_addr,s->addr_len);
                        free(s);
                        sessions[id]=NULL;
                    }
                }
            }
        }
    }
    close(ep); close(listen_fd); close(up_fd);
    return 0;
}
