#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>


const int buf_size = 4096;
const short port = 8000;



void* udp_echo(void* arg)
{
    int fd = *(int*)arg;
    char buf[buf_size];

    struct sockaddr_in client_addr;
    socklen_t socklen = sizeof(struct sockaddr_in);

    while (true)
    {
        int recv_len = recvfrom(fd, buf, buf_size, 0, (struct sockaddr*)&client_addr, &socklen);
        if  (recv_len <= 0)  break;
        printf("server recv %d bytes from %s:%d\n", 
                recv_len, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        int send_len = sendto(fd, buf, recv_len, 0, (struct sockaddr*)&client_addr, socklen); 
        printf("server echo %d bytes to %s:%d\n",
                send_len, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        printf("\n");
    }

    close(fd);
    printf("socket %d closed\n", fd);
    return NULL;
}




int main()
{
    int fd = -1;
    if  ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)  perror("socket error");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if  (bind(fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr)) == -1)  perror("bind error");

    udp_echo(&fd);


    return 0;
}