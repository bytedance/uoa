#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "uoa.h"


const int buf_size = 4096;
short port;


void uoa_display_v1(union uoa_sockopt_param* param)
{
    const int net_addr_size = 100;
    char net_addr[net_addr_size];
    char net_addr1[net_addr_size];

    if  (param->output.type == 0)
    {
        printf("uoa_sockopt_param: ipv4\n");
        printf("src: %s:%d -> dst: %s:%d\n", 
                inet_ntop(AF_INET, param->output.addrs.ipv4.saddr, net_addr, net_addr_size), ntohs(param->output.sport),
                inet_ntop(AF_INET, param->output.addrs.ipv4.daddr, net_addr1, net_addr_size), ntohs(param->output.dport)); 
    
    }
    else if  (param->output.type == 1)
    {
        printf("uoa_sockopt_param: ipv6\n");
        // if  the src and dst use same buf, the dst will display src
        printf("src: %s:%d -> dst: %s:%d\n", 
                inet_ntop(AF_INET6, param->output.addrs.ipv6.saddr, net_addr, net_addr_size), ntohs(param->output.sport),
                inet_ntop(AF_INET6, param->output.addrs.ipv6.daddr, net_addr1, net_addr_size), ntohs(param->output.dport)); 
    
        // printf("src: %s:%d\n", inet_ntop(AF_INET6, param->output.addrs.ipv6.saddr, net_addr, net_addr_size), ntohs(param->output.sport));
        // printf("dst: %s:%d\n", inet_ntop(AF_INET6, param->output.addrs.ipv6.daddr, net_addr, net_addr_size), ntohs(param->output.dport));
    }
    else
    {    printf("uoa_sockopt_param type error\n");
    }
}


// void uoa_display_v0(struct uoa_param_map* param)
// {
//     const int net_addr_len = 100;
//     char net_addr[net_addr_len];

//     if  (param->af == AF_INET)
//     {   printf("src: %s:%d\n", inet_ntop(AF_INET, &param->real_saddr, net_addr, net_addr_len), 
//                 ntohs(param->real_sport));
//     }
//     else if  (param->af == AF_INET6)
//     {
//         printf("src: %s:%d\n", inet_ntop(AF_INET6, &param->real_saddr, net_addr, net_addr_len), 
//                 ntohs(param->real_sport));
//     }
//     else
//         printf("%s: failed\n", __func__);
    
// }


void* udp_echo(void* arg)
{
    int fd = *(int*)arg;
    char buf[buf_size];
    int id = 0;

    struct sockaddr_in6 client_addr;
    socklen_t socklen = sizeof(struct sockaddr_in6);
    const int addr_buf_len = 100;
    char addr_buf[addr_buf_len];

    while (true)
    {
        int recv_len = recvfrom(fd, buf, buf_size, 0, (struct sockaddr*)&client_addr, &socklen);
        if  (recv_len <= 0)  break;
        printf("%d: server recv %d bytes from %s:%d\n", id, recv_len, 
                inet_ntop(AF_INET6, &client_addr.sin6_addr, addr_buf, addr_buf_len), ntohs(client_addr.sin6_port));
        
        {
            // v1
            union uoa_sockopt_param param;
            param.input.type = 1;
            param.input.sport = client_addr.sin6_port;
            param.input.dport = htons(port);
            memset(&param.input.addrs, 0, sizeof(union two_addr));
            memcpy(param.input.addrs.ipv6.saddr, &client_addr.sin6_addr, sizeof(client_addr.sin6_addr));
            int param_len = sizeof(union uoa_sockopt_param);
            if  (getsockopt(fd, IPPROTO_IP, UOA_SO_GET_LOOKUP1, &param, (socklen_t*)&param_len) == 0) {
                uoa_display_v1(&param);
                // printf("daddr: %s\n", inet_ntop(AF_INET6, param.output.addrs.ipv6.daddr, addr_buf, addr_buf_len));
            }
            else 
                printf("get param v1 failed\n");
        }
        // {
        //     // v0
        //     const int net_addr_len = 100;
        //     char net_addr[net_addr_len];
        //     struct uoa_param_map param;
        //     param.af = AF_INET6;
        //     param.sport = client_addr.sin6_port;
        //     param.dport = htons(port);
        //     param.saddr.in6 = client_addr.sin6_addr;
        //     param.daddr.in6 = in6addr_any;
        //     int param_len = sizeof(param);
        //     if  (getsockopt(fd, IPPROTO_IP, UOA_SO_GET_LOOKUP, &param, (socklen_t*)&param_len) == 0)
        //     {   uoa_display_v0(&param);
        //     }
        //     else
        //         printf("get param v0 failed\n");
        // }

        int send_len = sendto(fd, buf, recv_len, 0, (struct sockaddr*)&client_addr, socklen); 
        printf("%d: server echo %d bytes to %s:%d\n", id, send_len, 
                inet_ntop(AF_INET6, &client_addr.sin6_addr, addr_buf, addr_buf_len), ntohs(client_addr.sin6_port));
        printf("\n");
        id++;
    }

    close(fd);
    printf("socket %d closed\n", fd);
    return NULL;
}




int main(int argc, char** argv)
{
    if  (!(argc > 1))
    {   printf("usage: %s <port>\n", argv[0]);
        return 0;
    }

    struct sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(sockaddr_in6));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;

    int port_;
    if  (sscanf(argv[1], "%d", &port_) == -1)  perror("bad port");
    port = (short)port_;
    server_addr.sin6_port = htons(port);

    int fd = -1;
    if  ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)  perror("socket error");



    if  (bind(fd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in6)) == -1)  perror("bind error");

    udp_echo(&fd);


    return 0;
}