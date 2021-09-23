/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2018 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "common.h"
#include "uoa.h"
#include "uoa_opp.h"




#define IPOPT_UOA 31



/**
 * checksum codes from Linux Kernel.
 */
static inline __u16 csum_fold(__u32 csum)
{
    __u32 sum = (__u32)csum;
    sum += (sum >> 16) | (sum << 16);
    return ~(__u16)(sum >> 16);
}

static inline __u16 ip_fast_csum(const void *iph, unsigned int ihl)
{
    __uint128_t tmp;
    uint64_t sum;

    tmp = *(const __uint128_t *)iph;
    iph += 16;
    ihl -= 4;
    tmp += ((tmp >> 64) | (tmp << 64));
    sum = tmp >> 64;
    do {
        sum += *(const __u32 *)iph;
        iph += 4;
    } while (--ihl);

    sum += ((sum >> 32) | (sum << 32));
    return csum_fold((__u32)(sum >> 32));
}

/* Generate a checksum for an outgoing IP datagram. */
static void ip_send_check(struct iphdr *iph)
{
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}


struct in6_addr src_ip, dst_ip, client_ip;
short src_port, dst_port, client_port;


int parse_args(int argc, char** argv)
{
    int port_ = 0;

    if (argc != 7) 
    {   printf("usage: %s src_ip src_port dst_ip dst_port client_ip client_port\n", argv[0]);
        return -1;
    }

    if  (inet_pton(AF_INET6, argv[1], &src_ip) <= 0)
    {   printf("bad src_ip: %s\n", argv[1]);
        return -1;
    }

    if  (sscanf(argv[2], "%d", &port_) < 0)
    {   printf("bad src port: %s\n", argv[2]);
        return -1;
    }
    src_port = htons((short)port_);

    if  (inet_pton(AF_INET6, argv[3], &dst_ip) <= 0)
    {   printf("bad dst_ip: %s\n", argv[3]);
        return -1;
    }

    if  (sscanf(argv[4], "%d", &port_) < 0)
    {   printf("bad dst port: %s\n", argv[4]);
        return -1;
    }
    dst_port = htons((short)port_);


    if  (inet_pton(AF_INET6, argv[5], &client_ip) <= 0)
    {   printf("bad client_ip: %s\n", argv[5]);
        return -1;
    }
    
    if  (sscanf(argv[6], "%d", &port_) < 0)
    {   printf("bad client port: %s\n", argv[6]);
        return -1;
    }
    client_port = htons((short)port_);

    return 0;
}


int make_normal_pkt(uint8_t* pkt, uint8_t* payload, int payload_len)
{
    struct ipv6hdr* ip6h;
    struct udphdr *uh;

    //     /* build IP header */
    ip6h = (void *)pkt;
    ip6h->version    = 0x6;
    ip6h->payload_len    = htons(sizeof(*uh) + payload_len);
    ip6h->nexthdr = IPPROTO_UDP;
    ip6h->saddr = src_ip;
    ip6h->daddr = dst_ip;


    uh = (void*)ip6h + sizeof(*ip6h);
    uh->source    = src_port;
    uh->dest    = dst_port;
    uh->len        = htons(sizeof(*uh) + sizeof(payload));
    // uh->check    = 0; /* ok for UDP */
    uh->check = 0x56cb;

    // /* payload */
    memcpy(uh + 1, payload, payload_len);

    return sizeof(*ip6h) + ntohs(ip6h->payload_len);
}

int make_opp_pkt(uint8_t* pkt, uint8_t* payload, int payload_len)
{
    struct iphdr *iph;
    struct ipv6hdr* ip6h;
    struct opphdr *opph;
    struct kr_ipopt_uoa *uoa;
    struct udphdr *uh;

    //     /* build IP header */
    ip6h = (void *)pkt;
    ip6h->version    = 0x6;
    ip6h->payload_len    = htons(sizeof(*opph) + IPOLEN_UOA_IPV6 
            + sizeof(*uh) + payload_len);
    ip6h->nexthdr    = IPPROTO_OPT;
    ip6h->saddr = src_ip;
    ip6h->daddr = dst_ip;


    // /* build Option Protocol fixed header */
    opph = (void *)(ip6h + 1);
    opph->version    = 0x1;
    opph->protocol    = IPPROTO_UDP;
    opph->length    = htons(sizeof(*opph) + IPOLEN_UOA_IPV6);

    // /* uoa option */
    uoa = (void *)opph->options;
    uoa->op_code    = IPOPT_UOA;
    uoa->op_len    = IPOLEN_UOA_IPV6;
    uoa->op_port    = client_port;
    uoa->op_addr.in6 = client_ip;

    // /* udp header */
    uh = (void *)uoa + IPOLEN_UOA_IPV6;
    uh->source    = src_port;
    uh->dest    = dst_port;
    uh->len        = htons(sizeof(*uh) + payload_len);
    uh->check = 0x56cb;

    // /* payload */
    memcpy(uh + 1, payload, sizeof(payload));

    return sizeof(*ip6h) + ntohs(ip6h->payload_len);
}

int main(int argc, char *argv[])
{
    uint8_t pkt[4096] = {0};
    uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8};    
    int sockfd;
    int v = 1;
    struct sockaddr_in6 sin;
    int packet_len = -1;


    if  (parse_args(argc, argv) < 0)
    {   printf("parse args failed\n");
        return 0;
    }

    // --------------------------------------------------------------------

    // if  ((packet_len = make_normal_pkt(pkt, payload, 8)) < 0)
    // {   printf("make_nornal_packet failed\n");
    //     return 0;
    // }

    if  ((packet_len = make_opp_pkt(pkt, payload, 8)) < 0)
    {   printf("make_opp_packet failed\n");
        return 0;
    }


    // ---------------------------------------------------------------------

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family    = AF_INET6;
    sin.sin6_addr = dst_ip;
    
    sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if  (sockfd < 0) 
    {   perror("socket");
        exit(1);
    }

    if  (setsockopt(sockfd, IPPROTO_IPV6, IP_HDRINCL, &v, sizeof(v)) < 0) 
    {   perror("setsockopt");
        exit(1);
    }

    if  (sendto(sockfd, pkt, packet_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
    {   perror("sendto");
        exit(1);
    }

    close(sockfd);
    exit(0);
}
