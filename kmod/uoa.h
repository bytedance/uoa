#ifndef BYTEDANCE_UOA
#define BYTEDANCE_UOA


#ifdef __KERNEL__
#include <asm/byteorder.h>
#else
#include <endian.h>
#include <netinet/in.h>
#endif
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


union two_addr{
    struct{
        struct in_addr saddr;
        struct in_addr daddr;
    }ipv4;
    struct{
        struct in6_addr saddr;
        struct in6_addr daddr;
    }ipv6;
};

struct four_tuple{
    unsigned int type; // indicate this is ipv4 or ipv6 addresses;
    __be16 sport, dport;
    union two_addr addrs;
};



struct ip_option{
    union{
        struct{
            __u8 type;
            __u8 length;
        }ipv4;
        struct{
            __u8 next_hdr;
            __u8 len;
        }ipv6;
    }header;

    __u8 operation;
    __u8 padding;

    __be16 sport, dport;
    
    union two_addr addrs;
};

#define IP_OPTION_IPV4_LEN  16
#define IP_OPTION_IPV6_LEN  40

#define IP_OPTION_IPV4_TYPE  31
#define IP_OPTION_IPV6_NEXT_HDR 248


#endif