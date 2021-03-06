#ifndef BYTEDANCE_UOA
#define BYTEDANCE_UOA


#include <linux/types.h>


union two_addr{
    struct{
        unsigned char saddr[4];
        unsigned char daddr[4];
    }ipv4;
    struct{
        unsigned char saddr[16];
        unsigned char daddr[16];
    }ipv6;
};

enum UOA_IP_TYPE {
    UOA_IP_TYPE_V4 = 0,
    UOA_IP_TYPE_V6 = 1,
};

struct four_tuple{
    unsigned int type; // indicate this is ipv4 or ipv6 addresses; futurely use bit_field;
    __be16 sport, dport;
    union two_addr addrs;
};



/* uoa socket options */
enum {
    UOA_SO_BASE          = 2048,
    /* set */
    UOA_SO_SET_MAX       = UOA_SO_BASE,
    /* get */
    UOA_SO_GET_LOOKUP    = UOA_SO_BASE,
    UOA_SO_GET_LOOKUP1   = UOA_SO_BASE + 1,
    UOA_SO_GET_LOOKUP2   = UOA_SO_BASE + 2,
    UOA_SO_GET_MAX       = UOA_SO_GET_LOOKUP2,
};

union inet_addr {
    struct in_addr      in;
    struct in6_addr     in6;
};

// // param v0
// struct uoa_param_map {
//     /* input */
//     __be16           af;
//     union inet_addr  saddr;
//     union inet_addr  daddr;
//     __be16           sport;
//     __be16           dport;
//     /* output */
//     // __be16           real_af;
//     union inet_addr  real_saddr;
//     __be16           real_sport;
// } __attribute__((__packed__));


struct uoa_param_map {
	/* input */
	__be32	saddr;
	__be32	daddr;
	__be16	sport;
	__be16	dport;
	/* output */
	__be32	real_saddr;
	__be16	real_sport;
} __attribute__((__packed__));


// param v1
union uoa_sockopt_param{
    struct four_tuple input;
    struct four_tuple output;
};



struct four_tuple_with_vni{
    unsigned int type; // indicate this is ipv4 or ipv6 addresses;

    // little endian in userspace (as getsockopt param), big endian in kernel
    uint32_t svni;
    uint16_t sport, dport;

    union two_addr addrs;
};


// param v2
union uoa_sockopt_param_v2{
    struct four_tuple_with_vni input;
    struct four_tuple_with_vni output;
};


#endif