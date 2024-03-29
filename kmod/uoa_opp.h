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
#ifndef BYTEDANCE_UOA_OPP_H
#define BYTEDANCE_UOA_OPP_H

#include "uoa.h"


/**
 * Why use private IP protocol for Address ?
 *
 * we found not all l3-switch support IPv4 options,
 * or even if support, there's speed limitation like 300pps.
 *
 * the reason from provider is the switch HW (chips) do not
 * handle IP options, just have to drop the whole packet.
 * or pass the pkt with option to CPU for process, with a
 * limited speed which is too poor to accept.
 *
 * On the other hand, the switch can "support" unkown IP
 * protocol, we can forwarding this kind of packets.
 *
 * Why not use GRE ? there's no space for insert private data
 * like client IP/port.
 */

/**
 *  "Option Protocol": IPPROTO_OPT
 *
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +---------------+---------------+---------------+--------------+
 *  |  Ver. | Rsvd. |    Protocol   |            Length            |
 *  +---------------+---------------+---------------+--------------+
 *  :                           Options                            :
 *  +---------------+---------------+---------------+--------------+
 *
 *  Ve.     Version, now 0x1 (1) for ipv4 address family, OPPHDR_IPV4
 *                       0x2 (2) for ipv6 address family, OPPHDR_IPV6
 *  Rsvd.   Reserved bits, must be zero.
 *  Protocol    Next level protocol, e.g., IPPROTO_UDP.
 *  Length	Length of fixed header and options, not include payloads.
 *  Options	Compatible with IPv4 options, including IPOPT_UOA.
 *
 * the entire layout looks like this:
 * ip header | option protocol (nested ip option) | udp header
 * 
 */

#define IPPROTO_OPT	0xf8 /* 248 */

// #define OPPHDR_IPV6 0x02
// #define OPPHDR_IPV4 0x01

/* OPtion Protocol header */
struct opphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD) || (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN)
	unsigned int rsvd0:4;
	unsigned int version:4;
#elif defined (__BIG_ENDIAN_BITFIELD) || (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN)
	unsigned int version:4;
	unsigned int rsvd0:4;
#else
    #ifndef __KERNEL__
        # error	"Please fix <bits/endian.h>"
    #else
        # error	"Please fix <asm/byteorder.h>"
    #endif
#endif
	__u8	protocol;	/* IPPROTO_XXX */
	__be16	length;		/* length of fixed header and options */
	__u8	options[0];
} __attribute__((__packed__));

// struct kr_ipopt_uoa {
//     __u8                    op_code;
//     __u8                    op_len;
//     __be16                  op_port;
//     struct in_addr          op_addr;
// } __attribute__((__packed__));

struct kr_ipopt_uoa {
    __u8                    op_code;
    __u8                    op_len;
    __be16                  op_port;
    union inet_addr         op_addr;
} __attribute__((__packed__));

/* avoid IANA ip options */
// #define IPOPT_UOA        (31 | IPOPT_CONTROL)
#define IPOLEN_UOA_IPV4  (1 + 1 + 2 + 4)
#define IPOLEN_UOA_IPV6  (1 + 1 + 2 + 16)




#endif