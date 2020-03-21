/*
 * pkt.h
 * ptunnel is licensed under the BSD license:
 *
 * Copyright (c) 2004-2011, Daniel Stoedle <daniels@cs.uit.no>,
 * Yellow Lemon Software. All rights reserved.
 *
 * Copyright (c) 2017-2019, Toni Uhlig <matzeton@googlemail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - Neither the name of the Yellow Lemon Software nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contacting the author:
 * You can get in touch with me, Daniel Stødle (that's the Norwegian letter oe,
 * in case your text editor didn't realize), here: <daniels@cs.uit.no>
 *
 * The official ptunnel website is here:
 * <http://www.cs.uit.no/~daniels/PingTunnel/>
 *
 * Note that the source code is best viewed with tabs set to 4 spaces.
 */

#ifndef PKT_H
#define PKT_H 1

#include <stdint.h>

#ifndef __MINGW32__
#define __PTATTR__ __attribute__((packed))
#else
#define __PTATTR__ __attribute__((packed, gcc_struct))
#endif

#ifdef WIN32
#include <winsock2.h>
typedef int socklen_t;
typedef uint32_t in_addr_t;
#define ETH_ALEN 6 /* Octets in one ethernet addr   */
struct ether_header {
    uint8_t ether_dhost[ETH_ALEN]; /* destination eth addr */
    uint8_t ether_shost[ETH_ALEN]; /* source ether addr    */
    uint16_t ether_type;           /* packet type ID field */
} __PTATTR__;
#endif /* WIN32 */

/** Resend packets after this interval (in seconds) */
#define kResend_interval 1.5

/** ping_tunnel_pkt_t: This data structure represents the header of a ptunnel
 * packet, consisting of a magic number, the tunnel's destination IP and port,
 * as well as some other fields. Note that the dest IP and port is only valid
 * in packets from the client to the proxy.
 */
typedef struct {
    /** magic number, used to identify ptunnel packets. */
    uint32_t magic;
    /** destination IP and port (used by proxy to figure */
    uint32_t dst_ip;
    /** out where to tunnel to) */
    uint32_t dst_port;
    /** current connection state; see constants above. */
    uint32_t state;
    /** sequence number of last packet received from other end */
    uint32_t ack;
    /** length of data buffer */
    uint32_t data_len;
    /** sequence number of this packet */
    uint16_t seq_no;
    /** id number, used to separate different tunnels from each other */
    uint16_t id_no;
    /** optional data buffer */
    char data[0];
} __PTATTR__ ping_tunnel_pkt_t;

/** ip_packet_t: This is basically my own definition of the IP packet, which
 * of course complies with the official definition ;) See any good book on IP
 * (or even the RFC) for info on the contents of this packet.
 */
typedef struct {
    uint8_t vers_ihl;
    uint8_t tos;
    uint16_t pkt_len;
    uint16_t id;
    uint16_t flags_frag_offset;
    uint8_t ttl;
    uint8_t proto; // 1 for ICMP
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    char data[0];
} __PTATTR__ ip_packet_t;

/** icmp_echo_packet_t: This is the definition of a standard ICMP header. The
 * ptunnel packets are constructed as follows:
 * [    ip header (20 bytes)   ]
 * [   icmp header (8 bytes)   ]
 * [ ptunnel header (28 bytes) ]
 *
 * We actually only create the ICMP and ptunnel headers, the IP header is
 * taken care of by the OS.
 */
typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t seq;
    char data[0];
} __PTATTR__ icmp_echo_packet_t;

typedef struct forward_desc_t forward_desc_t;
typedef struct icmp_desc_t icmp_desc_t;
typedef struct proxy_desc_t proxy_desc_t;

void handle_packet(char * buf, unsigned bytes, int is_pcap, struct sockaddr_in * addr, int icmp_sock);

void handle_data(icmp_echo_packet_t * pkt, int total_len, proxy_desc_t * cur);

void handle_ack(uint32_t seq_no, proxy_desc_t * cur);

#endif
