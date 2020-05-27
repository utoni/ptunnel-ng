/*
 * pdesc.h
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

#ifndef PDESC_H
#define PDESC_H 1

#include <stdint.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "pkt.h"
#include "challenge.h"
#include "pconfig.h"

/** forward_desc_t: Describes a piece of that needs to be forwarded. This
 * structure is used for receiving data from the network, and for subsequent
 * forwarding over TCP:
 *
 * 1. Client sends data to proxy over ICMP
 * 2. Proxy receives the data, and puts it into a forward_desc_t
 * 3. The proxy starts send()-ing the data over the TCP socket to the destination,
 *    decreasing forward_desc_t->remaining with the number of bytes transferred.
 * 4. Once remaining reaches 0, the forward_desc_t is removed from the receive
 *    ring.
 *
 * The same procedure is followed in proxy-to-client communication. Just replace
 * proxy with client and vice versa in the list above.
 */
typedef struct forward_desc_t {
    /** ping_tunnel_pkt_t seq_no */
    uint16_t seq_no;
    /** length of data */
    uint16_t length;
    /** amount of data not yet transferred */
    size_t remaining;
    char data[0];
} forward_desc_t;

/** icmp_desc_t: This structure is used to track the ICMP packets sent by either
 * the client or proxy. The last_resend variable is used to prevent resending
 * the packet too often. Once the packet is acknowledged by the remote end,
 * it will be removed from the send-ring, freeing up space for more outgoing
 * ICMP packets.
 */
typedef struct icmp_desc_t {
    /** total length of ICMP packet, including ICMP header and ptunnel data. */
    uint16_t pkt_len;
    double last_resend;
    uint16_t seq_no;
    uint16_t icmp_id;
    icmp_echo_packet_t * pkt;
} icmp_desc_t;

/** xfer_stats_t: Various transfer statistics, such as bytes sent and received,
 * number of ping packets sent/received, etc.
 */
typedef struct xfer_stats_t {
    double bytes_in;
    double bytes_out;
    uint32_t icmp_in;
    uint32_t icmp_out;
    uint32_t icmp_resent;
    uint32_t icmp_ack_out;
} xfer_stats_t;

/** proxy_desc_t: This massive structure describes a tunnel instance.
 */
typedef struct proxy_desc_t {
    /** ICMP or UDP socket */
    int sock;
    /** number of bytes in receive buffer */
    int bytes;
    /** set to true once this instance should be removed */
    int should_remove;
    /** data buffer, used to receive ping and pong packets */
    char * buf;
    uint16_t id_no;
    uint16_t my_seq;
    uint16_t ping_seq;
    uint16_t next_remote_seq;
    uint16_t pkt_type;
    uint16_t remote_ack_val;
    uint16_t icmp_id;
    /** first available slot in recv ring */
    int recv_idx;
    /** current slot in recv ring being transferred */
    int recv_xfer_idx;
    /** first available slot in send ring */
    int send_idx;
    /** first packet in send ring not yet acked */
    int send_first_ack;
    /** number of items in recv ring awaiting send */
    int recv_wait_send;
    /** number of items in send ring awaiting ack */
    int send_wait_ack;
    int next_resend_start;
    int authenticated;
    /** Contains the challenge, if used. */
    challenge_t * challenge;
    /** Protocol state */
    uint32_t state;
    /** Either kProxy_flag or kUser_flag */
    enum pkt_flag type_flag;
    /** IP and port to which data should be forwarded. */
    uint32_t dst_ip;
    uint32_t dst_port;
    /** Same as above */
    struct sockaddr_in dest_addr;
    /** Time when last ack packet was sent. */
    double last_ack;
    /** Time when a packet was last received. */
    double last_activity;
    double last_data_activity;
    uint16_t window_size;
    double ack_interval;
    double resend_interval;
    icmp_desc_t * send_ring;
    forward_desc_t ** recv_ring;
    xfer_stats_t xfer;
    struct proxy_desc_t * next;
} proxy_desc_t;

proxy_desc_t * create_and_insert_proxy_desc(uint16_t id_no,
                                            uint16_t icmp_id,
                                            int sock,
                                            struct sockaddr_in * addr,
                                            uint32_t dst_ip,
                                            uint32_t dst_port,
                                            uint32_t init_state,
                                            enum pkt_flag type);

void remove_proxy_desc(proxy_desc_t * cur, proxy_desc_t * prev);

void remove_proxy_desc_rings(proxy_desc_t * cur);

forward_desc_t * create_fwd_desc(uint16_t seq_no, uint32_t data_len, char * data);

int queue_packet(
    int sock_fd, proxy_desc_t * cur, char * buf, size_t bufsiz, uint32_t dest_ip, uint32_t dest_port, uint32_t state);

uint32_t send_packets(forward_desc_t * ring[], int * xfer_idx, int * await_send, int * sock, uint16_t window_size);

#endif
