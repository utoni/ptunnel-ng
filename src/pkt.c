/*
 * pkt.c
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

#ifndef WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#endif
#include <sys/time.h>

#include "ptunnel.h"
#include "pkt.h"
#include "pdesc.h"
#include "options.h"
#include "utils.h"

static proxy_desc_t * handle_incoming_tunnel_request(unsigned bytes,
                                                     struct sockaddr_in * addr,
                                                     int icmp_sock,
                                                     icmp_echo_packet_t * const pkt,
                                                     ping_tunnel_pkt_t * const pt_pkt)
{
    struct timeval tt;
    struct in_addr in_addr;
    uint32_t init_state;
    proxy_desc_t * cur;

    pt_log(kLog_info, "Incoming tunnel request from %s.\n", inet_ntoa(*(struct in_addr *)&addr->sin_addr));

    gettimeofday(&tt, 0);
    if (tt.tv_sec < seq_expiry_tbl[pt_pkt->id_no]) {
        pt_log(kLog_verbose, "Dropping request: ID was recently in use.\n");
        return NULL;
    }

    in_addr.s_addr = pt_pkt->dst_ip;
    pt_log(kLog_info,
           "Starting new session to %s:%d with ID %d\n",
           inet_ntoa(in_addr),
           ntohl(pt_pkt->dst_port),
           pt_pkt->id_no);

    if ((opts.restrict_dst_ip && opts.given_dst_ip && opts.given_dst_ip != pt_pkt->dst_ip) ||
        (opts.restrict_dst_port && (uint32_t)-1 != opts.given_dst_port &&
         opts.given_dst_port != ntohl(pt_pkt->dst_port))) {
        pt_log(kLog_info, "Destination administratively prohibited!\n");
        return NULL;
    }

    if (opts.password) {
        init_state = kProto_authenticate;
    } else {
        init_state = kProto_data;
    }

    cur = (proxy_desc_t *)create_and_insert_proxy_desc(
        pt_pkt->id_no, pkt->identifier, 0, addr, pt_pkt->dst_ip, ntohl(pt_pkt->dst_port), init_state, kProxy_flag);
    if (!cur) {
        /* if failed, abort. Logging is done in create_insert_proxy_desc */
        pt_log(kLog_error, "Failed to create proxy descriptor!\n");
        return NULL;
    }
    if (pt_pkt->data_len > 0) {
        handle_data(pkt, bytes, cur);
    }
    if (init_state == kProto_authenticate) {
        pt_log(kLog_debug, "Sending authentication challenge..\n");
        /* Send challenge */
        cur->challenge = generate_challenge();
        memcpy(cur->buf, cur->challenge, sizeof(challenge_t));
        queue_packet(icmp_sock, cur, cur->buf, sizeof(challenge_t), 0, 0, kProto_authenticate | cur->type_flag);
    }

    return cur;
}

static void handle_auth_request(unsigned bytes,
                                int icmp_sock,
                                icmp_echo_packet_t * const pkt,
                                proxy_desc_t * const cur,
                                challenge_t * const challenge)
{
    if (!opts.password) {
        pt_log(kLog_error,
               "This proxy requires a password! "
               "Please supply one usin  g the -x switch.\n");
        send_termination_msg(cur, icmp_sock);
        cur->should_remove = 1;
        return;
    }
#ifdef ENABLE_SHA512
    if (opts.force_sha512) {
        pt_log(kLog_debug, "Got authentication challenge - sending SHA512 response\n");
        generate_response_sha512(&challenge->plain, &challenge->digest);
    } else
#endif
    {
        pt_log(kLog_debug, "Got authentication challenge - sending MD5 response\n");
        generate_response_md5(&challenge->plain, &challenge->digest);
    }

    memcpy(cur->buf, challenge, sizeof(challenge_t));
    queue_packet(icmp_sock, cur, cur->buf, sizeof(challenge_t), 0, 0, kProto_authenticate | cur->type_flag);
    /* We have authenticated locally.
     * It's up to the proxy now if it accepts our   response or not..
     */
    cur->authenticated = 1;
    handle_data(pkt, bytes, cur);
}

static void handle_auth_response(unsigned bytes,
                                 int icmp_sock,
                                 icmp_echo_packet_t * const pkt,
                                 proxy_desc_t * const cur,
                                 challenge_t * const challenge)
{
    pt_log(kLog_debug,
           "Received remote %s challenge response.\n",
           (challenge->digest.hash_type == HT_SHA512 ? "SHA512" : "MD5"));
    if ((!opts.force_sha512 && challenge->digest.hash_type == HT_MD5 &&
         validate_challenge_md5(cur->challenge, &challenge->digest)) ||
#ifdef ENABLE_SHA512
        (challenge->digest.hash_type == HT_SHA512 && validate_challenge_sha512(cur->challenge, &challenge->digest)) ||
#endif
        cur->authenticated) {
        pt_log(kLog_verbose, "Remote end authenticated successfully.\n");
        /* Authentication has succeeded, so now we can proceed
         * to handle incoming   TCP data.
         */
        cur->authenticated = 1;
        cur->state = kProto_data;
        /* Insert the packet into the receive ring, to avoid
         * confusing the reliab  ility mechanism.
         */
        handle_data(pkt, bytes, cur);
    } else {
        pt_log(kLog_info, "Remote end failed authentication.\n");
        send_termination_msg(cur, icmp_sock);
        cur->should_remove = 1;
    }
}

static void header_byteorder_ntoh(icmp_echo_packet_t * const icmp_pkt, ping_tunnel_pkt_t * const pt_pkt)
{
    pt_pkt->state = ntohl(pt_pkt->state);
    icmp_pkt->identifier = ntohs(icmp_pkt->identifier);
    icmp_pkt->seq = ntohs(icmp_pkt->seq);
    pt_pkt->id_no = ntohs(pt_pkt->id_no);
    pt_pkt->seq_no = ntohs(pt_pkt->seq_no);
}

static proxy_desc_t * get_proxy_descriptor(uint16_t id_no)
{
    proxy_desc_t * cur;

    /* Find the relevant connection, if it exists */
    pthread_mutex_lock(&chain_lock);
    for (cur = chain; cur; cur = cur->next) {
        if (cur->id_no == id_no) {
            break;
        }
    }
    pthread_mutex_unlock(&chain_lock);

    return cur;
}

/* handle_proxy_packet:
 * Processes incoming ICMP packets for the proxy. The packet can come either from the
 * packet capture lib, or from the actual socket or both.
 * Input:  A buffer pointing at the start of an IP header, the buffer length and the proxy
 * descriptor chain.
 */
void handle_packet(char * buf, unsigned bytes, int is_pcap, struct sockaddr_in * addr, int icmp_sock)
{
    ip_packet_t * ip_pkt = NULL;
    icmp_echo_packet_t * pkt;
    ping_tunnel_pkt_t * pt_pkt;
    proxy_desc_t * cur;
    int pkt_flag;
    enum pkt_flag type_flag, proxy_flag;
    challenge_t * challenge;

    proxy_flag = kProxy_flag;

    if (bytes < sizeof(icmp_echo_packet_t) + sizeof(ping_tunnel_pkt_t)) {
        pt_log(kLog_verbose,
               "Skipping this packet - too short. "
               "Expect: %lu+%lu = %lu ; Got: %u\n",
               sizeof(icmp_echo_packet_t),
               sizeof(ping_tunnel_pkt_t),
               sizeof(icmp_echo_packet_t) + sizeof(ping_tunnel_pkt_t),
               bytes);
        return;
    }

    if (opts.udp || opts.unprivileged) {
        pkt = (icmp_echo_packet_t *)buf;
        pt_pkt = (ping_tunnel_pkt_t *)pkt->data;
    } else {
        ip_pkt = (ip_packet_t *)buf;
        pkt = (icmp_echo_packet_t *)ip_pkt->data;
        pt_pkt = (ping_tunnel_pkt_t *)pkt->data;
    }

    if (ntohl(pt_pkt->magic) != opts.magic) {
        pt_log(kLog_verbose, "Ignored incoming packet. Magic value 0x%X mismatch.\n", ntohl(pt_pkt->magic));
        return;
    }

    header_byteorder_ntoh(pkt, pt_pkt);
    cur = get_proxy_descriptor(pt_pkt->id_no);

    /* Handle the packet if it comes from "the other end." This is a bit tricky
     * to get right, since we receive both our own and the other end's packets.
     * Basically, a proxy will accept any packet from a user, regardless if it
     * has a valid connection or not. A user will only accept the packet if there
     * exists a connection to handle it.
     */
    if (cur) {
        type_flag = cur->type_flag;
        if (type_flag == kProxy_flag) {
            cur->icmp_id = pkt->identifier;
            cur->ping_seq = pkt->seq;
        }
        if (!is_pcap)
            cur->xfer.icmp_in++;
    } else {
        type_flag = kProxy_flag;
    }

    pkt_flag = (int)pt_pkt->state & kFlag_mask;
    pt_pkt->state &= ~kFlag_mask;
    if (pt_pkt->state > (kNum_proto_types - 1)) {
        pt_log(kLog_error, "Dropping packet with invalid state.\n");
        return;
    }

    pt_log(kLog_sendrecv,
           "Recv: %4d [%4d] bytes "
           "[id = 0x%04X] [seq = %d] "
           "[seq_no = %d] [type = %s] "
           "[ack = %d] [icmp = %d] "
           "[user = %s] [pcap = %d]\n",
           bytes,
           ntohl(pt_pkt->data_len),
           pkt->identifier,
           ntohs(pkt->seq),
           pt_pkt->seq_no,
           state_name[pt_pkt->state & (~kFlag_mask)],
           ntohl(pt_pkt->ack),
           pkt->type,
           (pkt_flag == kUser_flag ? "yes" : "no"),
           is_pcap);
    log_sendrecv_hexstr("RECV ICMP", pkt, sizeof(*pkt));
    log_sendrecv_hexstr("RECV PTNG", pt_pkt, sizeof(*pt_pkt));
    if (bytes - (pt_pkt->data - buf) > 0) {
        log_sendrecv_hexstr("RECV PAYL", pt_pkt->data, bytes - (pt_pkt->data - buf));
    }

    /* This test essentially verifies that the packet comes from someone who isn't us. */
    if ((pkt_flag == kUser_flag && type_flag == proxy_flag) || (pkt_flag == proxy_flag && type_flag == kUser_flag)) {
        pt_pkt->data_len = ntohl(pt_pkt->data_len);
        pt_pkt->ack = ntohl(pt_pkt->ack);
        if (pt_pkt->state == kProxy_start) {
            if (!cur && type_flag == proxy_flag) {
                cur = handle_incoming_tunnel_request(bytes, addr, icmp_sock, pkt, pt_pkt);
                if (!cur) {
                    return;
                }
            } else if (type_flag == kUser_flag) {
                pt_log(kLog_error, "Dropping proxy session request - we are not a proxy!\n");
                return;
            } else {
                pt_log(kLog_error,
                       "Dropping duplicate proxy session request "
                       "with ID %d and seq %d.\n",
                       pt_pkt->id_no,
                       pt_pkt->seq_no);
            }
        } else if (cur && pt_pkt->state == kProto_authenticate) {
            /* Sanity check packet length, and make sure it matches what we expect */
            if (pt_pkt->data_len != sizeof(challenge_t)) {
                pt_log(kLog_error,
                       "Received challenge packet, but data length "
                       "is not as expected.\n");
                pt_log(kLog_debug, "Data length: %u  Expected: %lu\n", pt_pkt->data_len, sizeof(challenge_t));
                cur->should_remove = 1;
                return;
            }
            /* Prevent packet data from being forwarded over TCP! */
            pt_pkt->data_len = 0;
            challenge = (challenge_t *)pt_pkt->data;
            /* If client: Compute response to challenge */
            if (type_flag == kUser_flag) {
                /* Required for integration tests w/ passwd set. */
                pt_log(kLog_debug, "AUTH-REQUEST: Received ack-series starting at seq %d\n", pt_pkt->seq_no);
                handle_auth_request(bytes, icmp_sock, pkt, cur, challenge);
                return;
            }
            /* If proxy: Handle client's response to challenge */
            else if (type_flag == proxy_flag) {
                cur->next_remote_seq++;
                handle_auth_response(bytes, icmp_sock, pkt, cur, challenge);
                return;
            }
        }
        /* Handle close-messages for connections we know about */
        if (cur && pt_pkt->state == kProto_close) {
            pt_log(kLog_info, "Received session close from remote peer.\n");
            cur->should_remove = 1;
            return;
        }
        /* The proxy will ignore any other packets from the client
         * until it has been authenticated. The packet resend mechanism
         * insures that this isn't problematic.
         */
        if (type_flag == proxy_flag && opts.password && cur && !cur->authenticated) {
            pt_log(kLog_debug,
                   "Ignoring packet with seq-no %d "
                   "- not authenticated yet.\n",
                   pt_pkt->seq_no);
            return;
        }

        if (cur && cur->sock) {
            double now = time_as_double();
            if (pt_pkt->state != kProto_ack) {
                cur->last_data_activity = now;
            }
            if (pt_pkt->state == kProto_data || pt_pkt->state == kProxy_start || pt_pkt->state == kProto_ack) {
                if (pt_pkt->state == kProxy_start) {
                    pt_pkt->data_len = 0;
                }
                handle_data(pkt, bytes, cur);
            }
            handle_ack(pt_pkt->ack, cur);
            cur->last_activity = now;
        }
    }
}

static void queue_payload_data(ping_tunnel_pkt_t * const pt_pkt, proxy_desc_t * const cur)
{
    /* Check if we should add payload data to the queue. */
    if (!cur->recv_ring[cur->recv_idx] && pt_pkt->state == kProto_data) {
        pt_log(kLog_debug, "Queing data packet: %d\n", pt_pkt->seq_no);
        cur->recv_ring[cur->recv_idx] = create_fwd_desc(pt_pkt->seq_no, pt_pkt->data_len, pt_pkt->data);
        cur->recv_wait_send++;
        cur->recv_idx++;
    } else {
        pt_log(kLog_debug, "Dup packet for %d ?\n", pt_pkt->seq_no);
    }

    cur->next_remote_seq++;
    if (cur->recv_idx >= cur->window_size) {
        cur->recv_idx = 0;
    }

    /* Check if we have already received some of the next packets. */
    while (cur->recv_ring[cur->recv_idx]) {
        if (cur->recv_ring[cur->recv_idx]->seq_no == cur->next_remote_seq) {
            cur->next_remote_seq++;
            cur->recv_idx++;
            if (cur->recv_idx >= cur->window_size) {
                cur->recv_idx = 0;
            }
        } else {
            break;
        }
    }
}

static void queue_payload_data_out_of_order(ping_tunnel_pkt_t * const pt_pkt, proxy_desc_t * const cur)
{
    int r, s, d, pos;
    pos = -1; /* If pos ends up staying -1, packet is discarded. */
    r = cur->next_remote_seq;
    s = pt_pkt->seq_no;
    d = s - r;
    if (d < 0) { /* This packet _may_ be old, or seq_no may have wrapped around */
        d = (s + 0xFFFF) - r;
        if (cur->window_size && d < cur->window_size) {
            /* Counter has wrapped, so we should add this packet to the recv ring */
            pos = (cur->recv_idx + d) % cur->window_size;
        }
    } else if (cur->window_size && d < cur->window_size) {
        pos = (cur->recv_idx + d) % cur->window_size;
    }

    if (pos != -1) {
        if (!cur->recv_ring[pos]) {
            pt_log(kLog_verbose,
                   "Out of order. Expected: %d  Got: %d  Inserted: %d "
                   "(cur = %d)\n",
                   cur->next_remote_seq,
                   pt_pkt->seq_no,
                   pos,
                   cur->recv_idx);
            cur->recv_ring[pos] = create_fwd_desc(pt_pkt->seq_no, pt_pkt->data_len, pt_pkt->data);
            cur->recv_wait_send++;
        }
    } else {
        pt_log(kLog_info, "Packet discarded - outside receive window.\n");
    }
}

/* handle_data:
 * Utility function for handling kProto_data packets, and place the data it contains
 * onto the passed-in receive ring.
 */
void handle_data(icmp_echo_packet_t * pkt, int total_len, proxy_desc_t * cur)
{
    ping_tunnel_pkt_t * pt_pkt = (ping_tunnel_pkt_t *)pkt->data;
    int expected_len = sizeof(ip_packet_t) + sizeof(icmp_echo_packet_t) + sizeof(ping_tunnel_pkt_t); /* 20+8+28 */
    /* Place packet in the receive ring, in its proper place.
     * This works as follows:
     * -1. Packet == ack packet? Perform ack, and continue.
     * 0. seq_no < next_remote_seq, and absolute difference is bigger than w size => discard
     * 1. If seq_no == next_remote_seq, we have no problems; just put it in the ring.
     * 2. If seq_no > next_remote_seq + remaining window size, discard packet.
     *    Send resend request for missing packets.
     * 3. Else, put packet in the proper place in the ring
     *    (don't overwrite if one is already there), but don't increment next_remote_seq_no
     * 4. If packed was not discarded, process ack info in packet.
     */
    expected_len += pt_pkt->data_len;
    expected_len += expected_len % 2;
    if (opts.udp || opts.unprivileged) {
        expected_len -= sizeof(ip_packet_t);
    }
    if (total_len < expected_len) {
        pt_log(kLog_error, "Packet not completely received: %d Should be: %d.\n", total_len, expected_len);
        pt_log(kLog_debug, "Data length: %d Total length: %d\n", pt_pkt->data_len, total_len);
        /* just ignore that packet */
        return;
    }

    if (pt_pkt->seq_no == cur->next_remote_seq) {
        queue_payload_data(pt_pkt, cur);
    } else {
        queue_payload_data_out_of_order(pt_pkt, cur);
    }
}

void handle_ack(uint32_t seq_no, proxy_desc_t * cur)
{
    if (cur->send_wait_ack > 0) {
        int i, can_ack = 0, count = 0;
        i = cur->send_idx - 1;
        if (i < 0) {
            i = cur->window_size - 1;
        }

        pt_log(kLog_debug, "Received ack-series starting at seq %d\n", seq_no);
        while (count < cur->window_size) {
            if (!cur->send_ring[i].pkt) {
                break;
            }
            if (cur->send_ring[i].seq_no == seq_no) {
                can_ack = 1;
            } else if (!can_ack) {
                cur->send_first_ack = i;
            }
            if (can_ack) {
                free(cur->send_ring[i].pkt);
                cur->send_ring[i].pkt = 0;
                cur->send_ring[i].pkt_len = 0;
                cur->send_wait_ack--;
            }
            i--;
            if (i < 0) {
                i = cur->window_size - 1;
            }
            count++;
        }
    } else {
        pt_log(kLog_verbose,
               "Dropping superfluous acknowledgement for seq %d "
               "(no outstanding packets needing ack.)\n",
               seq_no);
    }
}
