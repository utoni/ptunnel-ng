/*
 * pdesc.c
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

#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>

#include "pdesc.h"
#include "options.h"
#include "utils.h"
#include "ptunnel.h"


/* create_and_insert_proxy_desc: Creates a new proxy descriptor, linking it into
 * the descriptor chain. If the sock argument is 0, the function will establish
 * a TCP connection to the ip and port given by dst_ip, dst_port.
 */
proxy_desc_t *create_and_insert_proxy_desc(uint16_t id_no, uint16_t icmp_id,
                                           int sock, struct sockaddr_in *addr,
			                               uint32_t dst_ip, uint32_t dst_port,
                                           uint32_t init_state, enum pkt_flag type) {
	proxy_desc_t *cur;

	pthread_mutex_lock(&chain_lock);
	if (num_tunnels >= opts.max_tunnels) {
		pt_log(kLog_info, "Discarding incoming connection - too many tunnels! Maximum count is %u (adjust with the   -m switch).\n", opts.max_tunnels);
		if (sock)
			close(sock);
		pthread_mutex_unlock(&chain_lock);
		return 0;
	}
	num_tunnels++;
	pthread_mutex_unlock(&chain_lock);

	pt_log(kLog_debug, "Adding proxy desc to run loop. Type is %s. Will create socket: %s\n", (type == kUser_flag ?   "user" : "proxy"), (sock ? "No" : "Yes"));
	cur                     = (proxy_desc_t *) calloc(1, sizeof(proxy_desc_t));
	cur->id_no              = id_no;
	cur->dest_addr          = *addr;
	cur->dst_ip             = dst_ip;
	cur->dst_port           = dst_port;
	cur->icmp_id            = icmp_id;
	if (!sock) {
		cur->sock               = socket(AF_INET, SOCK_STREAM, 0);
		memset(addr, 0, sizeof(struct sockaddr_in));
		addr->sin_port          = htons((uint16_t)dst_port);
		addr->sin_addr.s_addr   = dst_ip;
		addr->sin_family        = AF_INET;
		/*  Let's just assume success, shall we? */
		if (cur->sock >= 0 &&
			connect(cur->sock, (struct sockaddr*)addr, sizeof(struct sockaddr_in)) < 0)
		{
			pt_log(kLog_error, "Connect to %s:%d failed: %s\n", inet_ntoa(*(struct in_addr*)&addr->sin_addr.s_addr)  , ntohs(addr->sin_port), strerror(errno));
		}
	} else {
		cur->sock           = sock;
	}
	cur->state              = init_state;
	cur->type_flag          = type;
	if (cur->type_flag == kUser_flag) {
		cur->pkt_type       = kICMP_echo_request;
	} else {
		cur->pkt_type       = (opts.unprivileged ? kICMP_echo_request : kICMP_echo_reply);
	}
	cur->buf                = (char *) malloc(icmp_receive_buf_len);
	cur->last_activity      = time_as_double();
	cur->authenticated      = 0;

	pthread_mutex_lock(&chain_lock);
	cur->next               = chain;
	chain                   = cur;
	pthread_mutex_unlock(&chain_lock);
	cur->xfer.bytes_in      = 0.0;
	cur->xfer.bytes_out     = 0.0;
	cur->window_size        = kPing_window_size;
	cur->ack_interval       = 1.0;
	cur->resend_interval    = 1.5;
	cur->send_ring          = (icmp_desc_t *) calloc(cur->window_size, sizeof(icmp_desc_t));
	cur->recv_ring          = (forward_desc_t **) calloc(cur->window_size, sizeof(forward_desc_t *));
	return cur;
}

/* remove_proxy_desc: Removes the given proxy desc, freeing its resources.
 * Assumes that we hold the chain_lock.
 */
void remove_proxy_desc(proxy_desc_t *cur, proxy_desc_t *prev) {
	struct timeval tt;

	pt_log(kLog_debug, "Removing proxy descriptor.\n");
	/* Get a timestamp, for making an entry in the seq_expiry_tbl */
	gettimeofday(&tt, 0);
	seq_expiry_tbl[cur->id_no]  = tt.tv_sec+(2*kAutomatic_close_timeout);

	/* Free resources associated with connection */
	if (cur->buf)
		free(cur->buf);
	cur->buf    = 0;
	remove_proxy_desc_rings(cur);
	close(cur->sock);
	cur->sock   = 0;

    /* Keep list up-to-date */
	if (prev)
		prev->next  = cur->next;
	else
		chain       = cur->next;
	if (cur->challenge)
		free(cur->challenge);
	free(cur);
	num_tunnels--;
}

void remove_proxy_desc_rings(proxy_desc_t *cur) {
	int i;
	for (i=0;i<cur->window_size;i++) {
		if (cur->send_ring[i].pkt)
			free(cur->send_ring[i].pkt);
		cur->send_ring[i].pkt   = 0;
		if (cur->recv_ring[i])
			free(cur->recv_ring[i]);
		cur->recv_ring[i]       = 0;
	}
	free(cur->send_ring);
	free(cur->recv_ring);

	cur->recv_idx = 0;
	cur->recv_xfer_idx = 0;
	cur->send_idx = 0;
	cur->send_first_ack = 0;
	cur->recv_wait_send = 0;
	cur->send_wait_ack = 0;
	cur->next_resend_start = 0;
}

forward_desc_t* create_fwd_desc(uint16_t seq_no, uint32_t data_len, char *data) {
	forward_desc_t *fwd_desc;
	fwd_desc            = (forward_desc_t *) malloc(sizeof(forward_desc_t)+data_len);
	fwd_desc->seq_no    = seq_no;
	fwd_desc->length    = data_len;
	fwd_desc->remaining = data_len;
	if (data_len > 0)
		memcpy(fwd_desc->data, data, data_len);
	return fwd_desc;
}

/* queue_packet:
 * Creates an ICMP packet descriptor, and sends it. The packet descriptor is added
 * to the given send ring, for potential resends later on.
 */
int queue_packet(int sock_fd, proxy_desc_t *cur, char *buf, size_t bufsiz,
                 uint32_t dest_ip, uint32_t dest_port, uint32_t state)
{
	int pkt_len         = sizeof(icmp_echo_packet_t) +
	                      sizeof(ping_tunnel_pkt_t) + bufsiz;
	int err             = 0;
	icmp_echo_packet_t *pkt   = 0;
	ping_tunnel_pkt_t *pt_pkt = 0;
	uint16_t ack_val;
	uint8_t * icmp_chksm_ptr;

	assert(sock_fd >= 0);
	assert(cur);
	if (sock_fd < 0 || !cur)
		return -1;

	ack_val = cur->next_remote_seq - 1;

	if (pkt_len % 2)
		pkt_len++;

	pkt	              = (icmp_echo_packet_t *) calloc(1, pkt_len);
	/* ICMP Echo request or reply */
	pkt->type         = cur->pkt_type;
	/* Must be zero (non-zero requires root) */
	pkt->code         = 0;
	pkt->identifier   = htons(cur->icmp_id);
	pkt->seq          = htons(cur->ping_seq);
	pkt->checksum     = 0;
	cur->ping_seq++;
	/* Add our information */
	pt_pkt            = (ping_tunnel_pkt_t*)pkt->data;
	pt_pkt->magic     = htonl(opts.magic);
	pt_pkt->dst_ip    = dest_ip;
	pt_pkt->dst_port  = htonl(dest_port);
	pt_pkt->ack       = htonl(ack_val);
	pt_pkt->data_len  = htonl(bufsiz);
	pt_pkt->state     = htonl(state);
	pt_pkt->seq_no    = htons(cur->my_seq);
	pt_pkt->id_no     = htons(cur->id_no);
	/* Copy user data */
	if (buf && bufsiz > 0)
		memcpy(pt_pkt->data, buf, bufsiz);
	icmp_chksm_ptr	  = (uint8_t*)pkt;
	pkt->checksum     = htons(calc_icmp_checksum((uint16_t*)icmp_chksm_ptr, pkt_len));

	/* Send it! */
	pt_log(kLog_sendrecv, "Send: %4d [%4d] bytes "
	                      "[id = 0x%04X] [seq = %d] "
	                      "[seq_no = %d] [type = %s] "
	                      "[ack = %d] [icmp = %d] "
	                      "[user = %s]\n",
	                      pkt_len, bufsiz,
	                      cur->icmp_id, cur->ping_seq,
	                      cur->my_seq, state_name[state & (~kFlag_mask)],
	                      ack_val, cur->pkt_type,
	                      ((state & kUser_flag) == kUser_flag ? "yes" : "no"));
    log_sendrecv_hexstr("SEND ICMP", pkt, sizeof(*pkt));
    log_sendrecv_hexstr("SEND PTNG", pt_pkt, sizeof(*pt_pkt));
    if (pkt_len - (pt_pkt->data - (char *)pkt) > 0) {
        log_sendrecv_hexstr("SEND PAYL", pt_pkt->data, pkt_len - (pt_pkt->data - (char *)pkt));
    }

	err  = sendto(sock_fd, (const void*)pkt, pkt_len, 0,
	              (struct sockaddr*)&cur->dest_addr, sizeof(struct sockaddr));
	if (err < 0) {
		pt_log(kLog_error, "Failed to send ICMP packet: %s\n", strerror(errno));
		free(pkt);
		return -1;
	}
	else if (err != pkt_len)
		pt_log(kLog_error, "WARNING WARNING, didn't send entire packet\n");

	/* Update sequence no's and so on */
	cur->send_ring[cur->send_idx].pkt      = pkt;
	cur->send_ring[cur->send_idx].pkt_len  = pkt_len;
	cur->send_ring[cur->send_idx].last_resend = time_as_double();
	cur->send_ring[cur->send_idx].seq_no   = cur->my_seq;
	cur->send_ring[cur->send_idx].icmp_id  = cur->icmp_id;
	cur->my_seq++;
	if (!cur->send_ring[cur->send_first_ack].pkt)
		cur->send_first_ack = cur->send_idx;
	cur->send_wait_ack++;
    cur->send_idx++;
	if (cur->send_idx >= cur->window_size)
		cur->send_idx = 0;
	return 0;
}

/* send_packets:
 * Examines the passed-in ring, and forwards data in it over TCP.
 */
uint32_t send_packets(forward_desc_t *ring[], int *xfer_idx, int *await_send, int *sock, uint16_t window_size)   {
	forward_desc_t *fwd_desc;
	int            bytes, total = 0;

	while (*await_send > 0) {
		fwd_desc = ring[*xfer_idx];
		if (!fwd_desc)/* We haven't got this packet yet.. */
			break;
		if (fwd_desc->length > 0) {
			bytes = send(*sock, &fwd_desc->data[fwd_desc->length - fwd_desc->remaining],
				fwd_desc->remaining, 0);
			if (bytes < 0) {
				printf("Weirdness.\n");
				/* TODO: send close stuff */
				close(*sock);
				*sock = 0;
				break;
			}
			fwd_desc->remaining -= bytes;
			total               += bytes;
		}
		if (!fwd_desc->remaining) {
			ring[*xfer_idx] = 0;
			free(fwd_desc);
			(*xfer_idx)++;
			(*await_send)--;
			if (*xfer_idx >= window_size)
				*xfer_idx = 0;
		}
		else
			break;
	}
	return total;
}
