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

/* handle_proxy_packet:
 * Processes incoming ICMP packets for the proxy. The packet can come either from the
 * packet capture lib, or from the actual socket or both.
 * Input:  A buffer pointing at the start of an IP header, the buffer length and the proxy
 * descriptor chain.
 */
void handle_packet(char *buf, unsigned bytes, int is_pcap, struct sockaddr_in *addr, int icmp_sock) {
	ip_packet_t         *ip_pkt;
	icmp_echo_packet_t  *pkt;
	ping_tunnel_pkt_t   *pt_pkt;
	proxy_desc_t        *cur;
	uint32_t            type_flag, pkt_flag, init_state, proxy_flag;
	challenge_t         *challenge;
    struct timeval      tt;

	proxy_flag = kProxy_flag;

	if (bytes < sizeof(icmp_echo_packet_t)+sizeof(ping_tunnel_pkt_t))
		pt_log(kLog_verbose, "Skipping this packet - too short. "
		                     "Expect: %d+%d = %d ; Got: %d\n",
		                     sizeof(icmp_echo_packet_t),
		                     sizeof(ping_tunnel_pkt_t),
		                     sizeof(icmp_echo_packet_t) +
		                     sizeof(ping_tunnel_pkt_t), bytes);
	else {
		if (opts.udp) {
			ip_pkt      = 0;
			pkt         = (icmp_echo_packet_t*)buf;
			pt_pkt      = (ping_tunnel_pkt_t*)pkt->data;
		}
		else {
			ip_pkt      = (ip_packet_t*)buf;
			pkt         = (icmp_echo_packet_t*)ip_pkt->data;
			pt_pkt      = (ping_tunnel_pkt_t*)pkt->data;
		}

		if (ntohl(pt_pkt->magic) == opts.magic) {
			pt_pkt->state       = ntohl(pt_pkt->state);
			pkt->identifier     = ntohs(pkt->identifier);
			pt_pkt->id_no       = ntohs(pt_pkt->id_no);
			pt_pkt->seq_no      = ntohs(pt_pkt->seq_no);
			/* Find the relevant connection, if it exists */
			pthread_mutex_lock(&chain_lock);
			for (cur=chain;cur;cur=cur->next) {
				if (cur->id_no == pt_pkt->id_no)
					break;
			}
			pthread_mutex_unlock(&chain_lock);

			/* Handle the packet if it comes from "the other end." This is a bit tricky
			 * to get right, since we receive both our own and the other end's packets.
			 * Basically, a proxy will accept any packet from a user, regardless if it
			 * has a valid connection or not. A user will only accept the packet if there
			 * exists a connection to handle it.
			 */
			if (cur) {
				type_flag           = cur->type_flag;
				if (type_flag == (uint32_t)kProxy_flag)
					cur->icmp_id    = pkt->identifier;
				if (!is_pcap)
					cur->xfer.icmp_in++;
			}
			else
				type_flag           = kProxy_flag;
  
			pkt_flag        = pt_pkt->state & kFlag_mask;
			pt_pkt->state   &= ~kFlag_mask;
			pt_log(kLog_sendrecv, "Recv: %d [%d] bytes "
			                      "[seq = %d] [type = %s] "
			                      "[ack = %d] [icmp = %d] "
                                  "[user = %s] [pcap = %d]\n",
                                  bytes, ntohl(pt_pkt->data_len),
			                      pt_pkt->seq_no, state_name[pt_pkt->state & (~kFlag_mask)],
			                      ntohl(pt_pkt->ack), pkt->type,
			                      (pkt_flag == kUser_flag ? "yes" : "no"), is_pcap);

			/* This test essentially verifies that the packet comes from someone who isn't us. */
			if ((pkt_flag == kUser_flag && type_flag == proxy_flag) ||
			    (pkt_flag == proxy_flag && type_flag == kUser_flag))
			{
				pt_pkt->data_len    = ntohl(pt_pkt->data_len);
				pt_pkt->ack         = ntohl(pt_pkt->ack);
				if (pt_pkt->state == kProxy_start) {
					if (!cur && type_flag == proxy_flag) {
						pt_log(kLog_info, "Incoming tunnel request from %s.\n",
						                  inet_ntoa(*(struct in_addr *)&addr->sin_addr));
						gettimeofday(&tt, 0);
						if (tt.tv_sec < seq_expiry_tbl[pt_pkt->id_no]) {
							pt_log(kLog_verbose, "Dropping request: ID was recently in use.\n");
							return;
						}
						pt_log(kLog_info, "Starting new session to %s:%d with ID %d\n",
						                  inet_ntoa(*(struct in_addr *)&pt_pkt->dst_ip),
						                  ntohl(pt_pkt->dst_port), pt_pkt->id_no);
						if ((opts.given_dst_ip && opts.given_dst_ip != pt_pkt->dst_ip) ||
						    ((uint32_t)-1 != opts.given_dst_port && opts.given_dst_port != ntohl(pt_pkt->dst_port)))
						{
							pt_log(kLog_info, "Destination administratively prohibited!\n");
							return;
						}

						if (opts.password)
							init_state  = kProto_authenticate;
						else
							init_state  = kProto_data;

						cur = create_and_insert_proxy_desc(pt_pkt->id_no, pkt->identifier, 0,
						                                   addr, pt_pkt->dst_ip,
						                                   ntohl(pt_pkt->dst_port),
						                                   init_state, kProxy_flag);
						if (init_state == kProto_authenticate) {
							pt_log(kLog_debug, "Sending authentication challenge..\n");
							/* Send challenge */
							cur->challenge  = generate_challenge();
							memcpy(cur->buf, cur->challenge, sizeof(challenge_t));
							queue_packet(icmp_sock, cur->pkt_type, cur->buf,
							             sizeof(challenge_t), cur->id_no,
							             cur->icmp_id, &cur->my_seq, cur->send_ring,
							             &cur->send_idx, &cur->send_wait_ack, 0, 0,
							             kProto_authenticate | cur->type_flag,
							             &cur->dest_addr, cur->next_remote_seq,
							             &cur->send_first_ack, &cur->ping_seq);
						}
					}
					else if (type_flag == kUser_flag) {
						pt_log(kLog_error, "Dropping proxy session request - we are not a proxy!\n");
						return;
					}
					else
						pt_log(kLog_error, "Dropping duplicate proxy session request.\n");
				}
				else if (cur && pt_pkt->state == kProto_authenticate) {
					/* Sanity check packet length, and make sure it matches what we expect */
					if (pt_pkt->data_len != sizeof(challenge_t)) {
						pt_log(kLog_error, "Received challenge packet, but data length "
						                   "is not as expected.\n");
						pt_log(kLog_debug, "Data length: %d  Expected: %d\n",
						                   pt_pkt->data_len, sizeof  (challenge_t));
						cur->should_remove = 1;
						return;
					}
					/* Prevent packet data from being forwarded over TCP! */
					pt_pkt->data_len    = 0;
					challenge           = (challenge_t*)pt_pkt->data;
					/* If client: Compute response to challenge */
					if (type_flag == kUser_flag) {
						if (!opts.password) {
							pt_log(kLog_error, "This proxy requires a password! "
							                   "Please supply one usin  g the -x switch.\n");
							send_termination_msg(cur, icmp_sock);
							cur->should_remove  = 1;
							return;
						}
						pt_log(kLog_debug, "Got authentication challenge - sending response\n");
						generate_response(challenge);
						queue_packet(icmp_sock, cur->pkt_type, (char*)challenge,
						             sizeof(challenge_t), cur->id_no, cur->icmp_id,
						             &cur->my_seq, cur->send_ring, &cur->send_idx,
						             &cur->send_wait_ack, 0, 0,
						             kProto_authenticate | cur->type_flag, &cur->dest_addr,
						             cur->next_remote_seq, &cur->send_first_ack, &cur->  ping_seq);
						/* We have authenticated locally.
						 * It's up to the proxy now if it accepts our   response or not..
						 */
						cur->authenticated  = 1;
						handle_data(pkt, bytes, cur->recv_ring, &cur->recv_wait_send,
						            &cur->recv_idx, &cur->next_remote_seq);
						return;
					}
					/* If proxy: Handle client's response to challenge */
					else if (type_flag == proxy_flag) {
						pt_log(kLog_debug, "Received remote challenge response.\n");
						if (validate_challenge(cur->challenge, challenge) ||
						                       cur->authenticated)
						{
							pt_log(kLog_verbose, "Remote end authenticated successfully.\n");
							/* Authentication has succeeded, so now we can proceed
							 * to handle incoming   TCP data.
							 */
							cur->authenticated  = 1;
							cur->state          = kProto_data;
							/* Insert the packet into the receive ring, to avoid
							 * confusing the reliab  ility mechanism.
							 */
							handle_data(pkt, bytes, cur->recv_ring, &cur->recv_wait_send,
							            &cur->recv_idx, &cur->next_remote_seq);
						}
						else {
							pt_log(kLog_info, "Remote end failed authentication.\n");
							send_termination_msg(cur, icmp_sock);
							cur->should_remove = 1;
						}
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
				if (type_flag == proxy_flag && opts.password &&
				    cur && !cur->authenticated)
				{
					pt_log(kLog_debug, "Ignoring packet with seq-no %d "
					                   "- not authenticated yet.\n", pt_pkt->seq_no);
					return;
				}

				if (cur && cur->sock) {
					if (pt_pkt->state == kProto_data || pt_pkt->state == kProxy_start ||
					    pt_pkt->state   == kProto_ack)
					{
						handle_data(pkt, bytes, cur->recv_ring, &cur->recv_wait_send,
						            &cur->recv_idx,   &cur->next_remote_seq);
					}
					handle_ack((uint16_t)pt_pkt->ack, cur->send_ring, &cur->send_wait_ack,
					           0, cur->send_idx, &cur->send_first_ack, &cur->remote_ack_val,
					           is_pcap);
					cur->last_activity      = time_as_double();
				}
			}
		}
		else
			pt_log(kLog_verbose, "Ignored incoming packet.\n");
	}
}
