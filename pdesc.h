#ifndef PDESC_H
#define PDESC_H 1

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
	int seq_no;
	/** length of data */
	int length;
	/** amount of data not yet transferred */
	int remaining;
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
	int pkt_len;
	double  last_resend;
	int resend_count;
	uint16_t seq_no;
	uint16_t icmp_id;
	icmp_echo_packet_t *pkt;
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
	char *buf;
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
    challenge_t *challenge;
	/** Protocol state */
	uint32_t state;
	/** Either kProxy_flag or kUser_flag */
	uint32_t type_flag;
	/** IP and port to which data should be forwarded. */
	uint32_t dst_ip;
	uint32_t dst_port;
	/** Same as above */
    struct sockaddr_in dest_addr;
	/** Time when last ack packet was sent. */
	double last_ack;
	/** Time when a packet was last received. */
	double last_activity;
    icmp_desc_t send_ring[kPing_window_size];
    forward_desc_t *recv_ring[kPing_window_size];
    xfer_stats_t xfer;
    struct proxy_desc_t *next;
} proxy_desc_t;


proxy_desc_t*   create_and_insert_proxy_desc(uint16_t id_no, uint16_t icmp_id,
                                             int sock, struct sockaddr_in *addr,
                                             uint32_t dst_ip, uint32_t dst_port,
                                             uint32_t init_state, uint32_t type);

void            remove_proxy_desc(proxy_desc_t *cur, proxy_desc_t *prev);

forward_desc_t* create_fwd_desc(uint16_t seq_no, uint32_t data_len, char *data);

int             queue_packet(int icmp_sock, uint8_t type, char *buf, int num_bytes,
                             uint16_t id_no, uint16_t icmp_id, uint16_t *seq, icmp_desc_t ring[],
                             int *insert_idx, int *await_send, uint32_t ip, uint32_t port,
                             uint32_t state, struct sockaddr_in *dest_addr, uint16_t next_expected_seq,
                             int *first_ack, uint16_t *ping_seq);

uint32_t        send_packets(forward_desc_t *ring[], int *xfer_idx, int *await_send, int *sock);

#endif
