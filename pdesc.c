#include <stdlib.h>

#include "pdesc.h"
#include "options.h"
#include "utils.h"
#include "ptunnel.h"


/* create_and_insert_proxy_desc: Creates a new proxy descriptor, linking it into
 * the descriptor chain. If the sock argument is 0, the function will establish
 * a TCP connection to the ip and port given by dst_ip, dst_port.
 */
proxy_desc_t* create_and_insert_proxy_desc(uint16_t id_no, uint16_t icmp_id,
                                           int sock, struct sockaddr_in *addr,
			                               uint32_t dst_ip, uint32_t dst_port,
                                           uint32_t init_state, uint32_t type) {
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
		if (connect(cur->sock, (struct sockaddr*)addr, sizeof(struct sockaddr_in)) < 0) {
			pt_log(kLog_error, "Connect to %s:%d failed: %s\n", inet_ntoa(*(struct in_addr*)&addr->sin_addr.s_addr)  , ntohs(addr->sin_port), strerror(errno));
		}
	}
	else
		cur->sock           = sock;
	cur->state              = init_state;
	cur->type_flag          = type;
	if (cur->type_flag == kUser_flag)
		cur->pkt_type       = kICMP_echo_request;
	else
		cur->pkt_type       = (opts.unprivileged ? kICMP_echo_request : kICMP_echo_reply);
	cur->buf                = (char *) malloc(icmp_receive_buf_len);
	cur->last_activity      = time_as_double();
	cur->authenticated      = 0;

	pthread_mutex_lock(&chain_lock);
	cur->next               = chain;
	chain                   = cur;
	pthread_mutex_unlock(&chain_lock);
	cur->xfer.bytes_in      = 0.0;
	cur->xfer.bytes_out     = 0.0;
	return cur;
}

/* remove_proxy_desc: Removes the given proxy desc, freeing its resources.
 * Assumes that we hold the chain_lock.
 */
void remove_proxy_desc(proxy_desc_t *cur, proxy_desc_t *prev) {
	int i;
	struct timeval tt;

	pt_log(kLog_debug, "Removing proxy descriptor.\n");
	/* Get a timestamp, for making an entry in the seq_expiry_tbl */
	gettimeofday(&tt, 0);
	seq_expiry_tbl[cur->id_no]  = tt.tv_sec+(2*kAutomatic_close_timeout);

	/* Free resources associated with connection */
	if (cur->buf)
		free(cur->buf);
	cur->buf    = 0;
	for (i=0;i<kPing_window_size;i++) {
		if (cur->send_ring[i].pkt)
			free(cur->send_ring[i].pkt);
		cur->send_ring[i].pkt   = 0;
		if (cur->recv_ring[i])
			free(cur->recv_ring[i]);
		cur->recv_ring[i]       = 0;
	}
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

/* send_packets:
 * Examines the passed-in ring, and forwards data in it over TCP.
 */
uint32_t send_packets(forward_desc_t *ring[], int *xfer_idx, int *await_send, int *sock)   {
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
			if (*xfer_idx >= kPing_window_size)
				*xfer_idx = 0;
		}
		else
			break;
	}
	return total;
}
