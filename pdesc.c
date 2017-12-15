#include "pdesc.h"
#include "options.h"
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
	cur                     = calloc(1, sizeof(proxy_desc_t));
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
	cur->buf                = malloc(icmp_receive_buf_len);
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
