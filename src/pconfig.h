#ifndef PCONFIG_H
#define PCONFIG_H 1

enum {
	/** Ping tunnel's operating mode (client) */
	kMode_forward        = 0,
	/** Ping tunnel's operating mode (server) */
	kMode_proxy,
	/** Set this constant to the number of
	 * concurrent connections you wish to handle by default.
	 */
	kMax_tunnels         = 10,
	/** Different verbosity levels. */
	kNo_log              = -1,
	kLog_error           = 0,
	kLog_info,
	kLog_event,
	kLog_verbose,
	kLog_debug,
	kLog_sendrecv,
	/** Major (0.xx) and minor (x.70) version */
	kMajor_version       = 0,
	/** numbers */
	kMinor_version       = 72,
	kIP_packet_max_size  = 576,
	/** In bytes, mind you */
	kIP_header_size      = 20,
	kIP_actual_size      = (kIP_packet_max_size - kIP_header_size) - ((kIP_packet_max_size - kIP_header_size) % 8),
	/** Also in bytes */
	kICMP_header_size    = 8,
	/** This constant control the maximum size of
	 * the payload-portion of the ICMP packets
	 * we send. Note that this does not include
	 * the IP or ICMP headers!
	 */
	kDefault_buf_size    = 1024,
	/** Type code for echo request and replies */
	kICMP_echo_request   = 8,
	kICMP_echo_reply     = 0,
	/** number of packets we can have in our send/receive ring */
	kPing_window_size    = 64,
	/** Tunnels are automatically closed after one minute of inactivity. Since
	 * we continously send acknowledgements between the two peers, this mechanism
	 * won't disconnect "valid" connections.
	 */
	kAutomatic_close_timeout = 60,   //  Seconds!
	/** size of md5 digest in bytes */
	kMD5_digest_size     = 16,
	/** These constants are used to indicate the protocol state. The protocol
     * works as follows:
     * - The identifier is used by both the proxy and the forwarder
     * to identify the session (and thus the relevant sockets).
     * - The seq-no of the ping packet is used in a sliding-window-esque
     * way, and to identify the order of data.
     *
     * The protocol can be in any of the following states:
     * kProxy_start        Causes the proxy to open a connection to the given
     *                     host and port, associating the ID with the socket,
     *                     before the data on the socket are transmitted.
     * kProxy_data     Indicates that the packet contains data from the proxy.
     *                     Data ordering is indicated by the seq-no, which will start
     *                     at 0. (The proxy and forwarder maintain different seq-nos.)
     * kUser_data      This packet contains user data.
     * kConnection_close   Indicates that the connection is being closed.
     * kProxy_ack and      Acknowledges the packet (and all packets before it) with seq_no = ack.
     * kUser_ack       This is used if there are no implicit acknowledgements due to data
     *                     being sent.
     *
     * Acknowledgements work by the remote peer acknowledging the last
     * continuous seq no it has received.
     *
     * Note: A proxy receiving a kProxy_data packet, or a user receiving a
     * kUser_data packet, should ignore it, as it is the host operating system
     * actually returning the ping. This is mostly relevant for users, and for
     * proxies running in unprivileged mode.
     */
	kProxy_start         = 0,
	kProto_ack,
	kProto_data,
	kProto_close,
	kProto_authenticate,
	kNum_proto_types,
	/** set when packet comes from a user */
	kUser_flag           = 1 << 30,
	/** set when packet comes from the proxy */
    kProxy_flag          = 1 << 31,
    kFlag_mask           = kUser_flag | kProxy_flag,
    kDNS_port            = 53
};

#endif
