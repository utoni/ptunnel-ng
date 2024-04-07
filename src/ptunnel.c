/*
 * ptunnel.c
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
 * You can get in touch with me, Daniel Stoedle (that's the Norwegian letter oe,
 * in case your text editor didn't realize), here: <daniels@cs.uit.no>
 *
 * The official ptunnel website is here:
 * <http://www.cs.uit.no/~daniels/PingTunnel/>
 *
 * Note that the source code is best viewed with tabs set to 4 spaces.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "ptunnel.h"
#include "options.h"
#include "utils.h"
#include "md5.h"
#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifndef PACKAGE_STRING
#define PACKAGE_STRING "ptunnel-ng"
#endif

#ifdef WIN32
#include <tchar.h>
#include <winsock2.h>
/* Map errno (which Winsock doesn't use) to GetLastError; include the code in the strerror */
#ifdef errno
#undef errno
#endif /* errno */
#define errno GetLastError()
/** Local error string storage */
static char errorstr[255];
static char * print_last_windows_error() {
	char last_errorstr[255];
	DWORD last_error = GetLastError();

	memset(last_errorstr, 0, sizeof(last_errorstr));
	FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
	              NULL, last_error, 0, last_errorstr, sizeof(last_errorstr), NULL);
	snprintf(errorstr, sizeof(errorstr), "%s (%lu)", last_errorstr, last_error);
	return errorstr;
}
#define strerror(x) print_last_windows_error()
#endif /* WIN32 */

#ifdef HAVE_NPCAP
static BOOL LoadNpcapDlls()
{
	TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		pt_log(kLog_error, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		pt_log(kLog_error, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/* globals */
/** Lock protecting the chain of connections */
pthread_mutex_t chain_lock;
/** Lock protecting the num_threads variable */
pthread_mutex_t num_threads_lock;
/** Current thread count */
int num_threads = 0;
/** Current tunnel count */
uint32_t num_tunnels = 0;
/** Table indicating when a connection ID is allowable (used by proxy) */
time_t *seq_expiry_tbl = NULL;

/* Some buffer constants */
const int tcp_receive_buf_len  = kDefault_buf_size;
const int icmp_receive_buf_len = kDefault_buf_size + kIP_header_size +
                                 kICMP_header_size + sizeof(ping_tunnel_pkt_t);
const int pcap_buf_size        = (kDefault_buf_size + kIP_header_size +
                                 kICMP_header_size + sizeof(ping_tunnel_pkt_t)+64)*64;
/** (icmp[icmptype] = icmp-echo || icmp[icmptype] = icmp-echoreply) */
char pcap_filter_program[]     = "icmp";

/** The chain of client/proxy connections */
proxy_desc_t *chain = 0;
const char *state_name[kNum_proto_types] = { "start", "ack  ", "data ",
                                             "close", "authenticate" };

#ifdef HAVE_PCAP
static void print_pcap_devices(void) {
	pcap_if_t *devs, *cur_dev;
	pcap_addr_t *cur_addr;
	char errbuf[PCAP_ERRBUF_SIZE+1];

	if (pcap_findalldevs(&devs, errbuf)) {
		pt_log(kLog_error, "List all available pcap devices failed: %s.\n", errbuf);
	}
	printf("Available pcap devices:\n");
	for (cur_dev = devs; cur_dev; cur_dev = cur_dev->next) {
		if (cur_dev->description)
			printf("\n\t%s%c '%s'\n", cur_dev->name, (cur_dev->addresses ? ':' : ' '),
				cur_dev->description);
		else
			printf("\n\t%s%c\n", cur_dev->name, (cur_dev->addresses ? ':' : ' '));
		for (cur_addr = cur_dev->addresses; cur_addr; cur_addr = cur_addr->next) {
			if (cur_addr->addr->sa_family == AF_INET)
				printf("\t\t%s\n", inet_ntoa(((struct sockaddr_in*)cur_addr->addr)->sin_addr));
		}
	}
	pcap_freealldevs(devs);
}
#endif

/* Let the fun begin! */
int main(int argc, char *argv[]) {
#ifndef WIN32
	pid_t   pid;
#endif
#ifdef WIN32
	WORD    wVersionRequested;
	WSADATA wsaData;
	int     err;

	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		return -1;
	}

	if (LOBYTE( wsaData.wVersion ) != 2 ||
		HIBYTE( wsaData.wVersion ) != 2)
	{
		WSACleanup();
		return -1;
	}
#endif /* WIN32 */

#ifdef HAVE_NPCAP
	if (!LoadNpcapDlls())
		return -1;
#endif

	memset(opts.md5_password_digest, 0, kMD5_digest_size);
	memset(opts.sha512_password_digest, 0, kSHA512_digest_size);

	/* The seq_expiry_tbl is used to prevent the remote ends from prematurely
	 * re-using a sequence number.
	 */
	seq_expiry_tbl = (time_t *) calloc(65536, sizeof(time_t));

	/* Parse options */
	if (parse_options(argc, argv))
		return -1;

	/* Init ptunnel RNG */
	pt_random();

	if (opts.list_pcap_devices) {
#ifdef HAVE_PCAP
		print_pcap_devices();
		return 0;
#else
		pt_log(kLog_error, "Pcap not available!\n");
		return 1;
#endif
	}

#ifdef HAVE_PCAP
	if (opts.pcap && opts.udp) {
		pt_log(kLog_error, "Packet capture is not supported (or needed) when using UDP for transport.\n");
		opts.pcap = 0;
	}
#ifdef WIN32
	if (!opts.pcap && !opts.udp) {
		pt_log(kLog_info, "Running ptunnel-ng on Windows in ICMP mode without WinPcap/Npcap enabled is not supported and may not work!\n");
        pt_log(kLog_info, "If you encounter problems, install WinPCAP/Npcap from:\n");
		pt_log(kLog_info, "https://www.winpcap.org/install/default.htm or Npcap for WIN10: https://nmap.org/npcap/windows-10.html\n");
		pt_log(kLog_info, "After WinPCAP is installed, you can list pcap devices with: --list-libpcap-devices\n");
	}
#endif
#endif
	pt_log(kLog_info, "Starting %s.\n", PACKAGE_STRING);
	pt_log(kLog_info, "(c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>\n");
	pt_log(kLog_info, "(c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>\n");
#ifdef WIN32
	pt_log(kLog_info, "Windows version by Mike Miller, <mike@mikeage.net>\n");
#else
	pt_log(kLog_info, "Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>\n");
#endif
	pt_log(kLog_info, "%s.\n", (opts.mode == kMode_forward ? "Relaying packets from incoming TCP streams" :
	                                                         "Forwarding incoming ping packets over TCP"));
	if (opts.udp)
		pt_log(kLog_info, "UDP transport enabled.\n");

	pt_log(kLog_debug, "Destination at %s:%u\n", opts.given_dst_hostname, opts.given_dst_port);

	/* TODO: Maybe give the user the opportunity to bind to certain addresses e.g. 127.0.0.1 ? */
	if (opts.mode == kMode_forward)
		pt_log(kLog_debug, "Listen for incoming connections at 0.0.0.0:%u\n", opts.tcp_listen_port);

#ifndef WIN32
  	signal(SIGPIPE, SIG_IGN);
	if (opts.use_syslog) {
		if (opts.log_file != stdout) {
			pt_log(kLog_error, "Logging using syslog overrides the use of a specified logfile (using -f).\n");
			fclose(opts.log_file);
			opts.log_file = stdout;
		}
		openlog("ptunnel", LOG_PID, LOG_USER);
	}
	if (opts.chroot) {
		pt_log(kLog_info, "Restricting file access to %s\n", opts.root_dir);
		if (-1 == chdir(opts.root_dir) || -1 == chroot(".") || -1 == chdir("/")) {
			pt_log(kLog_error, "chdir/chroot `%s': %s\n", opts.root_dir, strerror(errno));
			exit(1);
		}
	}
	if (opts.daemonize) {
		pt_log(kLog_info, "Going to the background.\n");
		if (0 < (pid = fork()))
			exit(0);
		if (0 > pid)
			pt_log(kLog_error, "fork: %s\n", strerror(errno));
		else
			if (-1 == setsid())
				pt_log(kLog_error, "setsid: %s\n", strerror(errno));
			else {
				if (0 < (pid = fork()))
					exit(0);
				if (0 > pid)
					pt_log(kLog_error, "fork: %s\n", strerror(errno));
				else {
					if (NULL != opts.pid_file) {
						fprintf(opts.pid_file, "%d\n", getpid());
						fclose(opts.pid_file);
					}
					if (! freopen("/dev/null", "r", stdin) ||
					    ! freopen("/dev/null", "w", stdout) ||
					    ! freopen("/dev/null", "w", stderr))
						pt_log(kLog_error, "freopen `%s': %s\n", "/dev/null", strerror(errno));
				}
			}
	}
#endif /* !WIN32 */

	pthread_mutex_init(&chain_lock, 0);
	pthread_mutex_init(&num_threads_lock, 0);

	//	Check mode, validate arguments and start either client or proxy.
	if (opts.mode == kMode_forward) {
		if (!opts.given_proxy_ip || !opts.given_dst_ip || !opts.given_dst_port || !opts.tcp_listen_port) {
			printf("One of the options are missing or invalid.\n");
			print_usage(argv[0]);
			return -1;
		}
		pt_forwarder();
	}
	else
		pt_proxy(0);

#ifdef WIN32
	WSACleanup();
#else
	if (opts.root_dir)
		free(opts.root_dir);
#ifdef HAVE_SELINUX
	if (NULL != opts.selinux_context)
		free(opts.selinux_context);
#endif
#endif /* WIN32 */

	pt_log(kLog_info, "ptunnel is exiting.\n");
	return 0;
}

/**	pt_forwarder:
 * Sets up a listening TCP socket, and forwards incoming connections
 * over ping packets.
 */
void pt_forwarder(void) {
	int                 server_sock, new_sock, sock, yes = 1;
	fd_set              set;
	struct timeval      time;
	struct sockaddr_in  addr, dest_addr;
	socklen_t           addr_len;
	pthread_t           pid;
	uint16_t            rand_id;
	struct in_addr      in_addr;

	pt_log(kLog_debug, "Starting forwarder..\n");
	/** Open our listening socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		pt_log(kLog_error, "Failed to create socket: %s\n", strerror(errno));
		return;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &yes, sizeof(int)) == -1) {
		pt_log(kLog_error, "Failed to set SO_REUSEADDR option on listening socket: %s\n", strerror(errno));
		close(sock);
		return;
	}
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(opts.tcp_listen_port);
	addr.sin_addr.s_addr = INADDR_ANY;
	memset(&(addr.sin_zero), 0, 8);
	if (bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr)) == -1) {
		pt_log(kLog_error, "Failed to bind listening socket to port %u: %s\n", opts.tcp_listen_port, strerror(errno));
		close(sock);
		return;
	}
	server_sock	= sock;
	/* Fill out address structure */
	memset(&dest_addr, 0, sizeof(struct sockaddr_in));
	dest_addr.sin_family      = AF_INET;
	if (opts.udp)
		dest_addr.sin_port    = htons(kDNS_port /* dns port.. */);
	else
		dest_addr.sin_port    = 0;
	in_addr.s_addr = opts.given_proxy_ip;
	dest_addr.sin_addr.s_addr = opts.given_proxy_ip;
	pt_log(kLog_verbose, "Proxy IP address: %s\n", inet_ntoa(in_addr));

	listen(server_sock, 10);
	while (1) {
		FD_ZERO(&set);
		FD_SET(server_sock, &set);
		time.tv_sec		= 1;
		time.tv_usec	= 0;
		if (select(server_sock+1, &set, 0, 0, &time) > 0) {
			pt_log(kLog_info, "Incoming connection.\n");
			addr_len	= sizeof(struct sockaddr_in);
			new_sock	= accept(server_sock, (struct sockaddr*)&addr, &addr_len);
			if (new_sock < 0) {
				pt_log(kLog_error, "Accepting incoming connection failed.\n");
				continue;
			}
			pthread_mutex_lock(&num_threads_lock);
			if (num_threads <= 0) {
				pt_log(kLog_event, "No running proxy thread - starting it.\n");
#ifndef WIN32
				if (pthread_create(&pid, 0, pt_proxy, 0) != 0)
#else
				if (0 == (pid = _beginthreadex(0, 0, pt_proxy, 0, 0, 0)))
#endif
				{
					pt_log(kLog_error, "Couldn't create thread! Dropping incoming connection.\n");
					close(new_sock);
					pthread_mutex_unlock(&num_threads_lock);
					continue;
				}
			}
			addr	= dest_addr;
			rand_id	= pt_random();
			create_and_insert_proxy_desc(rand_id, rand_id, new_sock, &addr, opts.given_dst_ip, opts.given_dst_port, kProxy_start, kUser_flag);
			pthread_mutex_unlock(&num_threads_lock);
		}
	}
}


int pt_create_udp_socket(int port) {
	struct sockaddr_in addr; 
	int                sock, yes = 1;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		pt_log(kLog_error, "Failed to set create UDP socket..\n");
		return 0; 
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void*)&yes, sizeof(int)) < 0) {
		pt_log(kLog_error, "Failed to set UDP REUSEADDR socket option. (Not fatal, hopefully.)\n");
		close(sock);
		return 0;
	}
#ifdef SO_REUSEPORT
	yes = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&yes, sizeof(int)) < 0)
		pt_log(kLog_error, "Failed to set UDP REUSEPORT socket option. (Not fatal, hopefully.)\n");
#endif /* SO_REUSEPORT */

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family			= AF_INET;
	addr.sin_addr.s_addr	= htonl(INADDR_ANY);
	addr.sin_port			= htons(port);
	if (bind(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)) < 0) {
		pt_log(kLog_error, "Failed to bind UDP socket to port %d (try running as root).\n", port);
		close(sock);
		return 0;
	}
	return sock;
}

/* pt_proxy: This function does all the client and proxy stuff.
 */
#ifndef WIN32
void * pt_proxy(void *args)
#else
unsigned int __stdcall pt_proxy(void *args)
#endif
{
	(void) args;

	fd_set             set;
	struct timeval     timeout;
	int                bytes;
	struct sockaddr_in addr;
	socklen_t          addr_len;
	int                fwd_sock = 0,
	                   max_sock = 0,
	                   idx;
	char               *buf;
	double             now, last_status_update = 0.0;
	proxy_desc_t       *cur, *prev, *tmp;
#ifdef HAVE_PCAP
	pcap_info_t        pc;
	pcap_if_t          *alldevs = 0, *pdev;
#endif
	xfer_stats_t       xfer;
#ifdef HAVE_PCAP
	ip_packet_t        *pkt;
	uint32_t           ip;
	in_addr_t          *adr;
#endif
	struct in_addr     in_addr;
#ifdef HAVE_ICMPFILTER
	struct icmp_filter filt;
#endif

	/* Start the thread, initialize protocol and ring states. */
	pt_log(kLog_debug, "Starting ping proxy..\n");
	if (opts.udp) {
		pt_log(kLog_debug, "Creating UDP socket..\n");
		if (opts.mode == kMode_proxy)
			fwd_sock	= pt_create_udp_socket(kDNS_port);
		else
			fwd_sock	= pt_create_udp_socket(0);
		if (!fwd_sock) {
			pt_log(kLog_error, "Failed to create UDP socket.\n");
			return 0;
		}
	}
	else {
		if (opts.unprivileged)
		{
			pt_log(kLog_debug, "Attempting to create unprivileged ICMP datagram socket..\n");
			fwd_sock		= socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
		} else {
			pt_log(kLog_debug, "Attempting to create privileged ICMP raw socket..\n");
			fwd_sock		= socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#ifdef HAVE_ICMPFILTER
			if (opts.mode == kMode_forward)
				filt.data	= ~(1<<ICMP_ECHOREPLY);
			else
				filt.data	= ~(1<<ICMP_ECHO);
			if (fwd_sock >= 0 &&
			    setsockopt(fwd_sock, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) == -1)
			{
				pt_log(kLog_error, "setockopt for ICMP_FILTER: %s\n", strerror(errno));
			}
#endif
		}
		if (fwd_sock < 0) {
			pt_log(kLog_error, "Couldn't create %s socket: %s\n",
			                   (opts.unprivileged ? "unprivileged datagram" :
			                                        "privileged raw"), strerror(errno));
			return 0;
		}
	}
	max_sock			= fwd_sock+1;
#ifdef HAVE_PCAP
	if (opts.pcap) {
		if (opts.udp) {
			pt_log(kLog_error, "Packet capture is not useful with UDP [should not get here!]!\n");
			close(fwd_sock);
			return 0;
		}
		if (!opts.unprivileged) {
			memset(&pc, 0, sizeof(pc));
			pt_log(kLog_info, "Initializing pcap.\n");
			pc.pcap_err_buf		= (char *) malloc(PCAP_ERRBUF_SIZE);
			pc.pcap_data_buf	= (char *) malloc(pcap_buf_size);
			pc.pcap_desc		= pcap_open_live(opts.pcap_device,
			                                     pcap_buf_size, 0 /* promiscous */,
			                                     50 /* ms */, pc.pcap_err_buf);
			if (pc.pcap_desc) {
				if (pcap_lookupnet(opts.pcap_device, &pc.netp,
				                   &pc.netmask, pc.pcap_err_buf) == -1)
				{
					pt_log(kLog_error, "pcap error: %s\n", pc.pcap_err_buf);
					opts.pcap = 0;
				}
				in_addr.s_addr = pc.netp;
				pt_log(kLog_verbose, "Network: %s\n", inet_ntoa(in_addr));
				in_addr.s_addr = pc.netmask;
				pt_log(kLog_verbose, "Netmask: %s\n", inet_ntoa(in_addr));
				if (pcap_compile(pc.pcap_desc, &pc.fp, pcap_filter_program, 0, pc.netp) == -1) {
					pt_log(kLog_error, "Failed to compile pcap filter program.\n");
					pcap_close(pc.pcap_desc);
					opts.pcap = 0;
				}
				else if (pcap_setfilter(pc.pcap_desc, &pc.fp) == -1) {
					pt_log(kLog_error, "Failed to set pcap filter program.\n");
					pcap_close(pc.pcap_desc);
					opts.pcap = 0;
				}
			}
			else {
				pt_log(kLog_error, "pcap error: %s\n", pc.pcap_err_buf);
				opts.pcap = 0;

				if (pcap_findalldevs(&alldevs, pc.pcap_err_buf) == 0) {
					idx = 0;
					pt_log(kLog_error, "Available pcap devices:\n");
					for (pdev = alldevs; pdev != NULL; pdev = pdev->next) {
						pt_log(kLog_error, "[%d] \"%s\": \"%s\"\n", ++idx,
						       pdev->name, (pdev->description ? pdev->description : "UNKNOWN"));
					}
					pcap_freealldevs(alldevs);
				}
			}
			pc.pkt_q.head	= 0;
			pc.pkt_q.tail	= 0;
			pc.pkt_q.elems	= 0;
			/* Check if we have succeeded, and free stuff if not */
			if (!opts.pcap) {
				pt_log(kLog_error, "There were errors enabling pcap - pcap has been disabled.\n");
				free(pc.pcap_err_buf);
				free(pc.pcap_data_buf);
				return 0;
			}
		}
		else
			pt_log(kLog_info, "pcap disabled since we're running in unprivileged mode.\n");
	}
#endif

	pthread_mutex_lock(&num_threads_lock);
	num_threads++;
	pthread_mutex_unlock(&num_threads_lock);

	/* Allocate icmp receive buffer */
	buf					= (char *) malloc(icmp_receive_buf_len);

	/* Start forwarding :) */
	pt_log(kLog_info, "Ping proxy is listening in %s mode.\n",
	                  (opts.unprivileged ? "unprivileged" : "privileged"));

#ifndef WIN32
#ifdef HAVE_SELINUX
	if (opts.uid || opts.gid || opts.selinux_context)
#else
	if (opts.uid || opts.gid)
#endif
		pt_log(kLog_info, "Dropping privileges now.\n");
	if (opts.gid && -1 == setgid(opts.gid))
		pt_log(kLog_error, "setgid(%d): %s\n", opts.gid, strerror(errno));
	if (opts.uid && -1 == setuid(opts.uid))
		pt_log(kLog_error, "setuid(%d): %s\n", opts.uid, strerror(errno));
#ifdef HAVE_SELINUX
	if (opts.selinux) {
		if (NULL != opts.selinux_context && -1 == setcon(opts.selinux_context))
			pt_log(kLog_error, "setcon(%s) failed: %s\n", opts.selinux_context, strerror(errno));
	}
#endif
#endif

	while (1) {
		FD_ZERO(&set);
		FD_SET(fwd_sock, &set);
		max_sock = fwd_sock+1;
		pthread_mutex_lock(&chain_lock);
		for (cur = chain; cur; cur = cur->next) {
			/* Only handle traffic if there is traffic on the socket, we have
			 * room in our send window AND we either don't use a password, or
			 * have been authenticated.
			 */
			if (cur->sock && cur->send_wait_ack < cur->window_size &&
			    (!opts.password || cur->authenticated))
			{
				FD_SET(cur->sock, &set);
				if (cur->sock >= max_sock)
					max_sock = cur->sock+1;
			}
		}
		pthread_mutex_unlock(&chain_lock);
		timeout.tv_sec  = 0;
		timeout.tv_usec = 10000;
		/* Don't care about return val, since we need to check for new states anyway.. */
		select(max_sock, &set, 0, 0, &timeout);

		pthread_mutex_lock(&chain_lock);
		for (prev = 0, cur = chain; cur && cur->sock; cur = tmp) {
			/* Client: If we're starting up, send a message to the remote end saying so,
			 * causing him to connect to our desired endpoint.
			 */
			if (cur->state == kProxy_start) {
				pt_log(kLog_verbose, "Sending proxy request.\n");
				cur->last_ack = time_as_double();
				queue_packet(fwd_sock, cur, NULL, 0, cur->dst_ip, cur->dst_port, cur->state | cur->type_flag);
				cur->xfer.icmp_out++;
				cur->state = kProto_data;
			}
			if (cur->should_remove) {
				pt_log(kLog_info, "\nSession statistics:\n");
				print_statistics(&cur->xfer, 0);
				pt_log(kLog_info, "\n");
				tmp	= cur->next;
				remove_proxy_desc(cur, prev);
				continue;
			}
			/* Handle TCP traffic */
			if (FD_ISSET(cur->sock, &set)) {
				bytes = recv(cur->sock, cur->buf, tcp_receive_buf_len, 0);
				if (bytes <= 0) {
					pt_log(kLog_info, "Connection closed or lost.\n");
					tmp	= cur->next;
					send_termination_msg(cur, fwd_sock);
					pt_log(kLog_info, "Session statistics:\n");
					print_statistics(&cur->xfer, 0);
					remove_proxy_desc(cur, prev);
					/* No need to update prev */
					continue;
				}
				cur->xfer.bytes_out	+= bytes;
				cur->xfer.icmp_out++;
				queue_packet(fwd_sock, cur, cur->buf, bytes, 0, 0, cur->state | cur->type_flag);
			}
			prev = cur;
			tmp  = cur->next;
		}
		pthread_mutex_unlock(&chain_lock);

		if (FD_ISSET(fwd_sock, &set)) {
			/* Handle ping traffic */
			addr_len = sizeof(struct sockaddr);
			bytes    = recvfrom(fwd_sock, buf, icmp_receive_buf_len, 0, (struct sockaddr*)&addr, &addr_len);
			if (bytes < 0) {
				pt_log(kLog_error, "Error receiving packet on ICMP socket: %s\n", strerror(errno));
				break;
			}
			handle_packet(buf, bytes, 0, &addr, fwd_sock);
		}

		/* Check for packets needing resend, and figure out if any connections
		 * should be closed down due to inactivity.
		 */
		pthread_mutex_lock(&chain_lock);
		now = time_as_double();
		for (cur = chain; cur; cur = cur->next) {
			in_addr.s_addr = cur->dst_ip;
			if (cur->last_activity + kAutomatic_close_timeout < now) {
				pt_log(kLog_info, "Dropping tunnel %u to %s:%u due to inactivity.\n", cur->id_no, inet_ntoa(in_addr), cur->dst_port);
				cur->should_remove = 1;
				continue;
			}
			if (cur->recv_wait_send && cur->sock)
				cur->xfer.bytes_in += send_packets(cur->recv_ring, &cur->recv_xfer_idx, &cur->recv_wait_send, &cur->sock, cur->window_size);

			/* Check for any icmp packets requiring resend, and resend _only_ the first packet. */
			idx	= cur->send_first_ack;
			if (cur->send_ring[idx].pkt && cur->send_ring[idx].last_resend+cur->resend_interval < now) {
				pt_log(kLog_debug, "Resending packet with seq-no %d.\n", cur->send_ring[idx].seq_no);
				cur->send_ring[idx].last_resend   = now;
				cur->send_ring[idx].pkt->identifier = htons(cur->icmp_id);
				cur->send_ring[idx].pkt->seq      = htons(cur->ping_seq);
				cur->ping_seq++;
				cur->send_ring[idx].pkt->checksum = 0;
				cur->send_ring[idx].pkt->checksum = htons(calc_icmp_checksum((uint16_t*)cur->send_ring[idx].pkt, cur->send_ring[idx].pkt_len));
				/* printf("ID: %d\n", htons(cur->send_ring[idx].pkt->identifier)); */
				sendto(fwd_sock, (const void*)cur->send_ring[idx].pkt, cur->send_ring[idx].pkt_len,
				       0, (struct sockaddr*)&cur->dest_addr, sizeof(struct sockaddr));
				cur->xfer.icmp_resent++;
			}
			/* Figure out if it's time to send an explicit acknowledgement */
			if (cur->last_ack+cur->ack_interval < now && cur->send_wait_ack < cur->window_size &&
			    cur->remote_ack_val+1 != cur->next_remote_seq)
			{
				queue_packet(fwd_sock, cur, NULL, 0, cur->dst_ip, cur->dst_port, kProto_ack | cur->type_flag);
				cur->last_ack = now;
				cur->xfer.icmp_ack_out++;
			}
		}
		pthread_mutex_unlock(&chain_lock);
#ifdef HAVE_PCAP
		if (opts.pcap) {
			if (pcap_dispatch(pc.pcap_desc, 32, pcap_packet_handler, (u_char*)&pc.pkt_q) > 0) {
				pqueue_elem_t	*cur;
				pt_log(kLog_verbose, "pcap captured %d packets - handling them..\n", pc.pkt_q.elems);
				while (pc.pkt_q.head) {
					cur                  = pc.pkt_q.head;
					memset(&addr, 0, sizeof(struct sockaddr));
					addr.sin_family      = AF_INET;
					pkt                  = (ip_packet_t*)&cur->data[0];
					ip                   = pkt->src_ip;
					adr                  = (in_addr_t*)&ip;
					addr.sin_addr.s_addr = *adr;
					handle_packet(cur->data, cur->bytes, 1, &addr, fwd_sock);
					pc.pkt_q.head        = cur->next;
					free(cur);
					pc.pkt_q.elems--;
				}
				pc.pkt_q.tail            = 0;
				pc.pkt_q.head            = 0;
			}
		}
#endif
		/* Update running statistics, if requested (only once every second) */
		if (opts.print_stats && opts.mode == kMode_forward && now > last_status_update+1) {
			pthread_mutex_lock(&chain_lock);
			memset(&xfer, 0, sizeof(xfer_stats_t));
			for (cur = chain; cur; cur = cur->next) {
				xfer.bytes_in		+= cur->xfer.bytes_in;
				xfer.bytes_out		+= cur->xfer.bytes_out;
				xfer.icmp_in		+= cur->xfer.icmp_in;
				xfer.icmp_out		+= cur->xfer.icmp_out;
				xfer.icmp_resent	+= cur->xfer.icmp_resent;
			}
			pthread_mutex_unlock(&chain_lock);
			print_statistics(&xfer, (opts.log_level >= kLog_verbose ? 0 : 1));
			last_status_update		= now;
		}
	}
	pt_log(kLog_debug, "Proxy exiting..\n");
	if (fwd_sock)
		close(fwd_sock);
	/* TODO: Clean up the other descs. Not really a priority since there's no
	 * real way to quit ptunnel in the first place..
	 */
	free(buf);
	pt_log(kLog_debug, "Ping proxy done\n");
	return 0;
}

/* print_statistics: Prints transfer statistics for the given xfer block. The
 * is_continuous variable controls the output mode, either printing a new line
 * or overwriting the old line.
 */
void print_statistics(xfer_stats_t *xfer, int is_continuous) {
	const double mb   = 1024.0*1024.0;
	double       loss = 0.0;

	if (xfer->icmp_out > 0)
		loss = (double)xfer->icmp_resent/(double)xfer->icmp_out;

	if (is_continuous)
		printf("\r");

	printf("[inf]: I/O: %6.2f/%6.2f mb ICMP I/O/R: %8u/%8u/%8u Loss: %4.1f%%",
			xfer->bytes_in/mb, xfer->bytes_out/mb, xfer->icmp_in, xfer->icmp_out, xfer->icmp_resent, loss);

	if (!is_continuous)
		printf("\n");
	else
		fflush(stdout);
}

#ifdef HAVE_PCAP
/* pcap_packet_handler:
 * This is our callback function handling captured packets. We already know that the packets
 * are ICMP echo or echo-reply messages, so all we need to do is strip off the ethernet header
 * and append it to the queue descriptor (the refcon argument).
 *
 * Ok, the above isn't entirely correct (we can get other ICMP types as well). This function
 * also has problems when it captures packets on the loopback interface. The moral of the
 * story: Don't do ping forwarding over the loopback interface.
 *
 * Also, we currently don't support anything else than ethernet when in pcap mode. The reason
 * is that I haven't read up on yet on how to remove the frame header from the packet..
 */
void pcap_packet_handler(u_char *refcon, const struct pcap_pkthdr *hdr, const u_char* pkt) {
	pqueue_t      *q;
	pqueue_elem_t *elem;
	ip_packet_t   *ip;

	/* pt_log(kLog_verbose, "Packet handler: %d =? %d\n", hdr->caplen, hdr->len); */
	q    = (pqueue_t*)refcon;
	elem = (pqueue_elem_t *) malloc(sizeof(pqueue_elem_t)+hdr->caplen-sizeof(struct ether_header));
	memcpy(elem->data, pkt+sizeof(struct ether_header), hdr->caplen-sizeof(struct ether_header));
	ip   = (ip_packet_t*)elem->data;
	/* TODO: Add fragment support */
	elem->bytes	= ntohs(ip->pkt_len);
	if (elem->bytes > hdr->caplen-sizeof(struct ether_header)) {
		pt_log(kLog_error, "Received fragmented packet - unable to reconstruct!\n");
		pt_log(kLog_error, "This error usually occurs because pcap is used on "
		                   "devices that are not wlan or ethernet.\n");
		free(elem);
		return;
	}
	/* elem->bytes = hdr->caplen-sizeof(struct ether_header); */
	elem->next	= 0;
	if (q->tail) {
		q->tail->next = elem;
		q->tail       = elem;
	}
	else {
		q->head	= elem;
		q->tail	= elem;
	}
	q->elems++;
}
#endif

uint16_t calc_icmp_checksum(uint16_t *data, int bytes) {
	uint32_t sum;
	int      i;

	sum	= 0;
	for (i = 0; i < bytes / 2; i++) {
		/* WARNING; this might be a bug, but might explain why I occasionally
		 * see buggy checksums.. (added htons, that might be the correct behaviour)
		 */
		sum	+= data[i];
	}
	sum	= (sum & 0xFFFF) + (sum >> 16);
	sum	= htons(0xFFFF - sum);
	return sum;
}

/* send_termination_msg: Sends two packets to the remote end, informing it that
 * the tunnel is being closed down.
 */
void send_termination_msg(proxy_desc_t *cur, int icmp_sock) {
	size_t i;
	const size_t max_termination_msgs = 3;

	/* Send packet twice, hoping at least one of them makes it through.. */
	for (i = 0; i < max_termination_msgs; ++i) {
		queue_packet(icmp_sock, cur, NULL, 0, cur->dst_ip, cur->dst_port, kProto_close | cur->type_flag);
	}
	cur->xfer.icmp_out += max_termination_msgs;
}
