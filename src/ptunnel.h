/*
 * ptunnel.h
 * ptunnel is licensed under the BSD license:
 *
 * Copyright (c) 2004-2011, Daniel Stoedle <daniels@cs.uit.no>,
 * Yellow Lemon Software. All rights reserved.
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

#ifndef PING_TUNNEL_H
#define PING_TUNNEL_H 1

#ifndef WIN32
#ifdef HAVE_ICMPFILTER
#include <linux/icmp.h>
#endif
#ifdef HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <net/ethernet.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#endif /* !WIN32 */
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#ifdef HAVE_PCAP
#include <pcap.h>
#endif

#include "pkt.h"
#include "pdesc.h"
#include "challenge.h"

#ifdef WIN32
/* pthread porting to windows */
typedef CRITICAL_SECTION  pthread_mutex_t;
typedef unsigned long     pthread_t;
#define pthread_mutex_init    InitializeCriticalSectionAndSpinCount
#define pthread_mutex_lock    EnterCriticalSection
#define pthread_mutex_unlock  LeaveCriticalSection
#endif
extern pthread_mutex_t chain_lock;
extern uint32_t num_tunnels;
extern const int icmp_receive_buf_len;
extern proxy_desc_t *chain;
extern time_t *seq_expiry_tbl;
extern const char *state_name[kNum_proto_types];

/* pt_thread_info_t: A simple (very simple, in fact) structure that allows us
 * to pass an arbitrary number of params to the threads we create. Currently,
 * that's just one single parameter: The socket which the thread should listen
 * to.
 */
typedef struct {
	int sock;
} pt_thread_info_t;

#ifdef HAVE_PCAP
/* pqueue_elem_t: An queue element in the pqueue structure (below).
 */
typedef struct pqueue_elem_t {
	/** size of data buffer */
	unsigned long bytes;
	/** next queue element (if any) */
	struct pqueue_elem_t *next;
	/** optional data */
	char data[0];
} pqueue_elem_t;

/* pqueue_t: A simple queue strucutre.
 */
typedef struct {
	pqueue_elem_t *head;
	pqueue_elem_t *tail;
	int elems;
} pqueue_t;

/* pcap_info_t: Structure to hold information related to packet capturing.
 */
typedef struct {
	pcap_t *pcap_desc;
	/** compiled filter program */
	struct bpf_program fp;
	uint32_t netp;
	uint32_t netmask;
	/** buffers for error info */
	char *pcap_err_buf;
	/** buffers for packet info */
	char *pcap_data_buf;
	/** queue of packets to process */
	pqueue_t pkt_q;
} pcap_info_t;
#endif

/* function Prototypes */
#ifndef WIN32
void * pt_proxy(void *args);
#else
unsigned int __stdcall pt_proxy(void *args);
#endif

#ifdef HAVE_PCAP
void     pcap_packet_handler(u_char *refcon, const struct pcap_pkthdr *hdr,
                         const u_char* pkt);
#endif

void     pt_forwarder(void);

void     print_statistics(xfer_stats_t *xfer, int is_continuous);

uint16_t calc_icmp_checksum(uint16_t *data, int bytes);

void     send_termination_msg(proxy_desc_t *cur, int icmp_sock);

#endif
