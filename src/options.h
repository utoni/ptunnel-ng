/*
 * options.h
 * ptunnel is licensed under the BSD license:
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
 */

#ifndef OPTIONS_H
#define OPTIONS_H 1

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#ifndef WIN32
#include <pwd.h>
#include <grp.h>
#endif
#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "md5.h"
#include "pconfig.h"

struct options {
	/** user defined magic value (prevent Cisco WSA/IronPort fingerprint scan) */
	uint32_t magic;
	/** proxy or forwarder? */
	int mode;
	/** Proxy's internet address */
	char *given_proxy_hostname;
	uint32_t given_proxy_ip;
	/** Port the client listens on */
	uint32_t tcp_listen_port;
	/** restrict Forward/Proxy destination internet address */
	int restrict_dst_ip;
	char *given_dst_hostname;
	uint32_t given_dst_ip;
	/** restrict Forward/Proxy destination port */
	int restrict_dst_port;
	uint32_t given_dst_port;
	/** Default maximum number of tunnels to support at once */
	uint32_t max_tunnels;
	/** Default log level */
	int log_level;
#ifdef HAVE_PCAP
	/** Non zero value if user wants packet capturing */
	int pcap;
	/** Device to capture packets from */
	char *pcap_device;
#endif
	/** Force SHA512 based challenge response. */
	int force_sha512;
	/** List all available pcap devices and exit */
	int list_pcap_devices;
	/** Usually stdout, but can be altered by the user */
	char *log_path;
	FILE *log_file;
	/** Print more detailed traffic statistics if non zero value */
	int print_stats;
	/** Password (must be the same on proxy and client for authentica  tion to succeed) */
	char *password;
	/** MD5 digest of password */
	md5_byte_t md5_password_digest[kMD5_digest_size];
	/** SHA512 digest of password */
	unsigned char sha512_password_digest[kSHA512_digest_size];
	/** use UDP instead of ICMP */
	int udp;
	/** unpriviledged mode */
	int unprivileged;

#ifndef WIN32
	/** run as daemon if non zero value */
	int daemonize;
	/** PIDFILE if running as daemon */
	char *pid_path;
	FILE *pid_file;
	/** log to syslog if non zero value */
	int use_syslog;
	/** UID of the running process */
	uid_t uid;
	/** GID of the running process */
	gid_t gid;
	/** CHROOT dir */
	int chroot;
	char *root_dir;
#endif

#ifdef HAVE_SELINUX
	/** Non zero value if uer wants SeLinux */
	int selinux;
	/** SeLinux context name */
	char *selinux_context;
#endif
};

extern struct options opts;

void print_usage(const char *arg0);

int parse_options(int argc, char **argv);

#endif
