#ifndef OPTIONS_H
#define OPTIONS_H 1

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "ptunnel.h"


struct options {
	/** proxy or forwarder? */
	int proxy_mode;
	/** user defined magic value (prevent Cisco WSA/IronPort fingerprint scan) */
	uint32_t magic;
	/** Proxy's internet address */
	uint32_t given_proxy_ip; 
	/** Password-Digest (must be the same on proxy and client for authentication to succeed) */
	unsigned char *password_digest;
	/** Port the client listens on */
	uint16_t tcp_listen_port;
	/** Proxy's internet address */
	uint32_t given_dst_ip;
	/** Port to send data to from the proxy */
	int tcp_port;
	/** Default maximum number of tunnels to support at once */
	uint32_t max_tunnels;
	/** Default log level */
	int log_level;
	/** Device to capture packets from */
	char *pcap_device;
	/** Usually stdout, but can be altered by the user */
	FILE *log_file;
	/** Print more detailed traffic statistics if non zero value */
	int print_stats;
	/** use UDP instead of ICMP */
	int udp;
	/** unpriviledged mode */
	int unprivledged;

#ifdef HAVE_SELINUX
	char *selinux_context;
#endif
#ifndef WIN32
	/** UID of the running process */
	uid_t uid;
	/** GID of the running process */
	gid_t gid;
	/** CHROOT dir */
	char *root_dir;
	/** PIDFILE */
	FILE *pid_file;
	/** run as daemon */
	bool daemonize;
	/** log to syslog if non zero value */
	int syslog;
#endif
};

extern struct options opts;

void print_usage(const char *arg0);

int parse_options(int argc, char **argv);

#endif
