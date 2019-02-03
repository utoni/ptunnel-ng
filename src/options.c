/*
 * options.c
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

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <assert.h>
#ifdef WIN32
#include <ws2tcpip.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "options.h"
#include "utils.h"
#include "ptunnel.h"
#include "md5.h"


struct options opts;

enum option_type {
	OPT_BOOL, OPT_DEC32, OPT_HEX32, OPT_STR
};

struct option_usage {
	const char *short_help;
	int required;
	enum option_type otype;
	union {
		int32_t num;
		uint32_t unum;
		const char *str;
	};
	const char *long_help;
};

static const struct option_usage usage[] = {
	/** --magic */
	{"magic",        0, OPT_HEX32,  {.unum = 0xdeadc0de},
		"Set ptunnel magic hexadecimal number. (32-bit unsigned)\n"
		"It is an identifier for all ICMP/UDP packets\n"
		"and can be used to bypass Cisco IPS fingerprint scan.\n"
		"This value has to be the same on the server and client!\n"
	},
	/** --proxy */
	{"address",      1, OPT_STR,    {.str = NULL},
		"Set address of peer running packet forwarder. This causes\n"
		"ptunnel to operate in forwarding mode (Client) - the absence of this\n"
		"option causes ptunnel to operate in proxy mode (Server).\n"
	},
	/** --listen */
	{"port",         0, OPT_DEC32,  {.unum = 2222},
		"Set TCP listening port (only used when operating in forward mode)\n"
	},
	/** --remote-addr */
	{"address",      1, OPT_STR,    {.str = "127.0.0.1"},
		"Set remote proxy destination address if client\n"
		"Restrict to only this destination address if server\n"
	},
	/** --remote-port */
	{"port",         1, OPT_DEC32,  {.unum = 22},
		"Set remote proxy destination port if client\n"
		"Restrict to only this destination port if server\n"
	},
	/** --connections */
	{"connections",  0, OPT_DEC32,  {.unum = kMax_tunnels},
		"Set maximum number of concurrent tunnels\n"
	},
	/** --verbosity */
	{"level",        0, OPT_DEC32,  {.num = kLog_event},
		"Verbosity level (-1 to 4, where -1 is no output, and 4 is all output)\n"
		"The special level 5 (or higher) includes xfer logging (lots of output)\n"
	},
	/** --libpcap */
	{"interface",    0, OPT_STR,    {.str = "eth0"},
#ifndef HAVE_PCAP
		"(Not available on this platform.)\n"
#endif
		"Enable libpcap on the given device.\n"
	},
	/** --logfile */
	{"file",         0, OPT_STR,    {.str = "/var/log/ptunnel.log"},
		"Specify a file to log to, rather than printing to standard out.\n"
	},
	/** --statistics */
	{NULL,           0, OPT_BOOL,   {.num = 0},
		"Client only. Enables continuous output of statistics (packet loss, etc.)\n"
	},
	/** --passwd */
	{"password",     0, OPT_STR,    {.str = NULL},
		"Set a password (must be same on client and proxy)\n"
	},
	/** --udp */
	{NULL,           0, OPT_BOOL,   {.num = 0},
		"Toggle use of UDP instead of ICMP. Proxy will listen on port 53 (must be root).\n"
	},
	/** --unprivileged */
	{NULL,           0, OPT_BOOL,   {.num = 0},
		"Run proxy in unprivileged mode. This causes the proxy to forward\n"
		"packets using standard echo requests, instead of crafting custom echo replies.\n"
		"Unprivileged mode will only work on some systems, and is in general less reliable\n"
		"than running in privileged mode.\n"
	},
	/** --daemon */
	{"pidfile",      0, OPT_STR,    {.str = "/run/ptunnel.pid"},
#ifdef WIN32
		"(Not available on this platform.)\n"
#endif
		"Run in background, the PID will be written in the file supplied as argument\n"
	},
	/** --syslog */
	{NULL,           0, OPT_BOOL,   {.num = 0},
#ifdef WIN32
		"(Not available on this platform.)\n"
#endif
		"Output debug to syslog instead of standard out.\n"
	},
	/** --user */
	{"user",         0, OPT_STR,    {.str = "nobody"},
#ifdef WIN32
		"(Not available on this platform.)\n"
#endif
		"When started in privileged mode, drop down to user's rights as soon as possible\n"
	},
	/** --group */
	{"group",        0, OPT_STR,    {.str = "nogroup"},
#ifdef WIN32
		"(Not available on this platform.)\n"
#endif
		"When started in privileged mode, drop down to group's rights as soon as possible\n"
	},
	/** --chroot */
	{"directory",    0, OPT_STR,    {.str = "/var/lib/ptunnel"},
#ifdef WIN32
		"(Not available on this platform.)\n"
#endif
		"When started in privileged mode, restrict file access to the specified directory\n"
	},
	/** --setcon */
	{"context",      0, OPT_STR,    {.str = "ptunnel"},
#ifndef HAVE_SELINUX
		"(Not available on this platform.)\n"
#endif
		"Set SELinux context when all there is left to do are network I/O operations\n"
		"To combine with --chroot you will have to `mount --bind /proc /chrootdir/proc`\n"
	},
	/** --help */
	{NULL,           0, OPT_STR,    {.str = NULL}, "this\n"},
	{NULL,0,OPT_BOOL,{.unum=0},NULL}
};

static struct option long_options[] = {
	{"magic",       required_argument, 0, 'm'},
	{"proxy",       required_argument, 0, 'p'},
	{"listen",      required_argument, 0, 'l'},
	{"remote-addr", optional_argument, 0, 'r'},
	{"remote-port", optional_argument, 0, 'R'},
	{"connections", required_argument, 0, 'c'},
	{"verbosity",   required_argument, 0, 'v'},
	{"libpcap",     required_argument, 0, 'L'},
	{"logfile",     optional_argument, 0, 'o'},
	{"statistics",        no_argument, 0, 's'},
	{"passwd",      required_argument, 0, 'P'},
	{"udp",               no_argument, &opts.udp, 1 },
	{"unprivileged",      no_argument, &opts.unprivileged, 1 },
	{"daemon",      optional_argument, 0, 'd'},
	{"syslog",            no_argument, 0, 'S'},
	{"user",        optional_argument, 0, 'u'},
	{"group",       optional_argument, 0, 'g'},
	{"chroot",      optional_argument, 0, 'C'},
	{"setcon",      optional_argument, 0, 'e'},
	{"help",              no_argument, 0, 'h'},
	{NULL,0,0,0}
};


static const void *get_default_optval(enum option_type opttype, const char *optname) {
	for (unsigned i = 0; i < ARRAY_SIZE(long_options); ++i) {
		if (strncmp(long_options[i].name, optname, strlen(long_options[i].name)) == 0) {
			assert(usage[i].otype == opttype);
			return &usage[i].str;
		}
	}
	assert(NULL);
	return NULL;
}

static void set_options_defaults(void) {
#ifndef WIN32
	char *tmp;
	struct passwd *pwnam;
	struct group *grnam;
#endif

	memset(&opts, 0, sizeof(opts));
	opts.magic           = *(uint32_t *)  get_default_optval(OPT_HEX32, "magic");
	opts.mode            = kMode_proxy;
	opts.tcp_listen_port = *(uint32_t *)  get_default_optval(OPT_DEC32, "listen");
	opts.given_dst_hostname = strdup(*(char **) get_default_optval(OPT_STR, "remote-addr"));
	opts.given_dst_port  = *(uint32_t *)  get_default_optval(OPT_DEC32, "remote-port");
	opts.max_tunnels     = *(uint32_t *)  get_default_optval(OPT_DEC32, "connections");
	opts.log_level       = *(int *)       get_default_optval(OPT_DEC32, "verbosity");
#ifdef HAVE_PCAP
	opts.pcap_device     = strdup(*(char **)get_default_optval(OPT_STR, "libpcap"));
#endif
	opts.log_path        = strdup(*(char **)get_default_optval(OPT_STR, "logfile"));
	opts.log_file        = stdout;
	opts.print_stats     = *(int *)       get_default_optval(OPT_BOOL,  "statistics");
	opts.udp             = *(int *)       get_default_optval(OPT_BOOL,  "udp");
	opts.unprivileged    = *(int *)       get_default_optval(OPT_BOOL,  "unprivileged");
#ifndef WIN32
	opts.pid_path        = strdup(*(char **)get_default_optval(OPT_STR, "daemon"));

	errno = 0;
	tmp = *(char **) get_default_optval(OPT_STR, "user");
	if (NULL == (pwnam = getpwnam(tmp)))
		pt_log(kLog_error, "%s: %s\n", tmp, errno ? strerror(errno) : "unknown user");
	else {
		opts.uid = pwnam->pw_uid;
		if (!opts.gid)
			opts.gid = pwnam->pw_gid;
	}

	errno = 0;
	tmp = *(char **) get_default_optval(OPT_STR, "group");
	if (NULL != (grnam = getgrnam(tmp)))
		opts.gid = grnam->gr_gid;

	opts.root_dir        = strdup(*(char **)get_default_optval(OPT_STR, "chroot"));
#endif
#ifdef HAVE_SELINUX
	opts.selinux_context = strdup(*(char **)get_default_optval(OPT_STR, "setcon"));
#endif
}

static void print_multiline(const char *prefix, const char *multiline) {
	const char sep[] = "\n";
	const char *start, *end;

	start = multiline;
	do {
		if (start) {
			end = strstr(start, sep);
			if (end) {
				printf("%s%.*s\n", prefix, (int)(end-start), start);
				start = end + strlen(sep);
			}
		}
	} while (start && end);
}

static void print_long_help(unsigned index, int required_state) {
	const char spaces[] = "            ";

	if (usage[index].required != required_state)
		return;
	if (!long_options[index].name)
		return;

	if (isalpha(long_options[index].val)) {
		printf("%.*s-%c --%s\n", 4, spaces, long_options[index].val, long_options[index].name);
	} else {
		printf("%.*s--%s\n", 4, spaces, long_options[index].name);
	}

	if (usage[index].long_help) {
		print_multiline(&spaces[4], usage[index].long_help);
	}

	switch (usage[index].otype) {
		case OPT_BOOL:
			break;
		case OPT_DEC32:
			printf("%s(default: %d)\n", spaces, usage[index].num);
			break;
		case OPT_HEX32:
			printf("%s(default: 0x%X)\n", spaces, usage[index].unum);
			break;
		case OPT_STR:
			if (usage[index].str)
				printf("%s(default: %s)\n", spaces, usage[index].str);
			break;
	}
}

static void print_short_help(unsigned index, int required_state) {
	const char *ob = (required_state == 0 ? "[" : "");
	const char *cb = (required_state == 0 ? "]" : "");
	const char *ov = (long_options[index].has_arg != optional_argument ? " " : "");

	if (usage[index].required != required_state)
		return;
	if (!long_options[index].name)
		return;

	if (!usage[index].short_help && isalpha(long_options[index].val)) {
		printf(" %s-%c%s", ob, long_options[index].val, cb);
	}
	else if (!usage[index].short_help) {
		printf(" %s--%s%s", ob, long_options[index].name, cb);
	}
	else if (isalpha(long_options[index].val)) {
		printf(" %s-%c%s<%s>%s", ob, long_options[index].val, ov, usage[index].short_help, cb);
	}
	else {
		printf(" %s--%s <%s>%s", ob, long_options[index].name, usage[index].short_help, cb);
	}
}

void print_usage(const char *arg0) {
	unsigned i;

	printf("%s\n\nUsage: %s", PACKAGE_STRING, arg0);
	/* print (short)help argument line */
	for (i = 0; i < ARRAY_SIZE(usage); ++i) {
		print_short_help(i, 1);
	}
	for (i = 0; i < ARRAY_SIZE(usage); ++i) {
		print_short_help(i, 0);
	}

	printf("%s", "\n\n");
	/* print (long)help lines */
	for (i = 0; i < ARRAY_SIZE(usage); ++i) {
		print_long_help(i, 1);
	}
	for (i = 0; i < ARRAY_SIZE(usage); ++i) {
		print_long_help(i, 0);
	}
}

int parse_options(int argc, char **argv) {
	int c = 0, oidx = -1, has_logfile = 0, ret;
	md5_state_t state;
#ifndef WIN32
	struct passwd *pwnam;
	struct group *grnam;
#endif
	FILE *tmp_log;

	assert( ARRAY_SIZE(long_options) == ARRAY_SIZE(usage) );

	/* set defaults */
	set_options_defaults();

	/* parse command line arguments */
	while (1) {
        /* FIXME: We are using '::' (optional argument values). This is not optimal
         *        since you have to pass long options as '--option=value'. Commonly used
         *        '--option value' is *NOT* allowed for some libc implementations.
         */
		c = getopt_long(argc, argv, "m:p:l:r::R::c:v:L::o::sP:d::Su::g::C::e::h", &long_options[0], &oidx);
		if (c == -1) break;

		switch (c) {
			case 'm':
				if (!optarg)
					break;
				opts.magic = strtoul(optarg, NULL, 16);
				break;
			case 'p':
				if (!optarg)
					break;
				opts.mode = kMode_forward;
				if (opts.given_proxy_hostname)
					free(opts.given_proxy_hostname);
				opts.given_proxy_hostname = strdup(optarg);
				break;
			case 'l':
				if (!optarg)
					break;
				opts.tcp_listen_port = strtoul(optarg, NULL, 10);
				break;
			case 'r':
				opts.restrict_dst_ip = 1;
				if (!optarg)
					break;
				if (opts.given_dst_hostname)
					free(opts.given_dst_hostname);
				opts.given_dst_hostname = strdup(optarg);
				break;
			case 'R':
				opts.restrict_dst_port = 1;
				if (optarg)
					opts.given_dst_port = strtoul(optarg, NULL, 10);
				break;
			case 'c':
				if (!optarg)
					break;
				opts.max_tunnels = strtoul(optarg, NULL,10);
				if (opts.max_tunnels > kMax_tunnels)
					opts.max_tunnels = kMax_tunnels;
				break;
			case 'v':
				if (!optarg)
					break;
				opts.log_level = strtol(optarg, NULL, 10);
				break;
			case 'L':
#ifdef HAVE_PCAP
				opts.pcap = 1;
				if (!optarg)
					break;
				if (opts.pcap_device)
					free(opts.pcap_device);
				opts.pcap_device = strdup(optarg);
				break;
#else
				pt_log(kLog_error, "pcap: %s\n", "feature not supported");
				exit(1);
#endif
			case 'o':
				has_logfile = 1;
				if (!optarg)
					break;
				if (opts.log_path)
					free(opts.log_path);
				opts.log_path = strdup(optarg);
				break;
			case 's':
				opts.print_stats = !opts.print_stats;
				break;
			case 'P':
				if (!optarg)
					break;
				if (opts.password)
					free(opts.password);
				opts.password = strdup(optarg);
				pt_log(kLog_debug, "Password set - unauthenicated connections will be refused.\n");
				//  Compute the password digest
				md5_init(&state);
				md5_append(&state, (md5_byte_t*)optarg, strlen(opts.password));
				md5_finish(&state, &opts.password_digest[0]);
				//  Hide the password in process listing
				memset(optarg, '*', strlen(optarg));
				break;
#ifndef WIN32
			case 'd':
				opts.daemonize = true;
				if (!optarg)
					break;
				if (opts.pid_path)
					free(opts.pid_path);
				opts.pid_path = strdup(optarg);
				break;
			case 'S':
				opts.use_syslog = 1;
				break;
			case 'u':
				if (!optarg)
					break;
				errno = 0;
				if (NULL == (pwnam = getpwnam(optarg))) {
					pt_log(kLog_error, "%s: %s\n", optarg, errno ? strerror(errno) : "unknown user");
					exit(1);
				}
				opts.uid = pwnam->pw_uid;
				if (!opts.gid)
					opts.gid = pwnam->pw_gid;
				break;
			case 'g':
				if (!optarg)
					break;
				errno = 0;
				if (NULL == (grnam = getgrnam(optarg))) {
					pt_log(kLog_error, "%s: %s\n", optarg, errno ? strerror(errno) : "unknown group");
					exit(1);
				}
				opts.gid = grnam->gr_gid;
				break;
			case 'C':
				opts.chroot = 1;
				if (!optarg)
					break;
				if (opts.root_dir)
					free(opts.root_dir);
				opts.root_dir = strdup(optarg);
				break;
#else
			case 'd':
			case 'S':
			case 'u':
			case 'g':
			case 'C':
				pt_log(kLog_error, "-%c: %s\n", c, "feature not supported");
				exit(1);
#endif
			case 'e':
#ifdef HAVE_SELINUX
				opts.selinux = 1;
				if (!optarg)
					break;
				if (opts.selinux_context)
					free(opts.selinux_context);
				opts.selinux_context = strdup(optarg);
				break;
#else
				pt_log(kLog_error, "SeLinux: %s\n", "feature not supported");
				exit(1);
#endif
			case 'h':
				print_usage(argv[0]);
				exit(EXIT_SUCCESS);
			case 0: /* long opt only */
			default:
				break;
		}
	}

	if (optind != argc) {
		pt_log(kLog_error, "Unknown argument: '%s'\n", argv[optind]);
		exit(1);
	}

	if (opts.given_proxy_hostname) {
		if ((ret = host_to_addr(opts.given_proxy_hostname, &opts.given_proxy_ip)) != 0) {
			pt_log(kLog_error, "Failed to look up %s as destination address: %s\n",
			       opts.given_proxy_hostname, gai_strerror(ret));
			return 1;
		}
	}

	if ((ret = host_to_addr(opts.given_dst_hostname, &opts.given_dst_ip)) != 0) {
		pt_log(kLog_error, "Failed to look up %s as destination address: %s\n",
		       opts.given_dst_hostname, gai_strerror(ret));
		return 1;
	}

#ifndef WIN32
	if (NULL == (opts.pid_file = fopen(opts.pid_path, "w")))
		pt_log(kLog_error, "Failed to open pidfile: \"%s\", Cause: %s\n", opts.pid_path, strerror(errno));
#endif

	if (has_logfile && opts.log_path) {
		pt_log(kLog_info, "Open Logfile: \"%s\"\n", opts.log_path);
		tmp_log = fopen(opts.log_path, "a");
		if (!tmp_log) {
			pt_log(kLog_error, "Failed to open log file: \"%s\", Cause: %s\n", opts.log_path, strerror(errno));
			pt_log(kLog_error, "Reverting log to standard out.\n");
		} else opts.log_file = tmp_log;
	}

	return 0;
}
