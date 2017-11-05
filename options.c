#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <assert.h>

#include "options.h"
#include "utils.h"

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
	{"magic",        0, OPT_HEX32,  {.unum = 0xdeadc0de},
		"Set ptunnel magic hexadecimal number. (32-bit unsigned)\n"
		"This will be prefixed in all ICMP packets\n"
		"and can be used to bypass Cisco IPS\n"
		"This value has to be the same on the server and client!\n"
	},
	{"address:port", 1, OPT_STR,    {.unum = 0},
		"Set address of peer running packet forwarder. This causes\n"
		"ptunnel to operate in forwarding mode - the absence of this\n"
		"option causes ptunnel to operate in proxy mode.\n"
	},
	{"port",         1, OPT_DEC32,  {.num = 1234},
		"Set TCP listening port (only used when operating in forward mode)\n"
	},
	{"address:port", 1, OPT_STR,    {.str = "127.0.0.1:22"},
		"Set remote proxy destination address:port if client\n"
		"Restrict to only this destination address:port if server\n"
	},
	{"connections",  0, OPT_DEC32,  {.num = 4},
		"Set maximum number of concurrent tunnels\n"
	},
	{"level",        0, OPT_DEC32,  {.num = 1},
		"Verbosity level (-1 to 4, where -1 is no output, and 4 is all output)\n"
	},
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Enable libpcap on the given device.\n"
	},
	{"file",         0, OPT_STR,    {.str = "/var/log/ptunnel.log"},
		"Specify a file to log to, rather than printing to standard out.\n"
	},
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Client only. Enables continuous output of statistics (packet loss, etc.)\n"
	},
#ifndef WIN32
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Run in background, the PID will be written in the file supplied as argument\n"
	},
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Output debug to syslog instead of standard out.\n"
	},
#endif
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Toggle use of UDP instead of ICMP. Proxy will listen on port 53 (must be root).\n"
	},
	{"password",     0, OPT_STR,    {.str = NULL},
		"Set password (must be same on client and proxy)\n"
		"If no password is set, you will be asked during runtime.\n"
	},
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Run proxy in unprivileged mode. This causes the proxy to forward\n"
		"packets using standard echo requests, instead of crafting custom echo replies.\n"
		"Unprivileged mode will only work on some systems, and is in general less reliable\n"
		"than running in privileged mode.\n"
	},
#ifndef WIN32
	{"user",         0, OPT_STR,    {.str = "nobody"},
		"When started in privileged mode, drop down to user's rights as soon as possible\n"
	},
	{"group",        0, OPT_STR,    {.str = "nogroup"},
		"When started in privileged mode, drop down to group's rights as soon as possible\n"
	},
	{"directory",    0, OPT_STR,    {.str = "/var/lib/ptunnel"},
		"When started in privileged mode, restrict file access to the specified directory\n"
	},
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Set SELinux context when all there is left to do are network I/O operations\n"
		"To combine with -chroot you will have to `mount --bind /proc /chrootdir/proc`\n"
	},
#endif
	{NULL,0,OPT_BOOL,{.unum=0},NULL}
};

static struct option long_options[] = {
	{"magic",       required_argument, 0, 'm'},
	{"proxy",       required_argument, 0, 'p'},
	{"listen",      required_argument, 0, 'l'},
	{"remote",      required_argument, 0, 'r'},
	{"connections", required_argument, 0, 'c'},
	{"verbosity",   required_argument, 0, 'v'},
	{"libpcap",           no_argument, 0,  0 },
	{"logfile",     required_argument, 0, 'o'},
	{"statistics",        no_argument, 0, 's'},
#ifndef WIN32
	{"daemon",            no_argument, 0, 'd'},
	{"syslog",            no_argument, 0,  0 },
#endif
	{"udp",               no_argument, 0,  0 },
	{"passwd",      optional_argument, 0, 'x'},
	{"unprivileged",      no_argument, 0,  0 },
	{"user",        required_argument, 0, 'u'},
	{"group",       required_argument, 0, 'g'},
	{"chroot",      optional_argument, 0,  0 },
	{"setcon",            no_argument, 0, 'e'},
	{NULL,0,0,0}
};

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
		printf(" %s-%c <%s>%s", ob, long_options[index].val, usage[index].short_help, cb);
	}
	else {
		printf(" %s--%s <%s>%s", ob, long_options[index].name, usage[index].short_help, cb);
	}
}

void print_usage(const char *arg0) {
	unsigned i;

	assert( ARRAY_SIZE(long_options) == ARRAY_SIZE(usage) );

	printf("ptunnel-ng v%d.%.2d.\n\nUsage: %s", 12, 22, arg0);
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

_exit(0);
}

int parse_options(int argc, char **argv) {
	return 0;
}
