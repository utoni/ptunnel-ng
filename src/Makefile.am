bin_PROGRAMS = ptunnel-ng
man8_MANS = ptunnel-ng.8

ptunnel_ng_CFLAGS = -Wall
if HAVE_PCAP
ptunnel_ng_CFLAGS += -DHAVE_PCAP=1
endif
if HAVE_SELINUX
ptunnel_ng_CFLAGS += -DHAVE_SELINUX=1
endif

ptunnel_ng_SOURCES = \
	md5.c \
	challenge.c \
	options.c \
	utils.c \
	pkt.c \
	pdesc.c \
	ptunnel.c
