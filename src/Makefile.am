bin_PROGRAMS = ptunnel

ptunnel_CFLAGS = -Wall
if HAVE_PCAP
ptunnel_CFLAGS += -DHAVE_PCAP=1
endif
if HAVE_SELINUX
ptunnel_CFLAGS += -DHAVE_SELINUX=1
endif

ptunnel_SOURCES = \
	md5.c \
	challenge.c \
	options.c \
	utils.c \
	pkt.c \
	pdesc.c \
	ptunnel.c
