bin_PROGRAMS = ptunnel-ng
man8_MANS = ptunnel-ng.8

ptunnel_ng_CFLAGS = -Wall -Wextra
ptunnel_ng_LDADD =
CLEANFILES =
EXTTRA_DIST =

if HAVE_PCAP
ptunnel_ng_CFLAGS += -DHAVE_PCAP=1
endif

if ENABLE_SHA512
ptunnel_ng_CFLAGS += -DENABLE_SHA512=1
endif

if HAVE_SELINUX
ptunnel_ng_CFLAGS += -DHAVE_SELINUX=1
endif

if HAVE_ICMPFILTER
ptunnel_ng_CFLAGS += -DHAVE_ICMPFILTER=1
endif

if HAVE_ARC4RANDOM
ptunnel_ng_CFLAGS += -DHAVE_ARC4RANDOM=1
endif

if USE_CUSTOMRNG
ptunnel_ng_CFLAGS += -DUSE_CUSTOMRNG=1
endif

if DISABLE_ASSERTS
ptunnel_ng_CFLAGS += -DNDEBUG=1
endif

if ENABLE_SANITIZER
ptunnel_ng_CFLAGS += -fsanitize=address -fsanitize=leak -fsanitize=undefined
endif

ptunnel_ng_SOURCES = \
	md5.c \
	challenge.c \
	options.c \
	utils.c \
	pkt.c \
	pdesc.c \
	ptunnel.c

if IS_WINDOWS
wpcap_DEF = $(srcdir)/win32/WPCAP.DEF
wpcap_IMP = $(srcdir)/win32/libwpcap_implib.a
ptunnel_ng_CFLAGS += -I$(srcdir)/win32/includes -DHAVE_PCAP=1
if HAVE_NPCAP
ptunnel_ng_CFLAGS += -DHAVE_NPCAP=1
endif
ptunnel_ng_LDADD += $(wpcap_IMP)
ptunnel_ng_SOURCES += $(wpcap_DEF)

$(wpcap_IMP):
	@DLLTOOL@ -k -y $(wpcap_IMP) --def $(wpcap_DEF)

CLEANFILES += $(wpcap_IMP)
EXTTRA_DIST += $(wpcap_DEF)
endif
