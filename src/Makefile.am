bin_PROGRAMS = ptunnel-ng
man8_MANS = ptunnel-ng.8

ptunnel_ng_CFLAGS = -Wall
ptunnel_ng_LDADD =
CLEANFILES =
EXTTRA_DIST =

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

if IS_WINDOWS
wpcap_DEF = $(abs_srcdir)/win32/WPCAP.DEF
wpcap_IMP = $(abs_srcdir)/win32/libwpcap_implib.a
ptunnel_ng_CFLAGS += -I$(abs_srcdir)/win32/includes -DHAVE_PCAP=1
ptunnel_ng_LDADD += $(wpcap_IMP)
ptunnel_ng_SOURCES += $(wpcap_DEF)

$(wpcap_IMP):
	@DLLTOOL@ -k -l $(wpcap_IMP) --def $(wpcap_DEF)

CLEANFILES += $(wpcap_IMP)
EXTTRA_DIST += $(wpcap_DEF)
endif
