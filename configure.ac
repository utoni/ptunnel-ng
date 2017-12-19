AC_PREREQ(2.69)
AC_INIT([ptunnel-ng], [1.0], [], [], [])
AC_CONFIG_SRCDIR([src/config.h.in])
AC_CONFIG_FILES([Makefile src/Makefile])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
if test x"$cross_compiling" != x"no"; then
	HOST_PREFIX="${host_alias}-"
	HOST_SUFFIX="-$host_alias"
	if test x"${build_alias}" = x; then
		AC_MSG_ERROR([Cross compile enabled but no --build *explicitly* specified. For example: --build=$(gcc -dumpmachine)])
	fi
else
	HOST_PREFIX=
	HOST_SUFFIX=
fi
case x"${host}" in
	x*-*-cygwin* | x*-*-mingw32*)
		dnl Some Windows includes required by third-party modules.
		use_msw=yes
		PROGRAM_EXT=".exe"
	;;
esac

AM_SILENT_RULES([yes])
AM_INIT_AUTOMAKE
AC_PROG_INSTALL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_CHECK_HEADER_STDBOOL
AC_FUNC_VPRINTF
AC_FUNC_MEMCMP

dnl Check for std includes.
AC_CHECK_HEADERS([stdarg.h stdio.h unistd.h stdlib.h string.h stdint.h time.h signal.h assert.h],,
    [AC_MSG_ERROR([Missing essential std headers.])])
if test x"${use_msw}" != x"yes"; then
	AC_CHECK_HEADERS([sys/unistd.h sys/types.h sys/socket.h netinet/in.h arpa/inet.h netdb.h pthread.h errno.h net/ethernet.h syslog.h pwd.h grp.h],,
	    [AC_MSG_ERROR([Missing essential non-Windows std headers.])])
	AC_SEARCH_LIBS([pthread_create], [pthread],,
	    [AC_MSG_ERROR([Missing pthread library.])],)
	AC_CHECK_FUNCS([pthread_mutex_init pthread_mutex_lock pthread_mutex_unlock],,
	    [AC_MSG_ERROR([Missing essential pthread functions.])])
else
	AC_CHECK_HEADERS([winsock2.h windows.h ws2tcpip.h],,
	    [AC_MSG_ERROR([Missing essential Windows std headers.])])
fi

dnl Check timeval struct members.
AC_CHECK_MEMBER([struct timeval.tv_sec], [],
    [AC_MSG_ERROR([Invalid \`struct timeval\` structure.])],
    [[#include <sys/time.h>]])
AC_CHECK_MEMBER([struct timeval.tv_usec], [],
    [AC_MSG_ERROR([Invalid \`struct timeval\` structure.])],
	[[#include <sys/time.h>]])

dnl Check size
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(uint8_t)
AC_CHECK_SIZEOF(uint16_t)
AC_CHECK_SIZEOF(uint32_t)
AC_CHECK_SIZEOF(int)
if test $ac_cv_sizeof_char != "1" -o \
  $ac_cv_sizeof_uint8_t != "1" -o \
  $ac_cv_sizeof_uint16_t != "2" -o \
  $ac_cv_sizeof_uint32_t != "4" -o \
  $ac_cv_sizeof_int != "4"; then
	AC_MSG_ERROR([Invalid type size.])
fi

AC_MSG_CHECKING([for __attribute__ ((packed))])
AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([[
#include <stdlib.h>
struct foo {
    int num;
    char *str;
    void *ptr;
} __attribute__ ((packed));
]], [])]
,[AC_MSG_RESULT([yes])]
,[AC_MSG_ERROR([Your compiler does not support \`__attribute__ ((packed))\`.])])

dnl Check for std functions.
AC_CHECK_FUNCS([malloc calloc free memcpy memset signal printf sprintf vsnprintf strerror strlen strncmp strstr strtol strtoul fopen fprintf gettimeofday close fclose exit],,
    [AC_MSG_ERROR([Missing essential std functions.])])

dnl `--disable-pcap`: Enabled if found.
AC_ARG_ENABLE([pcap],
    [AS_HELP_STRING([--disable-pcap], [Disable pcap support. (default: enabled if found)])],,[pcap_enabled=yes])
pcap_enabled=$(echo ${pcap_enabled})
case ${pcap_enabled} in
	1|y|yes) pcap_enabled=yes ;;
	''|0|n|no) pcap_enabled= ;;
	*) AC_MSG_ERROR([Unknown option \`${pcap_enabled}\` for --disable-pcap]) ;;
esac

dnl `--disable-selinux`: Enabled if found.
AC_ARG_ENABLE([selinux],
    [AS_HELP_STRING([--disable-selinux], [Disable SELINUX support. (default: enabled if found)])],,[selinux_enabled=yes])
selinux_enabled=$(echo ${selinux_enabled})
case ${selinux_enabled} in
	1|y|yes) selinux_enabled=yes ;;
	''|0|n|no) selinux_enabled= ;;
	*) AC_MSG_ERROR([Unknown option \`${selinux_enabled}\` for --disable-selinux]) ;;
esac

dnl Check libcap headers/functions.
if test x"${pcap_enabled}" != x; then
	AC_CHECK_HEADERS([pcap.h],,
	    [pcap_enabled=])
	AC_SEARCH_LIBS([pcap_lookupnet], [pcap],,
	    [pcap_enabled=],)
	AC_CHECK_FUNCS([pcap_compile pcap_close pcap_setfilter pcap_dispatch],,
	    [pcap_enabled=])
fi

dnl Check for SELINUX
if test x"${selinux_enabled}" != x; then
	AC_CHECK_HEADERS([selinux/selinux.h],,
	    [selinux_enabled=])
	AC_SEARCH_LIBS([setcon], [selinux],,[selinux_enabled=],)
fi

dnl Set automake conf vars
AM_CONDITIONAL([HAVE_PCAP], [test x"${pcap_enabled}" = xyes])
AM_CONDITIONAL([HAVE_SELINUX], [test x"${selinux_enabled}" = xyes])

dnl output config headers
AC_CONFIG_HEADERS([src/config.h:src/config.h.in])
AC_OUTPUT
