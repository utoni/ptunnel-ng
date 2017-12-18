#include <stdarg.h>

#ifndef WIN32
#include <syslog.h>
#endif
#include <sys/time.h>

#include "utils.h"
#include "options.h"

void pt_log(int level, const char *fmt, ...) {
	va_list args;
	const char *header[] = { "[err]: ",
	                         "[inf]: ",
	                         "[evt]: ",
	                         "[vbs]: ",
	                         "[dbg]: ",
	                         "[xfr]: " };
#ifndef WIN32
	int syslog_levels[] = {LOG_ERR, LOG_NOTICE, LOG_NOTICE, LOG_INFO, LOG_DEBUG, LOG_DEBUG};
#endif /* !WIN32 */

	if (level <= opts.log_level) {
		va_start(args, fmt);
#ifndef WIN32
		if (opts.use_syslog) {
			char log[255];
			int header_len;
			header_len = snprintf(log,sizeof(log),"%s",header[level]);
			vsnprintf(log+header_len,sizeof(log)-header_len,fmt,args);
			syslog(syslog_levels[level], "%s", log);
		}
		else
#endif /* !WIN32 */
			fprintf(opts.log_file, "%s", header[level]), vfprintf(opts.log_file, fmt, args);
		va_end(args);
#ifndef WIN32
		if (opts.log_file != stdout && !opts.use_syslog)
#else
		if (opts.log_file != stdout)
#endif
		fflush(opts.log_file);
	}
}

double time_as_double(void) {
	double          result;
	struct timeval  tt;

	gettimeofday(&tt, 0);
	result = (double)tt.tv_sec + ((double)tt.tv_usec / (double)10e5);
	return result;
}

#if 0
static const char hextab[] = "0123456789ABCDEF";

void print_hexstr(unsigned char *buf, size_t siz) {
	char *out = (char *) calloc(3, siz+1);
	unsigned char high, low;

	for (size_t i = 0; i < siz; ++i) {
		high = (buf[i] & 0xF0) >> 4;
		low  = buf[i] & 0x0F;
		out[i  ] = hextab[high];
		out[i+1] = hextab[low];
		out[i+2] = ' ';
	}

	printf("%s\n", out);
	free(out);
}
#endif
