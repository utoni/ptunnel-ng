#include "putils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static char const * app_name = NULL;
static int log_to_console = 0;
static int log_to_file_fd = -1;

void init_logging(char const * const name)
{
    app_name = name;
    openlog(app_name, LOG_CONS, LOG_DAEMON);
}

void shutdown_logging(void)
{
    closelog();
}

int enable_file_logger(char const * const log_file)
{
    log_to_file_fd = open(log_file, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    if (log_to_file_fd < 0) {
        logger_early(1, "Could not open logfile %s for appending: %s", log_file, strerror(errno));
        return 1;
    }

    return 0;
}

int get_log_file_fd(void)
{
    return log_to_file_fd;
}

void enable_console_logger(void)
{
    if (setvbuf(stderr, NULL, _IOLBF, 0) != 0) {
        fprintf(stderr,
                "%s",
                "Could not set stderr line-buffered, "
                "console syslog() messages may appear weird.\n");
    } else {
        log_to_console = 1;
    }
}

int is_console_logger_enabled(void)
{
    return log_to_console != 0;
}

static void vlogger_to(int fd, int is_error, char const * const format, va_list * const ap)
{
    char logbuf[512];

    if (vsnprintf(logbuf, sizeof(logbuf), format, *ap) == sizeof(logbuf)) {
        fprintf(stderr, "%s\n", "BUG: Log output was truncated due the logging buffer size limit.");
    }

    if (is_error != 0) {
        if (dprintf(fd, "%s [error]: %s\n", app_name, logbuf) < 0) {
            fprintf(stderr, "Could not write to fd %d: %s\n", fd, strerror(errno));
        }
    } else {
        if (dprintf(fd, "%s: %s\n", app_name, logbuf) < 0) {
            fprintf(stderr, "Could not write to fd %d: %s\n", fd, strerror(errno));
        }
    }
}

void vlogger(int is_error, char const * const format, va_list ap)
{
    va_list logfile_ap, stderr_ap;

    va_copy(logfile_ap, ap);
    va_copy(stderr_ap, ap);

    if (log_to_console == 0) {
        if (is_error == 0) {
            vsyslog(LOG_DAEMON, format, ap);
        } else {
            vsyslog(LOG_DAEMON | LOG_ERR, format, ap);
        }
    } else {
        vlogger_to(fileno(stderr), is_error, format, &stderr_ap);
    }

    if (log_to_file_fd >= 0) {
        vlogger_to(log_to_file_fd, is_error, format, &logfile_ap);
    }

    va_end(stderr_ap);
    va_end(logfile_ap);
}

__attribute__((format(printf, 2, 3))) void logger(int is_error, char const * const format, ...)
{
    va_list ap;

    va_start(ap, format);
    vlogger(is_error, format, ap);
    va_end(ap);
}

__attribute__((format(printf, 2, 3))) void logger_early(int is_error, char const * const format, ...)
{
    int old_log_to_console = log_to_console;
    va_list ap;

    va_start(ap, format);
    vlogger_to(fileno(stderr), is_error, format, &ap);
    va_end(ap);

    log_to_console = 0;

    va_start(ap, format);
    vlogger(is_error, format, ap);
    va_end(ap);

    log_to_console = old_log_to_console;
}

int parse_address(struct sockaddr_storage * out, char const * address)
{
    char const * const colon_found = strrchr(address, ':');

    if (colon_found != NULL) {
        /* colon found, assume IPv6 */
        out->ss_family = AF_INET6;
    } else {
        /* no colon found, assume IPv4 */
        out->ss_family = AF_INET;
    }

    if (inet_pton(out->ss_family, address, out) != 0) {
        return -1;
    }

    return 0;
}

static inline uint16_t get_n16bit(uint8_t const * cbuf)
{
    uint16_t r = ((uint16_t)cbuf[0]) | (((uint16_t)cbuf[1]) << 8);
    return r;
}

uint16_t icmp_checksum_iovec(struct iovec const * iovec, size_t iovec_size)
{
    uint32_t checksum = 0;
    uint16_t result;
    uint8_t is_overlapping = 0;
    uint8_t overlap[2] = {0x00, 0x00};

    for (size_t iov_i = 0; iov_i < iovec_size; ++iov_i) {
        uint8_t const * buf = iovec[iov_i].iov_base;
        size_t len = iovec[iov_i].iov_len;

        if (is_overlapping != 0 && len > 0) {
            overlap[1] = buf[0];
            checksum += get_n16bit(overlap);
            buf++;
            len--;
            is_overlapping = 0;
        }

        for (; len > 1; len -= 2) {
            checksum += get_n16bit(buf);
            buf += 2;
        }

        if (len == 1) {
            overlap[0] = *buf;
            is_overlapping = 1;
        }
    }

    if (is_overlapping != 0) {
        checksum += overlap[0];
    }

    while (checksum >> 16 > 0) {
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    }

    result = ~checksum;

    return result;
}

uint16_t icmp_generate_identifier(void)
{
    uint64_t current_time = time(NULL);
    uint16_t identifier = 0;

    for (size_t i = 0; i < sizeof(current_time) / 2; ++i) {
        identifier += ((uint16_t *)&current_time)[i];
    }

    return identifier;
}
