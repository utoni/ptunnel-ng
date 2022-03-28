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
