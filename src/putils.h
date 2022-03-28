#ifndef PUTILS_H
#define PUTILS_H 1

#include <stdarg.h>

struct sockaddr_storage;

void init_logging(char const *);

void shutdown_logging(void);

int enable_file_logger(char const *);

int get_log_file_fd(void);

void enable_console_logger(void);

int is_console_logger_enabled(void);

void vlogger(int, char const *, va_list);

__attribute__((format(printf, 2, 3))) void logger(int, char const *, ...);

__attribute__((format(printf, 2, 3))) void logger_early(int, char const *, ...);

int parse_address(struct sockaddr_storage *, char const *);

#endif
