#ifndef UTILS_H
#define UTILS_H 1

#include <stdint.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

void pt_log(int level, const char *fmt, ...);

double time_as_double(void);

int host_to_addr(const char *hostname, uint32_t *result);

#if 0
void print_hexstr(unsigned char *buf, size_t siz);
#endif

#endif
