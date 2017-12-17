#ifndef UTILS_H
#define UTILS_H 1

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

void pt_log(int level, const char *fmt, ...);

double time_as_double(void);

#endif
