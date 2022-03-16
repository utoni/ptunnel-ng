#ifndef PSOCK_H
#define PSOCK_H 1

#include <stdlib.h>


struct pdesc;

struct psock
{
    int epoll_fd;
    int icmp_fd;
    struct {
        size_t used;
        size_t max;
        struct pdesc ** descriptors;
    } remotes;
};


int psock_init(struct psock *, size_t);

void psock_free(struct psock *);

void psock_loop(struct psock *);

#endif
