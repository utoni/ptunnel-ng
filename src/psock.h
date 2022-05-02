#ifndef PSOCK_H
#define PSOCK_H 1

#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>

struct icmphdr;
struct pdesc;
struct ppkt;

struct psock {
    int epoll_fd;
    int icmp_fd;

    struct {
        int is_client;
    } local;

    struct {
        struct sockaddr_storage peer;

        struct {
            size_t used;
            size_t max;
            uint8_t * buffer;
            struct icmphdr * icmphdr;
            struct ppkt * pkt;
        } packet;
    } current;

    struct {
        size_t used;
        size_t max;
        struct pdesc * descriptors;
    } remotes;
};

int psock_init(struct psock *, size_t, size_t);

int psock_setup_fds(struct psock *, int);

int psock_add_server(struct psock *, char const *);

void psock_free(struct psock *);

void psock_loop(struct psock *);

#endif
