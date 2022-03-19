#ifndef PDESC_H
#define PDESC_H

#include <netinet/in.h>
#include <stdint.h>

struct psock;

enum pdesc_state { PDESC_STATE_AUTH };

struct pdesc {
    enum pdesc_state state;
    struct sockaddr_storage peer;
    uint16_t identifier;
    uint16_t sequence;
};

struct pdesc * pdesc_find_remote(struct psock *);

#endif
