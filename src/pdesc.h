#ifndef PDESC_H
#define PDESC_H

#include <netinet/in.h>
#include <stdint.h>

struct psock;

enum pdesc_remote_errno {
    REMOTE_EXISTS,
    REMOTE_NOT_FOUND,
    REMOTE_PACKET_INVALID,
    REMOTE_ADDR_INVALID,
    REMOTE_ICMP_ECHO_CLIENT,
    REMOTE_ICMP_REPLY_SERVER,
    REMOTE_MAX_DESCRIPTORS,
};

enum pdesc_state { PDESC_STATE_INVALID = 0, PDESC_STATE_AUTH, PDESC_STATE_DATA };

struct paddr {
    struct sockaddr_storage sockaddr;
    char str[INET6_ADDRSTRLEN];
};

struct pdesc {
    enum pdesc_state state;
    struct paddr peer;
    uint16_t identifier;
    uint16_t sequence;
};

void pdesc_init(struct pdesc *, uint16_t identifier);

enum pdesc_remote_errno pdesc_find_current_remote(struct psock *, struct pdesc ** const);

int pdesc_set_addr(struct paddr *, struct sockaddr_storage const *);

#endif
