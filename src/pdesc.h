#ifndef PDESC_H
#define PDESC_H

#include <netinet/in.h>
#include <stdint.h>

struct psock;

enum pdesc_remote_errno {
    REMOTE_FOUND,
    REMOTE_PACKET_INVALID,
    REMOTE_ICMP_ECHO_CLIENT,
    REMOTE_ICMP_REPLY_SERVER,
    REMOTE_MAX_DESCRIPTORS,
};

enum pdesc_state { PDESC_STATE_AUTH, PDESC_STATE_DATA };

struct pdesc {
    enum pdesc_state state;
    struct sockaddr_storage peer;
    uint16_t identifier;
    uint16_t sequence;
};

enum pdesc_remote_errno pdesc_find_remote(struct psock *, struct pdesc ** const);

#endif
