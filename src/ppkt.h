#ifndef PPKT_H
#define PPKT_H 1

#include <stdint.h>

#define PTUNNEL_IDENT 0xdeadc0de

struct psock;

struct ppkt_option_header {
    uint16_t type;
    uint16_t size;
} __attribute__((__packed__));

struct ppkt_option_auth {
    struct ppkt_option_header option;
    uint8_t data[0];
} __attribute__((__packed__));

union ppkt_option {
    struct ppkt_option_auth auth;
} __attribute__((__packed__));
;

struct ppkt {
    uint32_t ident;
    uint16_t total_size;
    union ppkt_option current;
} __attribute__((__packed__));

int ppkt_process_icmp(struct psock *);

int ppkt_process_ppkt(struct psock *);

#endif
