#ifndef PPKT_H
#define PPKT_H 1

#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <sys/socket.h>

#define PTUNNEL_MAGIC 0xdeadc0de

#define U8_PTYPE_AUTH_REQUEST 0x01u
#define U8_PTYPE_AUTH_RESPONSE 0x02u

enum ptype {
    PTYPE_INVALID = 0,
    PTYPE_AUTH_REQUEST = U8_PTYPE_AUTH_REQUEST,
    PTYPE_AUTH_RESPONSE = U8_PTYPE_AUTH_RESPONSE,
};

struct psock;
struct pdesc;

struct ppkt_auth_request {
    uint32_t magic;
    uint16_t hash_siz;
    uint8_t hash[0];
} __attribute__((__packed__));

struct ppkt_auth_response {
    uint8_t code;
} __attribute__((__packed__));

struct ppkt {
    uint16_t total_size;
    uint8_t type;
    uint8_t data[0];
} __attribute__((__packed__));

struct ppkt_buffer {
    struct iovec iovec[4];
    size_t iovec_used;

    struct icmphdr icmphdr;
    struct ppkt pkt;
    union {
        struct ppkt_auth_request auth_request;
        struct ppkt_auth_response auth_response;
    };
};

enum ptype ppkt_type_to_enum(struct ppkt *);

int ppkt_process_icmp(struct psock *);

int ppkt_process_ppkt(struct psock *);

void ppkt_prepare_auth_request(struct pdesc *, struct ppkt_buffer *, uint8_t *, size_t);

#endif
