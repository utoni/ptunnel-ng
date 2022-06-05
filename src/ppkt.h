#ifndef PPKT_H
#define PPKT_H 1

#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <sys/socket.h>

#define PTUNNEL_MAGIC 0xdeadc0de

#define PTUNNAL_MAX_BODY_SIZE (1500 - sizeof(struct iphdr) \
                                    - sizeof(struct icmphdr) \
                                    - sizeof(struct ppkt_header))

enum ptype {
    PTYPE_INVALID = 0,
    PTYPE_AUTH_REQUEST,
    PTYPE_AUTH_RESPONSE,
};

struct psock;
struct pdesc;

struct ppkt_auth_request {
    uint32_t magic;
    uint16_t authdata_siz;
    uint8_t authdata[0];
} __attribute__((__packed__));

struct ppkt_auth_response {
    uint8_t code;
} __attribute__((__packed__));

struct ppkt_header {
    uint16_t total_size;
    uint8_t type;
} __attribute__((__packed__));

union ppkt_body {
    struct ppkt_auth_request auth_request;
    struct ppkt_auth_response auth_response;
    uint8_t buf[PTUNNAL_MAX_BODY_SIZE];
} __attribute__((__packed__));

struct ppkt_buffer {
    struct iovec iovec[4];
    size_t iovec_used;

    struct icmphdr icmphdr;
    struct ppkt_header pheader;
    union ppkt_body pbody;
};

enum ptype ppkt_type_to_enum(struct ppkt_header *);

int ppkt_process_icmp(struct psock *);

int ppkt_process_ppkt(struct psock *);

void ppkt_prepare_auth_request(struct pdesc *, struct ppkt_buffer *, uint8_t *, size_t);

#endif
