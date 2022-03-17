#ifndef PPKT_H
#define PPKT_H 1

#include <stdint.h>


#define PTUNNEL_IDENT 0xdeadc0de

struct psock;

struct ppkt
{
    uint32_t ident;
    uint16_t type;
    uint16_t data_size;
    uint8_t data[0];
} __attribute__((__packed__));


void ppkt_header_prepare(struct psock *);

void ppkt_header_process(struct psock *);

#endif
