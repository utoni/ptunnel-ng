#ifndef PPKT_H
#define PPKT_H 1

#include <stdint.h>

#define PPKT_TYPE_DATA 0x0001u

struct ppkt
{
    uint16_t type;
    uint16_t data_size;
    uint32_t sequence;
    uint8_t data[0];
};

void ppkt_header_prepare(struct ppkt *);

void ppkt_header_process(struct ppkt *);

#endif
