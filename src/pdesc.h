#ifndef PDESC_H
#define PDESC_H

#include <stdint.h>


struct psock;

struct pdesc
{
    uint16_t identifier;
    uint16_t sequence;
};

enum pdesc_retval
{
    PDESC_REMOTE_NEW,
    PDESC_REMOTE_INVALID,
    PDESC_REMOTE_FOUND
};


enum pdesc_retval pdesc_find_remote(struct psock *);

#endif
