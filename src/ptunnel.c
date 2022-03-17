#include "pdesc.h"
#include "psock.h"

#include <stdio.h>
#include <stdlib.h>


int main(void)
{
    struct psock psock = {};

    if (psock_init(&psock, 16, 2048) != 0)
    {
        return 1;
    }

    psock_loop(&psock);

    psock_free(&psock);

    return 0;
}
