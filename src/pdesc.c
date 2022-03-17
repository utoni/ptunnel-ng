#include "pdesc.h"
#include "psock.h"


enum pdesc_retval pdesc_find_remote(struct psock * psock)
{
    for (size_t i = 0; i < psock->remotes.used; ++i)
    {
    }

    return PDESC_REMOTE_FOUND;
}
