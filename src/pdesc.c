#include "pdesc.h"
#include "ppkt.h"
#include "psock.h"

#include <netinet/ip_icmp.h>

static void pdesc_init(struct psock * psock, struct pdesc * pdesc, uint16_t identifier)
{
    pdesc->state = PDESC_STATE_AUTH;
    pdesc->peer = psock->current.peer;
    pdesc->identifier = identifier;
    pdesc->sequence = 0;
}

struct pdesc * pdesc_find_remote(struct psock * psock)
{
    size_t i;

    if (psock->remotes.used == psock->remotes.max || ppkt_process_icmp(psock) != 0 ||
        psock->current.packet.icmphdr->type != ICMP_ECHOREPLY || ppkt_process_ppkt(psock) != 0) {
        return NULL;
    }

    for (i = 0; i < psock->remotes.used; ++i) {
        if (psock->current.packet.icmphdr->un.echo.id == psock->remotes.descriptors[i].identifier) {
            return &psock->remotes.descriptors[i];
        }
    }

    pdesc_init(psock, &psock->remotes.descriptors[i], psock->current.packet.icmphdr->un.echo.id);

    return &psock->remotes.descriptors[i];
}
