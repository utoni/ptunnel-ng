#include "pdesc.h"
#include "ppkt.h"
#include "psock.h"

#include <netinet/ip_icmp.h>

static void pdesc_init(struct psock * sock, struct pdesc * desc, uint16_t identifier)
{
    desc->state = PDESC_STATE_AUTH;
    desc->peer = sock->current.peer;
    desc->identifier = identifier;
    desc->sequence = 0;
}

enum pdesc_remote_errno pdesc_find_current_remote(struct psock * sock, struct pdesc ** const desc)
{
    size_t i;

    *desc = NULL;

    if (ppkt_process_icmp(sock) != 0 || ppkt_process_ppkt(sock) != 0) {
        return REMOTE_PACKET_INVALID;
    }

    if (sock->current.packet.icmphdr->type == ICMP_ECHO && sock->local.is_client != 0) {
        return REMOTE_ICMP_ECHO_CLIENT;
    }

    if (sock->current.packet.icmphdr->type == ICMP_ECHOREPLY && sock->local.is_client == 0) {
        return REMOTE_ICMP_REPLY_SERVER;
    }

    for (i = 0; i < sock->remotes.used; ++i) {
        if (sock->current.packet.icmphdr->un.echo.id == sock->remotes.descriptors[i].identifier) {
            *desc = &sock->remotes.descriptors[i];
            return REMOTE_EXISTS;
        }
    }
    if (i == sock->remotes.max) {
        return REMOTE_MAX_DESCRIPTORS;
    }

    pdesc_init(sock, &sock->remotes.descriptors[i], sock->current.packet.icmphdr->un.echo.id);

    *desc = &sock->remotes.descriptors[i];
    return REMOTE_NOT_FOUND;
}
