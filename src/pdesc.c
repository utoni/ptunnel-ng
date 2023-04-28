#include "pdesc.h"
#include "ppkt.h"
#include "psock.h"

#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

void pdesc_init(struct pdesc * desc, uint16_t identifier)
{
    desc->state = PDESC_STATE_AUTH;
    desc->identifier = identifier;
    desc->sequence = 0;
}

static enum pdesc_remote_errno pdesc_check_icmp_type(struct psock * sock, struct pdesc * const desc)
{
    if (sock->current.pkt_buf.icmphdr.type == ICMP_ECHO && sock->local.is_client != 0) {
        return REMOTE_ICMP_ECHO_CLIENT;
    }

    if (sock->current.pkt_buf.icmphdr.type == ICMP_ECHOREPLY && sock->local.is_client == 0) {
        return REMOTE_ICMP_REPLY_SERVER;
    }

    return REMOTE_EXISTS;
}

enum pdesc_remote_errno pdesc_find_current_remote(struct psock * sock, struct pdesc ** const desc)
{
    size_t i;

    *desc = NULL;

    if (ppkt_process_icmp(sock) != 0 || ppkt_process_ppkt(sock) != 0) {
        return REMOTE_PACKET_INVALID;
    }

    for (i = 0; i < sock->remotes.used; ++i) {
        if (sock->remotes.descriptors[i].state != PDESC_STATE_INVALID &&
            sock->current.pkt_buf.icmphdr.un.echo.id == sock->remotes.descriptors[i].identifier) {
            *desc = &sock->remotes.descriptors[i];
            return pdesc_check_icmp_type(sock, *desc);
        }
    }
    if (i == sock->remotes.max) {
        return REMOTE_MAX_DESCRIPTORS;
    }

    pdesc_init(&sock->remotes.descriptors[i], sock->current.pkt_buf.icmphdr.un.echo.id);
    if (pdesc_set_addr(&sock->remotes.descriptors[i].peer, &sock->current.peer_sockaddr) != 0) {
        return REMOTE_ADDR_INVALID;
    }

    *desc = &sock->remotes.descriptors[i];
    sock->remotes.used++;

    return REMOTE_NOT_FOUND;
}

int pdesc_set_addr(struct paddr * addr, struct sockaddr_storage const * sockaddr)
{
    addr->sockaddr = *sockaddr;

    switch (sockaddr->ss_family) {
        case AF_INET: ;
            struct in_addr in_addr = ((struct sockaddr_in *)sockaddr)->sin_addr;
            if (inet_ntop(AF_INET, &in_addr, addr->str, sizeof(struct sockaddr_in)) == NULL) {
                return -1;
            }
            break;

        case AF_INET6: ;
            struct in6_addr in6_addr = ((struct sockaddr_in6 *)sockaddr)->sin6_addr;
            if (inet_ntop(AF_INET, &in6_addr, addr->str, sizeof(struct sockaddr_in6)) == NULL) {
                return -1;
            }
            break;

        default:
            return -1;
    }

    return 0;
}
