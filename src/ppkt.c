#include "pdesc.h"
#include "ppkt.h"
#include "psock.h"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

enum ptype ppkt_type_to_enum(struct ppkt * pkt)
{
    enum ptype pt = (enum ptype)pkt->type;

    switch (pt) {
        case PTYPE_INVALID:
        case PTYPE_AUTH_REQUEST:
        case PTYPE_AUTH_RESPONSE:
            return pt;
    }

    return PTYPE_INVALID;
}

int ppkt_process_icmp(struct psock * sock)
{
    if (sock->current.peer.ss_family == AF_INET) {
        sock->current.packet.icmphdr = (struct icmphdr *)(sock->current.packet.buffer + sizeof(struct iphdr));

        sock->current.packet.icmphdr->checksum = ntohs(sock->current.packet.icmphdr->checksum);
        sock->current.packet.icmphdr->un.echo.id = ntohs(sock->current.packet.icmphdr->un.echo.id);
        sock->current.packet.icmphdr->un.echo.sequence = ntohs(sock->current.packet.icmphdr->un.echo.sequence);
    } else {
        return -1;
    }

    return 0;
}

int ppkt_process_ppkt(struct psock * sock)
{
    if (sock->current.peer.ss_family == AF_INET) {
        if (sock->current.packet.used < sizeof(struct iphdr) + sizeof(*sock->current.packet.icmphdr)) {
            return -1;
        }

        sock->current.packet.icmphdr = (struct icmphdr *)(sock->current.packet.buffer + sizeof(struct iphdr));
        sock->current.packet.icmphdr->un.echo.id = ntohs(sock->current.packet.icmphdr->un.echo.id);

        sock->current.packet.pkt =
            (struct ppkt *)(sock->current.packet.buffer + sizeof(struct iphdr) + sizeof(*sock->current.packet.icmphdr));
    } else {
        return -1;
    }

    sock->current.packet.pkt->total_size = ntohs(sock->current.packet.pkt->total_size);
    if (sock->current.packet.pkt->total_size >
        sizeof(struct iphdr) + sizeof(*sock->current.packet.icmphdr) + sock->current.packet.used) {
        return -1;
    }

    switch (ppkt_type_to_enum(sock->current.packet.pkt)) {
        case PTYPE_INVALID:
            return -1;
        case PTYPE_AUTH_REQUEST:
            break;
        case PTYPE_AUTH_RESPONSE:
            break;
    }

    return 0;
}

static size_t ppkt_prepare_ppkt(struct ppkt * pkt, enum ptype type, size_t additional_size)
{
    size_t subpkt_size;

    switch (type) {
        case PTYPE_INVALID:
            subpkt_size = 0;
            additional_size = 0;
            break;
        case PTYPE_AUTH_REQUEST:
            subpkt_size = sizeof(struct ppkt_auth_request);
            break;
        case PTYPE_AUTH_RESPONSE:
            subpkt_size = sizeof(struct ppkt_auth_response);
            break;
    }

    pkt->total_size = htons(sizeof(*pkt) + subpkt_size + additional_size);
    pkt->type = type;

    return sizeof(*pkt) + subpkt_size + additional_size;
}

void ppkt_prepare_auth_request(struct ppkt_buffer * const pkt_buf, uint8_t * const hash, size_t hash_siz)
{
    size_t total_size = ppkt_prepare_ppkt(&pkt_buf->pkt, PTYPE_AUTH_REQUEST, hash_siz);

    pkt_buf->auth_request.magic = htonl(PTUNNEL_MAGIC);
    pkt_buf->auth_request.hash_siz = hash_siz;

    pkt_buf->icmphdr.type = 8;
    pkt_buf->icmphdr.code = 0;

    pkt_buf->iovec[0].iov_base = &pkt_buf->icmphdr;
    pkt_buf->iovec[0].iov_len = sizeof(pkt_buf->icmphdr);

    pkt_buf->iovec[1].iov_base = &pkt_buf->pkt;
    pkt_buf->iovec[1].iov_len = total_size;

    pkt_buf->iovec[2].iov_base = &pkt_buf->auth_request;
    pkt_buf->iovec[2].iov_len = sizeof(pkt_buf->auth_request);

    pkt_buf->iovec[3].iov_base = hash;
    pkt_buf->iovec[3].iov_len = hash_siz;

    pkt_buf->iovec_used = 4;
}
