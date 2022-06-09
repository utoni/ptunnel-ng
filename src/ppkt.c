#include "pdesc.h"
#include "ppkt.h"
#include "psock.h"
#include "putils.h"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

enum ptype ppkt_type_to_enum(struct ppkt_header const * pheader)
{
    enum ptype pt = (enum ptype)pheader->type;

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
    if (sock->current.peer_sockaddr.ss_family == AF_INET) {
        sock->current.pkt_buf.icmphdr.checksum = ntohs(sock->current.pkt_buf.icmphdr.checksum);
        sock->current.pkt_buf.icmphdr.un.echo.id = ntohs(sock->current.pkt_buf.icmphdr.un.echo.id);
        sock->current.pkt_buf.icmphdr.un.echo.sequence = ntohs(sock->current.pkt_buf.icmphdr.un.echo.sequence);
    } else {
        return -1;
    }

    return 0;
}

static size_t ppkt_size(enum ptype type)
{
    size_t body_siz = 0;

    switch (type) {
        case PTYPE_INVALID:
            return 0;
        case PTYPE_AUTH_REQUEST:
            body_siz = sizeof(struct ppkt_auth_request);
            break;
        case PTYPE_AUTH_RESPONSE:
            body_siz = sizeof(struct ppkt_auth_response);
            break;
    }

    return sizeof(struct ppkt_header) + body_siz;
}

static size_t ppkt_data_size(union ppkt_body * pbody, enum ptype type)
{
    size_t data_siz = 0;

    switch (type) {
        case PTYPE_INVALID:
            return 0;
        case PTYPE_AUTH_REQUEST:
            data_siz = pbody->auth_request.authdata_siz;
            break;
        case PTYPE_AUTH_RESPONSE:
            data_siz = 0;
            break;
    }

    return data_siz;
}

int ppkt_process_ppkt(struct psock * sock)
{
    size_t const min_pkt_siz = sizeof(struct iphdr) + sizeof(sock->current.pkt_buf.icmphdr);

    if (sock->current.peer_sockaddr.ss_family != AF_INET) {
        return -1;
    }

    if (sock->current.bytes_read < min_pkt_siz + sizeof(sock->current.pkt_buf.pheader)) {
        return -1;
    }

    sock->current.pkt_buf.pheader.total_size = ntohs(sock->current.pkt_buf.pheader.total_size);
    if (sock->current.pkt_buf.pheader.total_size != sock->current.bytes_read - min_pkt_siz) {
        return -1;
    }

    enum ptype packet_type = ppkt_type_to_enum(&sock->current.pkt_buf.pheader);
    size_t packet_body_size = ppkt_size(packet_type);
    if (packet_body_size == 0 ||
        packet_body_size > sock->current.bytes_read - (min_pkt_siz + sizeof(sock->current.pkt_buf.pheader))) {
        return -1;
    }

    switch (packet_type) {
        case PTYPE_INVALID:
            return -1;
        case PTYPE_AUTH_REQUEST:
            sock->current.pkt_buf.pbody.auth_request.magic = ntohl(sock->current.pkt_buf.pbody.auth_request.magic);
            sock->current.pkt_buf.pbody.auth_request.authdata_siz =
                ntohs(sock->current.pkt_buf.pbody.auth_request.authdata_siz);
            break;
        case PTYPE_AUTH_RESPONSE:
            break;
    }

    size_t packet_data_size = ppkt_data_size(&sock->current.pkt_buf.pbody, packet_type);
    if (sock->current.bytes_read != min_pkt_siz + packet_body_size + packet_data_size) {
        return -1;
    }

    return 0;
}

static void ppkt_init_pkt(struct pdesc * desc, struct ppkt_buffer * pkt_buf, enum ptype type, size_t data_siz)
{
    pkt_buf->icmphdr.un.echo.id = desc->identifier;
    pkt_buf->icmphdr.un.echo.sequence = ++desc->sequence;
    switch (type) {
        case PTYPE_INVALID:
            pkt_buf->icmphdr.type = 3; // Destination Unreachable
            break;
        case PTYPE_AUTH_REQUEST:
            pkt_buf->icmphdr.type = 8; // Echo Request
            pkt_buf->pbody.auth_request.authdata_siz = data_siz;
            break;
        case PTYPE_AUTH_RESPONSE:
            pkt_buf->icmphdr.type = 0; // Echo Reply
            break;
    }
    pkt_buf->icmphdr.code = 0;
    pkt_buf->pheader.type = type;
    pkt_buf->pheader.total_size = ppkt_size(type) + ppkt_data_size(&pkt_buf->pbody, type);
}

static void ppkt_finalize_pkt(struct ppkt_buffer * const pkt_buf)
{
    pkt_buf->icmphdr.un.echo.id = htons(pkt_buf->icmphdr.un.echo.id);
    pkt_buf->icmphdr.un.echo.sequence = htons(pkt_buf->icmphdr.un.echo.sequence);
    switch (pkt_buf->pheader.type) {
        case PTYPE_INVALID:
            break;
        case PTYPE_AUTH_REQUEST:
            pkt_buf->pbody.auth_request.magic = htonl(PTUNNEL_MAGIC);
            pkt_buf->pbody.auth_request.authdata_siz = htons(pkt_buf->pbody.auth_request.authdata_siz);
            break;
        case PTYPE_AUTH_RESPONSE:
            break;
    }
    pkt_buf->pheader.total_size = htons(pkt_buf->pheader.total_size);

    pkt_buf->icmphdr.checksum = 0;
    pkt_buf->icmphdr.checksum = icmp_checksum_iovec(pkt_buf->iovec, pkt_buf->iovec_used);
}

void ppkt_prepare_auth_request(struct pdesc * desc,
                               struct ppkt_buffer * pkt_buf,
                               uint8_t * authdata,
                               size_t authdata_siz)
{
    ppkt_init_pkt(desc, pkt_buf, PTYPE_AUTH_REQUEST, authdata_siz);

    pkt_buf->iovec[0].iov_base = &pkt_buf->icmphdr;
    pkt_buf->iovec[0].iov_len = sizeof(pkt_buf->icmphdr);

    pkt_buf->iovec[1].iov_base = &pkt_buf->pheader;
    pkt_buf->iovec[1].iov_len = sizeof(pkt_buf->pheader);

    pkt_buf->iovec[2].iov_base = &pkt_buf->pbody.auth_request;
    pkt_buf->iovec[2].iov_len = sizeof(pkt_buf->pbody.auth_request);

    pkt_buf->iovec[3].iov_base = authdata;
    pkt_buf->iovec[3].iov_len = authdata_siz;

    pkt_buf->iovec_used = 4;

    ppkt_finalize_pkt(pkt_buf);
}
