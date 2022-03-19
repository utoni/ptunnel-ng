#include "ppkt.h"
#include "psock.h"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

int ppkt_process_icmp(struct psock * psock)
{
    if (psock->current.peer.ss_family == AF_INET) {
        psock->current.packet.icmphdr = (struct icmphdr *)(psock->current.packet.buffer + sizeof(struct iphdr));

        psock->current.packet.icmphdr->checksum = ntohs(psock->current.packet.icmphdr->checksum);
        psock->current.packet.icmphdr->un.echo.id = ntohs(psock->current.packet.icmphdr->un.echo.id);
        psock->current.packet.icmphdr->un.echo.sequence = ntohs(psock->current.packet.icmphdr->un.echo.sequence);
    } else {
        return -1;
    }

    return 0;
}

int ppkt_process_ppkt(struct psock * psock)
{
    if (psock->current.peer.ss_family == AF_INET) {
        if (psock->current.packet.used < sizeof(struct iphdr) + sizeof(*psock->current.packet.icmphdr)) {
            return -1;
        }

        psock->current.packet.ppkt = (struct ppkt *)(psock->current.packet.buffer + sizeof(struct iphdr) +
                                                     sizeof(*psock->current.packet.icmphdr));
    } else {
        return -1;
    }

    psock->current.packet.ppkt->ident = ntohl(psock->current.packet.ppkt->ident);
    if (psock->current.packet.ppkt->ident != PTUNNEL_IDENT) {
        return -1;
    }

    psock->current.packet.ppkt->total_size = ntohs(psock->current.packet.ppkt->total_size);
    if (psock->current.packet.ppkt->total_size > psock->current.packet.used) {
        return -1;
    }

    return 0;
}
