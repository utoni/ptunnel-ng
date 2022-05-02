#include "pdesc.h"
#include "psock.h"
#include "ppkt.h"
#include "putils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int psock_init(struct psock * sock, size_t max_descriptors, size_t packet_buffer_size)
{
    memset(sock, 0, sizeof(*sock));

    sock->current.packet.max = packet_buffer_size;
    sock->current.packet.used = 0;
    sock->current.packet.buffer = (uint8_t *)calloc(packet_buffer_size, sizeof(*sock->current.packet.buffer));
    if (sock->current.packet.buffer == NULL) {
        goto error;
    }

    sock->remotes.max = max_descriptors;
    sock->remotes.used = 0;
    sock->remotes.descriptors = (struct pdesc *)calloc(max_descriptors, sizeof(*sock->remotes.descriptors));
    if (sock->remotes.descriptors == NULL) {
        goto error;
    }

    return 0;
error:
    psock_free(sock);
    return -1;
}

int psock_setup_fds(struct psock * sock, int is_client)
{
    struct epoll_event ev;

    errno = 0;

    sock->icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock->icmp_fd < 0) {
        goto error;
    }

    sock->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (sock->epoll_fd < 0) {
        goto error;
    }

    ev.events = EPOLLIN;
    ev.data.fd = sock->icmp_fd;
    if (epoll_ctl(sock->epoll_fd, EPOLL_CTL_ADD, sock->icmp_fd, &ev) != 0) {
        goto error;
    }

    sock->local.is_client = is_client;
    return 0;
error:
    if (errno != 0) {
        logger(1, "file descriptor setup failed: %s", strerror(errno));
    }
    psock_free(sock);
    return -1;
}

static int psock_name_to_address(char const * address, struct sockaddr_storage * const sockaddr, size_t * sockaddr_size)
{
    struct addrinfo hints = {};
    struct addrinfo *result, *rp;
    int ret;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(address, NULL, &hints, &result);
    if (ret != 0) {
        logger_early(1, "Could not add server '%s': %s", address, gai_strerror(ret));
        return ret;
    }

    size_t i = 0;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (i == *sockaddr_size) {
            break;
        }
        switch (rp->ai_family) {
            case AF_INET: {
                memcpy(&sockaddr[i++], rp->ai_addr, sizeof(struct sockaddr_in));
                break;
            }
            case AF_INET6: {
                memcpy(&sockaddr[i++], rp->ai_addr, sizeof(struct sockaddr_in6));
                break;
            }
            default:
                logger_early(1, "getaddrinfo() returned an invalid address family: %d", rp->ai_family);
                break;
        }
    }
    *sockaddr_size = i;

    freeaddrinfo(result);
    return ret;
}

int psock_add_server(struct psock * sock, char const * address)
{
    size_t max_sockaddrs = 8;
    struct sockaddr_storage sockaddrs[max_sockaddrs];

    if (psock_name_to_address(address, sockaddrs, &max_sockaddrs) != 0) {
        return -1;
    }

    for (size_t addr_i = 0; sock->remotes.used < sock->remotes.max && addr_i < max_sockaddrs;
         ++sock->remotes.used, ++addr_i) {
        size_t desc_i = sock->remotes.used;

        switch (sockaddrs[addr_i].ss_family) {
            case AF_INET: {
                struct in_addr addr = ((struct sockaddr_in *)&sockaddrs[addr_i])->sin_addr;
                if (inet_ntop(AF_INET, &addr, sock->remotes.descriptors[desc_i].peer_str, sizeof(struct sockaddr_in)) ==
                    NULL) {
                    logger_early(1, "inet_ntop() conversion failed: %s", strerror(errno));
                    return -1;
                }
                break;
            }
            case AF_INET6: {
                struct in6_addr addr = ((struct sockaddr_in6 *)&sockaddrs[addr_i])->sin6_addr;
                if (inet_ntop(AF_INET6,
                              &addr,
                              sock->remotes.descriptors[desc_i].peer_str,
                              sizeof(struct sockaddr_in6)) == NULL) {
                    logger_early(1, "inet_ntop() conversion failed: %s", strerror(errno));
                    return -1;
                }
                break;
            }
        }
        logger_early(0, "Added remote: %s", sock->remotes.descriptors[desc_i].peer_str);
    }

    return 0;
}

void psock_free(struct psock * sock)
{
    free(sock->remotes.descriptors);
    sock->remotes.descriptors = NULL;
    sock->remotes.used = 0;
    sock->remotes.max = 0;

    close(sock->icmp_fd);
    sock->icmp_fd = -1;

    close(sock->epoll_fd);
    sock->epoll_fd = -1;
}

static void psock_process_cmsg(struct msghdr * hdr)
{
    for (struct cmsghdr * cmsg = CMSG_FIRSTHDR(hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(hdr, cmsg)) {
        printf("CMSG TYPE/LEVEL/LEN: %d / %d / %zu\n", cmsg->cmsg_type, cmsg->cmsg_level, cmsg->cmsg_len);
    }
}

static int psock_recvmsg(struct psock * sock)
{
    struct iovec iov;
    struct msghdr hdr = {};
    ssize_t nread;

    iov.iov_base = (void *)sock->current.packet.buffer;
    iov.iov_len = sock->current.packet.max;

    hdr.msg_name = &sock->current.peer;
    hdr.msg_namelen = sizeof(sock->current.peer);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;

    do {
        nread = recvmsg(sock->icmp_fd, &hdr, 0);
    } while (nread == -1 && errno == EINTR);

    if (nread >= 0) {
        sock->current.packet.used = nread;
        psock_process_cmsg(&hdr);
        return 0;
    } else {
        sock->current.packet.used = 0;
        return -1;
    }
}

static int psock_sendmsg(struct psock * sock, struct iovec * const iov, size_t iovlen)
{
    struct msghdr hdr = {};
    ssize_t nwritten;

    hdr.msg_name = &sock->current.peer;
    hdr.msg_namelen = sizeof(sock->current.peer);
    hdr.msg_iov = iov;
    hdr.msg_iovlen = iovlen;

    nwritten = sendmsg(sock->icmp_fd, &hdr, 0);

    return nwritten;
}

static void psock_handle_events(struct psock * sock)
{
    if (psock_recvmsg(sock) == 0) {
        struct pdesc * remote;

        switch (pdesc_find_current_remote(sock, &remote)) {
            case REMOTE_EXISTS:
                printf("Existing Remote with descriptor ID: %u\n", remote->identifier);
                break;
            case REMOTE_NOT_FOUND:
                printf("New Remote with descriptor ID: %u\n", remote->identifier);
                break;
            case REMOTE_PACKET_INVALID:
                fprintf(stderr, "Invalid packet received.\n");
                break;
            case REMOTE_ICMP_ECHO_CLIENT:
                fprintf(stderr, "Received ICMP echo, but I am a client.\n");
                break;
            case REMOTE_ICMP_REPLY_SERVER:
                fprintf(stderr, "Received ICMP reply, but I am a server.\n");
                break;
            case REMOTE_MAX_DESCRIPTORS:
                fprintf(stderr, "Max descriptors reached, sorry.\n");
                break;
        }
    }
}

void psock_loop(struct psock * sock)
{
    const int max_events = 32;
    struct epoll_event events[max_events];

    while (1) {
        int nready = epoll_wait(sock->epoll_fd, events, max_events, 1000);

        switch (nready) {
            case -1:
                break;
            case 0:
                if (sock->local.is_client != 0) {
                    uint8_t b[3] = {0x41, 0x42, 0x43};
                    struct ppkt_buffer pb;
                    ppkt_prepare_auth_request(&pb, b, 3);
                    psock_sendmsg(sock, pb.iovec, pb.iovec_used);
                }
                continue;
            default:
                psock_handle_events(sock);
                break;
        }
    }
}
