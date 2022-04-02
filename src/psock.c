#include "pdesc.h"
#include "psock.h"
#include "ppkt.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

int psock_init(struct psock * sock, int is_client, size_t max_descriptors, size_t packet_buffer_size)
{
    struct epoll_event ev;

    memset(sock, 0, sizeof(*sock));

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
    if (errno != 0) {
        perror("[FATAL] psock_init failed");
    }
    psock_free(sock);
    return -1;
}

int psock_add_server(char const * const address)
{
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

        switch (pdesc_find_remote(sock, &remote)) {
            case REMOTE_FOUND:
                printf("Remote descriptor ID: %u\n", remote->identifier);
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
