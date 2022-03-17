#include "pdesc.h"
#include "psock.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>


int psock_init(struct psock * psock, size_t max_descriptors, size_t packet_buffer_size)
{
    struct epoll_event ev;

    memset(psock, 0, sizeof(*psock));

    psock->icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (psock->icmp_fd < 0)
    {
        goto error;
    }

    psock->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (psock->epoll_fd < 0)
    {
        goto error;
    }

    ev.events = EPOLLIN;
    ev.data.fd = psock->icmp_fd;
    if (epoll_ctl(psock->epoll_fd, EPOLL_CTL_ADD, psock->icmp_fd, &ev) != 0)
    {
        goto error;
    }

    psock->packet.max = packet_buffer_size;
    psock->packet.used = 0;
    psock->packet.buffer = (uint8_t *)calloc(packet_buffer_size, sizeof(*psock->packet.buffer));
    if (psock->packet.buffer == NULL)
    {
        goto error;
    }

    psock->remotes.max = max_descriptors;
    psock->remotes.used = 0;
    psock->remotes.descriptors = (struct pdesc *)calloc(max_descriptors, sizeof(*psock->remotes.descriptors));
    if (psock->remotes.descriptors == NULL)
    {
        goto error;
    }

    return 0;
error:
    if (errno != 0)
    {
        perror("[FATAL] psock_init failed");
    }
    psock_free(psock);
    return -1;
}

void psock_free(struct psock * psock)
{
    free(psock->remotes.descriptors);
    psock->remotes.descriptors = NULL;
    psock->remotes.used = 0;
    psock->remotes.max = 0;

    close(psock->icmp_fd);
    psock->icmp_fd = -1;

    close(psock->epoll_fd);
    psock->epoll_fd = -1;
}

static void psock_process_cmsg(struct msghdr * hdr)
{
    for (struct cmsghdr * cmsg = CMSG_FIRSTHDR(hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(hdr, cmsg))
    {
        printf("CMSG TYPE/LEVEL/LEN: %d / %d / %zu\n", cmsg->cmsg_type, cmsg->cmsg_level, cmsg->cmsg_len);
    }
}

static int psock_recvmsg(struct psock * psock)
{
    struct sockaddr_storage peer;
    struct iovec iov;
    struct msghdr hdr = {};
    ssize_t nread;

    iov.iov_base = (void *)psock->packet.buffer;
    iov.iov_len = psock->packet.max;

    hdr.msg_name = &peer;
    hdr.msg_namelen = sizeof(peer);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;

    do {
        nread = recvmsg(psock->icmp_fd, &hdr, 0);
    } while (nread == -1 && errno == EINTR);

    if (nread >= 0)
    {
        psock->packet.used = nread;
        psock_process_cmsg(&hdr);
        return 0;
    } else {
        psock->packet.used = 0;
        return -1;
    }
}

static int psock_sendmsg(struct psock * psock)
{
    return -1;
}

static void psock_handle_events(struct psock * psock)
{
    if (psock_recvmsg(psock) == 0)
    {
        switch (pdesc_find_remote(psock))
        {
            case PDESC_REMOTE_NEW:
                fprintf(stderr, "Remote NEW.\n");
                break;
            case PDESC_REMOTE_INVALID:
                fprintf(stderr, "Remote INVALID\n");
                break;
            case PDESC_REMOTE_FOUND:
                fprintf(stderr, "Remote FOUND\n");
                break;
        }
    }
}

void psock_loop(struct psock * psock)
{
    const int max_events = 32;
    struct epoll_event events[max_events];

    while (1)
    {
        int nready = epoll_wait(psock->epoll_fd, events, max_events, -1);

        switch (nready)
        {
            case -1:
                break;
            case 0:
                continue;
            default:
                psock_handle_events(psock);
                break;
        }
    }
}
