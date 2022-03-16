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


int psock_init(struct psock * psock, size_t max_descriptors)
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

    psock->remotes.max = max_descriptors;
    psock->remotes.used = 0;
    psock->remotes.descriptors = (struct pdesc **)calloc(max_descriptors, sizeof(**psock->remotes.descriptors));

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

static void psock_handle_events(struct psock * psock)
{
    printf("!!!!!!\n");
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
