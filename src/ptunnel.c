#include "pdesc.h"
#include "psock.h"
#include "putils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct {
    int is_client;
    struct {
        char * str;
        struct sockaddr_storage sockaddr;
    } address;
} ptunnel_options = {.is_client = 0};

int parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "ca:")) != -1) {
        switch (opt) {
            case 'c':
                ptunnel_options.is_client = 1;
                break;
            case 'a':
                ptunnel_options.address.str = strdup(optarg);
                break;
        }
    }

    return 0;
}

int validate_options(void)
{
    logger_early(0, "Running in %s mode.", (ptunnel_options.is_client == 0 ? "proxy" : "forward"));

    if (ptunnel_options.is_client != 0 && ptunnel_options.address.str == NULL) {
        logger_early(1, "An adress (`-a') is mandatory in forward mode.");
        return -1;
    }

    return 0;
}

int main(int argc, char ** argv)
{
    struct psock psock = {};

    init_logging("ptunnel-ng");

    enable_console_logger();

    if (parse_options(argc, argv) != 0) {
        return 1;
    }

    if (validate_options() != 0) {
        return 1;
    }

    if (psock_init(&psock, 16, 1500) != 0) {
        return 1;
    }

    psock_loop(&psock);

    psock_free(&psock);

    shutdown_logging();

    return 0;
}
