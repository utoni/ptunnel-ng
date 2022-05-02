#include "pdesc.h"
#include "psock.h"
#include "putils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct {
    int is_client;
    int log_to_console;
} ptunnel_options = {.is_client = 0, .log_to_console = 0};

int parse_options(struct psock * sock, int argc, char ** argv)
{
    int ret = 0, opt;

    while ((opt = getopt(argc, argv, "lca:")) != -1) {
        switch (opt) {
            case 'l':
                ptunnel_options.log_to_console = 1;
                enable_console_logger();
                break;
            case 'c':
                ptunnel_options.is_client = 1;
                break;
            case 'a':
                if (psock_add_server(sock, optarg) != 0) {
                    logger_early(1, "Could not add server: %s", optarg);
                    ret++;
                }
                break;
        }
    }

    return ret;
}

int validate_options(struct psock const * sock)
{
    logger_early(0, "Running in %s mode.", (ptunnel_options.is_client == 0 ? "proxy" : "forward"));

    if (ptunnel_options.is_client != 0 && sock->remotes.used == 0) {
        logger_early(1, "An address (`-a') is mandatory in forward mode.");
        return -1;
    }

    return 0;
}

int main(int argc, char ** argv)
{
    int ret = 0;
    struct psock sock = {};

    init_logging("ptunnel-ng");

    if (psock_init(&sock, 16, 1500) != 0) {
        logger(1, "%s", "Socket initialization failed");
        ret++;
        goto failure;
    }

    ret += parse_options(&sock, argc, argv);
    if (ret != 0) {
        logger_early(1, "Command line option parsing failed: %d argument(s)", ret);
        ret++;
        goto failure;
    }

    shutdown_logging();
    init_logging((ptunnel_options.is_client == 0 ? "ptunnel-ng-proxy" : "ptunnel-ng-forwarder"));
    if (ptunnel_options.log_to_console != 0) {
        enable_console_logger();
    }

    if (validate_options(&sock) != 0) {
        logger(1, "%s", "Command line validation failed");
        ret++;
        goto failure;
    }

    if (psock_setup_fds(&sock, ptunnel_options.is_client) != 0) {
        logger(1, "%s", "Socket setup failed");
        ret++;
        goto failure;
    }
    psock_loop(&sock);

failure:
    psock_free(&sock);
    shutdown_logging();

    return ret;
}
