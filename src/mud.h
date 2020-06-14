#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MUD_PATH_MAX    (32U)
#define MUD_PUBKEY_SIZE (32U)

struct mud;

enum mud_state {
    MUD_EMPTY = 0,
    MUD_DOWN,
    MUD_PASSIVE,
    MUD_UP,
    MUD_LAST,
};

enum mud_path_status {
    MUD_DELETING = 0,
    MUD_PROBING,
    MUD_DEGRADED,
    MUD_LOSSY,
    MUD_WAITING,
    MUD_READY,
    MUD_RUNNING,
};

struct mud_stat {
    uint64_t val;
    uint64_t var;
    int setup;
};

struct mud_conf {
    uint64_t keepalive;
    uint64_t timetolerance;
    uint64_t kxtimeout;
};

union mud_sockaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

struct mud_path_conf {
    enum mud_state state;
    union mud_sockaddr local;
    union mud_sockaddr remote;
    uint64_t tx_max_rate;
    uint64_t rx_max_rate;
    uint64_t beat;
    unsigned char pref;
    unsigned char fixed_rate;
    unsigned char loss_limit;
};

struct mud_path {
    struct mud_path_conf conf;
    enum mud_path_status status;
    union mud_sockaddr remote;
    struct mud_stat rtt;
    struct {
        uint64_t total;
        uint64_t bytes;
        uint64_t time;
        uint64_t rate;
        uint64_t loss;
    } tx, rx;
    struct {
        struct {
            uint64_t total;
            uint64_t bytes;
            uint64_t time;
            uint64_t acc;
            uint64_t acc_time;
        } tx, rx;
        uint64_t time;
        uint64_t sent;
        uint64_t set;
    } msg;
    struct {
        size_t min;
        size_t max;
        size_t probe;
        size_t last;
        size_t ok;
    } mtu;
    uint64_t idle;
};

struct mud_error {
    union mud_sockaddr addr;
    uint64_t time;
    uint64_t count;
};

struct mud_errors {
    struct mud_error decrypt;
    struct mud_error clocksync;
    struct mud_error keyx;
};

struct mud_paths {
    struct mud_path path[MUD_PATH_MAX];
    unsigned count;
};

struct mud *mud_create (union mud_sockaddr *, unsigned char *, int *);
void        mud_delete (struct mud *);

int mud_set      (struct mud *, struct mud_conf *);
int mud_set_path (struct mud *, struct mud_path_conf *);

int mud_update    (struct mud *);
int mud_send_wait (struct mud *);

int mud_recv (struct mud *, void *, size_t);
int mud_send (struct mud *, const void *, size_t);

int    mud_get_errors (struct mud *, struct mud_errors *);
int    mud_get_fd     (struct mud *);
size_t mud_get_mtu    (struct mud *);
int    mud_get_paths  (struct mud *, struct mud_paths *,
                       union mud_sockaddr *, union mud_sockaddr *);
