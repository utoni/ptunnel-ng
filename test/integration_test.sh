#!/usr/bin/env bash

set -e
set -x
set -o pipefail


SRC_ROOT=$(realpath $(dirname $0)/..)
PTUNNEL_BIN=${SRC_ROOT}/src/ptunnel-ng

TUNNEL_TIMEOUT=25
timeout --foreground -k1 ${TUNNEL_TIMEOUT} \
    valgrind --error-exitcode=1 --exit-on-first-error=yes \
    "${PTUNNEL_BIN}" -v4 -r127.0.0.1 -R3000 -l4000 >/tmp/ptunnel-server.log &
PTUNNEL_SERVER_PID=$!

timeout --foreground -k1 ${TUNNEL_TIMEOUT} \
    valgrind --error-exitcode=1 --exit-on-first-error=yes \
    "${PTUNNEL_BIN}" -v4 -p127.0.0.1 -r127.0.0.1 -R3000 -l4000 >/tmp/ptunnel-client.log &
PTUNNEL_CLIENT_PID=$!

timeout --foreground -k1 ${TUNNEL_TIMEOUT} \
    nc -l -p 3000 >/dev/null &
DATA_SERVER_PID=$!

sleep 3
DATA_TIMEOUT=20
timeout --foreground -k1 ${DATA_TIMEOUT} \
    sh -c "dd if=/dev/urandom bs=8192 | nc 127.0.0.1 4000" || true

wait ${PTUNNEL_SERVER_PID} || true
wait ${PTUNNEL_CLIENT_PID} || true
wait ${DATA_SERVER_PID} || true

printf 'done\n'
