#!/usr/bin/env bash

set -e
set -x
set -o pipefail


BIN_ROOT="${BIN_ROOT:-$(realpath $(dirname $0)/..)}"
PTUNNEL_BIN=${PTUNNEL_BIN:-${BIN_ROOT}/src/ptunnel-ng}
PTUNNEL_ARGS="${PTUNNEL_ARGS:-}"
VALGRIND_BIN=${VALGRIND_BIN:-valgrind}
VALGRIND_ARGS="--error-exitcode=1 --exit-on-first-error=yes"
if [ "x${DISABLE_VALGRIND}" = xy ]; then
    VALGRIND_BIN=""
    VALGRIND_ARGS=""
fi

test -x "${PTUNNEL_BIN}"

####################
# Test PERFORMANCE #
####################
TUNNEL_TIMEOUT=25
DATA_TIMEOUT=22

echo -n >/tmp/ptunnel-server.log
echo -n >/tmp/ptunnel-client.log

timeout --foreground -k1 ${TUNNEL_TIMEOUT} \
    ${VALGRIND_BIN} ${VALGRIND_ARGS} \
    "${PTUNNEL_BIN}" -v4 -r127.0.0.1 -R3000 -l4000 ${PTUNNEL_ARGS} -o/tmp/ptunnel-server.log &
PTUNNEL_SERVER_PID=$!

timeout --foreground -k1 ${TUNNEL_TIMEOUT} \
    ${VALGRIND_BIN} ${VALGRIND_ARGS} \
    "${PTUNNEL_BIN}" -v4 -p127.0.0.1 -r127.0.0.1 -R3000 -l4000 ${PTUNNEL_ARGS} -o/tmp/ptunnel-client.log &
PTUNNEL_CLIENT_PID=$!

timeout --foreground -k1 ${DATA_TIMEOUT} \
    nc -l -p 3000 >/dev/null || true &
DATA_SERVER_PID=$!

sleep 3
timeout --foreground -k1 ${DATA_TIMEOUT} \
    sh -c "dd if=/dev/urandom bs=8192 | nc 127.0.0.1 4000" || true

wait ${PTUNNEL_CLIENT_PID} || true
wait ${PTUNNEL_SERVER_PID} || true
wait ${DATA_SERVER_PID} || true

cat /tmp/ptunnel-client.log
cat /tmp/ptunnel-server.log

cat /tmp/ptunnel-client.log |& grep 'Incoming connection.'
cat /tmp/ptunnel-server.log |& grep 'Starting new session to 127.0.0.1:3000'

# verify results
CLIENT_ACK_SERIES=$(cat /tmp/ptunnel-client.log |& grep 'Received ack-series starting at seq' | wc -l)
SERVER_ACK_SERIES=$(cat /tmp/ptunnel-server.log |& grep 'Received ack-series starting at seq' | \
                    grep -v 'Received ack-series starting at seq 65535' | wc -l)
test ${CLIENT_ACK_SERIES} -eq ${SERVER_ACK_SERIES}

#######################
# Test DATA INTEGRITY #
#######################
TUNNEL_TIMEOUT=10
DATA_TIMEOUT=7

echo -n >/tmp/ptunnel-server.log
echo -n >/tmp/ptunnel-client.log

timeout --foreground -k1 ${TUNNEL_TIMEOUT} \
    ${VALGRIND_BIN} ${VALGRIND_ARGS} \
    "${PTUNNEL_BIN}" -v4 -r127.0.0.1 -R3000 -l4000 ${PTUNNEL_ARGS} -o/tmp/ptunnel-server.log &
PTUNNEL_SERVER_PID=$!

timeout --foreground -k1 ${TUNNEL_TIMEOUT} \
    ${VALGRIND_BIN} ${VALGRIND_ARGS} \
    "${PTUNNEL_BIN}" -v4 -p127.0.0.1 -r127.0.0.1 -R3000 -l4000 ${PTUNNEL_ARGS} -o/tmp/ptunnel-client.log &
PTUNNEL_CLIENT_PID=$!

timeout --foreground -k1 ${DATA_TIMEOUT} \
    nc -l -p 3000 >/tmp/ptunnel-data-recv || true &
DATA_SERVER_PID=$!

sleep 3
timeout --foreground -k1 ${DATA_TIMEOUT} \
    sh -c "dd if=/dev/urandom bs=8192 count=1 >/tmp/ptunnel-data-send && cat /tmp/ptunnel-data-send | sha256sum | cut -d' ' -f1 >/tmp/ptunnel-data-send.sha256 && cat /tmp/ptunnel-data-send | nc 127.0.0.1 4000" || true

wait ${PTUNNEL_CLIENT_PID} || true
wait ${PTUNNEL_SERVER_PID} || true
wait ${DATA_SERVER_PID} || true

# verify results
test ${CLIENT_ACK_SERIES} -eq ${SERVER_ACK_SERIES}
CLIENT_SHA=$(cat /tmp/ptunnel-data-send.sha256)
SERVER_SHA=$(cat /tmp/ptunnel-data-recv | sha256sum | cut -d' ' -f1)
test ${CLIENT_SHA} = ${SERVER_SHA}


set +x
printf '[+] SUCCESS !!\n'
