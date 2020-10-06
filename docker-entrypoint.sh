#!/bin/sh
set -e
/usr/local/bin/ptunnel-ng "$@" &
wait