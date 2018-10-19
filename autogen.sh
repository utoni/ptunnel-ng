#!/bin/bash

set -x

if ! autoreconf -fi; then
    aclocal
    autoheader
    automake --force-missing --add-missing
    autoconf
fi

$(dirname $0)/configure $@ && make -j${BUILDJOBS:-4} all
