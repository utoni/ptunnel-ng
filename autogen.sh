#!/bin/bash

set -x

OLD_WD="$(pwd)"
NEW_WD="$(dirname ${0})"

cd "${NEW_WD}"

if ! autoreconf -fi; then
    aclocal
    autoheader
    automake --force-missing --add-missing
    autoconf
fi

cd "${OLD_WD}"

"${NEW_WD}/configure" $@ && make clean && make -j${BUILDJOBS:-4} all
