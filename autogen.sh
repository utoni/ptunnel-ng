#!/bin/bash

set -e
set -x

OLDPWD=$(pwd)
cd $(dirname $0)
test -f Makefile && make distclean

aclocal
autoheader
automake --force-missing --add-missing
autoconf

cd ${OLDPWD}
$(dirname $0)/configure $@ && make -j${BUILDJOBS:-4} all
