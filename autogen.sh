#!/bin/bash

set -e
set -x

test -f ./Makefile && make distclean

aclocal
autoheader
automake --force-missing --add-missing
autoconf

./configure $@ && make -j${BUILDJOBS:-4} all
