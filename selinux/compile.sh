#!/bin/sh

set -x
set -e

OUTDIR="$(dirname $0)"
checkmodule -M -m -o ${OUTDIR}/ptunnel-ng.mod ${OUTDIR}/ptunnel-ng.te
semodule_package -o ${OUTDIR}/ptunnel-ng.pp -m ${OUTDIR}/ptunnel-ng.mod

exit 0
