#!/bin/bash

BINDIR=../sandbox/7.8.3/bin
EXAMPLE_CLIENT=${BINDIR}/example-client
LOCAL_CACHE=../unversioned/cache/
#REPO=http://localhost:8080
REPO=http://localhost/~e/local-repo

rm -r ${LOCAL_CACHE}
${EXAMPLE_CLIENT} --repo ${REPO} --cache ${LOCAL_CACHE} bootstrap 0
dd if=/dev/zero of=${LOCAL_CACHE}/00-index.tar bs=1024 count=1
${EXAMPLE_CLIENT} --repo ${REPO} --cache ${LOCAL_CACHE} check

