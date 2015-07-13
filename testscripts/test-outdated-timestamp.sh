#!/bin/bash

##
# Cache incoherence test 1: outdated timestamp
#
# DESCRIPTION
#
# We request the timestamp from the server through the proxy, so that it's in
# the proxy's cache (assuming a `max-age` header was set on the file). We then
# ask Hackage to resign, and do a check-for-updates using `example-client`.
# This will cause the proxy to return the now-outdated `timestamp` but a newer
# snapshot.
#
# NOTE: We refer to the cache maintained by the `hackage-security` library
# (through `example-client`) as the "local cache", and the cache maintained by
# squid as the "proxy cache".
#
# EXPECTED OUTCOME
#
# The client should detect this and try the request again, asking the
# cache to fetch the file stream. See the example log file.
#
# ASSUMPTIONS
#
# We assume Hackage is running on the same machine as the test script (so that
# we can send it SIGHUP), and that we have a fresh (nothing cached yet) instance
# of squid. There is an example configuration file for squid in this directory;
# start with
#
#     ~/homebrew/sbin/squid -f ./squid.conf -N -d 1
#
# (mutatis mutandis).
##

# Configuration
BINDIR=../sandbox/7.8.3/bin
EXAMPLE_CLIENT=${BINDIR}/example-client
REPO=http://127.0.0.1:8080
PROXY=http://localhost:3128
LOCAL_CACHE=./tmp                        # NOTE: We will delete this directory

set -x

# Enable the proxy
export HTTP_PROXY=${PROXY}
export http_proxy=${PROXY}

# Start with a fresh local cache (so that we definitely have updates)
rm -rf ${LOCAL_CACHE}
${EXAMPLE_CLIENT} --repo ${REPO} --cache ${LOCAL_CACHE} bootstrap 0

# Get the timestamp from the server (so that it's in proxy cache)
curl -Lv ${REPO}/timestamp.json >/dev/null

# Make the server resign the timestamp
killall -SIGHUP hackage-server
sleep 5

# Now do an update
${EXAMPLE_CLIENT} --repo ${REPO} --cache ${LOCAL_CACHE} check
