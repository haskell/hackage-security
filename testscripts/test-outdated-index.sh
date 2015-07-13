#!/bin/bash

##
# Cache incoherence test 2: outdated index
#
# DESCRIPTION
#
# The general approach is the same as in test 1, except we now set things up
# so that the cache has an outdated index.
#
# EXPECTED OUTCOME
#
# We should recover from the cache incoherence problem and still download the
# index incrementally (rather than downloading the entire index from scratch).
# See example log file for a succcessful run.
#
# ASSUMPTIONS
#
# Since this relies on incremental downloads, it must currently be tested
# against Apache rather than Hackage. Make sure to have
#
#   Header set Cache-Control "max-age=5, public, no-transform"
#
# in your .htaccess (and set AllowOverride: All for your domain, if necessary).
# As for test 1, you should also have a fresh instance of squid running.
##

set -x

BINDIR=../sandbox/7.8.3/bin
EXAMPLE_CLIENT=${BINDIR}/example-client
SECURITY_UTILITY=${BINDIR}/hackage-security
REPO=http://127.0.0.1/~e/local-repo
PROXY=http://localhost:3128
LOCAL_REPO=../unversioned/local-repo
KEYS=../unversioned/keys
LOCAL_CACHE=./tmp                        # NOTE: We will delete this directory

# Reset the repo
rm -rf ${LOCAL_REPO}/index
${SECURITY_UTILITY} -v bootstrap --repo ${LOCAL_REPO} --keys ${KEYS}

# Start with a fresh local cache, and do an update (directly, without squid) so
# that we have a local copy of the index that we can update incrementally later
unset HTTP_PROXY
unset http_proxy
rm -rf ${LOCAL_CACHE}
${EXAMPLE_CLIENT} --repo ${REPO} --cache ${LOCAL_CACHE} bootstrap 0
${EXAMPLE_CLIENT} --repo ${REPO} --cache ${LOCAL_CACHE} check

# Now start using squid
export HTTP_PROXY=${PROXY}
export http_proxy=${PROXY}

# Get the index from the server so that it's in squid's cache
curl -Lv ${REPO}/00-index.tar >/dev/null

# Add something to the index, and update snapshot/timestamp
# Sleep a bit first, so that the time on the extra file is definitely different
# to the time on the index
sleep 5
dd bs=1 count=16384 if=/dev/random of=${LOCAL_REPO}/index/extra-file
${SECURITY_UTILITY} -v update --repo ${LOCAL_REPO} --keys ${KEYS}

# Now do another update.
# The timestamp and snapshot will be out of sync with each other.
${EXAMPLE_CLIENT} --repo ${REPO} --cache ${LOCAL_CACHE} check
