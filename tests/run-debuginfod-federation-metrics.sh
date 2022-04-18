#!/usr/bin/env bash
#
# Copyright (C) 2019-2021 Red Hat, Inc.
# This file is part of elfutils.
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# elfutils is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

. $srcdir/debuginfod-subr.sh

# for test case debugging, uncomment:
set -x
unset VALGRIND_CMD

DB=${PWD}/.debuginfod_tmp.sqlite
export DEBUGINFOD_CACHE_PATH=${PWD}/.client_cache
export DEBUGINFOD_URLS='http://127.0.0.1:0' # Note invalid, will trigger error_count metric
tempfiles $DB
# Clean old dirictories
mkdir F

# This variable is essential and ensures no time-race for claiming ports occurs
# set base to a unique multiple of 100 not used in any other 'run-debuginfod-*' test
base=9000
get_ports

# Launch server which will be unable to follow symlinks
env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../debuginfod/debuginfod $VERBOSE -d ${DB} -F -t0 -g0 -p $PORT1 F > vlog$PORT1 2>&1 &
PID1=$!
tempfiles vlog$PORT1
errfiles vlog$PORT1

wait_ready $PORT1 'ready' 1

# Wait till initial scan is done
wait_ready $PORT1 'thread_work_total{role="traverse"}' 1
wait_ready $PORT1 'thread_work_pending{role="scan"}' 0
wait_ready $PORT1 'thread_busy{role="scan"}' 0

echo "int main() { return 0; }" > ${PWD}/prog.c
tempfiles prog.c
gcc -Wl,--build-id -g -o prog ${PWD}/prog.c
testrun ${abs_top_builddir}/src/strip -g -f prog.debug ${PWD}/prog
BUILDID=`env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../src/readelf \
          -a prog | grep 'Build ID' | cut -d ' ' -f 7`
mv prog F
mv prog.debug F
kill -USR1 $PID1

# Wait till both files are in the index.
wait_ready $PORT1 'thread_work_total{role="traverse"}' 2
wait_ready $PORT1 'thread_work_pending{role="scan"}' 0
wait_ready $PORT1 'thread_busy{role="scan"}' 0

wait_ready $PORT1 'thread_busy{role="http-metrics"}' 1

export DEBUGINFOD_CACHE_PATH=${PWD}/.client_cache2
mkdir -p $DEBUGINFOD_CACHE_PATH

env LD_LIBRARY_PATH=$ldpath DEBUGINFOD_URLS=http://127.0.0.1:$PORT1 ${abs_builddir}/../debuginfod/debuginfod $VERBOSE -d ${DB}_2 -F -U -p $PORT2 > vlog$PORT2 2>&1 &
PID2=$!
tempfiles vlog$PORT2
errfiles vlog$PORT2
tempfiles ${DB}_2

# Wait till initial scan is done
wait_ready $PORT2 'thread_work_total{role="traverse"}' 1
wait_ready $PORT2 'thread_work_pending{role="scan"}' 0
wait_ready $PORT2 'thread_busy{role="scan"}' 0

wait_ready $PORT1 'thread_busy{role="http-metrics"}' 1

########################################################################
# Trigger http_responses_total.*result.*upstream in $PORT2
DEBUGINFOD_URLS=http://127.0.0.1:$PORT2 testrun  ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID
# Trigger error_count in $PORT1
DEBUGINFOD_URLS=http://127.0.0.1:$PORT1 testrun  ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo deadbeef && true

# Fetch some metrics
curl -s http://127.0.0.1:$PORT1/badapi
curl -s http://127.0.0.1:$PORT1/metrics
curl -s http://127.0.0.1:$PORT2/metrics
curl -s http://127.0.0.1:$PORT1/metrics | grep -q 'http_responses_total.*result.*error'
curl -s http://127.0.0.1:$PORT2/metrics | grep -q 'http_responses_total.*result.*upstream'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'http_responses_duration_milliseconds_count'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'http_responses_duration_milliseconds_sum'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'http_responses_transfer_bytes_count'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'http_responses_transfer_bytes_sum'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'fdcache_'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'error_count'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'traversed_total'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'scanned_bytes_total'

# And generate a few errors into the second debuginfod's logs, for analysis just below
curl -s http://127.0.0.1:$PORT2/badapi > /dev/null || true
curl -s http://127.0.0.1:$PORT2/buildid/deadbeef/debuginfo > /dev/null || true
# NB: this error is used to seed the 404 failure for the survive-404 tests

# Confirm bad artifact types are rejected without leaving trace
curl -s http://127.0.0.1:$PORT2/buildid/deadbeef/badtype > /dev/null || true
(curl -s http://127.0.0.1:$PORT2/metrics | grep 'badtype') && false

# Confirm that reused curl connections survive 404 errors.
# The rm's force an uncached fetch (in both servers and client cache)
DEBUGINFOD_URLS="http://127.0.0.1:$PORT2"
rm -f .client_cache*/$BUILDID/debuginfo
testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID
rm -f .client_cache*/$BUILDID/debuginfo
testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID
testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID
testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID
rm -f .client_cache*/$BUILDID/debuginfo
testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID

# Confirm that some debuginfod client pools are being used
curl -s http://127.0.0.1:$PORT2/metrics | grep 'dc_pool_op.*reuse'

# Trigger a flood of requests against the same archive content file.
# Use a file that hasn't been previously extracted in to make it
# likely that even this test debuginfod will experience concurrency
# and impose some "after-you" delays.
(for i in `seq 100`; do
    curl -s http://127.0.0.1:$PORT1/buildid/87c08d12c78174f1082b7c888b3238219b0eb265/executable >/dev/null &
 done;
 wait)
curl -s http://127.0.0.1:$PORT1/metrics | grep 'http_responses_after_you.*'
# If we could guarantee some minimum number of seconds of CPU time, we
# could assert that the after_you metrics show some nonzero amount of
# waiting.  A few hundred ms is typical on this developer's workstation.

kill $PID1
kill $PID2
wait $PID1
wait $PID2
PID1=0
PID2=0
exit 0
