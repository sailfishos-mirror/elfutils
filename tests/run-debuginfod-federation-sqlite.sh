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
tempfiles $DB

# Clean old dirictories
mkdir F

########################################################################
# Compile a simple program, strip its debuginfo and save the build-id.
echo "int main() { return 0; }" > ${PWD}/prog.c
# Create a subdirectory to confound source path names
gcc -Wl,--build-id -g -o prog ${PWD}/prog.c
tempfiles prog.c
testrun ${abs_top_builddir}/src/strip -g -f prog.debug ${PWD}/prog
BUILDID=`env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../src/readelf \
          -a prog | grep 'Build ID' | cut -d ' ' -f 7`

mv prog F
mv prog.debug F
# This variable is essential and ensures no time-race for claiming ports occurs
# set base to a unique multiple of 100 not used in any other 'run-debuginfod-*' test
base=9100
get_ports

env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../debuginfod/debuginfod $VERBOSE -d ${DB} -F -t0 -g0 -p $PORT1 F > vlog$PORT1 2>&1 &
DEBUGINFOD_URLS=http://127.0.0.1:$PORT1
PID1=$!
tempfiles vlog$PORT1
errfiles vlog$PORT1

wait_ready $PORT1 'ready' 1

# Wait till initial scan is done
wait_ready $PORT1 'thread_work_total{role="traverse"}' 1
wait_ready $PORT1 'thread_work_pending{role="scan"}' 0
wait_ready $PORT1 'thread_busy{role="scan"}' 0

# send a request to stress XFF and User-Agent federation relay;
# we'll grep for the two patterns in vlog$PORT1
curl -s -H 'User-Agent: TESTCURL' -H 'X-Forwarded-For: TESTXFF' $DEBUGINFOD_URLS/buildid/deaddeadbeef00000000/debuginfo -o /dev/null || true
curl -s -H 'User-Agent: TESTCURL' -H 'X-Forwarded-For: TESTXFF' $DEBUGINFOD_URLS/badapi -o /dev/null || true
curl -s -H 'User-Agent: TESTCURL' -H 'X-Forwarded-For: TESTXFF' $DEBUGINFOD_URLS/buildid/$BUILDID/executable > /dev/null

########################################################################
# Trigger some some random activity, then trigger a clean shutdown.
# We used to try to corrupt the database while the debuginfod server
# was running and check it detected errors, but that was unreliably
# and slightly dangerous since part of the database was already mapped
# into memory.
dd if=/dev/zero of=$DB bs=1 count=1
kill -USR1 $PID1
wait_ready $PORT1 'thread_work_total{role="traverse"}' 2
wait_ready $PORT1 'thread_work_pending{role="scan"}' 0
wait_ready $PORT1 'thread_busy{role="scan"}' 0
kill -USR2 $PID1
wait_ready $PORT1 'thread_work_total{role="groom"}' 2

testrun ${abs_builddir}/debuginfod_build_id_find -e F/prog 1

curl -s http://127.0.0.1:$PORT1/metrics | grep 'error_count.*sqlite'

# Run the tests again without the servers running. The target file should
# be found in the cache.
kill -INT $PID1
tempfiles .debuginfod_*
wait_ready $PORT1 'thread_work_total{role="traverse"}' 2
wait_ready $PORT1 'thread_work_pending{role="scan"}' 0
wait_ready $PORT1 'thread_busy{role="scan"}' 0
wait_ready $PORT1 'thread_work_total{role="groom"}' 2

curl -s http://127.0.0.1:$PORT1/metrics | grep 'error_count.*sqlite'

testrun ${abs_builddir}/debuginfod_build_id_find -e F/prog 1
# check out the debuginfod logs for the new style status lines
grep -q 'UA:.*XFF:.*GET /buildid/.* 200 ' vlog$PORT1
grep -q 'UA:.*XFF:.*GET /metrics 200 ' vlog$PORT1
grep -q 'UA:.*XFF:.*GET /badapi 503 ' vlog$PORT1
grep -q 'UA:.*XFF:.*GET /buildid/dead.* 404 ' vlog$PORT1

kill $PID1
wait $PID1
PID1=0
exit 0
