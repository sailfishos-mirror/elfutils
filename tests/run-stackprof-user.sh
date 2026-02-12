#!/usr/bin/env bash
#
# Copyright (C) 2026 Red Hat, Inc.
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

set -x

. $srcdir/test-subr.sh

# prerequisites
type timeout 2>/dev/null || (echo "no timeout installed"; exit 77)

# run a cpu-hungry shell script fragment, analyze verbose stats
tempfiles test.out
testrun ${abs_top_builddir}/src/stackprof -v -v -- timeout 2 /bin/sh -c "while true; do true; done" 2>&1 | tee test.out

grep "^perf_event_attr configuration" test.out
grep "Starting stack profile collection pid" test.out
grep -E "^[0-9]+ sh --" test.out


# run it again, producing gprof data
testrun ${abs_top_builddir}/src/stackprof -v -v -g -- timeout 2 /bin/sh -c "while true; do true; done" 2>&1 | tee test.out

tempfiles gmon.*
grep "^perf_event_attr configuration type=1 config=0 sample_freq=" test.out
grep "Starting stack profile collection pid" test.out
grep -E "^buildid [0-9a-f]+" test.out
rm gmon.*


if [ "x$HAVE_LIBPFM" = "x1" ]; then
    # test libpfm event listing
    testrun ${abs_top_builddir}/src/stackprof --event-list 2>&1 | tee test.out
    wc -l < test.out
    grep "^perf::BRANCHES" test.out

    # test libpfm event listing
    testrun ${abs_top_builddir}/src/stackprof -v -v -e perf::BRANCHES:freq=4000 -v -v -g -- timeout 2 /bin/sh -c "while true; do true; done" 2>&1 | tee test.out

    tempfiles gmon.*
    grep "^perf_event_attr configuration type=0 config=4 sample_freq=4000" test.out
    grep "Starting stack profile collection pid" test.out
    grep -E "^buildid [0-9a-f]+" test.out
fi



exit 0
