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
type gprof 2>/dev/null || (echo "no gprof installed"; exit 77)

# produce gprof data
testrun ${abs_top_builddir}/src/stackprof -v -v -g -- timeout 2 /bin/sh -c "while true; do true; done" 2>&1 | tee test.out
tempfiles test.out

tempfiles gmon.*
grep "^perf_event_attr configuration" test.out
grep "Starting stack profile collection pid" test.out
grep -E "^buildid [0-9a-f]+" test.out

export DEBUGINFOD_URLS=https://debuginfod.elfutils.org/

for f in gmon.*.out
do
    exe="`basename "$f" .out`.exe"
    echo "NOTE: analyzing $exe `readlink $exe`"
    tempfiles gprof_output.txt
    # Try a plain gprof attempt on the executable
    if gprof "$exe" > gprof_output.txt 2>&1; then
        # Success, use the output
        cat gprof_output.txt
    else
        # Fall back to debuginfod if necessary (e.g., if debug info is missing)
        echo "NOTE: stripped binary found, attempting to find debuginfo"
        if testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $exe; then
            debuginfo="`debuginfod-find debuginfo $exe`"
            gprof "$debuginfo" "$f"
        else
            echo "SKIPPING: debuginfo not found"
        fi
    fi
done
    
exit 0
