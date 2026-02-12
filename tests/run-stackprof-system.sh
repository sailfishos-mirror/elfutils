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
expr `whoami` = "root" || (echo "run as root"; exit 77) 

# run systemwide scan
tempfiles test.out
testrun timeout -p -sINT 10 ${abs_top_builddir}/src/stackprof -v -v 2>&1 | tee test.out

grep "^perf_event_attr configuration" test.out
grep "Starting stack profile collection systemwide" test.out
grep -E "^[0-9]+ " test.out

# run it again, producing gprof data
testrun timeout -p -sINT 10 ${abs_top_builddir}/src/stackprof -v -v -g  2>&1 | tee test.out

tempfiles gmon.*
grep "^perf_event_attr configuration type=1 config=0 sample_freq=" test.out
grep "Starting stack profile collection systemwide" test.out
grep -E "^buildid [0-9a-f]+" test.out


exit 0
