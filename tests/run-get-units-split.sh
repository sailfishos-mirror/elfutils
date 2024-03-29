#! /bin/sh
# Copyright (C) 2018 Red Hat, Inc.
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

. $srcdir/test-subr.sh

# See run-typeiter.sh
testfiles testfile-debug-types

testrun ${abs_builddir}/get-units-split testfile-debug-types

# see run-readelf-dwz-multi.sh
testfiles testfile_multi_main testfile_multi.dwz

testrun ${abs_builddir}/get-units-split testfile_multi_main

# see tests/run-dwflsyms.sh
testfiles testfilebazdbgppc64.debug

testrun ${abs_builddir}/get-units-split testfilebazdbgppc64.debug

# see tests/testfile-dwarf-45.source
testfiles testfile-dwarf-4 testfile-dwarf-5
testfiles testfile-splitdwarf-4 testfile-hello4.dwo testfile-world4.dwo
testfiles testfile-splitdwarf-5 testfile-hello5.dwo testfile-world5.dwo

testrun ${abs_builddir}/get-units-split testfile-dwarf-4
testrun ${abs_builddir}/get-units-split testfile-dwarf-5

# These two files are the only ones that actually have skeleton units.
testrun_compare ${abs_builddir}/get-units-split testfile-splitdwarf-4 << \EOF
file: testfile-splitdwarf-4
Got cudie unit_type: 4
Found a skeleton unit, with split die: hello.c
Got cudie unit_type: 4
Found a skeleton unit, with split die: world.c

EOF

testrun_compare ${abs_builddir}/get-units-split testfile-splitdwarf-5 << \EOF
file: testfile-splitdwarf-5
Got cudie unit_type: 4
Found a skeleton unit, with split die: hello.c
Got cudie unit_type: 4
Found a skeleton unit, with split die: world.c

EOF

# Self test (Not on obj files since those need relocation first).
testrun_on_self_exe ${abs_builddir}/get-units-split
testrun_on_self_lib ${abs_builddir}/get-units-split

# See testfile-dwp.source.
testfiles testfile-dwp-5 testfile-dwp-5.dwp
testfiles testfile-dwp-4 testfile-dwp-4.dwp
testfiles testfile-dwp-4-strict testfile-dwp-4-strict.dwp

for file in testfile-dwp-5 testfile-dwp-4 testfile-dwp-4-strict; do
	testrun_compare ${abs_builddir}/get-units-split "$file" << EOF
file: $file
Got cudie unit_type: 4
Found a skeleton unit, with split die: foo.cc
Got cudie unit_type: 4
Found a skeleton unit, with split die: bar.cc
Got cudie unit_type: 4
Found a skeleton unit, with split die: main.cc

EOF
done

exit 0
