#! /usr/bin/env bash
# Test dwelf_elf_remove_debug_relocations
# Copyright (C) 2024 Red Hat, Inc.
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

# = qq.c =
# int add (int a, int b)
# {
#   return a+b;
# }
#
# int main()
# {
#   return 0;
# }

# Using gcc (GCC) 14.2.1 20240801 (Red Hat 14.2.1-1)
# gcc -g -c qq.c -o testfile-remove-relocs

testfiles testfile-remove-relocs

# Before debug relocations are removed some indices into string tables are
# set to a default value of 0.  This causes incorrect file and function
# names to be displayed.
testrun_compare ${abs_builddir}/allfcts testfile-remove-relocs <<\EOF
qq.c/qq.c:6:GNU C17 14.2.1 20240801 (Red Hat 14.2.1-1) -mtune=generic -march=x86-64 -g
qq.c/qq.c:1:add
EOF

# Remove debug relocations and write the changes to the testfile.
testrun ${abs_builddir}/remove-relocs testfile-remove-relocs

# Correct file and function names should now be displayed.
testrun_compare ${abs_builddir}/allfcts testfile-remove-relocs <<\EOF
/home/dichen/elfutils/tests/qq.c:6:main
/home/dichen/elfutils/tests/qq.c:1:add
EOF

exit 0
