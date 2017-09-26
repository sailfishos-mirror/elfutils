#! /bin/sh
# Copyright (C) 2010 Red Hat, Inc.
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

. $srcdir/../tests/test-subr.sh

srcdir=$srcdir/tests

testfiles debug_abbrev-duplicate-attribute

testrun_compare ./dwarflint debug_abbrev-duplicate-attribute <<EOF
error: .debug_abbrev: abbr. attribute 0x19: duplicate attribute byte_size (first was at 0x13).
error: .debug_abbrev: abbr. attribute 0x1b: duplicate attribute decl_file (first was at 0x15).
error: .debug_abbrev: abbr. attribute 0x1d: duplicate attribute decl_line (first was at 0x17).
warning: .debug_info: DIE 0xb: DW_AT_low_pc value not below DW_AT_high_pc.
EOF