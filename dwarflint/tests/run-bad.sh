#! /bin/sh
# Copyright (C) 2011 Red Hat, Inc.
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

testfiles hello.bad-1 hello.bad-3 empty-1 \
    garbage-1 garbage-2 garbage-3 garbage-4 \
    garbage-5 garbage-6 garbage-7 garbage-8 \
    garbage-9 garbage-10 garbage-11 garbage-12

testrun_compare ./dwarflint hello.bad-1 <<EOF
error: .debug_info: DIE 0x83: abbrev section at 0x0 doesn't contain code 83.
EOF

testrun_compare ./dwarflint --check=@low hello.bad-3 <<EOF
error: .debug_info: DIE 0x2d: This DIE had children, but no DW_AT_sibling attribute.
error: .debug_info: DIE 0xb: This DIE had children, but no DW_AT_sibling attribute.
error: .debug_info: DIE 0x91: toplevel DIE chain contains more than one DIE.
error: .debug_info: DIE 0x98: toplevel DIE chain contains more than one DIE.
error: .debug_info: DIE 0x9e: toplevel DIE chain contains more than one DIE.
error: .debug_info: DIE 0xa4: toplevel DIE chain contains more than one DIE.
error: .debug_info: DIE 0xab: toplevel DIE chain contains more than one DIE.
EOF

testrun_compare ./dwarflint empty-1 <<EOF
warning: .debug_info: DIE 0xb: DW_AT_low_pc value not below DW_AT_high_pc.
warning: .debug_line: table 0: no CU uses this line table.
error: .debug_info: DIE 0x29, attr. decl_file: references .debug_line table, but CU DIE lacks DW_AT_stmt_list.
EOF

testrun_compare ./dwarflint garbage-1 <<EOF
error: Broken ELF: offset out of range.
error: .debug_abbrev: data not found.
error: .debug_info: data not found.
EOF

testrun_compare ./dwarflint garbage-2 <<EOF
error: .debug_info: CU 0: toplevel DIE must be either compile_unit or partial_unit.
error: .debug_info: DIE 0xab: DIE chain not terminated with null entry.
EOF

testrun_compare ./dwarflint --check=@low garbage-3 <<EOF
error: .debug_abbrev: abbr. attribute 0xc: invalid attribute code 0.
EOF

testrun_compare ./dwarflint garbage-4 <<EOF
error: .debug_info: DIE 0x6c: this DIE claims that its sibling is 0x80000085 but it's actually 0x85.
error: .debug_info: DIE 0xab: DIE chain not terminated with null entry.
EOF

testrun_compare ./dwarflint garbage-5 <<EOF
error: .debug_info: DIE 0xab: DIE chain not terminated with null entry.
error: .debug_line: offset 0x3e: not enough data to read an opcode of length 5.
error: .debug_info: DIE 0xb, attr. stmt_list: unresolved reference to .debug_line table 0x0.
EOF

testrun_compare ./dwarflint garbage-6 <<EOF
error: .debug_info: CU 0: invalid address size: 9 (only 4 or 8 allowed).
error: .debug_info: couldn't load CU headers for processing .debug_abbrev; assuming latest DWARF flavor.
error: .debug_abbrev: abbr. 0x0, attr. stmt_list: attribute with invalid form DW_FORM_data4.
error: .debug_abbrev: abbr. 0x13, attr. frame_base: attribute with invalid form DW_FORM_block1.
error: .debug_abbrev: abbr. 0x2c, attr. location: attribute with invalid form DW_FORM_block1.
EOF

testrun_compare ./dwarflint garbage-7 <<EOF
warning: .debug_abbrev: abbr. attribute 0x7e: invalid or unknown name 0x703.
error: .debug_abbrev: abbr. 0x7a, attr. 0x703: invalid form 0x0.
error: .debug_abbrev: missing zero to mark end-of-table.
EOF

testrun_compare ./dwarflint garbage-8 <<EOF
error: .debug_info: DIE 0x6c, attr. sibling: has a value of 0.
error: .debug_info: DIE 0x6c: This DIE had children, but no DW_AT_sibling attribute.
error: .debug_info: DIE 0xab: DIE chain not terminated with null entry.
EOF

testrun_compare ./dwarflint garbage-9 <<EOF
error: .debug_info: DIE 0x84, attr. type: invalid reference outside the CU: 0xef00ab.
error: .debug_info: DIE 0x6c: is the last sibling in chain, but has a DW_AT_sibling attribute.
error: .debug_info: DIE 0xab: DIE chain not terminated with null entry.
EOF

testrun_compare ./dwarflint garbage-10 <<EOF
warning: .rela 0xc of .debug_info: DIE 0xb, attr. producer: relocation formed using STT_SECTION symbol with non-zero value.
error: .rela 0x11 of .debug_info: DIE 0xb, attr. comp_dir: couldn't obtain symbol #7208969: invalid section index.
warning: .debug_info: DIE 0xb: DW_AT_low_pc value not below DW_AT_high_pc.
EOF

testrun_compare ./dwarflint garbage-11 <<EOF
error: .rela 0x600 of .debug_info: invalid relocation 2560 (<INVALID RELOC>).
error: .rela 0xc00 of .debug_info: invalid relocation 2560 (<INVALID RELOC>).
error: .rela 0x1100 of .debug_info: invalid relocation 2560 (<INVALID RELOC>).
error: .rela 0x1500 of .debug_info: invalid relocation 256 (<INVALID RELOC>).
error: .rela 0x1d00 of .debug_info: invalid relocation 256 (<INVALID RELOC>).
error: .rela 0x2500 of .debug_info: invalid relocation 2560 (<INVALID RELOC>).
error: .rela 0x3600 of .debug_info: invalid relocation 256 (<INVALID RELOC>).
warning: .debug_info: CU 0: abbrev table offset seems to lack a relocation
warning: .debug_info: DIE 0xb, attr. producer: strp seems to lack a relocation
warning: .debug_info: DIE 0xb, attr. comp_dir: strp seems to lack a relocation
warning: .debug_info: DIE 0xb, attr. stmt_list: data4 seems to lack a relocation
warning: .debug_info: DIE 0xb: DW_AT_low_pc value not below DW_AT_high_pc.
error: .debug_line: table 0: header claims that it has a size of 542, but in fact it has a size of 30.
error: .debug_info: DIE 0xb, attr. stmt_list: unresolved reference to .debug_line table 0x0.
EOF

testrun_compare ./dwarflint garbage-12 <<EOF
error: Broken ELF: invalid section header.
error: .debug_abbrev: data not found.
error: .debug_info: data not found.
EOF