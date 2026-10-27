#! /bin/sh
# Copyright (C) 2026 Mark J. Wielaard <mark@klomp.org>
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

# Create an ELF file that has the section headers in the middle of
# the file with some sections before the section table and some after.
# It has phdrs, so when (re)writing it we want to use ELF_F_LAYOUT.
#
# echo "" | gcc -shared -nostdlib -s -Wl,-soname,libshort.so \
# 	-o testfile-elfsection-gap.so -xc -
# patchelf --debug --set-soname large-testfile-soname.so.9 \
# 	testfile-elfsection-gap.so
# patching ELF file 'testfile-elfsection-gap.so'
# new SONAME is 'large-testfile-soname.so.9'
# SONAME is too long, resizing...
# replacing section '.dynstr' with size 40
# this is a dynamic library
# last page is 0x3000
# first page is 0x0
# needed space is 720
# allocating new PT_LOAD segment
# rewriting sht from offset 0x2098 to offset 0x3000 (size 640)
# rewriting section '.note.gnu.build-id' from offset 0x200 (size 36) to offset 0x3280 (size 36)
# rewriting section '.dynstr' from offset 0x1038 (size 13) to offset 0x32a8 (size 40)
# rewriting symbol table section 2
# writing testfile-elfsection-gap.so

testfiles testfile-elfsection-gap.so
testrun ${abs_builddir}/elfrdwrnop testfile-elfsection-gap.so
testrun ${abs_top_builddir}/src/readelf -S testfile-elfsection-gap.so \
	| grep -q "<corrupt>" && exit 1
echo $?

exit 0
