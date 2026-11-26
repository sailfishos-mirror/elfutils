#! /bin/sh
# Copyright (C) 2026 Minseok Kim
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

# Both inputs are hand built big-endian ELF shared objects of 4096 bytes
# whose only section header of interest is a note section placed so that
# the note data ends exactly at the end of the file.  Neither can be
# produced by a compiler, since both carry a malformed note on purpose.
#
# To regenerate testfile-badnote-sdt.bz2: write a big-endian ELFCLASS64
# shared object with a .note.stapsdt section at offset 0xfac holding one
# note with n_namesz 8 ("stapsdt\0"), n_descsz 64 and n_type 3.  Fill the
# descriptor with three 8-byte addresses followed by an empty provider
# string, a 37-byte probe name and an argument string that is not
# terminated before the end of the descriptor.  Then bzip2 -9 it.
#
# To regenerate testfile-badnote-ga.bz2: write a big-endian ELFCLASS64
# shared object with a .note.gnu.build.attributes section at offset 0xfec
# holding one note with n_namesz 4, n_descsz 4 and n_type 0x100
# (NT_GNU_BUILD_ATTRIBUTE_OPEN).  The four name bytes are "GA", then
# '$' (GNU_BUILD_ATTRIBUTE_TYPE_STRING) and 0x06
# (GNU_BUILD_ATTRIBUTE_ABI), with no NUL terminator, so the string value
# of the attribute begins at the end of the note name.  Then bzip2 -9 it.
#
# Before the note name and stapsdt descriptor reads in ebl_object_note
# were bounded, readelf -n on these two files read past the end of the
# buffer libelf allocated for the note data.
#
# The two inputs are not equally strong as regression tests.  The build
# attribute one changes what is printed, so it fails here without the
# fix.  The stapsdt one does not: an over-long memchr length cannot
# change which byte is found first, so the descriptor is rejected either
# way and only the read itself differs.  It is kept because it covers
# the path, and because configuring with --enable-valgrind turns it into
# a real check of that read.

testfiles testfile-badnote-sdt testfile-badnote-ga

# The argument string of the SDT probe is unterminated, so the
# descriptor has to be rejected rather than walked.
testrun_compare ${abs_top_builddir}/src/readelf -n testfile-badnote-sdt << EOF

Note section [ 1] '.note.stapsdt' of 84 bytes at offset 0xfac:
  Owner          Data size  Type
  stapsdt               64  Version: 3
invalid SDT probe descriptor
EOF

# The build attribute name is unterminated and its string value starts
# at the end of the note name, so the value has to print as empty.
testrun_compare ${abs_top_builddir}/src/readelf -n testfile-badnote-ga << EOF

Note section [ 1] '.note.gnu.build.attributes' of 20 bytes at offset 0xfec:
  Owner          Data size  Type
  GA                     4  GNU Build Attribute OPEN
    Address Range: <unknown data>
    ABI: ""
EOF

exit 0
