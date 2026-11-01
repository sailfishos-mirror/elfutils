#! /bin/sh
# Copyright (C) 2026 vivekjha
# This file is part of elfutils.
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# elfutils is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Regression test for a stack buffer overflow in unstrip's symbol section
# handling when the stripped file's SHT_SYMTAB has sh_entsize larger than
# the symbol size.
#
# The stripped file is ET_REL with four sections.  Its .symtab has
# sh_size 0x60 (four 24-byte symbols) and sh_entsize 0x30 (48).  Symbols
# 1..3 are STT_SECTION entries whose st_shndx equals their index.  The
# debug file has the same sections, no SHT_SYMTAB, and one extra section.
#
# sh_size / sh_entsize is two, but libelf accepts four symbols.  Before the
# fix, add_new_section_symbols() sized its symndx_map VLA from the count of
# two and then wrote symndx_map[i - 1] for i up to three, past the end of
# the array.  unstrip must reject the stripped SYMTAB instead.

. $srcdir/test-subr.sh

stripped=testfile-unstrip-symtab2.stripped
debug=testfile-unstrip-symtab2.debug

testfiles $stripped $debug
tempfiles symtab-entsize.out symtab-entsize.err

if testrun ${abs_top_builddir}/src/unstrip -o symtab-entsize.out $stripped $debug \
     2> symtab-entsize.err
then
  echo >&2 "unstrip accepted a SYMTAB whose sh_entsize is not the symbol size"
  exit 1
fi

grep -q ": SYMTAB section cannot" symtab-entsize.err

test_cleanup

exit 0
