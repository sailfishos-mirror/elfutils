#! /bin/sh
# Copyright (C) 2026 Red Hat, Inc.
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

# Regression test for the symbol count underflow in unstrip.
#
# Both files below declare a SHT_SYMTAB section whose sh_size is smaller
# than its sh_entsize.  The quotient sh_size / sh_entsize is therefore zero,
# and the code that used to compute "symbol count minus one" wrapped.  unstrip
# must reject such a file instead of doing the subtraction.
#
# symtab0: the unstripped (debug) file is the malformed one.  This reaches
#   copy_elided_sections(), where "stripped_nsym - 1 + unstripped_nsym - 1"
#   wrapped and collect_symbols() then wrote one struct symbol past the end
#   of the allocation.  It aborted under glibc heap checking before the fix.
#
# symtab1: the stripped file is the malformed one, and its debug file has no
#   symbol table at all.  That skips the merge step above and reaches
#   add_new_section_symbols(), where "size_t symndx_map[nsym - 1]" was
#   declared with nsym == 0.  Before the fix unstrip accepted this file and
#   produced output; now it is rejected.
#
# symtab2: the stripped file has an empty symbol table while the debug file is
#   valid.  Without the guard on stripped_symtab, "stripped_nsym - 1" wrapped
#   to SIZE_MAX, leading to out-of-bounds pointer arithmetic (&symbols[SIZE_MAX])
#   and a heap-buffer-overflow write in collect_symbols().

# To regenerate the test files:
#
#   testfile-unstrip-symtab0.stripped: a valid ET_REL object with a four
#     entry .symtab (sh_size 0x60, sh_entsize 0x18).  Any small ET_REL file
#     with an unstrippable symbol table will do.
#   testfile-unstrip-symtab0.debug: the same file with the .symtab section
#     header's sh_size field changed from 0x60 to 0x00.  Offset 0x188, the
#     low byte of that sh_size, is the only difference.
#   testfile-unstrip-symtab1.stripped: a valid ET_REL object whose .symtab
#     has sh_size 0x78 (120) and sh_entsize 0x79 (121).  Both fields are
#     needed: a nonzero sh_size keeps libelf willing to return the symbol
#     data, while sh_entsize > sh_size drives the quotient to zero.  Symbols
#     1..4 are STT_SECTION entries with st_shndx equal to their index.
#   testfile-unstrip-symtab1.debug: the symtab0 debug file with its .symtab
#     section header retyped SHT_PROGBITS (so it is not seen as a symbol
#     table) plus one extra unnamed SHT_PROGBITS section header appended.

. $srcdir/test-subr.sh

stripped0=testfile-unstrip-symtab0.stripped
debug0=testfile-unstrip-symtab0.debug
stripped1=testfile-unstrip-symtab1.stripped
debug1=testfile-unstrip-symtab1.debug

testfiles $stripped0 $debug0 $stripped1 $debug1
tempfiles symtab-count.out symtab-count.err

# Case 0: the debug file has an empty symbol table.  This used to corrupt the
# heap in collect_symbols().
if testrun ${abs_top_builddir}/src/unstrip -o symtab-count.out $stripped0 $debug0 \
     2> symtab-count.err
then
  echo >&2 "unstrip accepted a SYMTAB with sh_size smaller than sh_entsize"
  exit 1
fi

grep "sh_size smaller than sh_entsize" symtab-count.err

# Case 1: the stripped file has sh_entsize one larger than sh_size, and its
# debug file has no symbol table.  This used to build a stack array declared
# with nsym - 1 == SIZE_MAX elements.
if testrun ${abs_top_builddir}/src/unstrip -o symtab-count.out $stripped1 $debug1 \
     2> symtab-count.err
then
  echo >&2 "unstrip accepted a SYMTAB with sh_size smaller than sh_entsize"
  exit 1
fi

grep "sh_size smaller than sh_entsize" symtab-count.err

# Case 2: the stripped file has an empty symbol table while the debug file is
# valid.  This used to corrupt the heap in collect_symbols() by passing an
# underflowed pointer (&symbols[SIZE_MAX]) when merging symbols.
if testrun ${abs_top_builddir}/src/unstrip -o symtab-count.out $debug0 $stripped0 \
     2> symtab-count.err
then
  echo >&2 "unstrip accepted a stripped SYMTAB with sh_size smaller than sh_entsize"
  exit 1
fi

grep "sh_size smaller than sh_entsize" symtab-count.err

test_cleanup

exit 0
