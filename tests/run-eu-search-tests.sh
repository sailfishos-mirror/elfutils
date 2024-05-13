#! /bin/sh
# Copyright (C) 2015, 2018 Red Hat, Inc.
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

# Extract the value of USE_ADDRESS_SANITIZER_TRUE from config.status
# Cannot use Helgrind and Address Sanitizer together.
# Test will be skipped if Address Sanitizer is enabled.
USE_ADDRESS_SANITIZER=$(grep 'USE_ADDRESS_SANITIZER_TRUE' ${abs_builddir}/../config.status | awk -F'=' '{print $2}')

if [[ "$USE_ADDRESS_SANITIZER" == "\"#\"" ]]; then
    echo "Address Sanitizer is disabled."
else
    echo "Address Sanitizer is enabled. Skipping test."
    exit 77
fi

# Extract the value of USE_MEMORY_SANITIZER_TRUE from config.status
# Cannot use Helgrind and Memory Sanitizer together.
# Test will be skipped if Memory Sanitizer is enabled.
USE_MEMORY_SANITIZER=$(grep 'USE_MEMORY_SANITIZER_TRUE' ${abs_builddir}/../config.status | awk -F'=' '{print $2}')

if [[ "$USE_MEMORY_SANITIZER" == "\"#\"" ]]; then
    echo "Memory Sanitizer is disabled."
else
    echo "Memory Sanitizer is enabled. Skipping test."
    exit 77
fi

# Extract the value of USE_LOCKS from config.h
# Test will only be run if USE_LOCKS is defined. Otherwise, skip.
USE_LOCKS=$(grep '^#define USE_LOCKS' ${abs_builddir}/../config.h | awk '{print $3}')

if [[ "$USE_LOCKS" -eq 1 ]]; then
    echo "USE_LOCKS is defined."
else
    echo "USE_LOCKS is not defined. Skipping test."
    exit 77
fi

# Disable valgrind if configured, since we are already using it here.
SAVED_VALGRIND_CMD="$VALGRIND_CMD"
unset VALGRIND_CMD

echo "Begin tests..."

# Begin data race test for parallelized dwarf-die-addr-die
# Tests thread safety for updated libdw_findcu.c and libdw_find_split_unit.c
testfiles testfile-debug-types
testfiles testfile_multi_main testfile_multi.dwz
testfiles testfilebazdbgppc64.debug
testfiles testfile-dwarf-4 testfile-dwarf-5
testfiles testfile-splitdwarf-4 testfile-hello4.dwo testfile-world4.dwo
testfiles testfile-splitdwarf-5 testfile-hello5.dwo testfile-world5.dwo

die_test_files=("testfile-debug-types"
                "testfile_multi_main" "testfile_multi.dwz"
                "testfilebazdbgppc64.debug"
                "testfile-dwarf-4" "testfile-dwarf-5"
                "testfile-splitdwarf-4" "testfile-hello4.dwo" "testfile-world4.dwo"
                "testfile-splitdwarf-5" "testfile-hello5.dwo" "testfile-world5.dwo")

echo -e "\nStarting data race test for dwarf-die-addr-die"

for file in "${die_test_files[@]}"; do
    helgrind_output=$(valgrind --tool=helgrind "${abs_builddir}/eu_search_die" "$file" 2>&1)

    if grep -q "ERROR SUMMARY: 0 errors" <<< "$helgrind_output"; then
        echo "No data races found for $file. Test passed."
    else
        echo "Data races found for $file. Test failed."
        echo "$helgrind_output"
        exit 1
    fi
done

# Begin data race test for parallelized next_cfi
# Tests thread safety for updated cie.c and fde.c
testfiles testfile11 testfile12
testfiles testfilearm testfileaarch64
testfiles testfileppc32 testfileppc64

cfi_test_files=("testfile11" "testfile12"
                "testfilearm" "testfileaarch64"
                "testfileppc32" "testfileppc64")

echo -e "\nStarting data race test for next_cfi"

for file in "${cfi_test_files[@]}"; do

    helgrind_output=$(valgrind --tool=helgrind "${abs_builddir}/eu_search_cfi" $file 2>&1)

    if grep -q "ERROR SUMMARY: 0 errors" <<< "$helgrind_output"; then
        echo "No data races found for $file. Test passed."
    else
        echo "Data races found for $file. Test failed."
        echo "$helgrind_output"
        exit 1
    fi

done

# Begin data race test for parallelizd dwarf-getmacros
# Tests thread safety for updated dwarf_getmacros.c
testfiles testfile51
testfiles testfile-macros
testfiles testfile-macros-0xff

macro_test_files=("testfile51 0xb"
                  "testfile51 0x84"
                  "testfile-macrosm 0xb"
                  "testfile-macros-0xff 0xb")

echo -e "\nStarting data race test for dwarf-getmacros"

for file in "${macro_test_files[@]}"; do

    helgrind_output=$(valgrind --tool=helgrind "${abs_builddir}/eu_search_macros" $file 2>&1)

    if grep -q "ERROR SUMMARY: 0 errors" <<< "$helgrind_output"; then
        echo "No data races found for $file. Test passed."
    else
        echo "Data races found for $file. Test failed."
        echo "$helgrind_output"
        exit 1
    fi

done

# Begin data race test for parallelized get-lines
# Tests thread safety for updated dwarf_getsrclines.c
testfiles testfile testfile2 testfilenolines

lines_test_files=("testfile" "testfile2" "testfilenolines")

echo -e "\nStarting data race test for get-lines"

for file in "${lines_test_files[@]}"; do

    helgrind_output=$(valgrind --tool=helgrind "${abs_builddir}/eu_search_lines" $file 2>&1)

    if grep -q "ERROR SUMMARY: 0 errors" <<< "$helgrind_output"; then
        echo "No data races found for $file. Test passed."
    else
        echo -e "$helgrind_output"
        echo "Data races found for $file. Test failed."
        exit 1
    fi

done

# This line is reached only if no data races were found in any test
# Exit with success status.
exit 0