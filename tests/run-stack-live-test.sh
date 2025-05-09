#! /bin/sh
# Copyright (C) 2025 Red Hat, Inc.
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

# Depending on whether we are running make check or make installcheck
# the actual binary name under test might be different. It is used in
# the error message, which we also try to match.
if test "$elfutils_testrun" = "installed"; then
STACKCMD=${bindir}/`program_transform stack`
else
STACKCMD=${abs_top_builddir}/src/stack
fi

# TODO(REVIEW): Can we make the data-scrubbing generic enough
# (across multiple eu-stack/eu-stacktrace test cases) to move
# to test_subr.sh?
#
# TODO(REVIEW): Better shell-isms for comparing file and regex?
# \(\s\e\d\)\+\i\s\a\d\d\i\c\t\e\d\\t\o\b\a\ck\s\l\a\s\h\e\s
testrun_compare_fuzzy()
{
    outfile="${1##*/}.out"
    testrun_out $outfile "$@"
    sed -i 's/\(PID\|TID\|#[0-9]\+\)\( \+\)\(\(0x\)\?[0-9a-f]\+\)/\1\2nn/g' $outfile
    diff -u $outfile -
}

# TODO: Need to scrub more data (e.g. GLIBC_ bits),
# and use a program whose inner content we control:
sleep 10 &
PID=$!
testrun_compare_fuzzy ${abs_top_builddir}/src/stack -p $PID <<EOF
PID nn - process
TID nn:
#0  nn clock_nanosleep@GLIBC_2.2.5
#1  nn __nanosleep
#2  nn main
#3  nn __libc_start_call_main
#4  nn __libc_start_main@@GLIBC_2.34
#5  nn _start
EOF
# fedora-s390x: need GLIBC_nn
# fedora-i386: kernel_vsyscall in front, more blank frames
# opensusetw-x86_64: internal_syscall_cancel in front, more blank frames (main)
# fedora-ppc64le: need @@GLIBC_nn vs @GLIBC_nn, rpl_nanosleep, xnanosleep in front, no _start in back
# debian-ppc64: need @@GLIBC_nn vs @GLIBC_nn, __internal_syscall_cancel in front, more blank frames (main)
# debian-coverage: more blank frames (main, _start)
# opensuseleap-x86_64: more blank frames (main, _start)
# debian-amd64: more blank frames (main, _start)
# fedora-coverage: __internal_syscall_cancel in front
# fedora-x86_64: __internal_syscall_cancel in front
# ubuntu-riscv: 'Operation not permitted' (run a simpler eu-stack test and skip on this error?)
# debian-armhf: 'Operation not permitted'
# alma-x86_64: no clock_nanosleep in front, rpl_nanosleep, x_nanosleep in front
# fedora-arm64: need @@GLIBC_nn vs @GLIBC_nn
#
# blank frames issue might be due to debuginfo availability, go away
# when we use our own program rather than /usr/bin/sleep

# PID 169385 - process
# TID 169385:
# #0  0x00007f04a98adbd7 clock_nanosleep@GLIBC_2.2.5
# #1  0x00007f04a98b9c47 __nanosleep
# #2  0x0000561e7fdd9a9f main
# #3  0x00007f04a97f4088 __libc_start_call_main
# #4  0x00007f04a97f414b __libc_start_main@@GLIBC_2.34
# #5  0x0000561e7fdd9c05 _start
