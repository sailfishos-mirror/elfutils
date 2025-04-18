#! /bin/sh
# Subroutines for thread safety testing
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

# Verify that thread safety tests can be run.  If not, skip further testing.
check_thread_safety_enabled()
{
  # Extract lock setting.
  USE_LOCKS=$(grep '^#define USE_LOCKS' \
	${abs_builddir}/../config.h | awk '{print $3}')

  # Test will only be run if USE_LOCKS is defined. Otherwise, skip.
  if [ "$USE_LOCKS" != 1 ]; then
    echo "USE_LOCKS is not defined. Skipping test."
    exit 77
  fi
}
