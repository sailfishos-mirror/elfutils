/* Dwfl_Process_Tracker Dwfl table.
   Copyright (C) 2025 Red Hat, Inc.
   This file is part of elfutils.

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.  */

#ifndef DWFL_PROCESS_TRACKER_DWFLTAB_H
#define DWFL_PROCESS_TRACKER_DWFLTAB_H 1

/* Definitions for the Dwfl table.  */
#define TYPE dwfltracker_dwfl_info *
#define NAME dwfltracker_dwfltab
#define ITERATE 1
#define COMPARE(a, b) \
  ((a->invalid && b->invalid) || \
   (!a->invalid && !b->invalid && \
    (a)->dwfl->process->pid == (b)->dwfl->process->pid))
#include <dynamicsizehash_concurrent.h>

#endif
