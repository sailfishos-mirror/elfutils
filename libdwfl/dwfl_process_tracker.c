/* Track multiple Dwfl structs for multiple processes.
   Copyright (C) 2025, Red Hat, Inc.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "libdwflP.h"

Dwfl_Process_Tracker *dwfl_process_tracker_begin (const Dwfl_Callbacks *callbacks)
{
  Dwfl_Process_Tracker *tracker = calloc (1, sizeof *tracker);
  if (tracker == NULL)
    {
      __libdwfl_seterrno (DWFL_E_NOMEM);
      return tracker;
    }

  tracker->callbacks = callbacks;
  return tracker;
}

Dwfl *dwfl_begin_with_tracker (Dwfl_Process_Tracker *tracker)
{
  Dwfl *dwfl = dwfl_begin (tracker->callbacks);
  if (dwfl == NULL)
    return dwfl;

  /* TODO: Could also share dwfl->debuginfod, but thead-safely? */
  dwfl->tracker = tracker;
  return dwfl;
}

void dwfl_process_tracker_end (Dwfl_Process_Tracker *tracker)
{
  if (tracker == NULL)
    return;

  /* TODO: Call dwfl_end for each Dwfl connected to this tracker. */
  free (tracker);
}
