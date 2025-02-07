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

#define HTAB_DEFAULT_SIZE 1021

Dwfl_Process_Tracker *dwfl_process_tracker_begin (const Dwfl_Callbacks *callbacks)
{
  Dwfl_Process_Tracker *tracker = calloc (1, sizeof *tracker);
  if (tracker == NULL)
    {
      __libdwfl_seterrno (DWFL_E_NOMEM);
      return tracker;
    }

  dwfltracker_elftab_init (&tracker->elftab, HTAB_DEFAULT_SIZE);

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

  /* HACK to allow iteration of dynamicsizehash_concurrent. */
  /* XXX Based on lib/dynamicsizehash_concurrent.c free().  */
  pthread_rwlock_destroy(&tracker->elftab.resize_rwl);
  for (size_t idx = 1; idx <= tracker->elftab.size; idx++)
    {
      dwfltracker_elftab_ent *ent = &tracker->elftab.table[idx];
      if (ent->hashval == 0)
	continue;
      dwfltracker_elf_info *t = (dwfltracker_elf_info *) atomic_load_explicit (&ent->val_ptr,
									       memory_order_relaxed);
      free(t->module_name);
      if (t->fd >= 0)
	close(t->fd);
      if (t->elf != NULL)
	elf_end(t->elf);
      free(t); /* TODO: Check necessity. */
    }
  free (tracker->elftab.table);

  /* TODO: Call dwfl_end for each Dwfl connected to this tracker. */
  free (tracker);
}

