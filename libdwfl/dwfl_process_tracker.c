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
  dwfltracker_dwfltab_init (&tracker->dwfltab, HTAB_DEFAULT_SIZE);

  tracker->callbacks = callbacks;
  return tracker;
}

Dwfl *dwfl_begin_with_tracker (Dwfl_Process_Tracker *tracker)
{
  Dwfl *dwfl = dwfl_begin (tracker->callbacks);
  if (dwfl == NULL)
    return dwfl;

  /* TODO: Could also share dwfl->debuginfod, but thread-safely? */
  dwfl->tracker = tracker;

  /* XXX: dwfl added to dwfltab when dwfl->process set in dwfl_attach_state. */
  /* XXX: dwfl removed from dwfltab in dwfl_end() */

  return dwfl;
}

Dwfl *dwfl_process_tracker_find_pid (Dwfl_Process_Tracker *tracker,
				     pid_t pid,
				     Dwfl *(*callback) (Dwfl_Process_Tracker *,
							pid_t, void *),
				     void *arg)
{
  Dwfl *dwfl = NULL;
  dwfltracker_dwfl_info *ent = dwfltracker_dwfltab_find(&tracker->dwfltab, pid);
  if (ent != NULL && !ent->invalid)
    dwfl = ent->dwfl;
  if (dwfl == NULL && callback != NULL)
    dwfl = callback(tracker, pid, arg);
  if (dwfl != NULL)
    {
      assert (dwfl->tracker == tracker);
      /* XXX: dwfl added to dwfltab when dwfl->process set in dwfl_attach_state. */
    }

  return dwfl;
}

void __libdwfl_add_dwfl_to_tracker (Dwfl *dwfl) {
  Dwfl_Process_Tracker *tracker = dwfl->tracker;
  assert (tracker != NULL);

  /* First try to find an existing entry to replace: */
  dwfltracker_dwfl_info *ent = NULL;
  unsigned long int hval = dwfl->process->pid;
  ent = dwfltracker_dwfltab_find(&tracker->dwfltab, hval);
  if (ent != NULL)
    {
      ent->dwfl = dwfl;
      ent->invalid = false;
      return;
    }

  /* Only otherwise try to insert an entry: */
  ent = calloc (1, sizeof(dwfltracker_dwfl_info));
  ent->dwfl = dwfl;
  ent->invalid = false;
  if (dwfltracker_dwfltab_insert(&tracker->dwfltab, hval, ent) != 0)
    {
      /* assert(false); */ /* TODO: Need additional locking to guard against this case. */
      free(ent);
      return;
    }
}

void __libdwfl_remove_dwfl_from_tracker (Dwfl *dwfl) {
  if (dwfl->tracker == NULL)
    return;
  Dwfl_Process_Tracker *tracker = dwfl->tracker;

  dwfltracker_dwfl_info *ent = NULL;
  unsigned long int hval = dwfl->process->pid;
  ent = dwfltracker_dwfltab_find(&tracker->dwfltab, hval);
  if (ent != NULL && ent->dwfl == dwfl)
    {
      ent->dwfl = NULL;
      ent->invalid = true;
    }
}

void dwfl_process_tracker_end (Dwfl_Process_Tracker *tracker)
{
  if (tracker == NULL)
    return;

  size_t idx;

  /* HACK to allow iteration of dynamicsizehash_concurrent.  */
  /* XXX Based on lib/dynamicsizehash_concurrent.c free().  */
  pthread_rwlock_destroy(&tracker->elftab.resize_rwl);
  for (idx = 1; idx <= tracker->elftab.size; idx++)
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

  /* XXX Based on lib/dynamicsizehash_concurrent.c free().  */
  pthread_rwlock_destroy(&tracker->dwfltab.resize_rwl);
  for (idx = 1; idx <= tracker->dwfltab.size; idx++)
    {
      dwfltracker_dwfltab_ent *ent = &tracker->dwfltab.table[idx];
      if (ent->hashval == 0)
	continue;
      dwfltracker_dwfl_info *t = (dwfltracker_dwfl_info *) atomic_load_explicit (&ent->val_ptr,
										 memory_order_relaxed);
      if (t->dwfl != NULL)
	dwfl_end(t->dwfl);
      free(t);
    }
  free (tracker->dwfltab.table);

  free (tracker);
}
