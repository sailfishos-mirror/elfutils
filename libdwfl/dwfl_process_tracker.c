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
extern size_t next_prime (size_t); /* XXX from libeu.a lib/next_prime.c */

Dwfl_Process_Tracker *dwfl_process_tracker_begin (const Dwfl_Callbacks *callbacks)
{
  Dwfl_Process_Tracker *tracker = calloc (1, sizeof *tracker);
  if (tracker == NULL)
    {
      __libdwfl_seterrno (DWFL_E_NOMEM);
      return tracker;
    }

  /* XXX based on lib/dynamicsizehash.* *_init */
  tracker->elftab_size = HTAB_DEFAULT_SIZE;
  tracker->elftab_filled = 0;
  tracker->elftab = calloc ((tracker->elftab_size + 1), sizeof(tracker->elftab[0]));

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

  for (unsigned idx = 1; idx < tracker->elftab_size; idx++)
    {
      dwfltracker_elftab_ent *t = &tracker->elftab[idx];
      if (!DWFL_ELFTAB_ENT_USED(t))
	continue;
      if (t->fd >= 0)
	close(t->fd);
      free(t->module_name);
      elf_end(t->elf);
    }
  free(tracker->elftab);

  /* TODO: Call dwfl_end for each Dwfl connected to this tracker. */
  free (tracker);
}

/* XXX based on lib/dynamicsizehash.* insert_entry_2 */
bool
__libdwfl_process_tracker_elftab_resize (Dwfl_Process_Tracker *tracker)
{
  ssize_t old_size = tracker->elftab_size;
  dwfltracker_elftab_ent *oldtab = tracker->elftab;
  tracker->elftab_size = next_prime (tracker->elftab_size * 2);
  tracker->elftab = calloc ((tracker->elftab_size + 1), sizeof(tracker->elftab[0]));
  if (tracker->elftab == NULL)
    {
      tracker->elftab_size = old_size;
      tracker->elftab = oldtab;
      return false;
    }
  tracker->elftab_filled = 0;
  /* Transfer the old entries to the new table. */
  for (ssize_t idx = 1; idx <= old_size; ++idx)
    if (DWFL_ELFTAB_ENT_USED(&oldtab[idx]))
      {
	dwfltracker_elftab_ent *ent0 = &oldtab[idx];
	dwfltracker_elftab_ent *ent1 = __libdwfl_process_tracker_elftab_find(tracker, ent0->module_name, false/* should_resize */);
	assert (ent1 != NULL);
	memcpy (ent1, ent0, sizeof(dwfltracker_elftab_ent));
      }
  free(oldtab);
  return true;
}

/* TODO: Hashing is tentative, consider direct use of lib/dynamicsizehash_concurrent.c for this. */
ssize_t
djb2_hash (const char *str)
{
  unsigned long hash = 5381;
  int c;

  while ((c = *str++))
    hash = ((hash << 5) + hash) ^ c; /* hash * 33 XOR c */

  ssize_t shash = (ssize_t)hash;
  if (shash < 0) shash = -shash;
  return shash;
}

/* XXX based on lib/dynamicsizehash.* *_find */
dwfltracker_elftab_ent *
__libdwfl_process_tracker_elftab_find (Dwfl_Process_Tracker *tracker,
				       const char *module_name,
				       bool should_resize)
{
  dwfltracker_elftab_ent *htab = tracker->elftab;
  ssize_t hval = djb2_hash(module_name);
  ssize_t idx = 1 + (hval < tracker->elftab_size ? hval : hval % tracker->elftab_size);

  if (!DWFL_ELFTAB_ENT_USED(&htab[idx]))
    goto found;
  if (strcmp(htab[idx].module_name, module_name) == 0)
    goto found;

  int64_t hash = 1 + hval % (tracker->elftab_size - 2);
  do
    {
      if (idx <= hash)
	idx = tracker->elftab_size + idx - hash;
      else
	idx -= hash;

      if (!DWFL_ELFTAB_ENT_USED(&htab[idx]))
	goto found;
      if (strcmp(htab[idx].module_name, module_name) == 0)
	goto found;
    }
  while (true);

 found:
  if (!DWFL_ELFTAB_ENT_USED(&htab[idx]))
    {
      if (100 * tracker->elftab_filled > 90 * tracker->elftab_size)
	{
	  if (!should_resize || !__libdwfl_process_tracker_elftab_resize (tracker))
	    return NULL;
	}
      /* XXX Caller is responsible for setting module_name,
	 calling __libdwfl_process_tracker_elftab_mark_used;
         not guaranteed that caller will want to do this. */
    }
  return &htab[idx];
}

void
__libdwfl_process_tracker_elftab_mark_used (Dwfl_Process_Tracker *tracker,
					    const dwfltracker_elftab_ent *ent)
{
  assert(DWFL_ELFTAB_ENT_USED(ent));
  tracker->elftab_filled ++;
}
