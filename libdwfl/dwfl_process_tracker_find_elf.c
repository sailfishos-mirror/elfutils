/* Find Elf file from dwfl_linux_proc_report, cached via Dwfl_Process_Tracker.
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

#include <sys/stat.h>
#include "../libelf/libelfP.h"
/* XXX: Private header needed for Elf * ref_count field. */
/* TODO: Consider dup_elf() rather than direct ref_count access. */

#include "libdwflP.h"

/* TODO: Consider making this a public api, dwfl_process_tracker_find_cached_elf. */
bool
find_cached_elf (Dwfl_Process_Tracker *tracker,
		 const char *module_name,
		 char **file_name, Elf **elfp, int *fdp)
{
  dwfltracker_elf_info *ent = NULL;
  int rc;
  struct stat sb;

  unsigned long int hval = elf_hash(module_name);

  rwlock_rdlock(tracker->elftab_lock);
  ent = dwfltracker_elftab_find(&tracker->elftab, hval);
  rwlock_unlock(tracker->elftab_lock);

  if (ent == NULL)
    return false;

  /* Verify that ent->fd has not been updated: */
  rc = fstat(ent->fd, &sb);
  if (rc < 0 || ent->dev != sb.st_dev || ent->ino != sb.st_ino
      || ent->last_mtime != sb.st_mtime)
    return false;

  if (ent->elf != NULL)
    ent->elf->ref_count++;
  *elfp = ent->elf;
  *file_name = strdup(ent->module_name);
  *fdp = ent->fd;
  return true;
}

/* TODO: Consider making this a public api, dwfl_process_tracker_cache_elf. */
bool
cache_elf (Dwfl_Process_Tracker *tracker,
	   const char *module_name,
	   char *file_name __attribute__((unused)),
	   Elf *elf, int fd)
{
  dwfltracker_elf_info *ent = NULL;
  int rc;
  struct stat sb;

  unsigned long int hval = elf_hash(module_name);
  rc = fstat(fd, &sb);

  rwlock_wrlock(tracker->elftab_lock);
  ent = dwfltracker_elftab_find(&tracker->elftab, hval);
  if (ent == NULL)
    {
      ent = calloc (1, sizeof (dwfltracker_elf_info));
      ent->module_name = strdup(module_name);

      if (dwfltracker_elftab_insert(&tracker->elftab, hval, ent) != 0)
	{
	  free(ent->module_name);
	  free(ent);
	  rwlock_unlock(tracker->elftab_lock);
	  assert(false); /* Should not occur due to the wrlock on elftab. */
	}
    }
  else
    {
      /* Safe to replace the existing elf, keep module_name. */
      if (ent->elf != NULL)
	elf_end(ent->elf);
      return true;
    }
  if (elf != NULL)
    elf->ref_count++;
  ent->elf = elf;
  ent->fd = fd;
  if (rc == 0) /* TODO(REVIEW): Report rc != 0 via errno? */
    {
      ent->dev = sb.st_dev;
      ent->ino = sb.st_ino;
      ent->last_mtime = sb.st_mtime;
    }
  rwlock_unlock(tracker->elftab_lock);
  return true;
}

int
dwfl_process_tracker_find_elf (Dwfl_Module *mod,
			       void **userdata __attribute__ ((unused)),
			       const char *module_name, Dwarf_Addr base,
			       char **file_name, Elf **elfp)
{
  /* TODO(REVIEW): Assuming this isn't called with elfp already set. */
  assert (*elfp == NULL);

  Dwfl_Process_Tracker *tracker = mod->dwfl->tracker;
  int fd;

  if (tracker != NULL
      && find_cached_elf (tracker, module_name,
			  file_name, elfp, &fd))
    {
      return fd;
    }

  fd = INTUSE(dwfl_linux_proc_find_elf) (mod, userdata, module_name,
					 base, file_name, elfp);

  if (tracker != NULL && fd >= 0 && *file_name != NULL)
    {
      cache_elf (tracker, module_name,
		 *file_name, *elfp, fd);
    }
  return fd;
}
