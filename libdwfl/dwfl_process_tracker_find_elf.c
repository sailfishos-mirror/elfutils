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

int
dwfl_process_tracker_find_elf (Dwfl_Module *mod,
			  void **userdata __attribute__ ((unused)),
			  const char *module_name, Dwarf_Addr base,
			  char **file_name, Elf **elfp)
{
  /* TODO(WIP): Do we need to handle if elfp is already set?? */
  assert (*elfp == NULL);
  Dwfl_Process_Tracker *tracker = mod->dwfl->tracker;
  dwfltracker_elf_info *ent = NULL;
  int rc;
  struct stat sb;

  if (tracker != NULL)
    {
      unsigned long int hval = elf_hash(module_name);
      ent = dwfltracker_elftab_find(&tracker->elftab, hval);
      if (ent != NULL)
	{
	  /* TODO: Also reopen the file when module_name set but fd not set? */
	  rc = fstat(ent->fd, &sb);
	  if (rc < 0 || ent->dev != sb.st_dev || ent->ino != sb.st_ino
	      || ent->last_mtime != sb.st_mtime)
	    ent = NULL; /* file modified, fall back to uncached behaviour */
	  else
	    {
	      /* XXX Caller also holds the Elf * jointly with prior owners: */
	      if (ent->elf != NULL)
		ent->elf->ref_count++;
	      *elfp = ent->elf;
	      *file_name = strdup(ent->module_name);
	      return ent->fd;
	    }
	}
      else
	{
	  ent = calloc (1, sizeof (dwfltracker_elf_info));
	  ent->module_name = strdup(module_name);
	  if (dwfltracker_elftab_insert(&tracker->elftab, hval, ent) != 0)
	    {
	      free(ent->module_name);
	      free(ent);
	      ent = NULL; /* fall back to uncached behaviour */
	      /* TODO(WIP): Could goto and repeat the find operation? */
	    }
	}
    }

  int fd = INTUSE(dwfl_linux_proc_find_elf) (mod, userdata, module_name,
					     base, file_name, elfp);

  /* XXX fd < 0 implies elf_from_remote_memory, uses base, not cacheable */
  if (tracker != NULL && ent != NULL && fd >= 0 && *file_name != NULL)
    {
      /* TODO(WIP): *elfp may be NULL here, need to be populated later. */
      /* XXX Dwfl_Process_Tracker also holds the Elf * jointly with the caller: */
      if (*elfp != NULL)
	(*elfp)->ref_count++;
      ent->elf = *elfp;
      ent->fd = fd;
      rc = fstat(fd, &sb);
      if (rc == 0) /* TODO: report error otherwise */
	{
	  ent->dev = sb.st_dev;
	  ent->ino = sb.st_ino;
	  ent->last_mtime = sb.st_mtime;
	}
    }

  return fd;
}
