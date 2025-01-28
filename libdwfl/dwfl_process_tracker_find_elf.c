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
  dwfltracker_elftab_ent *ent = NULL;
  int rc;
  struct stat sb;

  if (tracker != NULL)
    {
      ent = __libdwfl_process_tracker_elftab_find(tracker, module_name,
						  true/*should_resize*/);
      /* TODO: Also reopen the file when module_name set but fd not set? */
      if (DWFL_ELFTAB_ENT_USED(ent))
	{
	  rc = fstat(ent->fd, &sb);
	  if (rc < 0 || ent->dev != sb.st_dev || ent->ino != sb.st_ino
	      || ent->last_mtime != sb.st_mtime)
	      ent = NULL; /* file modified, fall back to uncached behaviour */
	  else
	    {
	      *elfp = ent->elf;
	      *file_name = strdup(ent->module_name);
	      return ent->fd;
	    }
	}
      else if (ent->module_name == NULL)
	{
	  /* TODO: For multithreaded access, we mark used here rather
	     than after the dwfl_linux_proc_find_elf() call.  Need to
	     add appropriate locking.  */
	  ent->module_name = strdup(module_name);
	  __libdwfl_process_tracker_elftab_mark_used(tracker, ent);
	}
    }

  int fd = INTUSE(dwfl_linux_proc_find_elf) (mod, userdata, module_name,
					     base, file_name, elfp);

  /* XXX fd < 0 implies elf_from_remote_memory, uses base, not cacheable */
  if (tracker != NULL && ent != NULL && fd >= 0 && *file_name != NULL)
    {
      /* TODO(WIP): *elfp may be NULL here, need to be populated later. */
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
