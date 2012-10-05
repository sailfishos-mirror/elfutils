/* Finish a session using libdwfl.
   Copyright (C) 2005, 2008 Red Hat, Inc.
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

#include "libdwflP.h"
#include "../libdw/cfi.h"
#include <unistd.h>
#include <sys/ptrace.h>

void
dwfl_end (Dwfl *dwfl)
{
  if (dwfl == NULL)
    return;

  /* FIXME: Unify with dwfl_frame_state.c.  */
  Dwarf_Frame_State_Process *process = dwfl->framestatelist;
  while (process != NULL)
    {
      Dwarf_Frame_State_Thread *thread = process->thread;
      while (thread != NULL)
	{
	  if (thread->tid_attached)
	    ptrace (PTRACE_DETACH, thread->tid, NULL, NULL);
	  Dwarf_Frame_State *state = thread->unwound;
	  while (state != NULL)
	    {
	      Dwarf_Frame_State *dead = state;
	      state = state->unwound;
	      free (dead);
	    }
	  Dwarf_Frame_State_Thread *dead = thread;
	  thread = thread->next;
	  free (dead);
	}
      ebl_closebackend (process->ebl);
      elf_end (process->core);
      if (process->core_fd != -1)
	close (process->core_fd);
      Dwarf_Frame_State_Process *dead = process;
      process = process->next;
      free (dead);
    }

  free (dwfl->lookup_addr);
  free (dwfl->lookup_module);
  free (dwfl->lookup_segndx);

  Dwfl_Module *next = dwfl->modulelist;
  while (next != NULL)
    {
      Dwfl_Module *dead = next;
      next = dead->next;
      __libdwfl_module_free (dead);
    }

  free (dwfl);
}
