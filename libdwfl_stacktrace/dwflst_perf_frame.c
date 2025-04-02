/* Get Dwarf Frame state for perf stack sample data.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(__linux__)
# include <linux/perf_event.h>
#endif

#include "libdwfl_stacktraceP.h"

Ebl *default_ebl = NULL;
GElf_Half default_ebl_machine = EM_NONE;

uint64_t dwflst_perf_sample_preferred_regs_mask (GElf_Half machine)
{
  /* XXX The most likely case is that this will only be called once,
     for the current architecture.  So we keep one Ebl* around for
     answering this query and replace it in the unlikely case of
     getting called with different architectures.  */
  if (default_ebl != NULL && default_ebl_machine != machine)
    {
      ebl_closebackend(default_ebl);
      default_ebl = NULL;
    }
  if (default_ebl == NULL)
    {
      default_ebl = ebl_openbackend_machine(machine);
      default_ebl_machine = machine;
    }
  if (default_ebl != NULL)
    return ebl_perf_frame_regs_mask (default_ebl);
  return 0;
}

/* XXX dwflst_perf_sample_getframes to be added in subsequent patch */
