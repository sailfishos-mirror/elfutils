/* Populate process registers from a register sample.
   Copyright (C) 2026 Red Hat Inc.
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

#include <stdlib.h>
#include <assert.h>

#define BACKEND s390_
#include "libebl_CPU.h"
#include "libebl_PERF_FLAGS.h"

bool
s390_sample_sp_pc (const Dwarf_Word *regs, uint32_t n_regs,
		   const int *regs_mapping, size_t n_regs_mapping,
		   Dwarf_Word *sp, Dwarf_Word *pc)
{
  return generic_sample_sp_pc (regs, n_regs, regs_mapping, n_regs_mapping,
			       sp, 31 /* index of sp in dwarf_regs */,
			       pc, 32 /* index of pc in dwarf_regs */);
}

bool
s390_set_initial_registers_sample (const Dwarf_Word *regs, uint32_t n_regs,
				   const int *regs_mapping, size_t n_regs_mapping,
				   ebl_tid_registers_t *setfunc,
				   void *arg)
{
/* TODO(REVIEW): The #ifdef here seems strictly optional as we don't
   refer to perf_events or ptrace arch-specific declarations.  */
#if !defined(__s390__)
  (void)regs; (void)n_regs;
  (void)regs_mapping; (void)n_regs_mapping;
  (void)setfunc; (void)arg;
  return false;
#else
#define N_GREGS 16
  Dwarf_Word dwarf_regs[N_GREGS];
  Dwarf_Word psw = 0x0;
  bool scratch_present = false;
  size_t i;
  for (i = 0; i < N_GREGS; i++)
    dwarf_regs[i] = 0x0;
  for (i = 0; i < n_regs; i++)
    {
      if (i >= n_regs_mapping)
	break;
      if (regs_mapping[i] == 16)
	psw = regs[i]; /* TODO(REVIEW): NEED to correctly extract psw.addr?  */
      if (regs_mapping[i] < 0 || regs_mapping[i] >= N_GREGS)
	continue;
      if (regs_mapping[i] < 6)
	scratch_present = true;
      dwarf_regs[regs_mapping[i]] = regs[i];
    }

  /* R0..R5 only if present.  */
  if (scratch_present && ! setfunc (0, 6, &dwarf_regs[0], arg))
    return false;

  /* R6..R13, R14(LR), R15(SP).  */
  if (! setfunc (6, 15 - 5, &dwarf_regs[6], arg))
    return false;

  /* TODO(REVIEW): Do we also need the floating-point regs?  */

  return setfunc (-1, 1, &psw, arg);
#endif /* __s390__ */
}
