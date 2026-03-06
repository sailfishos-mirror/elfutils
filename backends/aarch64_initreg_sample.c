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

#define BACKEND aarch64_
#include "libebl_CPU.h"
#include "libebl_PERF_FLAGS.h"
/* TODO(REVIEW): PERF_FLAGS includes generic_sample_sp_pc -- rename?  */

bool
aarch64_sample_sp_pc (const Dwarf_Word *regs, uint32_t n_regs,
		      const int *regs_mapping, size_t n_regs_mapping,
		      Dwarf_Word *sp, Dwarf_Word *pc)
{
  return generic_sample_sp_pc (regs, n_regs, regs_mapping, n_regs_mapping,
			       sp, 31 /* index of sp in dwarf_regs */,
			       pc, 32 /* index of pc in dwarf_regs */);
}

bool
aarch64_set_initial_registers_sample (const Dwarf_Word *regs, uint32_t n_regs,
				      const int *regs_mapping, size_t n_regs_mapping,
				      ebl_tid_registers_t *setfunc,
				      void *arg)
{
/* TODO(REVIEW): The #ifdef here seems strictly optional as we don't
   refer to perf_events or ptrace arch-specific declarations. */
#if !defined(__aarch64__)
  (void)regs; (void)n_regs;
  (void)regs_mapping; (void)n_regs_mapping;
  (void)setfunc; (void)arg;
  return false;
#else
  /* TODO(REVIEW) verify here and above following the convention in aarch64_initreg.c */
#define N_GREGS 33
  Dwarf_Word dwarf_regs[N_GREGS];
  bool scratch_present = false;
  size_t i;
  for (i = 0; i < N_GREGS; i++)
    dwarf_regs[i] = 0x0;
  for (i = 0; i < n_regs; i++)
    {
      if (i >= n_regs_mapping)
	break;
      if (regs_mapping[i] < 0 || regs_mapping[i] >= N_GREGS)
	continue;
      if (regs_mapping[i] < 19)
	scratch_present = true;
      dwarf_regs[regs_mapping[i]] = regs[i];
    }

  /* X0..X18 only if present.  */
  if (scratch_present && ! setfunc (0, 19, &dwarf_regs[0], arg))
    return false;

  /* X19..X29, X30(LR) plus SP.  */
  if (! setfunc (19, 32 - 18, &dwarf_regs[19], arg))
    return false;

  /* PC.  */
  if (! setfunc (-1, 1, &dwarf_regs[32], arg))
    return false;

  /* TODO(REVIEW) Need to obtain PAC mask since the unwinder needs to
     strip it from LR/X30 to handle pointer authentication.  */

  /* Skip ELR, RA_SIGN_STATE  */

  /* XXX Skip FP registers.  */
  return true;
#endif /* __aarch64__ */
}
