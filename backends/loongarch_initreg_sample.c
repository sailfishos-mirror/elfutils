/* Populate process registers from a register sample.
   Copyright (C) 2026 WANG Xuerui.
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

#define BACKEND loongarch_
#include "libebl_CPU.h"
#include "libebl_PERF_FLAGS.h"

bool
loongarch_sample_sp_pc (const Dwarf_Word *regs, uint32_t n_regs,
			const int *regs_mapping, size_t n_regs_mapping,
			Dwarf_Word *sp, Dwarf_Word *pc)
{
  return generic_sample_sp_pc (regs, n_regs, regs_mapping, n_regs_mapping,
			       sp, 3 /* index of sp in dwarf_regs */,
			       pc, 0 /* index of pc in dwarf_regs */);
}

bool
loongarch_set_initial_registers_sample (const Dwarf_Word *regs,
					uint32_t n_regs,
					const int *regs_mapping,
					size_t n_regs_mapping,
					ebl_tid_registers_t *setfunc,
					void *arg)
{
  /* LoongArch defines no PC in DWARF so here we reuse r0 (constant zero) as
     PC.  */
#define N_GPRS 32
  Dwarf_Word dwarf_regs[N_GPRS];
  bool scratch_present = false;
  size_t i;
  for (i = 0; i < N_GPRS; i++)
    dwarf_regs[i] = 0x0;
  for (i = 0; i < n_regs; i++)
    {
      if (i >= n_regs_mapping)
	break;
      if (regs_mapping[i] < 0 || regs_mapping[i] >= N_GPRS)
	continue;
      if (regs_mapping[i] >= 4 && regs_mapping[i] < 21)
	/* $a0 to $t8 inclusive.  */
	scratch_present = true;
      dwarf_regs[regs_mapping[i]] = regs[i];
    }

  /* $a0 (r4) through $t8 (r20) only if present.  */
  if (scratch_present && ! setfunc (4, 21 - 4, &dwarf_regs[4], arg))
    return false;

  /* $fp/$s9 (r22) plus $s0 (r23)..$s8 (r31).  */
  if (! setfunc (22, 32 - 22, &dwarf_regs[22], arg))
    return false;

  /* RA.  */
  if (! setfunc (1, 1, &dwarf_regs[1], arg))
    return false;

  /* SP.  */
  if (! setfunc (3, 1, &dwarf_regs[3], arg))
    return false;

  /* PC.  */
  if (! setfunc (-1, 1, &dwarf_regs[0], arg))
    return false;

  /* XXX Skip FP registers.  */
  return true;
}
