/* Populate process registers from a linux perf_events sample.
   Copyright (C) 2026 Matt Turner
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

#define BACKEND alpha_
#include "libebl_CPU.h"
#include "libebl_PERF_FLAGS.h"

/* The default sample_perf_regs_mapping maps perf register numbers 1:1,
   which gives the DWARF number for $0-$30.  PERF_REG_ALPHA_PC is 31,
   which cannot be mistaken for $31 since the kernel does not sample
   the zero register.  */
#define SAMPLE_PC 31

bool
alpha_sample_sp_pc (const Dwarf_Word *regs, uint32_t n_regs,
		    const int *regs_mapping, size_t n_regs_mapping,
		    Dwarf_Word *sp, Dwarf_Word *pc)
{
  return generic_sample_sp_pc (regs, n_regs, regs_mapping, n_regs_mapping,
			       sp, 30 /* index of sp in dwarf_regs */,
			       pc, SAMPLE_PC);
}

bool
alpha_set_initial_registers_sample (const Dwarf_Word *regs, uint32_t n_regs,
				    const int *regs_mapping, size_t n_regs_mapping,
				    ebl_tid_registers_t *setfunc,
				    void *arg)
{
  Dwarf_Word dwarf_regs[32] = { 0 };
  for (size_t i = 0; i < n_regs && i < n_regs_mapping; i++)
    if (regs_mapping[i] >= 0 && regs_mapping[i] < 32)
      dwarf_regs[regs_mapping[i]] = regs[i];

  Dwarf_Word pc = dwarf_regs[SAMPLE_PC];
  dwarf_regs[31] = 0;

  /* The kernel cannot sample the callee-saved $9-$15.  Leave them
     unset so that the unwinder does not use a bogus value.  */
  return (setfunc (0, 9, &dwarf_regs[0], arg)
	  && setfunc (16, 16, &dwarf_regs[16], arg)
	  && setfunc (-1, 1, &pc, arg));
}
