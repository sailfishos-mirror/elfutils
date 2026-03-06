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

#define BACKEND arm_
#include "libebl_CPU.h"
#include "libebl_PERF_FLAGS.h"

bool
arm_sample_sp_pc (const Dwarf_Word *regs, uint32_t n_regs,
		  const int *regs_mapping, size_t n_regs_mapping,
		  Dwarf_Word *sp, Dwarf_Word *pc)
{
  return generic_sample_sp_pc (regs, n_regs, regs_mapping, n_regs_mapping,
			       sp, 13 /* index of sp in dwarf_regs */,
			       pc, 15 /* index of pc in dwarf_regs */);
}

bool
arm_set_initial_registers_sample (const Dwarf_Word *regs, uint32_t n_regs,
				  const int *regs_mapping, size_t n_regs_mapping,
				  ebl_tid_registers_t *setfunc,
				  void *arg)
{
#if !defined(__linux__) || (!defined __arm__ && !defined __aarch64__)
  (void)regs; (void)n_regs;
  (void)regs_mapping; (void)n_regs_mapping;
  (void)setfunc; (void)arg;
  return false;
#else	/* __arm__ || __aarch64__ */
  /* __arm__: Regular 32-bit arm
     __aarch64__: Compat mode, arm compatible code running on aarch64

     TODO(REVIEW) For __aarch64__, the extraction of a compact perf
     register file to Dwarf_Word should have happened already,
     probably in whatever code unpacks the PERF_RECORD_SAMPLE;
     or perf_events already provides an array of 64-bit regs?  */

  /* TODO(REVIEW): It seems like the default
     ebl_set_initial_registers_sample implementation can be used
     here.  */

#define N_GREGS 16
  Dwarf_Word dwarf_regs[N_GREGS];
  for (i = 0; i < N_GREGS; i++)
    dwarf_regs[i] = 0x0;
  for (i = 0; i < n_regs; i++)
    {
      if (i >= n_regs_mapping)
	break;
      if (regs_mapping[i] < 0 || regs_mapping[i] >= N_GREGS)
	continue;
      dwarf_regs[regs_mapping[i]] = regs[i];
    }

  return setfunc (0, 16, dwarf_regs, arg);
#endif
}
