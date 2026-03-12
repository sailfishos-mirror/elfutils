/* Populate process registers from a register sample.
   Copyright (C) 2026 Red Hat, Inc.
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

#define BACKEND ppc_
#include "libebl_CPU.h"
#include "libebl_PERF_FLAGS.h"

/* LINK at dwarf_reg 65 from perf_reg 36 */
#define LINK_DWARF 65
#define LINK_PERF 36
/* pc/NIP at dwarf_reg 64 from perf_reg 32 */
#define NIP_DWARF 64
#define NIP_PERF 32
/* GPRS R0..R31 */
#define GPRS 32


bool
ppc_sample_sp_pc (const Dwarf_Word *regs, uint32_t n_regs,
                  const int *regs_mapping, size_t n_regs_mapping,
                  Dwarf_Word *sp, Dwarf_Word *pc)
{
  return generic_sample_sp_pc (regs, n_regs, regs_mapping, n_regs_mapping,
			       sp, 1 /* index of sp/GPR1 in dwarf_regs */,
			       pc, 64 /* index of pc/NIP in dwarf_regs */);
}

bool
ppc_set_initial_registers_sample (const Dwarf_Word *regs, uint32_t n_regs,
				  const int *regs_mapping, size_t n_regs_mapping,
				  ebl_tid_registers_t *setfunc,
				  void *arg)
{
/* TODO(REVIEW): The #ifdef here seems strictly optional as we don't
   refer to perf_events or ptrace arch-specific declarations. */
#if !defined(__powerpc__)
  (void)regs; (void)n_regs;
  (void)regs_mapping; (void)n_regs_mapping;
  (void)setfunc; (void)arg;
  return false;
#else /* __powerpc__ */
  Dwarf_Word link = 0x0;
  Dwarf_Word pc = 0x0;
  Dwarf_Word dwarf_regs[GPRS];
  for (i = 0; i < GPRS; i++)
    dwarf_regs[i] = 0x0;
  for (i = 0; i < n_regs; i++)
    {
      if (i >= n_regs_mapping)
	break;
      if (regs_mapping[i] == LINK_DWARF)
	link = regs[i];
      if (regs_mapping[i] == NIP_DWARF)
	pc = regs[i];
      if (regs_mapping[i] < 0 || regs_mapping[i] >= GPRS)
	continue;
      dwarf_regs[regs_mapping[i]] = regs[i];
    }

  if (!setfunc (0, GPRS, dwarf_regs, arg))
    return false;
  if (!setfunc (65, 1, &link, arg))
    return false;
  return setfunc (-1, 1, &pc, arg);
#endif
}

bool
ppc_sample_perf_regs_mapping (Ebl *ebl,
			      uint64_t perf_regs_mask,
			      uint32_t abi __attribute__((unused)),
			      const int **regs_mapping,
			      size_t *n_regs_mapping)
{
#if !defined(__powerpc__)
  (void)ebl; (void)perf_regs_mask;
  (void)regs_mapping; (void)n_regs_mapping;
  return false;
#else /* __powerpc__ */
  if (perf_regs_mask != 0 && ebl->cached_perf_regs_mask == perf_regs_mask)
    {
      *regs_mapping = ebl->cached_regs_mapping;
      *n_regs_mapping = ebl->cached_n_regs_mapping;
      return true;
    }

  /* Only slight remapping of perf_regs to dwarf_regs needed:
     - GPRS 0..31 unchanged;
     - PC 32 sent to dwarf_reg 64 (then to -1 when using setfunc);
     - LC 36 sent to dwarf_reg 65.
     - Other registers not used for unwinding cf ppc_initreg.c.  */

  /* Count bits and allocate regs_mapping:  */
  int j, k, kmax, count; uint64_t bit;
  for (k = 0, kmax = -1, count = 0, bit = 1;
       k < PERF_REG_POWERPC_MAX; k++, bit <<= 1)
    {
      if ((bit & perf_regs_mask)) {
	count++;
	kmax = k;
      }
    }
  ebl->cached_perf_regs_mask = perf_regs_mask;
  ebl->cached_regs_mapping = (int *)calloc (count, sizeof(int));
  ebl->cached_n_regs_mapping = count;

  /* Locations of perf_regs in the dwarf_regs array,
     according to perf_regs_mask: */
  for (j = 0, k = 0, bit = 1; k <= kmax; k++, bit <<= 1)
    {
      int i = -1;
      if (!(bit & perf_regs_mask))
	{
	  continue;
	}
      if (0 <= k && k < GPRS)
	i = k;
      else if (k == LINK_PERF)
	i = LINK_DWARF;
      else if (k == NIP_PERF)
	i = NIP_DWARF;
      ebl->cached_regs_mapping[j] = i;
      j++;
    }
  for (; j < count; j++)
    ebl->cached_regs_mapping[j] = -1;

  *regs_mapping = ebl->cached_regs_mapping;
  *n_regs_mapping = ebl->cached_n_regs_mapping;
  return true;
#endif /* __powerpc__ */
}

__typeof (ppc_sample_sp_pc)
     ppc64_sample_sp_pc
     __attribute__ ((alias ("ppc_sample_sp_pc")));

__typeof (ppc_set_initial_registers_sample)
     ppc64_set_initial_registers_sample
     __attribute__ ((alias ("ppc_set_initial_registers_sample")));

__typeof (ppc_sample_perf_regs_mapping)
     ppc64_sample_perf_regs_mapping
     __attribute__ ((alias ("ppc_sample_perf_regs_mapping")));
