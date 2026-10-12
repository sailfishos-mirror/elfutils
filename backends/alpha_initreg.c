/* Fetch live process registers from TID.
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

#if defined __alpha__ && defined __linux__
# include <errno.h>
# include <stdint.h>
# include <sys/ptrace.h>
#endif

#define BACKEND alpha_
#include "libebl_CPU.h"

bool
alpha_set_initial_registers_tid (pid_t tid __attribute__ ((unused)),
				 ebl_tid_registers_t *setfunc __attribute__ ((unused)),
				 void *arg __attribute__ ((unused)))
{
#if !defined __alpha__ || !defined __linux__
  return false;
#else /* __alpha__ */
  /* PTRACE_PEEKUSER takes a register number: 0-31 for the integer
     registers, 32-62 for $f0-$f30, 63 for the FPCR and 64 for the PC.
     The value is the return value, so check errno rather than for -1.  */
  Dwarf_Word regs[65];
  for (int i = 0; i < 65; i++)
    {
      /* $31 and $f31 always read as zero.  */
      if (i == 31 || i == 63)
	{
	  regs[i] = 0;
	  continue;
	}
      errno = 0;
      regs[i] = ptrace (PTRACE_PEEKUSER, tid, (void *) (uintptr_t) i, NULL);
      if (errno != 0)
	return false;
    }

  /* $0-$31 and $f0-$f31, then the PC.  */
  return setfunc (0, 64, regs, arg) && setfunc (-1, 1, &regs[64], arg);
#endif /* __alpha__ */
}
