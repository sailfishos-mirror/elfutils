/* Fetch live process registers from TID.
   Copyright (C) 2013, 2014 Red Hat, Inc.
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

#include "system.h"
#include <assert.h>
#if defined(__aarch64__) && defined(__linux__)
# include <linux/uio.h>
# include <sys/user.h>
# include <sys/ptrace.h>
# include <asm/ptrace.h>
/* Deal with old glibc defining user_pt_regs instead of user_regs_struct.  */
# ifndef HAVE_SYS_USER_REGS
#  define user_regs_struct user_pt_regs
#  define user_fpsimd_struct user_fpsimd_state
# endif
#endif

#define BACKEND aarch64_
#include "libebl_CPU.h"

/*
 * pointer authentication masks (NT_ARM_PAC_MASK)
 *
 * Defined by Linux kernel headers since Linux 5.0. Define it here if kernel
 * headers are older than that, to ensure this file builds regardless.
 */
#if defined(__aarch64__) && defined(__linux__)

#ifndef NT_ARM_PAC_MASK
#define NT_ARM_PAC_MASK 0x406
#endif

#ifndef HAVE_USER_PACK_MASK
struct user_pac_mask {
  __u64 data_mask;
  __u64 insn_mask;
};
#endif

#endif /* __aarch64__ && __linux__ */

bool
aarch64_set_initial_registers_tid (pid_t tid __attribute__ ((unused)),
			  ebl_tid_registers_t *setfunc __attribute__ ((unused)),
				void *arg __attribute__ ((unused)))
{
#if !defined(__aarch64__) || !defined(__linux__)
  return false;
#else /* __aarch64__ */

  /* General registers.  */
  struct user_regs_struct gregs;
  struct user_pac_mask pac_mask;
  struct iovec iovec;
  iovec.iov_base = &gregs;
  iovec.iov_len = sizeof (gregs);
  if (ptrace (PTRACE_GETREGSET, tid, NT_PRSTATUS, &iovec) != 0)
    return false;

  iovec.iov_base = &pac_mask;
  iovec.iov_len = sizeof (pac_mask);
  if (ptrace (PTRACE_GETREGSET, tid, NT_ARM_PAC_MASK, &iovec) != 0)
    pac_mask.insn_mask = 0;

  /* X0..X30 plus SP.  */
  if (! setfunc (0, 32, (Dwarf_Word *) &gregs.regs[0], arg))
    return false;

  /* PC.  */
  if (! setfunc (-1, 1, (Dwarf_Word *) &gregs.pc, arg))
    return false;

  if (! setfunc (-2, 1, (Dwarf_Word *) &pac_mask.insn_mask, arg))
    return false;

  /* ELR cannot be found.  */

  /* RA_SIGN_STATE cannot be found */

  /* FP registers (only 64bits are used).  */
  struct user_fpsimd_struct fregs;
  iovec.iov_base = &fregs;
  iovec.iov_len = sizeof (fregs);
  if (ptrace (PTRACE_GETREGSET, tid, NT_FPREGSET, &iovec) != 0)
    return false;

  Dwarf_Word dwarf_fregs[32];
  for (int r = 0; r < 32; r++)
    dwarf_fregs[r] = fregs.vregs[r] & 0xFFFFFFFF;

  if (! setfunc (64, 32, dwarf_fregs, arg))
    return false;

  return true;
#endif /* __aarch64__ */
}
