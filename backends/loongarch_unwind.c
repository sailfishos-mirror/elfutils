/* Get previous frame state for an existing frame state.
   Copyright (C) 2023 OpenAnolis community LoongArch SIG.
   Copyright (C) 2023 Loongson Technology Corporation Limited.
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
#define RA_REG 1
#define SP_REG 3
#define FP_REG 22

#define RA_OFFSET 8
#define FP_OFFSET 16

#include "libebl_CPU.h"

/* There was no CFI. Maybe we happen to have a frame pointer and can unwind from that?  */

bool
EBLHOOK(unwind) (Ebl *ebl __attribute__ ((unused)), Dwarf_Addr pc,
                 ebl_tid_registers_t *setfunc, ebl_tid_registers_get_t *getfunc,
                 ebl_pid_memory_read_t *readfunc, void *arg,
                 bool *signal_framep __attribute__ ((unused)))
{
  Dwarf_Word fp, ra, sp;

  // RA must be available in the current frame.
  if (!getfunc(RA_REG, 1, &ra, arg))
    return false;

  // RA must be meaningful, and not equal to PC or we would loop infinitely.
  // `RA == PC + 1` is the same stuck case when the frame is a non-initial
  // caller frame.
  //
  // In case of retries from the forwarding heuristics below, if we arrive
  // here the previous frame's RA (which is the current PC) does not have
  // CFI either, so we stop.
  if (ra == 0 || ra == pc || ra == pc + 1 || !setfunc(-1, 1, &ra, arg))
    return false;

  // FP and SP must be available too.
  if (!getfunc(FP_REG, 1, &fp, arg))
    fp = 0;

  if (!getfunc(SP_REG, 1, &sp, arg))
    sp = 0;

  // The LoongArch stack must be 16-byte aligned at procedure entry, and
  // essentially all compiled code respects the invariant at all times.
  // So if SP is unaligned, the frame is not ABI-conformant, and not usable.
  //
  // Maybe we lose some samples landing right in hand-written asm snippets
  // that have SP temporarily unaligned, but such code should be rare in
  // practice.
  if ((sp & 0xf) != 0)
    return false;

  Dwarf_Word newRa, newFp, newSp;

  // For code compiled without frame pointer, FP can contain arbitrary data,
  // so do not try to read anything based on this FP if this is the case,
  // and just forward everything unwind-related except PC and retry.
  //
  // This can happen if the current frame is a leaf function call or inside a
  // PLT stub.  LoongArch PLT stub sequences do not touch SP nor FP, so this
  // forwarding in effect gives us the parent frame.
  //
  // Here we use the stack growth direction and FP alignment as a heuristic,
  // because at this point we already have SP satisfying alignment, and valid
  // frames always have `fp > sp`.
  if (fp <= sp || (fp & 0xf) != 0)
    {
      // Retry this frame with PC set to RA (done earlier).  We either land
      // back in CFI-covered region or fail.
      setfunc(RA_REG, 1, &ra, arg);
      setfunc(FP_REG, 1, &fp, arg);
      setfunc(SP_REG, 1, &sp, arg);
      return true;
    }

  // The stack frame seems plausible, try reading from the expected slots.
  if (!readfunc(fp - RA_OFFSET, &newRa, arg))
    newRa = 0;

  if (!readfunc(fp - FP_OFFSET, &newFp, arg))
    newFp = 0;

  newSp = fp;

  // These are not fatal if they don't work. They will just prevent unwinding at the next frame.
  setfunc(RA_REG, 1, &newRa, arg);
  setfunc(FP_REG, 1, &newFp, arg);
  setfunc(SP_REG, 1, &newSp, arg);

  return true;
}
