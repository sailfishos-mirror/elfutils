/* Alpha ABI-specified defaults for DWARF CFI.
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

#include <dwarf.h>

#define BACKEND alpha_
#include "libebl_CPU.h"

int
alpha_abi_cfi (Ebl *ebl __attribute__ ((unused)), Dwarf_CIE *abi_info)
{
  static const uint8_t abi_cfi[] =
    {
      /* The CFA is the value of $sp ($30) in the previous frame.  */
      DW_CFA_def_cfa, ULEB128_7 (30), ULEB128_7 (0),

      /* $sp is restored from the CFA.  */
      DW_CFA_val_offset, ULEB128_7 (30), ULEB128_7 (0),

#define SV(n) DW_CFA_same_value, ULEB128_7 (n)
      /* The return address in $ra ($26) is set up by the caller.  */
      SV (26),

      /* Callee-saved registers $s0-$s5 ($9-$14) and $fp ($15).  */
      SV (9), SV (10), SV (11), SV (12), SV (13), SV (14), SV (15),

      /* Callee-saved registers $f2-$f9.  */
      SV (34), SV (35), SV (36), SV (37), SV (38), SV (39), SV (40), SV (41),
#undef SV
    };

  abi_info->initial_instructions = abi_cfi;
  abi_info->initial_instructions_end = &abi_cfi[sizeof abi_cfi];
  abi_info->data_alignment_factor = -8;

  abi_info->return_address_register = 26; /* $ra */

  return 0;
}
