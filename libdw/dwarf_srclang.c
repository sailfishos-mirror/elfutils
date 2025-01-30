/* Return source language attribute of DIE.
   Copyright (C) 2003-2010 Red Hat, Inc.
   Copyright (C) 2025 Mark J. Wielaard <mark@klomp.org>
   This file is part of elfutils.
   Written by Ulrich Drepper <drepper@redhat.com>, 2003.

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
#include "libdwP.h"


static int srclang_to_language (Dwarf_Word srclang,
				Dwarf_Word *lname,
				Dwarf_Word *lversion)
{
  switch (srclang)
    {
    case DW_LANG_C89:
      *lname = DW_LNAME_C;
      *lversion = 198912;
      return 0;
    case DW_LANG_C:
      *lname = DW_LNAME_C;
      *lversion = 0;
      return 0;
    case DW_LANG_Ada83:
      *lname = DW_LNAME_Ada;
      *lversion = 1983;
      return 0;
    case DW_LANG_C_plus_plus:
      *lname = DW_LNAME_C_plus_plus;
      *lversion = 199711;
      return 0;
    case DW_LANG_Cobol74:
      *lname = DW_LNAME_Cobol;
      *lversion = 1974;
      return 0;
    case DW_LANG_Cobol85:
      *lname = DW_LNAME_Cobol;
      *lversion = 1985;
      return 0;
    case DW_LANG_Fortran77:
      *lname = DW_LNAME_Fortran;
      *lversion = 1977;
      return 0;
    case DW_LANG_Fortran90:
      *lname = DW_LNAME_Fortran;
      *lversion = 1990;
      return 0;
    case DW_LANG_Pascal83:
      *lname = DW_LNAME_Pascal;
      *lversion = 1983;
      return 0;
    case DW_LANG_Modula2:
      *lname = DW_LNAME_Modula2;
      *lversion = 0;
      return 0;
    case DW_LANG_Java:
      *lname = DW_LNAME_Java;
      *lversion = 0;
      return 0;
    case DW_LANG_C99:
      *lname = DW_LNAME_C;
      *lversion = 199901;
      return 0;
    case DW_LANG_Ada95:
      *lname = DW_LNAME_Ada;
      *lversion = 1995;
      return 0;
    case DW_LANG_Fortran95:
      *lname = DW_LNAME_Fortran;
      *lversion = 1995;
      return 0;
    case DW_LANG_PLI:
      *lname = DW_LNAME_PLI;
      *lversion = 0;
      return 0;
    case DW_LANG_ObjC:
      *lname = DW_LNAME_ObjC;
      *lversion = 0;
      return 0;
    case DW_LANG_ObjC_plus_plus:
      *lname = DW_LNAME_ObjC_plus_plus;
      *lversion = 0;
      return 0;
    case DW_LANG_UPC:
      *lname = DW_LNAME_UPC;
      *lversion = 0;
      return 0;
    case DW_LANG_D:
      *lname = DW_LNAME_D;
      *lversion = 0;
      return 0;
    case DW_LANG_Python:
      *lname = DW_LNAME_Python;
      *lversion = 0;
      return 0;
    case DW_LANG_OpenCL:
      *lname = DW_LNAME_OpenCL_C;
      *lversion = 0;
      return 0;
    case DW_LANG_Go:
      *lname = DW_LNAME_Go;
      *lversion = 0;
      return 0;
    case DW_LANG_Modula3:
      *lname = DW_LNAME_Modula3;
      *lversion = 0;
      return 0;
    case DW_LANG_Haskell:
      *lname = DW_LNAME_Haskell;
      *lversion = 0;
      return 0;
    case DW_LANG_C_plus_plus_03:
      *lname = DW_LNAME_C_plus_plus;
      *lversion = 199711; /* This is really just c++98. */
      return 0;
    case DW_LANG_C_plus_plus_11:
      *lname = DW_LNAME_C_plus_plus;
      *lversion = 201103;
      return 0;
    case DW_LANG_OCaml:
      *lname = DW_LNAME_OCaml;
      *lversion = 0;
      return 0;
    case DW_LANG_Rust:
      *lname = DW_LNAME_Rust;
      *lversion = 0;
      return 0;
    case DW_LANG_C11:
      *lname = DW_LNAME_C;
      *lversion = 201112;
      return 0;
    case DW_LANG_Swift:
      *lname = DW_LNAME_Swift;
      *lversion = 0;
      return 0;
    case DW_LANG_Julia:
      *lname = DW_LNAME_Julia;
      *lversion = 0;
      return 0;
    case DW_LANG_C_plus_plus_14:
      *lname = DW_LNAME_C_plus_plus;
      *lversion = 201402;
      return 0;
    case DW_LANG_Fortran03:
      *lname = DW_LNAME_Fortran;
      *lversion = 2003;
      return 0;
    case DW_LANG_Fortran08:
      *lname = DW_LNAME_Fortran;
      *lversion = 2008;
      return 0;
    case DW_LANG_RenderScript:
      *lname = DW_LNAME_RenderScript;
      *lversion = 0;
      return 0;
    case DW_LANG_BLISS:
      *lname = DW_LNAME_BLISS;
      *lversion = 0;
      return 0;
    case DW_LANG_Kotlin:
      *lname = DW_LNAME_Kotlin;
      *lversion = 0;
      return 0;
    case DW_LANG_Zig:
      *lname = DW_LNAME_Zig;
      *lversion = 0;
      return 0;
    case DW_LANG_Crystal:
      *lname = DW_LNAME_Crystal;
      *lversion = 0;
      return 0;
    case DW_LANG_C_plus_plus_17:
      *lname = DW_LANG_C_plus_plus;
      *lversion = 201703;
      return 0;
    case DW_LANG_C_plus_plus_20:
      *lname = DW_LANG_C_plus_plus;
      *lversion = 202002;
      return 0;
    case DW_LANG_C17:
      *lname = DW_LNAME_C;
      *lversion = 201710;
      return 0;
    case DW_LANG_Fortran18:
      *lname = DW_LNAME_Fortran;
      *lversion = 2018;
      return 0;
    case DW_LANG_Ada2005:
      *lname = DW_LNAME_Ada;
      *lversion = 2005;
      return 0;
    case DW_LANG_Ada2012:
      *lname = DW_LNAME_Ada;
      *lversion = 2012;
      return 0;
    case DW_LANG_HIP:
      *lname = DW_LNAME_HIP;
      *lversion = 0;
      return 0;
    case DW_LANG_Assembly:
    case DW_LANG_Mips_Assembler:
      *lname = DW_LNAME_Assembly;
      *lversion = 0;
      return 0;
    case DW_LANG_C_sharp:
      *lname = DW_LNAME_C_sharp;
      *lversion = 0;
      return 0;
    case DW_LANG_Mojo:
      *lname = DW_LNAME_Mojo;
      *lversion = 0;
      return 0;
    case DW_LANG_GLSL:
      *lname = DW_LNAME_GLSL;
      *lversion = 0;
      return 0;
    case DW_LANG_GLSL_ES:
      *lname = DW_LNAME_GLSL_ES;
      *lversion = 0;
      return 0;
    case DW_LANG_HLSL:
      *lname = DW_LNAME_HLSL;
      *lversion = 0;
      return 0;
    case DW_LANG_OpenCL_CPP:
      *lname = DW_LNAME_OpenCL_CPP;
      *lversion = 0;
      return 0;
    case DW_LANG_CPP_for_OpenCL:
      *lname = DW_LNAME_CPP_for_OpenCL;
      *lversion = 0;
      return 0;
    case DW_LANG_SYCL:
      *lname = DW_LNAME_SYCL;
      *lversion = 0;
      return 0;
    case DW_LANG_C_plus_plus_23:
      *lname = DW_LNAME_C_plus_plus;
      *lversion = 202302;
      return 0;
    case DW_LANG_Odin:
      *lname = DW_LNAME_Odin;
      *lversion = 0;
      return 0;
    case DW_LANG_P4:
      *lname = DW_LNAME_P4;
      *lversion = 0;
      return 0;
    case DW_LANG_Metal:
      *lname = DW_LNAME_Metal;
      *lversion = 0;
      return 0;
    case DW_LANG_C23:
      *lname = DW_LNAME_C;
      *lversion = 202311;
      return 0;
    case DW_LANG_Fortran23:
      *lname = DW_LNAME_Fortran;
      *lversion = 2023;
      return 0;
    case DW_LANG_Ruby:
      *lname = DW_LNAME_Ruby;
      *lversion = 0;
      return 0;
    case DW_LANG_Move:
      *lname = DW_LNAME_Move;
      *lversion = 0;
      return 0;
    case DW_LANG_Hylo:
      *lname = DW_LNAME_Hylo;
      *lversion = 0;
      return 0;
    default:
      __libdw_seterrno (DWARF_E_UNKNOWN_LANGUAGE);
      return -1;
    }
}

NEW_VERSION (dwarf_srclang, ELFUTILS_0.143)
int
dwarf_srclang (Dwarf_Die *die)
{
  Dwarf_Attribute attr_mem;
  Dwarf_Word value;

  return INTUSE(dwarf_formudata) (INTUSE(dwarf_attr_integrate)
				  (die, DW_AT_language, &attr_mem),
				  &value) == 0 ? (int) value : -1;
}
NEW_INTDEF (dwarf_srclang)
OLD_VERSION (dwarf_srclang, ELFUTILS_0.122)

int
dwarf_language (Dwarf_Die *cudie, Dwarf_Word *lname, Dwarf_Word *lversion)
{
  Dwarf_Attribute attr;
  Dwarf_Word val;

  int res = INTUSE(dwarf_formudata) (INTUSE(dwarf_attr_integrate)
				     (cudie, DW_AT_language_name, &attr),
				     &val);
  if (res == 0)
    {
      *lname = val;
      if (lversion != NULL)
	{
	  /* We like to get the version, but given we already have the
	     lang, we will ignore errors here and just return zero as
	     version.  */
	  res = INTUSE(dwarf_formudata) (INTUSE(dwarf_attr_integrate)
					 (cudie, DW_AT_language_version,
					  &attr), &val);
	  *lversion = (res == 0) ? val : 0;
	}
    }
  else
    {
      /* Try the get the old style pre DWARF6 DW_AT_LANG and translate
	 that to the new language name/version style.  */
      res = INTUSE(dwarf_formudata) (INTUSE(dwarf_attr_integrate)
				     (cudie, DW_AT_language, &attr), &val);
      if (res == 0)
	{
	  Dwarf_Word version;
	  res = srclang_to_language (val, lname, (lversion == NULL
						  ? &version : lversion));
	}
    }

  return res;
}
INTDEF (dwarf_language)
