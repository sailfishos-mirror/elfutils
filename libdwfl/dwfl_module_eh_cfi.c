/* Find EH CFI for a module in libdwfl.
   Copyright (C) 2009-2010 Red Hat, Inc.
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

#include "libdwflP.h"
#include "cfi.h"

Dwarf_CFI *
dwfl_module_eh_cfi (Dwfl_Module *mod, Dwarf_Addr *bias)
{
  if (mod == NULL)
    return NULL;

  Dwarf_CFI *cfi = atomic_load_acquire (&mod->eh_cfi);
  if (cfi != NULL)
    {
      *bias = dwfl_adjusted_address (mod, 0);
      return cfi;
    }

  mutex_lock (mod->dwfl->load_lock);
  cfi = mod->eh_cfi;
  if (cfi == NULL)
    {
      __libdwfl_getelf (mod);
      if (mod->elferr != DWFL_E_NOERROR)
	{
	  __libdwfl_seterrno (mod->elferr);
	  mutex_unlock (mod->dwfl->load_lock);
	  return NULL;
	}

      cfi = __libdwfl_set_cfi_locked (mod, &mod->eh_cfi,
				      INTUSE(dwarf_getcfi_elf) (mod->main.elf));
    }

  mutex_unlock (mod->dwfl->load_lock);
  *bias = dwfl_adjusted_address (mod, 0);
  return cfi;
}
INTDEF (dwfl_module_eh_cfi)
