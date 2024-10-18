/* Remove relocations from debug sections.
   Copyright (C) 2014 Red Hat, Inc.
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

#include "libdwelfP.h"
#include "libelfP.h"
#include "libebl.h"

typedef uint8_t GElf_Byte;

const char *
secndx_name (Elf *elf, size_t ndx)
{
  size_t shstrndx;
  GElf_Shdr mem;
  Elf_Scn *sec = elf_getscn (elf, ndx);
  GElf_Shdr *shdr = gelf_getshdr (sec, &mem);
  if (shdr == NULL || elf_getshdrstrndx (elf, &shstrndx) < 0)
    return "???";
  return elf_strptr (elf, shstrndx, shdr->sh_name) ?: "???";
}


Elf_Data *
get_xndxdata (Elf *elf, Elf_Scn *symscn)
{
  Elf_Data *xndxdata = NULL;
  GElf_Shdr shdr_mem;
  GElf_Shdr *shdr = gelf_getshdr (symscn, &shdr_mem);
  if (shdr != NULL && shdr->sh_type == SHT_SYMTAB)
    {
      size_t scnndx = elf_ndxscn (symscn);
      Elf_Scn *xndxscn = NULL;
      while ((xndxscn = elf_nextscn (elf, xndxscn)) != NULL)
	{
	  GElf_Shdr xndxshdr_mem;
	  GElf_Shdr *xndxshdr = gelf_getshdr (xndxscn, &xndxshdr_mem);

	  if (xndxshdr != NULL
	      && xndxshdr->sh_type == SHT_SYMTAB_SHNDX
	      && xndxshdr->sh_link == scnndx)
	    {
	      xndxdata = elf_getdata (xndxscn, NULL);
	      break;
	    }
	}
    }

  return xndxdata;
}


bool
relocate (Elf *elf, GElf_Addr offset, const GElf_Sxword addend,
	  Elf_Data *tdata, unsigned int ei_data, bool is_rela,
	  GElf_Sym *sym, int addsub, Elf_Type type)
{
  /* These are the types we can relocate.  */
#define TYPES   DO_TYPE (BYTE, Byte); DO_TYPE (HALF, Half);		\
      DO_TYPE (WORD, Word); DO_TYPE (SWORD, Sword);		\
      DO_TYPE (XWORD, Xword); DO_TYPE (SXWORD, Sxword)

  size_t size;

#define DO_TYPE(NAME, Name) GElf_##Name Name;
  union { TYPES; } tmpbuf;
#undef DO_TYPE

  switch (type)
    {
#define DO_TYPE(NAME, Name)				\
      case ELF_T_##NAME:			\
	size = sizeof (GElf_##Name);	\
	tmpbuf.Name = 0;			\
	break;
      TYPES;
#undef DO_TYPE
    default:
      return false;
    }

  if (offset > tdata->d_size
      || tdata->d_size - offset < size)
    {
      //__libelf_seterrno (ELF_E_INVALID_OFFSET);
      return false;
    }

  /* When the symbol value is zero then for SHT_REL
     sections this is all that needs to be checked.
     The addend is contained in the original data at
     the offset already.  So if the (section) symbol
     address is zero and the given addend is zero
     just remove the relocation, it isn't needed
     anymore.  */
  if (addend == 0 && sym->st_value == 0)
    return true;

  Elf_Data tmpdata =
    {
      .d_type = type,
      .d_buf = &tmpbuf,
      .d_size = size,
      .d_version = EV_CURRENT,
    };
  Elf_Data rdata =
    {
      .d_type = type,
      .d_buf = tdata->d_buf + offset,
      .d_size = size,
      .d_version = EV_CURRENT,
    };

  GElf_Addr value = sym->st_value;
  if (is_rela)
    {
      /* For SHT_RELA sections we just take the
	 given addend and add it to the value.  */
      value += addend;
      /* For ADD/SUB relocations we need to fetch the
	 current section contents.  */
      if (addsub != 0)
	{
	  Elf_Data *d = gelf_xlatetom (elf, &tmpdata,
				       &rdata,
				       ei_data);
	  if (d == NULL || d != &tmpdata)
	    {
	      //__libelf_seterrno (ELF_E_INVALID_HANDLE);
	      return false;
	    }
	}
    }
  else
    {
      /* For SHT_REL sections we have to peek at
	 what is already in the section at the given
	 offset to get the addend.  */
      Elf_Data *d = gelf_xlatetom (elf, &tmpdata,
				   &rdata,
				   ei_data);
      if (d == NULL || d != &tmpdata)
	{
	  //__libelf_seterrno (ELF_E_INVALID_HANDLE);
	  return false;
	}
    }

  switch (type)
    {
#define DO_TYPE(NAME, Name)					 \
      case ELF_T_##NAME:				 \
	if (addsub < 0)				 \
	  tmpbuf.Name -= (GElf_##Name) value;	 \
	else					 \
	  tmpbuf.Name += (GElf_##Name) value;	 \
	break;
      TYPES;
#undef DO_TYPE
    default:
      //__libelf_seterrno (ELF_E_UNKNOWN_TYPE);
      return false;
    }

  /* Now finally put in the new value.  */
  Elf_Data *s = gelf_xlatetof (elf, &rdata,
			       &tmpdata,
			       ei_data);
  if (s == NULL || s != &rdata)
    {
      //__libelf_seterrno (ELF_E_INVALID_HANDLE);
      return false;
    }

  return true;
}


int dwelf_elf_remove_debug_relocations (Elf *elf)
{
  size_t shstrndx;
  if (elf_getshdrstrndx (elf, &shstrndx) < 0)
    return -1;

  GElf_Ehdr ehdr_mem, *ehdr = gelf_getehdr (elf, &ehdr_mem);
  if (ehdr == NULL)
    return -1;

  const unsigned int ei_data = ehdr->e_ident[EI_DATA];

  Ebl *ebl = ebl_openbackend (elf);
  if (ebl == NULL)
    return -1;

  int res = -1;
  Elf_Scn *scn = NULL;
  while ((scn = elf_nextscn (elf, scn)) != NULL)
  {
    /* We need the actual section and header from the elf
	not just the cached original in shdr_info because we
	might want to change the size.  */
	GElf_Shdr shdr_mem;
	GElf_Shdr *shdr = gelf_getshdr (scn, &shdr_mem);

    if (shdr != NULL
	&& (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA))
      {
	/* Make sure that this relocation section points to a
	   section to relocate with contents, that isn't
	   allocated and that is a debug section.  */
	Elf_Scn *tscn = elf_getscn (elf, shdr->sh_info);
	GElf_Shdr tshdr_mem;
	GElf_Shdr *tshdr = gelf_getshdr (tscn, &tshdr_mem);
	if (tshdr == NULL
	    || tshdr->sh_type == SHT_NOBITS
	    || tshdr->sh_size == 0
	    || (tshdr->sh_flags & SHF_ALLOC) != 0)
	  continue;

	const char *tname =  elf_strptr (elf, shstrndx,
					 tshdr->sh_name);
	if (! tname || ! ebl_debugscn_p (ebl, tname))
	  continue;

	/* OK, lets relocate all trivial cross debug section
	   relocations. */
	Elf_Data *reldata = elf_getdata (scn, NULL);
	if (reldata == NULL || reldata->d_buf == NULL)
	  goto exit;

	/* Make sure we adjust the uncompressed debug data
	   (and recompress if necessary at the end).  */
	GElf_Chdr tchdr;
	int tcompress_type = 0;
	bool is_gnu_compressed = false;
	if (startswith (tname, ".zdebug"))
	  {
	    is_gnu_compressed = true;
	    if (elf_compress_gnu (tscn, 0, 0) != 1)
	      goto exit;
	  }
	else
	  {
	    if (gelf_getchdr (tscn, &tchdr) != NULL)
	      {
		tcompress_type = tchdr.ch_type;
		if (elf_compress (tscn, 0, 0) != 1)
		  goto exit;
	      }
	  }

	Elf_Data *tdata = elf_getdata (tscn, NULL);
	if (tdata == NULL || tdata->d_buf == NULL
	    || tdata->d_type != ELF_T_BYTE)
	  goto exit;

	/* Pick up the symbol table and shndx table to
	   resolve relocation symbol indexes.  */
	Elf64_Word symt = shdr->sh_link;
	Elf_Data *symdata, *xndxdata;
	Elf_Scn * symscn = elf_getscn (elf, symt);
	symdata = elf_getdata (symscn, NULL);
	xndxdata = get_xndxdata (elf, symscn);
	if (symdata == NULL)
	  goto exit;

	if (shdr->sh_entsize == 0)
	  goto exit;

	size_t nrels = shdr->sh_size / shdr->sh_entsize;
	size_t next = 0;
	const bool is_rela = (shdr->sh_type == SHT_RELA);

	for (size_t relidx = 0; relidx < nrels; ++relidx)
	  {
	    int rtype, symndx, offset, addend;
	    union { GElf_Rela rela; GElf_Rel rel; } mem;
	    void *rel_p; /* Pointer to either rela or rel above */

	    if (is_rela)
	      {
		GElf_Rela *r = gelf_getrela (reldata, relidx, &mem.rela);
		if (r == NULL)
		  goto exit;
		offset = r->r_offset;
		addend = r->r_addend;
		rtype = GELF_R_TYPE (r->r_info);
		symndx = GELF_R_SYM (r->r_info);
		rel_p = r;
	      }
	    else
	      {
		GElf_Rel *r = gelf_getrel (reldata, relidx, &mem.rel);
		if (r == NULL)
		  goto exit;
		offset = r->r_offset;
		addend = 0;
		rtype = GELF_R_TYPE (r->r_info);
		symndx = GELF_R_SYM (r->r_info);
		rel_p = r;
	      }

	    /* R_*_NONE relocs can always just be removed.  */
	    if (rtype == 0)
	      continue;

	    /* We only do simple absolute relocations.  */
	    int addsub = 0;
	    Elf_Type type = ebl_reloc_simple_type (ebl, rtype, &addsub);
	    if (type == ELF_T_NUM)
	      goto relocate_failed;

	    /* And only for relocations against other debug sections.  */
	    GElf_Sym sym_mem;
	    Elf32_Word xndx;
	    GElf_Sym *sym = gelf_getsymshndx (symdata, xndxdata,
					      symndx, &sym_mem,
					      &xndx);
	    if (sym == NULL)
	      goto exit;
	    Elf32_Word sec = (sym->st_shndx == SHN_XINDEX
				? xndx : sym->st_shndx);

	    bool dbg_scn = ebl_debugscn_p (ebl, secndx_name (elf, sec));

	    if (!dbg_scn)
	      goto relocate_failed;

	    if (! relocate (elf, offset, addend, tdata, ei_data, is_rela,
			    sym, addsub, type))
	    goto relocate_failed;

	    continue; /* Next */

relocate_failed:
	    if (relidx != next)
	      {
		int updated;
		if (is_rela)
		  updated = gelf_update_rela (reldata, next, rel_p);
		else
		  updated = gelf_update_rel (reldata, next, rel_p);
		if (updated == 0)
		  goto exit;
	      }
	    ++next;
	  }

	nrels = next;
	shdr->sh_size = reldata->d_size = nrels * shdr->sh_entsize;
	if (gelf_update_shdr (scn, shdr) == 0)
	  goto exit;

	if (is_gnu_compressed)
	  {
	    if (elf_compress_gnu (tscn, 1, ELF_CHF_FORCE) != 1)
	      goto exit;
	  }
	else if (tcompress_type != 0)
	  {
	    if (elf_compress (tscn, tcompress_type, ELF_CHF_FORCE) != 1)
	      goto exit;
	  }
      }
  }

  res = 0;

exit:
  ebl_closebackend (ebl);
  return res;
}
