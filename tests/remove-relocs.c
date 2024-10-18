/* Test program for dwelf_elf_remove_debug_relocs
   Copyright (C) 2024 Red Hat, Inc.
   This file is part of elfutils.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <fcntl.h>
#include ELFUTILS_HEADER(dw)
#include ELFUTILS_HEADER(dwelf)

int main(int argc __attribute__ ((unused)), char **argv) {
  Elf *elf;
  elf_version (EV_CURRENT);
  int fd = open (argv[1], O_RDWR);

  elf = elf_begin (fd, ELF_C_RDWR, NULL);

  dwelf_elf_remove_debug_relocations (elf);
  elf_update (elf, ELF_C_WRITE);

  elf_end (elf);
  return 0;
}
