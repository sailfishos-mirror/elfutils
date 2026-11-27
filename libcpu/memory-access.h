/* Unaligned memory access functionality.
   Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2008 Red Hat, Inc.
   Copyright (C) 2026 Mark J. Wielaard <mark@klomp.org>
   Written by Ulrich Drepper <drepper@redhat.com>, 2001.

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

#ifndef _MEMORY_ACCESS_H
#define _MEMORY_ACCESS_H 1

#include <limits.h>
#include <stdint.h>

#include <system.h>

/* When loading this file we require the macro MACHINE_ENCODING to be
   defined to signal the endianness of the architecture which is
   defined.  */
#ifndef MACHINE_ENCODING
# error "MACHINE_ENCODING needs to be defined"
#endif
#if MACHINE_ENCODING != BIG_ENDIAN && MACHINE_ENCODING != LITTLE_ENDIAN
# error "MACHINE_ENCODING must signal either big or little endian"
#endif


/* We use memcpy to read the values so that the compiler takes care of
   alignment.  The caller has to make sure we don't have alias problems.  */

static inline uint16_t
read_2ubyte_unaligned (const void *p)
{
  uint16_t v;
  memcpy (&v, p, sizeof v);
  return unlikely (MACHINE_ENCODING != BYTE_ORDER) ? bswap_16 (v) : v;
}

static inline int16_t
read_2sbyte_unaligned (const void *p)
{
  return (int16_t) read_2ubyte_unaligned (p);
}

static inline uint32_t
read_4ubyte_unaligned (const void *p)
{
  uint32_t v;
  memcpy (&v, p, sizeof v);
  return unlikely (MACHINE_ENCODING != BYTE_ORDER) ? bswap_32 (v) : v;
}

static inline int32_t
read_4sbyte_unaligned (const void *p)
{
  return (int32_t) read_4ubyte_unaligned (p);
}

static inline uint64_t
read_8ubyte_unaligned (const void *p)
{
  uint64_t v;
  memcpy (&v, p, sizeof v);
  return unlikely (MACHINE_ENCODING != BYTE_ORDER) ? bswap_64 (v) : v;
}

static inline int64_t
read_8sbyte_unaligned (const void *p)
{
  return (int64_t) read_8ubyte_unaligned (p);
}

#define read_2ubyte_unaligned_inc(Addr) \
  ({ uint16_t t_ = read_2ubyte_unaligned (Addr);			      \
     Addr = (__typeof (Addr)) (((uintptr_t) (Addr)) + 2);		      \
     t_; })
#define read_2sbyte_unaligned_inc(Addr) \
  ({ int16_t t_ = read_2sbyte_unaligned (Addr);				      \
     Addr = (__typeof (Addr)) (((uintptr_t) (Addr)) + 2);		      \
     t_; })

#define read_4ubyte_unaligned_inc(Addr) \
  ({ uint32_t t_ = read_4ubyte_unaligned (Addr);			      \
     Addr = (__typeof (Addr)) (((uintptr_t) (Addr)) + 4);		      \
     t_; })
#define read_4sbyte_unaligned_inc(Addr) \
  ({ int32_t t_ = read_4sbyte_unaligned (Addr);				      \
     Addr = (__typeof (Addr)) (((uintptr_t) (Addr)) + 4);		      \
     t_; })

#define read_8ubyte_unaligned_inc(Addr) \
  ({ uint64_t t_ = read_8ubyte_unaligned (Addr);			      \
     Addr = (__typeof (Addr)) (((uintptr_t) (Addr)) + 8);		      \
     t_; })
#define read_8sbyte_unaligned_inc(Addr) \
  ({ int64_t t_ = read_8sbyte_unaligned (Addr);				      \
     Addr = (__typeof (Addr)) (((uintptr_t) (Addr)) + 8);		      \
     t_; })

#endif	/* memory-access.h */
