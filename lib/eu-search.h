/* Calls for thread-safe tsearch/tfind
   Copyright (C) 2023 Rice University
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

#ifndef EU_SEARCH_H
#define EU_SEARCH_H 1

#include <search.h>

extern void *eu_tsearch(const void *key, void **rootp,
			int (*compar)(const void *, const void *));
extern void *eu_tfind(const void *key, void *const *rootp,
		      int (*compar)(const void *, const void *));

#endif