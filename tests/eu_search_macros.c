/*Test program for eu_search_macros
   Copyright (C) 2023 Red Hat, Inc.
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
   along with this program.  If not, see<http://www.gnu.org/licenses/>.  */

#include <config.h>
#include ELFUTILS_HEADER(dw)
#include <dwarf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <pthread.h>

static void *thread_work(void *arg);
static int mac(Dwarf_Macro *macro, void *dbg);
static void include(Dwarf *dbg, Dwarf_Off macoff, ptrdiff_t token);

typedef struct
{
	Dwarf * dbg;
	Dwarf_Die * cudie;
	bool new_style;
}

ThreadData;

static void *thread_work(void *arg)
{
	ThreadData *data = (ThreadData*) arg;
	Dwarf *dbg = data->dbg;
	Dwarf_Die *cudie = data->cudie;
	bool new_style = data->new_style;

	for (ptrdiff_t off = new_style ? DWARF_GETMACROS_START : 0;
		(off = dwarf_getmacros(cudie, mac, dbg, off));)
	{
		if (off == -1)
		{
			puts(dwarf_errmsg(dwarf_errno()));
			break;
		}
	}

	return NULL;
}

static void include(Dwarf *dbg, Dwarf_Off macoff, ptrdiff_t token)
{
	while ((token = dwarf_getmacros_off(dbg, macoff, mac, dbg, token)) != 0)
	{
		if (token == -1)
		{
			puts(dwarf_errmsg(dwarf_errno()));
			break;
		}
	}
}

static int
mac(Dwarf_Macro *macro, void *dbg)
{
	static atomic_int level = 0;

	unsigned int opcode;
	dwarf_macro_opcode(macro, &opcode);
	switch (opcode)
	{
		case DW_MACRO_import:
			{
				Dwarf_Attribute at;
				int r = dwarf_macro_param(macro, 0, &at);
				assert(r == 0);

				Dwarf_Word w;
				r = dwarf_formudata(&at, &w);
				assert(r == 0);

				printf ("%dinclude %#" PRIx64 "\n", atomic_load (&level), w);

				atomic_fetch_add(&level, 1);

				include(dbg, w, DWARF_GETMACROS_START);

				atomic_fetch_sub(&level, 1);

				printf ("%d/include\n", atomic_load (&level));
				break;
			}

		case DW_MACRO_start_file:
			{
				Dwarf_Files * files;
				size_t nfiles;
				if (dwarf_macro_getsrcfiles(dbg, macro, &files, &nfiles) < 0)
					printf("dwarf_macro_getsrcfiles: %s\n", dwarf_errmsg(dwarf_errno()));

				Dwarf_Word w = 0;
				dwarf_macro_param2(macro, &w, NULL);

				const char *name = dwarf_filesrc (files, (size_t) w, NULL, NULL);
				printf ("%dfile %s\n", atomic_load (&level), name);
				atomic_fetch_add(&level, 1);
				break;
			}

		case DW_MACRO_end_file:
			{
				atomic_fetch_sub(&level, 1);
				printf ("%d/file\n", atomic_load (&level));
				break;
			}

		case DW_MACINFO_define:
		case DW_MACRO_define_strp:
			{
				const char *value;
				dwarf_macro_param2(macro, NULL, &value);
				printf ("%d%s\n", atomic_load (&level), value);
				break;
			}

		case DW_MACINFO_undef:
		case DW_MACRO_undef_strp:
			break;

		default:
			{
				size_t paramcnt;
				dwarf_macro_getparamcnt(macro, &paramcnt);
				printf ("%dopcode %u with %zd arguments\n", atomic_load (&level), opcode, paramcnt);
				break;
			}
	}

	return DWARF_CB_ABORT;
}

int main(int argc, char *argv[])
{
	assert(argc >= 3);
	const char *name = argv[1];
	ptrdiff_t cuoff = strtol(argv[2], NULL, 0);
	bool new_style = argc > 3;

	int fd = open(name, O_RDONLY);
	Dwarf *dbg = dwarf_begin(fd, DWARF_C_READ);

	Dwarf_Die cudie_mem, *cudie = dwarf_offdie(dbg, cuoff, &cudie_mem);

	int num_threads = 4;
	pthread_t *threads = malloc(num_threads* sizeof(pthread_t));
	ThreadData *thread_data = malloc(num_threads* sizeof(ThreadData));

	if (!threads || !thread_data)
	{
		fprintf(stderr, "Failed to allocate memory for threads.\n");
		free(threads);
		free(thread_data);
		return 1;
	}

	for (int i = 0; i < num_threads; i++)
	{
		thread_data[i].dbg = dbg;
		thread_data[i].cudie = cudie;
		thread_data[i].new_style = new_style;

		if (pthread_create(&threads[i], NULL, thread_work, (void*) &thread_data[i]) != 0)
		{
			perror("Failed to create thread");
			for (int j = 0; j < i; j++)
			{
				pthread_cancel(threads[j]);
			}
			free(threads);
			free(thread_data);
			return 1;
		}
	}

	for (int i = 0; i < num_threads; i++)
	{
		if (pthread_join(threads[i], NULL) != 0)
		{
			perror("Failed to join thread");
			free(threads);
			free(thread_data);
			return 1;
		}
	}

	free(threads);
	free(thread_data);

	dwarf_end(dbg);

	return 0;
}
