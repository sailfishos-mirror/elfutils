/*Test program for eu_search_die.
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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

static void *thread_work(void *arg);
static int check_die(Dwarf_Die *die);
static int check_dbg(Dwarf *dbg);

/*The main Dwarf file.  */
static Dwarf * dwarf;

typedef struct
{
	Dwarf * dbg;
	Dwarf_Off start_offset;
	Dwarf_Off end_offset;
	int result;
}

ThreadData;

static void *thread_work(void *arg)
{
	ThreadData *data = (ThreadData*) arg;
	data->result = check_dbg(data->dbg);
	return NULL;
}

static int check_die(Dwarf_Die *die)
{
	if (dwarf_tag(die) == DW_TAG_invalid)
	{
		printf("Invalid die\n");
		return -1;
	}

	int res = 0;
	void *addr = die->addr;
	Dwarf_Die die2;
	if (dwarf_die_addr_die(dwarf, addr, &die2) == NULL)
	{
		printf("Bad die addr die at offset %" PRIx64 "\n", dwarf_dieoffset(die));
		res = -1;
	}

	if (dwarf_tag(die) != dwarf_tag(&die2))
	{
		printf("Tags differ for die at offset %" PRIx64 "\n", dwarf_dieoffset(die));
		res = -1;
	}

	if (dwarf_cuoffset(die) != dwarf_cuoffset(&die2))
	{
		printf("CU offsets differ for die at offset %" PRIx64 "\n", dwarf_dieoffset(die));
		res = -1;
	}

	Dwarf_Die child;
	if (dwarf_child(die, &child) == 0)
		res |= check_die(&child);

	Dwarf_Die sibling;
	if (dwarf_siblingof(die, &sibling) == 0)
		res |= check_die(&sibling);

	return res;
}

static int check_dbg(Dwarf *dbg)
{
	int res = 0;
	Dwarf_Off off = 0;
	Dwarf_Off old_off = 0;
	size_t hsize;
	Dwarf_Off abbrev;
	uint8_t addresssize;
	uint8_t offsetsize;

	while (dwarf_nextcu(dbg, off, &off, &hsize, &abbrev, &addresssize, &offsetsize) == 0)
	{
		Dwarf_Die die;
		if (dwarf_offdie(dbg, old_off + hsize, &die) != NULL)
		{
			printf("checking CU at %" PRIx64 "\n", old_off);
			res |= check_die(&die);
		}

		old_off = off;
	}

	// Same for type...
	Dwarf_Half version;
	uint64_t typesig;
	Dwarf_Off typeoff;
	off = 0;
	old_off = 0;

	while (dwarf_next_unit(dbg, off, &off, &hsize, &version, &abbrev, &addresssize, &offsetsize, &typesig, &typeoff) == 0)
	{
		Dwarf_Die die;
		if (dwarf_offdie_types(dbg, old_off + hsize, &die) != NULL)
		{
			printf("checking TU at %" PRIx64 "\n", old_off);
			res |= check_die(&die);
		}

		// We should have seen this already, but double check...
		if (dwarf_offdie_types(dbg, old_off + typeoff, &die) != NULL)
		{
			printf("checking Type DIE at %" PRIx64 "\n", old_off + hsize + typeoff);
			res |= check_die(&die);
		}

		old_off = off;
	}

	Dwarf *alt = dwarf_getalt(dbg);

	if (alt != NULL)
	{
		printf("checking alt debug\n");
		res |= check_dbg(alt);
	}

	// Split or Type Dwarf_Dies gotten through dwarf_get_units.
	Dwarf_CU *cu = NULL;
	Dwarf_Die subdie;
	uint8_t unit_type;
	while (dwarf_get_units(dbg, cu, &cu, NULL, &unit_type, NULL, &subdie) == 0)
	{
		if (dwarf_tag(&subdie) != DW_TAG_invalid)
		{
			printf("checking %"
				PRIx8 " subdie\n", unit_type);
			res |= check_die(&subdie);
		}
	}

	return res;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("No file given.\n");
		return -1;
	}

	const char *name = argv[1];
	int fd = open(name, O_RDONLY);
	if (fd < 0)
	{
		printf("Cannot open '%s': %s\n", name, strerror(errno));
		return -1;
	}

	dwarf = dwarf_begin(fd, DWARF_C_READ);
	if (dwarf == NULL)
	{
		printf("Not a Dwarf file '%s': %s\n", name, dwarf_errmsg(-1));
		close(fd);
		return -1;
	}

	printf("checking %s\n", name);

	int num_threads = 4;
	pthread_t *threads = (pthread_t*) malloc(num_threads* sizeof(pthread_t));
	ThreadData *thread_data = (ThreadData*) malloc(num_threads* sizeof(ThreadData));

	if (!threads || !thread_data)
	{
		fprintf(stderr, "Failed to allocate memory for threads.\n");
		free(threads);
		free(thread_data);
		return 1;
	}

	Dwarf_Off total_off = 0;
	Dwarf_Off unit_off = 0;
	size_t hsize;
	Dwarf_Off abbrev;
	uint8_t addresssize;
	uint8_t offsetsize;

	while (dwarf_nextcu(dwarf, unit_off, &unit_off, &hsize, &abbrev, &addresssize, &offsetsize) == 0)
	{
		thread_data[total_off % num_threads].start_offset = unit_off;
		thread_data[total_off % num_threads].end_offset = unit_off + hsize;
		total_off++;
	}

	for (int i = 0; i < num_threads; i++)
	{
		thread_data[i].dbg = dwarf;
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

	int res = 0;
	for (int i = 0; i < num_threads; i++)
	{
		res |= thread_data[i].result;
	}

	free(threads);
	free(thread_data);

	dwarf_end(dwarf);
	close(fd);

	return res;
}