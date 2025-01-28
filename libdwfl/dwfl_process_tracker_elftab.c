#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <string.h>

#include <libdwflP.h>

/* Definitions for the Elf table. */
#define TYPE dwfltracker_elf_info *
#define NAME dwfltracker_elftab
#define ITERATE 1
/* TODO: Need REVERSE? */
#define REVERSE 1
#define COMPARE(a, b) \
  strcmp ((a)->module_name, (b)->module_name)

/* TODO needed? */
/* #define next_prime __libdwfl_next_prime */
/* extern size_t next_prime (size_t) attribute_hidden; */

#include "../lib/dynamicsizehash_concurrent.c"
