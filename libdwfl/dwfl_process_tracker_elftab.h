#ifndef DWFL_PROCESS_TRACKER_ELFTAB_H
#define DWFL_PROCESS_TRACKER_ELFTAB_H 1

/* Definitions for the Elf table.  */
#define TYPE dwfltracker_elf_info *
#define NAME dwfltracker_elftab
#define ITERATE 1
#define COMPARE(a, b) \
  strcmp ((a)->module_name, (b)->module_name)
#include <dynamicsizehash_concurrent.h>

#endif
