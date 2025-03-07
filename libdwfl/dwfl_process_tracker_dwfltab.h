#ifndef DWFL_PROCESS_TRACKER_DWFLTAB_H
#define DWFL_PROCESS_TRACKER_DWFLTAB_H 1

/* Definitions for the Dwfl table.  */
#define TYPE dwfltracker_dwfl_info *
#define NAME dwfltracker_dwfltab
#define ITERATE 1
#define COMPARE(a, b) \
  ((a->invalid && b->invalid) || \
   (!a->invalid && !b->invalid && \
    (a)->dwfl->process->pid == (b)->dwfl->process->pid))
#include <dynamicsizehash_concurrent.h>

#endif
