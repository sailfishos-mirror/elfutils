#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <libdwflP.h>

/* Definitions for the Dwfl table. */
#define TYPE dwfltracker_dwfl_info *
#define NAME dwfltracker_dwfltab
#define ITERATE 1
/* TODO: Need REVERSE? */
#define REVERSE 1
#define COMPARE(a, b) \
  ((a->invalid && b->invalid) || \
   (!a->invalid && !b->invalid && \
    (a)->dwfl->process->pid == (b)->dwfl->process->pid))

/* TODO needed? */
/* #define next_prime __libdwfl_next_prime */
/* extern size_t next_prime (size_t) attribute_hidden; */

#include "../lib/dynamicsizehash_concurrent.c"
