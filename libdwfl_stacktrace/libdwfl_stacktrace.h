/* Interfaces for libdwfl_stacktrace.

   XXX: This is an experimental initial version of the API, and is
   liable to change in future releases of elfutils, especially as
   we figure out how to generalize the work to other sample data
   formats in addition to perf_events.

   Copyright (C) 2025 Red Hat, Inc.
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

#ifndef _LIBDWFL_STACKTRACE_H
#define _LIBDWFL_STACKTRACE_H  1

#include "libdwfl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Keeps track of and caches Elf structs across multiple libdwfl
   sessions corresponding to different processes.  */
typedef struct Dwflst_Process_Tracker Dwflst_Process_Tracker;


/* Initialize a new tracker for multiple libdwfl sessions.  Since Elf
   data will shared between the libdwfl sessions, each Dwfl must use
   the same Dwfl_Callbacks CALLBACKS provided when the tracker is
   created.  */
extern Dwflst_Process_Tracker *dwflst_tracker_begin (const Dwfl_Callbacks *callbacks)
  __nonnull_attribute__ (1);

/* Create a new Dwfl linked to this tracker.  */
extern Dwfl *dwflst_tracker_dwfl_begin (Dwflst_Process_Tracker *tracker)
  __nonnull_attribute__ (1);

/* End all sessions with this tracker.  */
extern void dwflst_tracker_end (Dwflst_Process_Tracker *tracker);


/* XXX dwflst_perf_sample_getframes to be added in subsequent patch */

/* Returns the linux perf_events register mask describing a set of
   registers sufficient for unwinding on MACHINE, or 0 if libdwfl does
   not handle perf_events samples for MACHINE.  Does not take a Dwfl*
   or Elf* since this is meant to allow a profiling tool to configure
   perf_events to produce meaningful data for a libdwfl session to be
   opened later.  */
uint64_t dwflst_perf_sample_preferred_regs_mask (GElf_Half machine);

#ifdef __cplusplus
}
#endif

#endif  /* libdwfl_stacktrace.h */
