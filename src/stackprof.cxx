/* Collect stack-trace profiles of running program(s).
   Copyright (C) 2025 Red Hat, Inc.
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

#include "printversion.h"

#include <set>
#include <string>
#include <memory>
#include <sstream>
#include <vector>
#include <bitset>
#include <stdexcept>
#include <cstring>
#include <csignal>
#include <cassert>
#include <chrono>

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <linux/perf_event.h>

#include <dwarf.h>
#include <argp.h>
#include <gelf.h>
#include <libdwfl.h>
#include <fcntl.h>
#include <iostream>
#include <libdw.h>

#include "../libebl/libebl.h"


#include ELFUTILS_HEADER(dwfl_stacktrace)

using namespace std;


////////////////////////////////////////////////////////////////////////
// class decls

class PerfConsumer;


class PerfReader
{
private:
  /* Sized by number of CPUs or threads: */
  vector<int> perf_fds;
  vector<perf_event_mmap_page *> perf_headers;
  vector<pollfd> pollfds;

  PerfConsumer* consumer; // pluralize!
  
  uint64_t sample_regs_user;
  int sample_regs_count;
  bool enabled;
  int page_size;
  int page_count;
  int mmap_size;

public:
  // PerfReader(perf_event_attr* attr, int pid, PerfConsumer* consumer); // attach to process hierarchy; may modify *attr
  PerfReader(perf_event_attr* attr, PerfConsumer* consumer, int pid=-1);          // systemwide; may modify *attr
  
  ~PerfReader();

  void process_some(); // run briefly, relay PerfSample events to consumer
};


struct PerfSample // perf event as found in ring buffer
{
  struct perf_event_header header;
  uint64_t ip;
  uint32_t pid, tid;
  uint64_t time;
  uint64_t abi;
  uint64_t *regs; /* XXX variable size */
  /* uint64_t size; */
  /* char *data; -- XXX variable size */
};


class PerfConsumer
{
public:
  PerfConsumer() {}
  virtual ~PerfConsumer() {}
  virtual void process(const PerfSample* sample) = 0;
};


struct UnwindSample
{
  // pid_t pid; etc.?
  vector<pair<string,Dwarf_Addr>> buildid_reladdrs;
};

class UnwindSampleConsumer
{
public:
  virtual unsigned maxdepth() const; // how deep unwinding is desired
  virtual void process(const UnwindSample* sample) = 0;
};


class StatsPerfConsumer: public PerfConsumer
{
public:
  StatsPerfConsumer() {}
  ~StatsPerfConsumer(); // report to stdout
  void process(const PerfSample* sample);
};

class PerfConsumerUnwinder: public PerfConsumer // a perf sample consumer that always unwinds perf samples 
{
public:
  PerfConsumerUnwinder(perf_event_attr* attr, UnwindSampleConsumer* usc) {}
  virtual ~PerfConsumerUnwinder() {}
  void process(const PerfSample* sample); // handle process lifecycle events; relay unwound call stack events to a consumer 
};


class GprofUnwindSampleConsumer: public UnwindSampleConsumer
{
public:
  GprofUnwindSampleConsumer() {}
  ~GprofUnwindSampleConsumer(); // write out all the gmon.$BUILDID.out files
  void process(const UnwindSample* sample); // accumulate hits / callgraph edges (need maxdepth=1 only)
};

// hypothetical: FlamegraphUnwindSampleConsumer, taking in a bigger maxdepth
// hypothetical: PprofUnwindSampleConsumer, https://github.com/google/pprof



////////////////////////////////////////////////////////////////////////
// command line parsing


/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = print_version;

/* Bug report address.  */
ARGP_PROGRAM_BUG_ADDRESS_DEF = PACKAGE_BUGREPORT;


/* Definitions of arguments for argp functions.  */
static const struct argp_option options[] =
{
  { NULL, 0, NULL, OPTION_DOC, N_("Output options:"), 1 },
  { "verbose", 'v', NULL, 0,
    N_ ("Increase verbosity of logging messages."), 0 },
  { "gmon", 'g', NULL, 0, N_("Generate gmon.out files for each binary."), 0 },
  // --pid $PID
  // --cmd $CMD
  // --systemwide [assumed for now]
  // --event $LIBPFM
  { NULL, 0, NULL, 0, NULL, 0 }
};

/* Short description of program.  */
static const char doc[] = N_("Collect systemwide stack-trace profiles.");
/* Strings for arguments in help texts.  */
static const char args_doc[] = N_("");
/* Prototype for option handler.  */
static error_t parse_opt (int key, char *arg, struct argp_state *state);
/* Data structure to communicate with argp functions.  */
static const struct argp argp =
{
  options, parse_opt, args_doc, doc, NULL, NULL, NULL
};


// Globals set based on command line options:

static unsigned verbose;
static bool gmon;


static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Suppress "unused parameter" warning.  */
  (void)arg;
  (void)state;
  switch (key)
    {
    case ARGP_KEY_INIT:
      break;

    case 'v':
      verbose ++;
      break;

    case 'g':
      gmon = true;
      break;
      
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}


sig_atomic_t interrupted;

void sigint_handler(int sig)
{
  interrupted ++;
  if (interrupted > 1)
    _exit(1);
}



int
main (int argc, char *argv[])
{
  (void) argp_parse (&argp, argc, argv, ARGP_IN_ORDER, NULL /* CMD */, NULL);


  try
    {
      // Create the perf processing pipeline as per command line options
      GprofUnwindSampleConsumer usc;
      perf_event_attr x; // initialize
      PerfConsumerUnwinder pcu(&x, &usc);
      PerfReader pr(&x, &pcu); // , CMD->fork->pid
      
      signal(SIGINT, sigint_handler);
      signal(SIGTERM, sigint_handler);      
      
      while (! interrupted)
        pr.process_some();
    }
  catch (const exception& e)
    {
      cerr << e.what() << endl; 
    }
  
  return 0;
}



////////////////////////////////////////////////////////////////////////
// perf reader

PerfReader::PerfReader(perf_event_attr* attr, PerfConsumer* consumer, int pid)
{
  this->page_size = getpagesize();
  this->page_count = 64; /* TODO: Decide on a large-enough power-of-2. */
  this->mmap_size = this->page_size * (this->page_count + 1);

  Ebl *default_ebl = NULL; // XXX
  this->sample_regs_user = ebl_perf_frame_regs_mask (default_ebl);
  this->sample_regs_count = bitset<64>(this->sample_regs_user).count();
  attr->sample_regs_user = this->sample_regs_user;
  attr->sample_stack_user = 8192;
  /* TODO? attr.sample_stack_user = 65536; */

  this->consumer = consumer;
  
  if (pid > 0) // attach to all threads
    throw invalid_argument("pid attachment not yet supported");
  else
    {
      // iterate over all cpus
      int ncpus = sysconf(_SC_NPROCESSORS_CONF);
      if (ncpus <= 0)
        for (int cpu=0; cpu<ncpus; cpu++)
          {
            int fd = syscall(__NR_perf_event_open, attr, -1, cpu, -1, 0);
            if (fd < 0)
              {
                cerr << "WARNING: unable to open perf event for cpu " << cpu
                     << ": " << strerror(errno) << endl;
                continue;
              }
            void *buf = mmap(NULL, this->mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (buf == MAP_FAILED)
              {
                cerr << "ERROR: perf event mmap failed"
                     << ": " << strerror(errno) << endl;
                close(fd);
                continue;
              }
            this->perf_fds.push_back(fd);
            this->perf_headers.push_back((perf_event_mmap_page*) buf);
            struct pollfd pfd = {.fd = fd, .events=POLLIN};
            this->pollfds.push_back(pfd);
          }
    }
}



PerfReader::~PerfReader()
{
  for (auto fd : this->perf_fds)
    close(fd);
  for (auto m : this->perf_headers)
    munmap((void*) m, this->mmap_size);
}



uint64_t millis_monotonic()
{
  return chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count();
}


void PerfReader::process_some()
{
  if (! this->enabled)
    {
      for (auto fd : this->perf_fds)
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0 /* value ignored */);
      this->enabled = true;
    }

  uint64_t starttime = millis_monotonic();
  uint64_t endtime = starttime + 1000; // run at most one second
  while (true)
    {
      uint64_t now = millis_monotonic();
      if (endtime < now)
        break;
      int ready = poll(this->pollfds.data(), this->pollfds.size(), (int)(endtime-now));
      if (ready < 0)
        break;

      for (auto& pollfd : this->pollfds)
        {
          if (pollfd.revents & POLLIN) ;
        }
      
    }
  

  
}




////////////////////////////////////////////////////////////////////////
// perf event consumers / unwinders


////////////////////////////////////////////////////////////////////////
// unwind consumers


