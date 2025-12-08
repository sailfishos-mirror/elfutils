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

#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include <bitset>
#include <stdexcept>
#include <cstring>
#include <csignal>
#include <cassert>
#include <chrono>
#include <iostream>

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <poll.h>
#ifdef HAVE_LINUX_PERF_EVENT_H
#include <linux/perf_event.h>
#endif
#include <argp.h>
#include <fcntl.h>

#ifdef HAVE_PERFMON_PFMLIB_PERF_EVENT_H
#include <perfmon/pfmlib_perf_event.h>
#endif

#include <gelf.h>
#include <dwarf.h>
#include <libdwfl.h>
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

  vector<uint8_t> event_wraparound_temp;

public:
  // PerfReader(perf_event_attr* attr, int pid, PerfConsumer* consumer); // attach to process hierarchy; may modify *attr
  PerfReader(perf_event_attr* attr, PerfConsumer* consumer, int pid=-1);          // systemwide; may modify *attr
  
  ~PerfReader();

  void process_some(); // run briefly, relay perf_events to consumer
};


class PerfConsumer
{
public:
  PerfConsumer() {}
  virtual ~PerfConsumer() {}
  virtual void process(const perf_event_header* sample) = 0;
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
  unordered_map<int,unsigned> event_type_counts;
  
public:
  StatsPerfConsumer() {}
  ~StatsPerfConsumer(); // report to stdout
  void process(const perf_event_header* sample);
};

class PerfConsumerUnwinder: public PerfConsumer // a perf sample consumer that always unwinds perf samples 
{
public:
  PerfConsumerUnwinder(perf_event_attr* attr, UnwindSampleConsumer* usc) {}
  virtual ~PerfConsumerUnwinder() {}
  void process(const perf_event_header* sample); // handle process lifecycle events; relay unwound call stack events to a consumer 
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
  { "verbose", 'v', NULL, 0, N_ ("Increase verbosity of logging messages."), 0 },
  { "gmon", 'g', NULL, 0, N_("Generate gmon.BUILDID.out files for each binary."), 0 },
  { "pid", 'p', "PID", 0, N_("Profile given PID, and its future children."), 0 },
#ifdef HAVE_PERFMON_PFMLIB_PERF_EVENT_H  
  { "event", 'e', "EVENT", 0, N_("Sample given LIBPFM event specification."), 0 },
#endif
  { NULL, 0, NULL, 0, NULL, 0 }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static const struct argp argp =
  {
    options, parse_opt, "[--] [CMD]...", N_("Collect systemwide stack-trace profiles."),
    NULL, NULL, NULL
  };


// Globals set based on command line options:
static unsigned verbose;
static bool gmon;
static int pid;
static string libpfm_event;
static bool libpfm_event_list;

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
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

    case 'p':
      pid = atoi(arg);
      break;

    case 'e':
      libpfm_event = arg;
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
  int remaining;
  int pipefd[2] = {-1, -1}; // for CMD child process post-fork sync
  (void) argp_parse (&argp, argc, argv, 0, &remaining, NULL);

  try
    {
      perf_event_attr attr;
      memset(&attr, 0, sizeof(attr));
      attr.size = sizeof(attr);
      
      if (libpfm_event != "")
        {
#if HAVE_PERFMON_PFMLIB_PERF_EVENT_H
          pfm_err_t rc = pfm_initialize();
          if (rc != PFM_SUCCESS)
            {
              cerr << "ERROR: pfm_initialized failed"
                   << ": " << pfm_strerror(rc) << endl;
              exit(1);
            }
          pfm_perf_encode_arg_t arg = { .attr = &attr, .size = sizeof(arg) };
          rc = pfm_get_os_event_encoding(libpfm_event.c_str(),
                                         PFM_PLM3, /* user level */ /* user+kernel: PFM_PLM3|PFM_PLM0 */
                                         PFM_OS_PERF_EVENT_EXT, &arg);
          if (rc != PFM_SUCCESS)
            {
              cerr << "ERROR: pfm_get_os_event_encoding failed"
                   << ": " << pfm_strerror(rc) << endl;
              exit(1);
            }
#endif
        }
      else
        {
          attr.type = PERF_TYPE_SOFTWARE;
          attr.config = PERF_COUNT_SW_CPU_CLOCK;
          attr.sample_freq = 1000;
        }

      attr.sample_type =  (PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME);
      attr.disabled = 1;
      attr.exclude_kernel = 1; /* TODO: Probably don't care about this for our initial usecase. */
      attr.mmap = 1;
      attr.mmap2 = 1;

      if (pid == 0 && remaining < argc) // got a CMD... suffix?  ok start it
        {
          int rc = pipe (pipefd); // will use pipefd[] >= 0 as flag for synchronization just below
          if (rc < 0)
            {
              cerr << "ERROR: pipe failed"
                   << ": " << strerror(errno) << endl;
              exit(1);
            }

          pid = fork();
          if (pid == 0) // in child
            {
              close (pipefd[1]); // close write end
              char dummy;
              int rc = read (pipefd[0], &dummy, 1); // block until parent is ready
              assert (rc == 1);              
              close (pipefd[0]);
              execvp (argv[remaining], & argv[remaining] /* not +1: child argv[0] included! */ );
              // notreached unless error
              cerr << "ERROR: execvp failed"
                   << ": " << strerror(errno) << endl;
              exit(1);
            }
          else if (pid > 0) // in parent
            {
              close (pipefd[0]); // close read end
              // will write to pipefd[1] after perfreader sicced at child
            }
          else // error
            {
              cerr << "ERROR: fork failed"
                   << ": " << strerror(errno) << endl;
              exit(1);
            }
        }
      
#if 0
      // Create the perf processing pipeline as per command line options
      GprofUnwindSampleConsumer usc;
      PerfConsumerUnwinder pcu(&attr, &usc);
      PerfReader pr(&attr, &pcu, pid);
#else      
      StatsPerfConsumer pcu;
      PerfReader pr(&attr, &pcu, pid);
#endif
      
      signal(SIGINT, sigint_handler);
      signal(SIGTERM, sigint_handler);      

      if (pid > 0 && pipefd[0]>=0) // need to release child CMD process?
        {
          int rc = write(pipefd[1], "x", 1); // unblock child
          assert (rc == 1);
          close(pipefd[1]);
        }

      if (verbose)
        {
          clog << "Starting stack profile collection ";
          if (pid) clog << "pid " << pid;
          else clog << "systemwide";
          clog << endl;
        }
      
      while (true) // main loop
        {
          if (interrupted) break;
          if (pid > 0) waitpid(pid, NULL, WNOHANG); // reap dead child to allow kill(pid, 0) to signal death
          if (pid > 0 && kill(pid, 0) != 0) break; // exit if child or targeted non-child process died
          pr.process_some();
        }

      // reporting done in various destructors
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
  this->mmap_size = this->page_size * (this->page_count + 1); // total mmap size, incl header page
  this->event_wraparound_temp.resize(this->mmap_size); // NB: never resize this object again!
  
  Ebl *default_ebl = ebl_openbackend_machine(EM_X86_64); // XXX
  this->sample_regs_user = ebl_perf_frame_regs_mask (default_ebl);
  this->sample_regs_count = bitset<64>(this->sample_regs_user).count();
  attr->sample_regs_user = this->sample_regs_user;
  attr->sample_stack_user = 8192; // enough?
  attr->sample_type |= PERF_SAMPLE_REGS_USER;
  attr->sample_type |= PERF_SAMPLE_STACK_USER;

  this->consumer = consumer;
  
  while (pid > 0) // actually only once, to allow break in case of error
    {
      // XXX: later: attach to each preexisting thread of $pid
      int fd = syscall(__NR_perf_event_open, attr, pid, -1, -1, 0);
      if (fd < 0)
        {
          cerr << "WARNING: unable to open perf event for pid " << pid
               << ": " << strerror(errno) << endl;
          break;
        }
      void *buf = mmap(NULL, this->mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if (buf == MAP_FAILED)
        {
          cerr << "ERROR: perf event mmap failed"
               << ": " << strerror(errno) << endl;
          close(fd);
          break;
        }
      this->perf_fds.push_back(fd);
      this->perf_headers.push_back((perf_event_mmap_page*) buf);
      struct pollfd pfd = {.fd = fd, .events=POLLIN};
      this->pollfds.push_back(pfd);

      attr->inherit = 1; // propagate to child processes
      attr->task = 1; // catch FORK/EXIT
      attr->comm = 1; // catch EXEC
      break;
    }
  if (pid == 0) // systemwide!
    {
      // iterate over all cpus
      int ncpus = sysconf(_SC_NPROCESSORS_CONF);
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

  if (this->perf_fds.size() == 0)
    throw runtime_error("ERROR: no perf events opened");
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
  uint64_t ring_buffer_size = this->page_size * this->page_count; // just the ring buffer size
  
  while (! interrupted)
    {
      uint64_t now = millis_monotonic();
      if (endtime < now)
        break;
      int ready = poll(this->pollfds.data(), this->pollfds.size(), (int)(endtime-now)); // wait a little while
      if (ready < 0)
        break;

      for (int i = 0; i < pollfds.size(); i++)
        if (this->pollfds[i].revents & POLLIN) // found an fd with fresh yummy events
          {
            perf_event_mmap_page *header = perf_headers[i];
            uint64_t data_head = header->data_head;
            asm volatile("" ::: "memory"); // memory fence
            uint64_t data_tail = header->data_tail; 
            uint8_t *base = ((uint8_t *) header) + this->page_size;
            struct perf_event_header *ehdr;
            size_t ehdr_size;

            while (data_head != data_tail) // consume all packets in ring buffer XXX why?
              {
                ehdr = (perf_event_header*) (base + (data_tail & (ring_buffer_size - 1)));
                ehdr_size = ehdr->size;
                if (verbose > 3)
                  clog << "perf head=" << (void*) data_head
                       << " tail=" << (void*) data_tail
                       << " ehdr=" << (void*) ehdr << " size=" << ehdr_size << endl;
                
                if (((uint8_t *)ehdr) + ehdr_size > base + ring_buffer_size) // mmap region wraparound?
                  {
                    // need to copy it to a contiguous temporary
                    uint8_t *copy_start = (uint8_t*) ehdr;
                    size_t len_first = base + ring_buffer_size - copy_start;
                    size_t len_secnd = ehdr_size - len_first;
                    uint8_t *event_temp = this->event_wraparound_temp.data();
                    memcpy(event_temp, copy_start, len_first);       // part at end of mmap'd region
                    memcpy(event_temp + len_first, base, len_secnd); // part at beginning of mmap'd region
                    ehdr = (perf_event_header*) event_temp; 
                  }

                this->consumer->process (ehdr);
                data_tail += ehdr_size;
              }

            asm volatile("" ::: "memory"); // memory fence
            header->data_tail = data_tail;
          }
    }
}


////////////////////////////////////////////////////////////////////////
// perf event consumers / unwinders

StatsPerfConsumer::~StatsPerfConsumer()
{
  for (const auto& kv : this->event_type_counts)
    {
      cout << "event type " << kv.first << " count " << kv.second << endl;
    }
}

void StatsPerfConsumer::process(const perf_event_header* ehdr)
{
  this->event_type_counts[ehdr->type] ++;
}




////////////////////////////////////////////////////////////////////////
// unwind consumers // gprof


