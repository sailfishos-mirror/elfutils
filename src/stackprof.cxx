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

/* TODO Run the prototype e.g.
   sudo env LD_LIBRARY_PATH=...prefix/lib:$LD_LIBRARY_PATH ...prefix/bin/eu-stackprof --gmon -vvvv
*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "printversion.h"

#include <string>
#include <memory>
#include <iomanip>
#include <unordered_map>
#include <vector>
#include <bitset>
#include <stdexcept>
#include <cstring>
#include <csignal>
#include <cassert>
#include <chrono>
#include <iostream>
#include <cinttypes>

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
#include <dirent.h>

#include <system.h>

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
// find_debuginfo callbacks

#ifdef FIND_DEBUGINFO

static char *debuginfo_path = NULL;

static const Dwfl_Callbacks dwfl_cfi_callbacks =
  {
    .find_elf = dwflst_tracker_linux_proc_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .debuginfo_path = &debuginfo_path,
  };

#else

int
nop_find_debuginfo (Dwfl_Module *mod __attribute__((unused)),
		    void **userdata __attribute__((unused)),
		    const char *modname __attribute__((unused)),
		    GElf_Addr base __attribute__((unused)),
		    const char *file_name __attribute__((unused)),
		    const char *debuglink_file __attribute__((unused)),
		    GElf_Word debuglink_crc __attribute__((unused)),
		    char **debuginfo_file_name __attribute__((unused)))
{
#ifdef DEBUG_MODULES
  fprintf(stderr, "nop_find_debuginfo: modname=%s file_name=%s debuglink_file=%s\n",
	  modname, file_name, debuglink_file);
#endif
  return -1;
}

static const Dwfl_Callbacks dwfl_cfi_callbacks =
{
  .find_elf = dwflst_tracker_linux_proc_find_elf,
  .find_debuginfo = nop_find_debuginfo, /* work with CFI only */
};

#endif /* FIND_DEBUGINFO */

////////////////////////////////////////////////////////////////////////
// class decls

class PerfConsumer;


// A PerfReader creates perf_events file descriptors, monitors the
// mmap'd ring buffers for events, and dispatches decoded forms to a
// PerfConsumer.
class PerfReader
{
private:
  /* Sized by number of CPUs or threads: */
  vector<int> perf_fds;
  vector<perf_event_mmap_page *> perf_headers;
  vector<pollfd> pollfds;

  PerfConsumer* consumer; // pluralize!
  Ebl* default_ebl;
  uint64_t sample_regs_user;
  int sample_regs_count;
  bool enabled;
  int page_size;
  int page_count;
  int mmap_size;
  vector<uint8_t> event_wraparound_temp; // for events straddling ring buffer end

  void decode_event(const perf_event_header* ehdr);

public:
  // PerfReader(perf_event_attr* attr, int pid, PerfConsumer* consumer); // attach to process hierarchy; may modify *attr
  PerfReader(perf_event_attr* attr, PerfConsumer* consumer, int pid=-1);          // systemwide; may modify *attr

  ~PerfReader();

  void process_some(); // run briefly, relay decoded perf_events to consumer
  uint64_t regs_mask() { return this->sample_regs_user; }
  Ebl *ebl() { return this->default_ebl; }
};


// A PerfConsumer receives both raw and decoded (fields split out into function parameters)
// perf event records from a PerfReader.  Pure interface.
class PerfConsumer
{
public:
  /* TODO(REVIEW.1): Need a cleaner way to access PerfReader metadata than this two-way spaghetti. */
  PerfReader *reader; /* access sample_regs_user etc. metadata */
  PerfConsumer() {}
  PerfConsumer(PerfReader *reader) : reader(reader) {}
  virtual ~PerfConsumer() {}
  virtual void process(const perf_event_header* sample) {}

  virtual void process_comm(const perf_event_header* sample,
			    uint32_t pid, uint32_t tid, bool exec, const char* comm) {}
  virtual void process_exit(const perf_event_header* sample,
			    uint32_t pid, uint32_t ppid,
			    uint32_t tid, uint32_t ptid) {}
  virtual void process_fork(const perf_event_header* sample,
			    uint32_t pid, uint32_t ppid,
			    uint32_t tid, uint32_t ptid) {}
  virtual void process_sample(const perf_event_header* sample,
			      uint64_t ip,
			      uint32_t pid, uint32_t tid,
			      uint64_t time,
			      uint64_t abi,
			      uint32_t nregs, const uint64_t *regs,
			      uint64_t data_size, const uint8_t *data) {}
  virtual void process_mmap2(const perf_event_header* sample,
			     uint32_t pid, uint32_t tid,
			     uint64_t addr, uint64_t len, uint64_t pgoff,
			     uint8_t build_id_size, const uint8_t *build_id,
			     const char *filename) {}
};


// A StatsPerfConsumer is a toy concrete object that accepts decoded
// perf events and logs and records basic stats about them.
class StatsPerfConsumer: public PerfConsumer
{
  unordered_map<int,unsigned> event_type_counts;

public:
  StatsPerfConsumer() {}
  ~StatsPerfConsumer(); // report to stdout
  void process_comm(const perf_event_header* sample,
		    uint32_t pid, uint32_t tid, bool exec, const char* comm);
  void process_exit(const perf_event_header* sample,
			    uint32_t pid, uint32_t ppid,
		    uint32_t tid, uint32_t ptid);
  void process_fork(const perf_event_header* sample,
			    uint32_t pid, uint32_t ppid,
		    uint32_t tid, uint32_t ptid);
  void process_sample(const perf_event_header* sample,
			      uint64_t ip,
			      uint32_t pid, uint32_t tid,
			      uint64_t time,
			      uint64_t abi,
			      uint32_t nregs, const uint64_t *regs,
		      uint64_t data_size, const uint8_t *data);
  void process_mmap2(const perf_event_header* sample,
			     uint32_t pid, uint32_t tid,
			     uint64_t addr, uint64_t len, uint64_t pgoff,
			     uint8_t build_id_size, const uint8_t *build_id,
		     const char *filename);
  void process(const perf_event_header* sample);
};


// An UnwindSample records an unwound call stack from a perf-event
// sample.
struct UnwindSample
{
  const perf_event_header *event;
  uint32_t pid, tid;
  vector<pair<string,Dwarf_Addr>> buildid_reladdrs;
  vector<Dwarf_Addr> addrs;
  int elfclass;
  Dwarf_Addr base; /* for diagnostic purposes */
  Dwarf_Addr sp; /* for diagnostic purposes */
  Dwfl *dwfl; /* for diagnostic purposes */
};


struct DwflEntry;
class UnwindSampleConsumer;


// A PerfConsumerUnwinder accepts decoded perf events, and produces
// UnwindSample objects from them for relaying to an
// UnwindSampleConsumer.
class PerfConsumerUnwinder: public PerfConsumer
{
  UnwindSampleConsumer *consumer;
  UnwindSample last_us;
  Dwflst_Process_Tracker *tracker;
  unordered_map<pid_t, DwflEntry> dwfltab;

  DwflEntry *dwfltab_find(pid_t pid);
  const char *pid_find_comm(pid_t pid);
  void pid_store_dwfl(pid_t pid, Dwfl *dwfl);
  int find_procfile(Dwfl *dwfl, pid_t *pid, Elf **elf, int *elf_fd);
  Dwfl *find_dwfl(pid_t pid, const uint64_t *regs, uint32_t nregs,
		  Elf **elf, bool *cached);

public:
  PerfConsumerUnwinder(UnwindSampleConsumer* usc): consumer(usc) {
    this->tracker = dwflst_tracker_begin (&dwfl_cfi_callbacks);
  }
  PerfConsumerUnwinder(UnwindSampleConsumer* usc, PerfReader *reader): consumer(usc) {
    this->reader = reader;
    this->tracker = dwflst_tracker_begin (&dwfl_cfi_callbacks);
  }
  ~PerfConsumerUnwinder() {
    dwflst_tracker_end (this->tracker);
  }

  /* libdwfl{st} callbacks */
  Dwfl *init_dwfl(pid_t pid);
  int unwind_frame_cb(Dwfl_Frame *state);

  void process_comm(const perf_event_header* sample,
		    uint32_t pid, uint32_t tid, bool exec, const char* comm);
  void process_exit(const perf_event_header* sample,
		    uint32_t pid, uint32_t ppid,
		    uint32_t tid, uint32_t ptid);
  void process_fork(const perf_event_header* sample,
		    uint32_t pid, uint32_t ppid,
		    uint32_t tid, uint32_t ptid);
  void process_sample(const perf_event_header* sample,
		      uint64_t ip,
		      uint32_t pid, uint32_t tid,
		      uint64_t time,
		      uint64_t abi,
		      uint32_t nregs, const uint64_t *regs,
		      uint64_t data_size, const uint8_t *data);
  void process_mmap2(const perf_event_header* sample,
		     uint32_t pid, uint32_t tid,
		     uint64_t addr, uint64_t len, uint64_t pgoff,
		     uint8_t build_id_size, const uint8_t *build_id,
		     const char *filename);
};

// An UnwindSampleConsumer receives an UnwindSample from a PerfConsumerUnwinder.
// Pure abstract.
class UnwindSampleConsumer
{
public:
  UnwindSampleConsumer() {}
  virtual ~UnwindSampleConsumer() {}
  virtual void process(const UnwindSample* sample) = 0;
};


// An UnwindStatsConsumer is a toy that just collects statistics about
// a received stream of UnwindSamples.
class UnwindStatsConsumer: public UnwindSampleConsumer
{
  unordered_map<int,unsigned> event_unwind_counts;
  unordered_map<string,unsigned> event_buildid_hits;

public:
 UnwindStatsConsumer() {}
  ~UnwindStatsConsumer();
  void process(const UnwindSample* sample);
};


// An GprofUnwindSampleConsumer instance consumes UnwindSamples and tabulates
// them by buildid, for eventual writing out into gmon.out format files.
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
#define ARGP_KEY_EVENT_LIST 0x1000
  { "event-list", ARGP_KEY_EVENT_LIST, NULL, 0, N_("Sample given LIBPFM event specification."), 0 },  
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
static unsigned verbose; /* TODO(REVIEW.2): Return the show_ETC constants, derived from verbosity level. */
static bool gmon;
static int pid;
static string libpfm_event;

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

#ifdef HAVE_PERFMON_PFMLIB_PERF_EVENT_H
    case 'e':
      libpfm_event = arg;
      break;

    case ARGP_KEY_EVENT_LIST:
      {
	pfm_pmu_info_t pinfo;
	pfm_event_info_t info;

	pfm_err_t rc = pfm_initialize();
	if (rc != PFM_SUCCESS)
	  {
	    cerr << "ERROR: pfm_initialized failed"
		 << ": " << pfm_strerror(rc) << endl;
	    exit(1);
	  }

	memset(&pinfo, 0, sizeof(pinfo));
	memset(&info, 0, sizeof(info));
	pinfo.size = sizeof(pinfo);
	info.size = sizeof(info);

        for(int j= PFM_PMU_NONE ; j< PFM_PMU_MAX; j++)
	  {
	    pfm_err_t ret = pfm_get_pmu_info((pfm_pmu_t) j, &pinfo);
	    if (ret != PFM_SUCCESS)
	      continue;
	    if (! pinfo.is_present)
	      continue;
	    for (int i = pinfo.first_event; i != -1; i = pfm_get_event_next(i))
	      {
		ret = pfm_get_event_info(i, PFM_OS_PERF_EVENT_EXT, &info);
		if (ret == PFM_SUCCESS)
		  cout << pinfo.name << "::" << info.name << endl;
	      }
	  }
      }
      exit(0);
#endif

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


  if (pid > 0 && remaining < argc) // got a pid AND a cmd? reject
    {
      cerr << "ERROR: Must not specify both -p PID and CMD" << endl;
      exit(1);
    }

  bool systemwide = (pid == 0) || (remaining == argc);
  (void) systemwide;

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
	  char* fstr = nullptr;
          pfm_perf_encode_arg_t arg = { .attr = &attr, .fstr=&fstr, .size = sizeof(arg) };
          rc = pfm_get_os_event_encoding(libpfm_event.c_str(),
                                         PFM_PLM3, /* userspace, whether systemwide or not */
                                         PFM_OS_PERF_EVENT_EXT, &arg);
          if (rc != PFM_SUCCESS)
            {
              cerr << "ERROR: pfm_get_os_event_encoding failed"
                   << ": " << pfm_strerror(rc) << endl;
              exit(1);
            }
	  if (verbose)
	    {
	      clog << "libpfm expanded " << libpfm_event << " to " << fstr << endl;
	    }
	  free(fstr);
#endif
        }
      else
        {
	  // same as: -e perf::CPU-CLOCK:freq=1000
          attr.type = PERF_TYPE_SOFTWARE;
          attr.config = PERF_COUNT_SW_CPU_CLOCK;
          attr.sample_freq = 1000;
	  attr.freq = 1;
	  attr.exclude_kernel = 1;
	  attr.exclude_hv = 1;
	  attr.exclude_guest = 1;
        }


      if (verbose>1)
	{
	  auto oldf = clog.flags();
	  clog << "perf_event_attr configuration" << hex << showbase
	       << " type=" << attr.type
	       << " config=" << attr.config
	       << (attr.freq ? " sample_freq=" : " sample_period=")
	       << (attr.freq ? attr.sample_freq : attr.sample_period)
	       << endl;
	  clog.setf(oldf);
	}

      if (remaining < argc) // got a CMD... suffix?  ok start it
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
	      if (rc != 1)
		{
		  cerr << "ERROR: child sync read failed"
		       << ": " << strerror(errno) << endl;
		  exit(1);
		}
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

      // Create the perf processing pipeline as per command line options
      PerfReader *pr = nullptr;
      UnwindStatsConsumer *usc = nullptr;
      PerfConsumerUnwinder *pcu = nullptr;
      StatsPerfConsumer *spc = nullptr;

      if (gmon)
	{
	  usc = new UnwindStatsConsumer();
	  pcu = new PerfConsumerUnwinder(usc);
	  pr = new PerfReader(&attr, pcu, pid);
#if 0
	  GprofUnwindSampleConsumer usc;
	  PerfReader pr(&attr, &pcu, pid);
	  PerfConsumerUnwinder pcu(&usc, pr);
#endif
	}
      else
	{
	  spc = new StatsPerfConsumer();
	  pr = new PerfReader(&attr, spc, pid);
	}

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
          pr->process_some();
        }

      delete pr;
      delete usc;
      delete pcu;
      delete spc;

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
  this->consumer = consumer;
  consumer->reader = this;
  this->enabled = false;

  this->default_ebl = ebl_openbackend_machine(EM_X86_64); /* TODO: Generalize to architectures beyond x86. */
  this->sample_regs_user = ebl_perf_frame_regs_mask (this->default_ebl);
  this->sample_regs_count = bitset<64>(this->sample_regs_user).count();

  attr->sample_regs_user = this->sample_regs_user;
  attr->sample_stack_user = 8192; // enough?
  attr->sample_type = (PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME);
  attr->sample_type |= PERF_SAMPLE_REGS_USER;
  attr->sample_type |= PERF_SAMPLE_STACK_USER;
  // maybe: ask for PERF_SAMPLE_CALLCHAIN, in case kernel can unwind for us?
  attr->mmap = 1;
  attr->mmap2 = 1;
  attr->exclude_kernel = 1; /* TODO: Probably don't care about this for our initial usecase. */
  attr->disabled = 1; /* will get enabled soon */
  attr->task = 1; // catch FORK/EXIT
  attr->comm = 1; // catch EXEC
  attr->comm_exec = 1; // catch EXEC
  // attr->precise_ip = 2; // request 0 skid ... but that conflicts with PERF_COUNT_HW_BRANCH_INSTRUCTIONS:freq=4000
  attr->build_id = 1; // request build ids in MMAP2 events

  if (pid > 0) // actually only once, to allow break in case of error
    attr->inherit = 1; // propagate to child processes


  if (verbose>3)
    { // hexdump attr
      auto oldf = clog.flags();
      clog << "perf_event_attr hexdump:";
      auto bytes = (unsigned char*) attr;
      for (size_t x = 0; x<sizeof(*attr); x++)
	cout << ((x % 8) ? "" : " ")
	     << ((x % 32) ? "" : "\n")
	     << hex << setw(2) << setfill('0') << (unsigned)bytes[x];
      cout << endl;
      clog.setf(oldf);
    }

  // Iterate over all cpus, even if attaching to a single pid, because
  // we set ->inherit=1.  That requires possible concurrency, which is
  // enabled by per-cpu ring buffers.
  int ncpus = sysconf(_SC_NPROCESSORS_CONF);
  for (int cpu=0; cpu<ncpus; cpu++)
    {
      int fd = syscall(__NR_perf_event_open, attr,
		       (pid > 0 ? pid : -1), cpu, -1,
		       PERF_FLAG_FD_CLOEXEC);
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



static inline uint64_t
ring_buffer_read_head(volatile struct perf_event_mmap_page *base)
{
  uint64_t head = base->data_head;
  asm volatile("" ::: "memory"); // memory fence
  return head;
}

static inline void
ring_buffer_write_tail(volatile struct perf_event_mmap_page *base,
		       uint64_t tail)
{
  asm volatile("" ::: "memory"); // memory fence
  base->data_tail = tail;
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

      for (size_t i = 0; i < pollfds.size(); i++)
        if (this->pollfds[i].revents & POLLIN) // found an fd with fresh yummy events
          {
            perf_event_mmap_page *header = perf_headers[i];
            uint64_t data_head = ring_buffer_read_head(header);
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
                       << " ehdr=" << (void*) ehdr
                       << " size=" << setbase(10) << ehdr_size << setbase(16) << endl;

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

                this->decode_event(ehdr);
                data_tail += ehdr_size;
              }

	    ring_buffer_write_tail(header, data_tail);
          }
    }
}


void PerfReader::decode_event(const perf_event_header* ehdr)
{
  consumer->process(ehdr); // allow general processing

  // and decode into individual event types
  switch (ehdr->type)
    {
    case PERF_RECORD_SAMPLE:
      {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(ehdr) + sizeof(perf_event_header);
        uint64_t ip = *reinterpret_cast<const uint64_t*>(data); data += sizeof(uint64_t);
        uint32_t pid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint32_t tid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint64_t time = *reinterpret_cast<const uint64_t*>(data); data += sizeof(uint64_t);
        // PERF_SAMPLE_CALLCHAIN would be here if requested
        uint64_t abi = *reinterpret_cast<const uint64_t*>(data); data += sizeof(uint64_t);
        uint32_t nregs = this->sample_regs_count;
        const uint64_t* regs = reinterpret_cast<const uint64_t*>(data); data += nregs * sizeof(uint64_t);
        uint64_t data_size = *reinterpret_cast<const uint64_t*>(data); data += sizeof(uint64_t);
        const uint8_t* stack_data = data;
        consumer->process_sample(ehdr, ip, pid, tid, time, abi, nregs, regs, data_size, stack_data);
        break;
      }
    case PERF_RECORD_COMM:
      {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(ehdr) + sizeof(perf_event_header);
        uint32_t pid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint32_t tid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        const char* comm = reinterpret_cast<const char*>(data);
        consumer->process_comm(ehdr, pid, tid, (ehdr->misc & PERF_RECORD_MISC_COMM_EXEC), comm);
        break;
      }
    case PERF_RECORD_EXIT:
      {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(ehdr) + sizeof(perf_event_header);
        uint32_t pid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint32_t ppid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint32_t tid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint32_t ptid = *reinterpret_cast<const uint32_t*>(data);
        consumer->process_exit(ehdr, pid, ppid, tid, ptid);
        break;
      }
    case PERF_RECORD_FORK:
      {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(ehdr) + sizeof(perf_event_header);
        uint32_t pid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint32_t ppid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint32_t tid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint32_t ptid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        consumer->process_fork(ehdr, pid, ppid, tid, ptid);
        break;
      }
    case PERF_RECORD_MMAP2:
      {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(ehdr) + sizeof(perf_event_header);
        uint32_t pid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint32_t tid = *reinterpret_cast<const uint32_t*>(data); data += sizeof(uint32_t);
        uint64_t addr = *reinterpret_cast<const uint64_t*>(data); data += sizeof(uint64_t);
        uint64_t len = *reinterpret_cast<const uint64_t*>(data); data += sizeof(uint64_t);
        uint64_t pgoff = *reinterpret_cast<const uint64_t*>(data); data += sizeof(uint64_t);
        uint8_t build_id_size = 0;
        const uint8_t* build_id = nullptr;
        if (ehdr->misc & PERF_RECORD_MISC_MMAP_BUILD_ID)
          {
            build_id_size = *reinterpret_cast<const uint8_t*>(data); data += sizeof(uint8_t);
            data += sizeof(uint8_t) + sizeof(uint16_t); // skip padding
            build_id = reinterpret_cast<const uint8_t*>(data);
            data += build_id_size;
          }
        else
          {
            data += 4 + 4 + 8 + 8; // maj, min, ino, ino_generation
          }
        data += sizeof(uint32_t) + sizeof(uint32_t); // prot, flags
        const char* filename = reinterpret_cast<const char*>(data);
        consumer->process_mmap2(ehdr, pid, tid, addr, len, pgoff, build_id_size, build_id, filename);
        break;
      }
    default:
      break;
    }
}



////////////////////////////////////////////////////////////////////////
// perf event consumers

void StatsPerfConsumer::process_comm(const perf_event_header *sample,
				     uint32_t pid, uint32_t tid, bool exec, const char *comm)
{
  if (verbose > 2)
    {
      clog << "process_comm: pid=" << pid << " tid=" << tid << " exec=" << exec << " comm=" << comm << endl;
    }
}

void StatsPerfConsumer::process_exit(const perf_event_header *sample,
				     uint32_t pid, uint32_t ppid,
				     uint32_t tid, uint32_t ptid)
{
  if (verbose > 2)
    {
      clog << "process_exit: pid=" << pid << " ppid=" << ppid << " tid=" << tid << " ptid=" << ptid << endl;
    }
}

void StatsPerfConsumer::process_fork(const perf_event_header *sample,
				     uint32_t pid, uint32_t ppid,
				     uint32_t tid, uint32_t ptid)
{
  if (verbose > 2)
    {
      clog << "process_fork: pid=" << pid << " ppid=" << ppid << " tid=" << tid << " ptid=" << ptid << endl;
    }
}

void StatsPerfConsumer::process_sample(const perf_event_header *sample,
				       uint64_t ip,
				       uint32_t pid, uint32_t tid,
				       uint64_t time,
				       uint64_t abi,
				       uint32_t nregs, const uint64_t *regs,
				       uint64_t data_size, const uint8_t *data)
{
  if (verbose > 2)
    {
      auto oldf = clog.flags();
      clog << "process_sample: pid=" << pid << " tid=" << tid << " ip=" << hex << ip 
           << " time=" << time << " abi=" << abi << " nregs=" << nregs
           << " data_size=" << data_size << endl;
      clog.setf(oldf);
    }
}

void StatsPerfConsumer::process_mmap2(const perf_event_header *sample,
				      uint32_t pid, uint32_t tid,
				      uint64_t addr, uint64_t len, uint64_t pgoff,
				      uint8_t build_id_size, const uint8_t *build_id,
				      const char *filename)
{
  if (verbose > 2)
    {
      auto oldf = clog.flags();
      clog << "process_mmap2: pid=" << pid << " tid=" << tid << " addr=" << hex << addr
           << " len=" << len << " pgoff=" << pgoff << " build_id_size=" << (unsigned)build_id_size
           << " filename=" << filename << endl;
      clog.setf(oldf);
    }
}

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
// real perf consumer: unwind helpers

/* TODO (REVIEW.3): Add the code to print the final statistics table neatly. */
struct DwflEntry {
  Dwfl *dwfl;
  char *comm;
  int max_frames; /* for diagnostic purposes */
  int total_samples; /* for diagnostic purposes */
  int lost_samples; /* for diagnostic purposes */
  Dwfl_Unwound_Source last_unwound; /* track CFI source, for diagnostic purposes */
  Dwfl_Unwound_Source worst_unwound; /* track CFI source, for diagnostic purposes */
};

DwflEntry *PerfConsumerUnwinder::dwfltab_find(pid_t pid)
{
  if (this->dwfltab.count(pid) == 0)
    this->dwfltab.emplace(pid, DwflEntry());
  return &this->dwfltab[pid];
}

static const char *unknown_comm = "<unknown>";

/* TODO (REVIEW.4): Obtaining comm is helpful for statistics, but should be disabled on low verbosity levels. */
const char *PerfConsumerUnwinder::pid_find_comm(pid_t pid)
{
  DwflEntry *entry = this->dwfltab_find(pid);
  if (entry == NULL)
    return unknown_comm;
  if (entry->comm != NULL)
    return entry->comm;
  char name[64];
  int i = snprintf (name, sizeof(name), "/proc/%ld/comm", (long) pid);
  FILE *procfile = fopen(name, "r");
  size_t linelen = 0;
  if (procfile == NULL)
    goto fail;
  i = getline(&entry->comm, &linelen, procfile);
  if (i < 0)
    {
      free(entry->comm);
      goto fail;
    }
  for (i = linelen - 1; i > 0; i--)
    if (entry->comm[i] == '\n')
	entry->comm[i] = '\0';
  fclose(procfile);
  goto done;
 fail:
  entry->comm = (char *)malloc(16);
  snprintf (entry->comm, 16, unknown_comm);
 done:
  return entry->comm;
}

void PerfConsumerUnwinder::pid_store_dwfl (pid_t pid, Dwfl *dwfl)
{
  DwflEntry *entry = this->dwfltab_find(pid);
  if (entry == NULL)
    return;
  entry->dwfl = dwfl;
  this->pid_find_comm(pid);
  return;
}

/* TODO: Including extern "C" libdwflP.h in a C++ program is a no-go. Add dwfl_process() &c as an API? */
struct _DwflHack
{
  const Dwfl_Callbacks *callbacks;
  Dwflst_Process_Tracker *tracker;
#ifdef ENABLE_LIBDEBUGINFOD
  debuginfod_client *debuginfod;
#endif
  Dwfl_Module *modulelist;
  void *process;
  /* Dwfl_Error attacherr; -- private type :( */
  /* ... */
};

void *dwfl_process(Dwfl *dwfl)
{
  // return dwfl->process;
  return ((_DwflHack*)dwfl)->process;
}

// bool dwfl_has_attacherr(Dwfl *dwfl)
// {
//   return dwfl->attacherr != DWFL_E_NOERROR;
// }

/* TODO: Could be relocated to libdwfl/linux-pid-attach.c
   to remove a dependency on the libdwflP.h interface. */
int PerfConsumerUnwinder::find_procfile (Dwfl *dwfl, pid_t *pid, Elf **elf, int *elf_fd)
{
  char buffer[36];
  FILE *procfile;
  int err = 0; /* The errno to return and set for dwfl->attacherr.  */

  /* Make sure to report the actual PID (thread group leader) to
     dwfl_attach_state.  */
  snprintf (buffer, sizeof (buffer), "/proc/%ld/status", (long) *pid);
  procfile = fopen (buffer, "r");
  if (procfile == NULL)
    {
      err = errno;
    fail:
      /* TODO: Including extern "C" libdwflP.h in a C++ program is a no-go. */
      // if (dwfl->process == NULL && dwfl->attacherr == DWFL_E_NOERROR) /* XXX requires libdwflP.h */
      // if (dwfl_process(dwfl) == NULL && !dwfl_has_attacherr(dwfl))
      //   {
      //     errno = err;
      //     /* TODO: __libdwfl_canon_error not exported from libdwfl */
      //     /* dwfl->attacherr = __libdwfl_canon_error (DWFL_E_ERRNO); */
      //   }
      return err;
    }

  char *line = NULL;
  size_t linelen = 0;
  while (getline (&line, &linelen, procfile) >= 0)
    if (startswith (line, "Tgid:"))
      {
	errno = 0;
	char *endptr;
	long val = strtol (&line[5], &endptr, 10);
	if ((errno == ERANGE && val == LONG_MAX)
	    || *endptr != '\n' || val < 0 || val != (pid_t) val)
	  *pid = 0;
	else
	  *pid = (pid_t) val;
	break;
      }
  free (line);
  fclose (procfile);

  if (*pid == 0)
    {
      err = ESRCH;
      goto fail;
    }

  char name[64];
  int i = snprintf (name, sizeof (name), "/proc/%ld/task", (long) *pid);
  if (i <= 0 || i >= (ssize_t) sizeof (name) - 1)
    {
      errno = -ENOMEM;
      goto fail;
    }
  DIR *dir = opendir (name);
  if (dir == NULL)
    {
      err = errno;
      goto fail;
    }
  else
    closedir(dir);

  i = snprintf (name, sizeof (name), "/proc/%ld/exe", (long) *pid);
  assert (i > 0 && i < (ssize_t) sizeof (name) - 1);
  *elf_fd = open (name, O_RDONLY);
  if (*elf_fd >= 0)
    {
      *elf = elf_begin (*elf_fd, ELF_C_READ_MMAP, NULL);
      if (*elf == NULL)
	{
	  /* Just ignore, dwfl_attach_state will fall back to trying
	     to associate the Dwfl with one of the existing Dwfl_Module
	     ELF images (to know the machine/class backend to use).  */
	  if (verbose > 1) /* TODO show_failures */
	    fprintf(stderr, N_("find_procfile pid %lld: elf not found"),
		    (long long)*pid);
	  close (*elf_fd);
	  *elf_fd = -1;
	}
    }
  else
    *elf = NULL;
  return 0;
}

Dwfl *PerfConsumerUnwinder::init_dwfl(pid_t pid)
{
  Dwfl *dwfl = dwflst_tracker_dwfl_begin (this->tracker);

  int err = dwfl_linux_proc_report (dwfl, pid);
  if (err < 0)
    {
      if (verbose > 1) /* TODO show_failures */
	fprintf(stderr, "dwfl_linux_proc_report pid %lld: %s",
		(long long) pid, dwfl_errmsg (-1));
      return NULL;
    }
  err = dwfl_report_end (dwfl, NULL, NULL);
  if (err != 0)
    {
      if (verbose > 1) /* TODO show_failures */
	fprintf(stderr, "dwfl_report_end pid %lld: %s",
		(long long) pid, dwfl_errmsg (-1));
      return NULL;
    }

  return dwfl;
}

Dwfl *pcu_init_dwfl_cb (Dwflst_Process_Tracker *cb_tracker __attribute__ ((unused)),
			pid_t pid,
			void *arg)
{
  PerfConsumerUnwinder *pcu = (PerfConsumerUnwinder *)arg;
  return pcu->init_dwfl (pid);
}

Dwfl *PerfConsumerUnwinder::find_dwfl(pid_t pid, const uint64_t *regs, uint32_t nregs,
				      Elf **out_elf, bool *cached)
{
  /* XXX: Note that requesting the x86_64 register file from
     perf_events will result in an array of 17 regs even for 32-bit
     applications. */
  if (nregs < ebl_frame_nregs(this->reader->ebl())) /* XXX expecting everything except FLAGS */
    {
      if (verbose > 1) /* TODO show_failures */
	fprintf(stderr, N_("find_dwfl: nregs=%d, expected %ld\n"),
		nregs, ebl_frame_nregs(this->reader->ebl()));
      return NULL;
    }

  Elf *elf = NULL;
  Dwfl *dwfl = dwflst_tracker_find_pid (this->tracker, pid, pcu_init_dwfl_cb, this);
  int elf_fd = -1;
  int err;
  if (dwfl != NULL && dwfl_process(dwfl) != NULL)
    {
      *cached = true;
      goto reuse;
    }
  err = this->find_procfile (dwfl, &pid, &elf, &elf_fd);
  if (err < 0)
    {
      if (verbose > 1) /* TODO show_failures */
	fprintf(stderr, "find_procfile pid %lld: %s",
		(long long) pid, dwfl_errmsg (-1));
      return NULL;
    }

 reuse:
  /* TODO: Generalize to other architectures than x86. */
  this->last_us.sp = regs[7];
  this->last_us.base = this->last_us.sp;

  if (!*cached)
    this->pid_store_dwfl (pid, dwfl);
  *out_elf = elf;
  return dwfl;
}

int PerfConsumerUnwinder::unwind_frame_cb(Dwfl_Frame *state)
{
  /* TODO */
  Dwarf_Addr pc;
  bool isactivation;
  if (! dwfl_frame_pc (state, &pc, &isactivation))
    {
      if (verbose > 1) /* TODO show_failures */
	fprintf(stderr, "dwfl_frame_pc: %s\n",
		dwfl_errmsg(-1));
      return DWARF_CB_ABORT;
    }

  Dwarf_Addr pc_adjusted = pc - (isactivation ? 0 : 1);
  Dwarf_Addr sp;

  int is_abi32 = (this->last_us.elfclass == ELFCLASS32);
  /* DWARF register order cf. elfutils backends/{x86_64,i386}_initreg.c: */
  int user_regs_sp = is_abi32 ? 4 : 7;
  int rc = dwfl_frame_reg (state, user_regs_sp, &sp);
  if (rc < 0)
    {
      if (verbose > 1) /* TODO show_failures */
	fprintf(stderr, "dwfl_frame_reg: %s\n",
		dwfl_errmsg(-1));
      return DWARF_CB_ABORT;
    }

#ifdef DEBUG_MODULES
  Dwfl_Module *mod = dwfl_addrmodule(this->last_us.dwfl, pc);
  if (mod == NULL)
    {
      fprintf(stderr, "* pc=%lx -> NO MODULE\n", pc);
    }
  else
    {
      const char *mainfile;
      const char *debugfile;
      const char *modname = dwfl_module_info (mod, NULL, NULL, NULL, NULL,
					      NULL, &mainfile, &debugfile);
      fprintf (stderr, "* module %s -> mainfile=%s debugfile=%s\n", modname, mainfile, debugfile);
      Dwarf_Addr bias;
      Dwarf_CFI *cfi_eh = dwfl_module_eh_cfi (mod, &bias);
      if (cfi_eh == NULL)
	fprintf(stderr, "* pc=%lx -> NO EH_CFI\n", pc);
    }
#endif

  DwflEntry *dwfl_ent = this->dwfltab_find(this->last_us.pid);
  if (dwfl_ent != NULL)
    {
      Dwfl_Unwound_Source unwound_source = dwfl_frame_unwound_source(state);
      if (unwound_source > dwfl_ent->worst_unwound)
	dwfl_ent->worst_unwound = unwound_source;
      dwfl_ent->last_unwound = unwound_source;
      if (verbose > 3) /* TODO show_frames */
	fprintf(stderr, "* frame %ld: pc_adjusted=%lx sp=%lx+(%lx) [%s]\n",
		this->last_us.addrs.size(), pc_adjusted, this->last_us.base, sp - this->last_us.base,
		dwfl_unwound_source_str(unwound_source));
    }
  else
    {
      if (verbose > 3) /* TODO show_frames */
	fprintf(stderr, N_("* frame %ld: pc_adjusted=%lx sp=%lx+(%lx) [dwfl_ent not found]\n"),
		this->last_us.addrs.size(), pc_adjusted, this->last_us.base, sp - this->last_us.base);
    }
  if (verbose > 4) /* TODO show_buildid */
    {
      Dwfl_Module *m = dwfl_addrmodule(this->last_us.dwfl, pc);
      const unsigned char *desc;
      GElf_Addr vaddr;
      int build_id_len = dwfl_module_build_id (m, &desc, &vaddr);
      fprintf(stderr, "* pid %d build_id ", this->last_us.pid);
      for (int i = 0; i < build_id_len; ++i)
	fprintf(stderr, "%02" PRIx8, (uint8_t) desc[i]);
      fprintf(stderr, "\n");
    }

#if 0
  /* TODO */
  if (this->last_us.addrs.size() > maxframes)
    {
      /* XXX very rarely, the unwinder can loop infinitely; worth investigating? */
      if (verbose > 1) /* TODO show_frames */
	fprintf(stderr, N_("unwind_frame_cb: sample exceeded maxframes %d\n"),
		maxframes);
      return DWARF_CB_ABORT;
    }
#endif

  this->last_us.sp = sp;
  this->last_us.addrs.push_back(pc);
  return DWARF_CB_OK;
}

int pcu_unwind_frame_cb(Dwfl_Frame *state, void *arg)
{
  PerfConsumerUnwinder *pcu = (PerfConsumerUnwinder *)arg;
  return pcu->unwind_frame_cb(state);
}

////////////////////////////////////////////////////////////////////////
// real perf consumer: event handler callbacks

void PerfConsumerUnwinder::process_comm(const perf_event_header *sample,
					uint32_t pid, uint32_t tid, bool exec, const char *comm)
{
  // have dwflst ditch data for process and start anew, if EXEC
}
void PerfConsumerUnwinder::process_exit(const perf_event_header *sample,
					uint32_t pid, uint32_t ppid,
					uint32_t tid, uint32_t ptid)
{
  // have dwflst ditch data for process
}
void PerfConsumerUnwinder::process_fork(const perf_event_header *sample,
					uint32_t pid, uint32_t ppid,
					uint32_t tid, uint32_t ptid)
{
  // have dwflst begin tracking a new process
}
void PerfConsumerUnwinder::process_sample(const perf_event_header *sample,
					  uint64_t ip,
					  uint32_t pid, uint32_t tid,
					  uint64_t time,
					  uint64_t abi,
					  uint32_t nregs, const uint64_t *regs,
					  uint64_t data_size, const uint8_t *data)
{
  const char *comm = this->pid_find_comm(pid);

  if (verbose > 3) /* TODO show_frames */
    cout << endl; /* extra newline for padding */

  Elf *elf = NULL;
  bool cached = false;
  Dwfl *dwfl = this->find_dwfl (pid, regs, nregs, &elf, &cached);
  DwflEntry *dwfl_ent = NULL;
  if (dwfl == NULL)
    {
      if (verbose > 2) /* TODO show_summary */
	{
	  if (dwfl_ent == NULL)
	    dwfl_ent = this->dwfltab_find(pid);
	  dwfl_ent->total_samples++;
	  dwfl_ent->lost_samples++;
	}
      if (verbose > 1) /* TODO show_failures */
	{
	  fprintf(stderr, "find_dwfl pid %lld (%s) (failed)\n",
		  (long long)pid, comm);
	}
      return;
    }

  if (verbose > 3) /* TODO show_frames */
    {
      bool is_abi32 = (abi == PERF_SAMPLE_REGS_ABI_32);
      fprintf(stderr, "find_dwfl pid %lld%s (%s): hdr_size=%d size=%ld%s pc=%lx sp=%lx+(%lx)\n",
	      (long long)pid, cached ? " (cached)" : "", comm,
	      sample->size, data_size, is_abi32 ? " (32-bit)" : "",
	      ip, this->last_us.base, (long)0);
    }

  this->last_us.addrs.clear();
  this->last_us.elfclass = (abi == PERF_SAMPLE_REGS_ABI_32 ? ELFCLASS32 : ELFCLASS64);
  this->last_us.dwfl = dwfl;
  this->last_us.pid = pid;
  int rc = dwflst_perf_sample_getframes (dwfl, elf, pid, tid,
					 data, data_size,
					 regs, nregs,
					 this->reader->regs_mask(), abi,
					 pcu_unwind_frame_cb, this);
  if (rc < 0)
    {
      if (verbose > 1) /* TODO show_failures */
	{
	  fprintf(stderr, "dwflst_perf_sample_getframes pid %lld: %s\n",
		  (long long)pid, dwfl_errmsg(-1));
	}
    }
  if (verbose > 2) /* TODO show_summary */
    {
      /* For final diagnostics. */
      if (dwfl_ent == NULL)
	dwfl_ent = this->dwfltab_find(pid);
      if (this->last_us.addrs.size() > (unsigned long)dwfl_ent->max_frames)
	dwfl_ent->max_frames = this->last_us.addrs.size();
      dwfl_ent->total_samples++;
      if (this->last_us.addrs.size() <= 2)
	dwfl_ent->lost_samples++;
    }

  this->consumer->process (&this->last_us);
  return;
}
void PerfConsumerUnwinder::process_mmap2(const perf_event_header *sample,
					 uint32_t pid, uint32_t tid,
					 uint64_t addr, uint64_t len, uint64_t pgoff,
					 uint8_t build_id_size, const uint8_t *build_id,
					 const char *filename)
{
  // TODO(REVIEW.5): have dwflst for pid report new module
}


////////////////////////////////////////////////////////////////////////
// unwind data consumers // gprof

UnwindStatsConsumer::~UnwindStatsConsumer()
{
  cout << "pid / unwind-hit counts:" << endl;
  for (const auto& kv : this->event_unwind_counts)
    cout << "pid " << setbase(10) << kv.first << setbase(16) << " count " << kv.second << endl;

  cout << "buildid / unwind-hit counts:" << endl;
  for (const auto& kv : this->event_buildid_hits)
    cout << "buildid " << kv.first << " count " << kv.second << endl;
}

void UnwindStatsConsumer::process(const UnwindSample* sample)
{
  this->event_unwind_counts[sample->pid] ++;

  for (auto& p : sample->buildid_reladdrs)
    this->event_buildid_hits[p.first] ++;
}

