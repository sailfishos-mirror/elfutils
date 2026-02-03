/* Collect stack-trace profiles of running program(s).
   Copyright (C) 2025-2026 Red Hat, Inc.
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
#include <map>
#include <unordered_map>
#include <vector>
#include <bitset>
#include <stdexcept>
#include <cstring>
#include <csignal>
#include <cassert>
#include <chrono>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cinttypes>
#include <format>
#include <sys/utsname.h>

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

#include <json-c/json.h>

#include <gelf.h>
#include <dwarf.h>
#include <libdwfl.h>
#include <libdw.h>
#include "../libebl/libebl.h"
#include "../libdwfl_stacktrace/libdwfl_stacktrace.h"

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
  cerr << "nop_find_debuginfo: modname=" << modname << " file_name=" << file_name << " debuglink_file=" << debuglink_file << endl;
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

// Unwind statistics for a Dwfl and associated process.
struct UnwindDwflStats {
  Dwfl *dwfl;
  char *comm;  // XXX need dtor to free?  or std::string?
  int max_frames; /* for diagnostic purposes */
  int total_samples; /* for diagnostic purposes */
  int lost_samples; /* for diagnostic purposes */
  Dwfl_Unwound_Source last_unwound; /* track CFI source, for diagnostic purposes */
  Dwfl_Unwound_Source worst_unwound; /* track CFI source, for diagnostic purposes */
};

struct hash_arc {
  template <class T1, class T2>
  size_t operator()(const pair<T1, T2> &p) const {
    return hash<T1>()(p.first) ^ hash<T2>()(p.second);
  }
};

// Unwind statistics for a single module identified by build-id.
struct UnwindModuleStats {
  map<uint64_t, uint32_t> histogram; /* sorted by pc */
  unordered_map<pair<uint64_t, uint64_t>, uint32_t, hash_arc> callgraph;

  void record_pc(Dwarf_Addr pc) {
    if (histogram.count(pc) == 0)
      histogram[pc] = 0;
    histogram[pc]++;
  }
  void record_callgraph_arc(Dwarf_Addr from, Dwarf_Addr to) {
    std::pair<uint64_t, uint64_t> arc(from, to);
    if (callgraph.count(arc) == 0)
      callgraph[arc] = 0;
    callgraph[arc]++;
  }
};

struct UnwindStatsTable
{
  unordered_map<pid_t, UnwindDwflStats> dwfl_tab;
  unordered_map<string, UnwindModuleStats> buildid_tab;
  typedef map<string, UnwindModuleStats> buildid_map_t;
  
  UnwindStatsTable () {}
  ~UnwindStatsTable () {}

  UnwindDwflStats *pid_find(pid_t pid);
  UnwindDwflStats *pid_find_or_create(pid_t pid);
  const char *pid_find_comm(pid_t pid);
  Dwfl *pid_find_dwfl(pid_t pid);
  void pid_store_dwfl(pid_t pid, Dwfl *dwfl);

  UnwindModuleStats *buildid_find(string buildid);
  UnwindModuleStats *buildid_find_or_create(string buildid, Dwfl_Module *mod);
};

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
protected:
  PerfReader *reader; /* access sample_regs_user etc. metadata */

public:
  PerfConsumer() {}
  PerfConsumer(PerfReader *reader) : reader(reader) {}
  void set_reader(PerfReader *reader) { this->reader = reader; }

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
  Dwfl *dwfl;
  uint32_t pid, tid;
  vector<pair<string,Dwarf_Addr>> buildid_reladdrs; /* TODO: Populate. */
  vector<Dwarf_Addr> addrs;
  int elfclass;

  Dwarf_Addr base; /* for diagnostic purposes */
  Dwarf_Addr sp; /* for diagnostic purposes */
};


class UnwindSampleConsumer;


// A PerfConsumerUnwinder accepts decoded perf events, and produces
// UnwindSample objects from them for relaying to an
// UnwindSampleConsumer.
class PerfConsumerUnwinder: public PerfConsumer
{
  UnwindSampleConsumer *consumer;
  UnwindSample last_us;
  Dwflst_Process_Tracker *tracker;
  UnwindStatsTable *stats;

  int find_procfile(Dwfl *dwfl, pid_t *pid, Elf **elf, int *elf_fd);
  Dwfl *find_dwfl(pid_t pid, const uint64_t *regs, uint32_t nregs,
		  Elf **elf, bool *cached);

  int get_sp_reg(bool is_abi32);

public:
  PerfConsumerUnwinder(UnwindSampleConsumer* usc, UnwindStatsTable *ust)
    : consumer(usc), stats(ust) {
    this->tracker = dwflst_tracker_begin (&dwfl_cfi_callbacks);
  }
  PerfConsumerUnwinder(UnwindSampleConsumer* usc, UnwindStatsTable *ust, PerfReader *reader)
    : consumer(usc), stats(ust) {
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
  UnwindStatsTable *stats;

  /* TODO subsumed by stats? */
  unordered_map<int,unsigned> event_unwind_counts; /* TODO by pid? */
  unordered_map<string,unsigned> event_buildid_hits; /* by buildid */

public:
  UnwindStatsConsumer(UnwindStatsTable *usc) : stats(usc) {}
  ~UnwindStatsConsumer();
  void process(const UnwindSample* sample);
};


extern "C" {
struct gmon_hist_hdr;
}

// An GprofUnwindSampleConsumer instance consumes UnwindSamples and tabulates
// them by buildid, for eventual writing out into gmon.out format files.
class GprofUnwindSampleConsumer: public UnwindSampleConsumer
{
  UnwindStatsTable *stats;
  unordered_map<string, string> buildid_to_mainfile;
  unordered_map<string, string> buildid_to_debugfile;

public:
  GprofUnwindSampleConsumer(UnwindStatsTable *usc) : stats(usc) {}
  ~GprofUnwindSampleConsumer(); // write out all the gmon.$BUILDID.out files
  void record_gmon_out(const string& buildid, UnwindModuleStats& m); // write out one gmon.$BUILDID.out file
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
  { "output", 'o', "DIR", 0, N_("Output directory for gmon files."), 0 },
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
static unsigned verbose;
static bool gmon;
static string output_dir = ".";
static int pid;
static unsigned long maxframes = 256;
static string libpfm_event;
static perf_event_attr attr;

// Verbosity beyond level 1:
static bool show_summary = false;
static bool show_events = false;
static bool show_frames = false;
static bool show_tmi = false; /* -> perf, cfi details */

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

    case 'o':
      output_dir = arg;
      break;

    case 'p':
      pid = atoi(arg);
      break;

    case 'd':
      maxframes = atoi(arg);
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
  bool has_cmd = false;
  (void) argp_parse (&argp, argc, argv, 0, &remaining, NULL);

  if (verbose > 1) show_summary = true;
  if (verbose > 2) show_events = true;
  if (verbose > 3) show_frames = true;
  if (verbose > 4) show_tmi = true;

  if (pid > 0 && remaining < argc) // got a pid AND a cmd? reject
    {
      cerr << "ERROR: Must not specify both -p PID and CMD" << endl;
      exit(1);
    }

  bool systemwide = (pid == 0) || (remaining == argc);
  (void) systemwide;

  try
    {
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


      if (show_summary)
	{
	  clog << format("perf_event_attr configuration type={:x} config={:x} {}{} \n",
			      attr.type, attr.config,
			      (attr.freq ? "sample_freq=" : "sample_period="),
			      (attr.freq ? attr.sample_freq : attr.sample_period));
	}

      if (remaining < argc) // got a CMD... suffix?  ok start it
        {
          has_cmd = true;
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
      UnwindStatsTable *tab = nullptr;
      UnwindSampleConsumer *usc = nullptr;
      PerfConsumerUnwinder *pcu = nullptr;
      StatsPerfConsumer *spc = nullptr;

      if (gmon)
	{
	  tab = new UnwindStatsTable();
	  usc = new GprofUnwindSampleConsumer(tab); /* TODO also reduce maxdepth */
	  pcu = new PerfConsumerUnwinder(usc, tab);
	  pr = new PerfReader(&attr, pcu, pid);
	}
      else
	{
	  tab = new UnwindStatsTable();
	  usc = new UnwindStatsConsumer(tab);
	  pcu = new PerfConsumerUnwinder (usc, tab);
	  pr = new PerfReader(&attr, pcu, pid);
#if 0
	  spc = new StatsPerfConsumer();
	  pr = new PerfReader(&attr, spc, pid);
#endif
	}

      signal(SIGINT, sigint_handler);
      signal(SIGTERM, sigint_handler);

      if (pid > 0 && has_cmd) // need to release child CMD process?
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
      delete tab;

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
  this->consumer->set_reader(this);
  this->enabled = false;

  struct utsname u;
  uname(&u);
  int em = EM_NONE;
  if (strcmp(u.machine, "x86_64") == 0) em = EM_X86_64;
  else if (strcmp(u.machine, "i686") == 0 || strcmp(u.machine, "i386") == 0) em = EM_386;
  else {
    cerr << "Unsupported architecture: " << u.machine << endl;
    exit(1);
  }
  this->default_ebl = ebl_openbackend_machine(em);
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


  if (show_tmi)
    { // hexdump attr
      clog << "perf_event_attr hexdump: ";
      auto bytes = (unsigned char*) attr;
      for (size_t x = 0; x<sizeof(*attr); x++)
	clog << ((x % 8) ? "" : " ")
	     << ((x % 32) ? "" : "\n")
	     << format("{:02x}", (unsigned)bytes[x]);
      clog << endl;
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
  ebl_closebackend (this->default_ebl);
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
                if (show_tmi)
                  clog << format("perf head={:p} tail={:p} ehdr={:p} size={:d}{:x}\n",
				      (void*) data_head, (void*) data_tail, (void*) ehdr, ehdr_size, 0);

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
  if (show_events)
    {
      clog << "process_comm: pid=" << pid << " tid=" << tid << " exec=" << exec << " comm=" << comm << endl;
    }
}

void StatsPerfConsumer::process_exit(const perf_event_header *sample,
				     uint32_t pid, uint32_t ppid,
				     uint32_t tid, uint32_t ptid)
{
  if (show_events)
    {
      clog << "process_exit: pid=" << pid << " ppid=" << ppid << " tid=" << tid << " ptid=" << ptid << endl;
    }
}

void StatsPerfConsumer::process_fork(const perf_event_header *sample,
				     uint32_t pid, uint32_t ppid,
				     uint32_t tid, uint32_t ptid)
{
  if (show_events)
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
  if (show_events)
    {
      clog << format("process_sample: pid={:d} tid={:d} ip={:x} time={:d} abi={:d} nregs={:d} data_size={:d}\n",
			  pid, tid, ip, time, abi, nregs, data_size);
    }
}

void StatsPerfConsumer::process_mmap2(const perf_event_header *sample,
				      uint32_t pid, uint32_t tid,
				      uint64_t addr, uint64_t len, uint64_t pgoff,
				      uint8_t build_id_size, const uint8_t *build_id,
				      const char *filename)
{
  if (show_events)
    {
      clog << format("process_mmap2: pid={:d} tid={:d} addr={:x} len={:x} pgoff={:x} build_id_size={:d} filename={:s}\n",
			  pid, tid, addr, len, pgoff, (unsigned)build_id_size, filename);
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

//////////////////////////////////////////////////////////////////////
// unwind stats table for PerfConsumerUnwinder + downstream consumers

UnwindDwflStats *UnwindStatsTable::pid_find (pid_t pid)
{
  if (this->dwfl_tab.count(pid) == 0)
    this->dwfl_tab.emplace(pid, UnwindDwflStats());
  return &this->dwfl_tab[pid];
}

UnwindDwflStats *UnwindStatsTable::pid_find_or_create (pid_t pid)
{
  if (this->dwfl_tab.count(pid) == 0)
    this->dwfl_tab.emplace(pid, UnwindDwflStats());
  return &this->dwfl_tab[pid];
}

static const char *unknown_comm = "<unknown>";

const char *UnwindStatsTable::pid_find_comm (pid_t pid)
{
  UnwindDwflStats *entry = this->pid_find_or_create(pid);
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

Dwfl *UnwindStatsTable::pid_find_dwfl (pid_t pid)
{
  if (this->dwfl_tab.count(pid) == 0)
    return NULL;
  return this->dwfl_tab[pid].dwfl;
}

void UnwindStatsTable::pid_store_dwfl (pid_t pid, Dwfl *dwfl)
{
  UnwindDwflStats *entry = this->pid_find_or_create(pid);
  if (entry == NULL)
    return;
  entry->dwfl = dwfl;
  if (show_summary)
    this->pid_find_comm(pid);
  return;
}

UnwindModuleStats *UnwindStatsTable::buildid_find (string buildid)
{
  if (this->buildid_tab.count(buildid) == 0)
    return NULL;
  return &this->buildid_tab[buildid];
}

UnwindModuleStats *UnwindStatsTable::buildid_find_or_create (string buildid, Dwfl_Module *mod)
{
  if (this->buildid_tab.count(buildid) == 0)
    {
      this->buildid_tab.emplace(buildid, UnwindModuleStats());
      /* TODO: Guess text range for mod? */
      (void)mod;
    }
  return &this->buildid_tab[buildid];
}

////////////////////////////////////////////////////////////////////////
// real perf consumer: unwind helpers

/* TODO: Could be relocated to libdwfl/linux-pid-attach.c
   to remove some duplication of existing linux-pid-attach code. */
int PerfConsumerUnwinder::find_procfile (Dwfl *dwfl, pid_t *pid, Elf **elf, int *elf_fd)
{
  char buffer[36];
  FILE *procfile;
  int err = 0; /* The errno to return. XXX libdwfl would also set this for dwfl->attacherr.  */

  /* Make sure to report the actual PID (thread group leader) to
     dwfl_attach_state.  */
  snprintf (buffer, sizeof (buffer), "/proc/%ld/status", (long) *pid);
  procfile = fopen (buffer, "r");
  if (procfile == NULL)
    {
      err = errno;
    fail:
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
  fclose(procfile);

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
	  if (verbose)
	    cerr << N_("find_procfile pid ") << (long long)*pid << ": elf not found" << endl;
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
      if (verbose)
	cerr << "dwfl_linux_proc_report pid " << (long long) pid << ": " << dwfl_errmsg (-1) << endl;
      return NULL;
    }
  err = dwfl_report_end (dwfl, NULL, NULL);
  if (err != 0)
    {
      if (verbose)
	cerr << "dwfl_report_end pid " << (long long) pid << ": " << dwfl_errmsg (-1) << endl;
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
      if (verbose)
	cerr << N_("find_dwfl: nregs=") << nregs << ", expected " << ebl_frame_nregs(this->reader->ebl()) << endl;
      return NULL;
    }

  Elf *elf = NULL;
  Dwfl *dwfl = dwflst_tracker_find_pid (this->tracker, pid, pcu_init_dwfl_cb, this);
  int elf_fd = -1;
  int err;
  if (dwfl != NULL && dwfl_pid(dwfl) != -1 /* dwfl is attached */)
    {
      *cached = true;
      goto reuse;
    }
  err = this->find_procfile (dwfl, &pid, &elf, &elf_fd);
  if (err < 0)
    {
      if (verbose)
	cerr << "find_procfile pid " << (long long) pid << ": " << dwfl_errmsg (-1) << endl;
      return NULL;
    }

 reuse:
  /* TODO: Generalize to other architectures than x86. */
  this->last_us.sp = regs[this->get_sp_reg(this->last_us.elfclass == ELFCLASS32)];
  this->last_us.base = this->last_us.sp;

  if (!*cached)
    this->stats->pid_store_dwfl (pid, dwfl);
  *out_elf = elf;
  return dwfl;
}

int PerfConsumerUnwinder::get_sp_reg(bool is_abi32)
{
  int machine = ebl_get_elfmachine(this->reader->ebl());
  if (machine == EM_X86_64 || machine == EM_386) return is_abi32 ? 4 : 7;
  else { assert(0); return 7; }
}

int PerfConsumerUnwinder::unwind_frame_cb(Dwfl_Frame *state)
{
  Dwarf_Addr pc;
  bool isactivation;
  if (! dwfl_frame_pc (state, &pc, &isactivation))
    {
      if (verbose)
	cerr << "dwfl_frame_pc: " << dwfl_errmsg(-1) << endl;
      return DWARF_CB_ABORT;
    }

  Dwarf_Addr pc_adjusted = pc - (isactivation ? 0 : 1);
  Dwarf_Addr sp;

  int is_abi32 = (this->last_us.elfclass == ELFCLASS32);
  int user_regs_sp = this->get_sp_reg(is_abi32);
  int rc = dwfl_frame_reg (state, user_regs_sp, &sp);
  if (rc < 0)
    {
      if (verbose)
	cerr << "dwfl_frame_reg: " << dwfl_errmsg(-1) << endl;
      return DWARF_CB_ABORT;
    }

  UnwindDwflStats *dwfl_ent = this->stats->pid_find_or_create(this->last_us.pid);
  if (dwfl_ent != NULL)
    {
      Dwfl_Unwound_Source unwound_source = dwfl_frame_unwound_source(state);
      if (unwound_source > dwfl_ent->worst_unwound)
	dwfl_ent->worst_unwound = unwound_source;
      dwfl_ent->last_unwound = unwound_source;
      if (show_frames)
	cerr << format("* frame {:d}: pc_adjusted={:x} sp={:x}+{:x} [{}]\n",
			    this->last_us.addrs.size(), pc_adjusted, this->last_us.base, (sp - this->last_us.base), dwfl_unwound_source_str(unwound_source));
    }
  else
    {
      if (show_frames)
	cerr << format(N_("* frame {:d}: pc_adjusted={:x} sp={:x}+{:x} [dwfl_ent not found]\n"),
			    this->last_us.addrs.size(), pc_adjusted, this->last_us.base, (sp - this->last_us.base));
    }
  if (show_tmi)
    {
      Dwfl_Module *m = dwfl_addrmodule(this->last_us.dwfl, pc);
      /* TODO: Handle (m == NULL)? */
      const unsigned char *desc;
      GElf_Addr vaddr;
      int build_id_len = dwfl_module_build_id (m, &desc, &vaddr);
      cerr << format("* pid {:d} build_id=", this->last_us.pid);
      for (int i = 0; i < build_id_len; ++i)
        cerr << format("{:02x}", static_cast<int>(desc[i]));

      /* TODO also extract mainfile= debugfile= */
      const char *mainfile;
      const char *debugfile;
      const char *modname = dwfl_module_info (m, NULL, NULL, NULL, NULL,
					      NULL, &mainfile, &debugfile);
      cerr << format(" module={} mainfile={} debugfile={}\n",
			  modname, mainfile, debugfile);
      /* TODO: Also store this data for the final buildid summary? */
#ifdef DEBUG_MODULES
      Dwarf_Addr bias;
      Dwarf_CFI *cfi_eh = dwfl_module_eh_cfi (m, &bias);
      if (cfi_eh == NULL)
	cerr << format("* pc={:x} -> NO EH_CFI\n", pc);
#endif
    }

  if (this->last_us.addrs.size() > maxframes)
    {
      /* XXX very rarely, the unwinder can loop infinitely; worth investigating? */
      if (verbose)
	cerr << format(N_("unwind_frame_cb: sample exceeded maxframes {:d}\n"), maxframes);
      return DWARF_CB_ABORT;
    }

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
  const char *comm = NULL;
  if (show_summary)
    comm = this->stats->pid_find_comm(pid);

  if (show_frames)
    cout << endl; /* extra newline for padding */

  Elf *elf = NULL; // XXX: when is this released?
  bool cached = false;
  Dwfl *dwfl = this->find_dwfl (pid, regs, nregs, &elf, &cached);
  UnwindDwflStats *dwfl_ent = NULL;
  if (dwfl == NULL)
    {
      if (show_summary)
	{
	  if (dwfl_ent == NULL)
	    dwfl_ent = this->stats->pid_find_or_create(pid);
	  dwfl_ent->total_samples++;
	  dwfl_ent->lost_samples++;
	}
      if (verbose && show_summary)
	{
	  cerr << "find_dwfl pid " << (long long)pid << " (" << comm << ") (failed)" << endl;
	}
      else
	{
	  cerr << "find_dwfl pid " << (long long)pid << " (failed)" << endl;
	}
      return;
    }

  if (show_events)
    {
      bool is_abi32 = (abi == PERF_SAMPLE_REGS_ABI_32);
      cerr << format("find_dwfl pid {:d} {} ({}): hdr_size={:d} size={:d} {} pc={:x} sp={:x}+{:d}\n",
			  (long long)pid, (cached ? "(cached)" : ""), comm, sample->size, data_size, (is_abi32 ? "(32-bit)" : ""), ip, this->last_us.base, 0);
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
      if (verbose)
	{
	  cerr << "dwflst_perf_sample_getframes pid " << (long long)pid << ": " << dwfl_errmsg(-1) << endl;
	}
    }
  if (show_summary)
    {
      /* For final diagnostics. */
      if (dwfl_ent == NULL)
	dwfl_ent = this->stats->pid_find_or_create(pid);
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
  Dwfl *dwfl = this->stats->pid_find_dwfl(pid);
  if (dwfl != NULL)
    {
      dwfl_report_begin_add(dwfl);
      dwfl_report_module(dwfl, filename, /*start*/ addr, /*end*/ addr + len);
      dwfl_report_end(dwfl, NULL, NULL);
    }
}


////////////////////////////////////////////////////////////////////////
// unwind data consumers // basic statistics

UnwindStatsConsumer::~UnwindStatsConsumer()
{
  /* TODO: Perhaps move this to a this->stats->show_summary() method, also invokable from GmonUnwindSampleConsumer? */
  if (show_summary)
    {
#define PERCENT(x,tot) ((x+tot == 0)?0.0:((double)x)/((double)tot)*100.0)
      int total_samples = 0;
      int total_lost_samples = 0;
      cout << endl << "=== pid / sample counts ===" << endl;
      for (auto& p : this->stats->dwfl_tab)
	{
	  pid_t pid = p.first;
	  UnwindDwflStats& d = p.second;
	  clog << format(N_("{} {} -- max {} frames, received {} samples, lost {} samples ({:.1f}%) (last {}, worst {})\n"),
		   pid, d.comm, d.max_frames,
		   d.total_samples, d.lost_samples,
		   PERCENT(d.lost_samples, d.total_samples),
		   dwfl_unwound_source_str(d.last_unwound),
		   dwfl_unwound_source_str(d.worst_unwound));
	  total_samples += d.total_samples;
	  total_lost_samples += d.lost_samples;
	}
      clog << "===\n";
      clog << format(N_("TOTAL -- received {} samples, lost {} samples, loaded {} processes\n"),
	      total_samples, total_lost_samples,
	      this->stats->dwfl_tab.size() /* TODO: If implementing eviction, need to maintain a separate count of evicted pids. */);
      cout << endl;

      /* TODO: Implement in terms of the build-id table. */
      cout << "=== buildid / unwind-hit counts ===" << endl;
      for (const auto& kv : this->event_buildid_hits)
	cout << "buildid " << kv.first << " -- received " << kv.second << " samples" << endl;
    }
}

void UnwindStatsConsumer::process(const UnwindSample* sample)
{
  this->event_unwind_counts[sample->pid] ++;

  for (auto& p : sample->buildid_reladdrs)
    this->event_buildid_hits[p.first] ++;
}

////////////////////////////////////////////////////////////////////////
// unwind data consumers // gprof

/* gmon.out file format bits */
extern "C" {

#define GMON_MAGIC "gmon"
#define GMON_VERSION 1

struct gmon_hdr {
  char cookie[4];
  char version[4];
  char spare[3 * 4];
};

enum gmon_entry_tag {
  GMON_TAG_TIME_HIST = 0,
  GMON_TAG_CG_ARC = 1,
  GMON_TAG_BB_COUNT = 2,
};

};

void GprofUnwindSampleConsumer::record_gmon_out(const string& buildid, UnwindModuleStats& m)
{
  string filename = output_dir + "/" + "gmon." + buildid + ".out";
  string exe_symlink_path = output_dir + "/" + "gmon." + buildid + ".exe";
  string json_path = output_dir + "/" + "gmon." + buildid + ".json";

  string target_path = buildid_to_mainfile[buildid];
  if (symlink(target_path.c_str(), exe_symlink_path.c_str()) == -1) {
    // Handle error, e.g., print errno or throw exception
    cerr << "symlink failed: " << strerror(errno) << endl;
    //return; /* TODO: We may want to re-create the symlink on repeated runs. */
  }

  // TODO(REVIEW.4): plop buildid_to_{mainfile,debugfile} bits into per-gmon-out json files
  json_object *metadata = json_object_new_object();
  if (!metadata) {
  json_fail:
    cerr << "json allocation failed: " << strerror(errno) << endl;
    return;
  }
  json_object *buildid_js = json_object_new_string(buildid.c_str());
  if (NULL == buildid_js) goto json_fail;
  json_object_object_add(metadata, "buildid", buildid_js);
  const char *mainfile = NULL;
  if (buildid_to_mainfile.count(buildid) != 0)
    mainfile = buildid_to_mainfile[buildid].c_str();
  if (mainfile != NULL)
    {
      json_object *mainfile_js = json_object_new_string(mainfile);
      if (NULL == mainfile_js) goto json_fail;
      json_object_object_add(metadata, "mainfile", mainfile_js);
    }
  const char *debugfile = NULL;
  if (buildid_to_debugfile.count(buildid) != 0)
    debugfile = buildid_to_debugfile[buildid].c_str();
  if (debugfile != NULL)
    {
      json_object *debugfile_js = json_object_new_string(debugfile);
      if (NULL == debugfile_js) goto json_fail;
      json_object_object_add(metadata, "debugfile", debugfile_js);
    }
  const char *metadata_str = json_object_to_json_string(metadata);
  if (!metadata_str) goto json_fail;
  ofstream of_js (json_path);
  of_js << metadata_str;
  of_js.close();
  json_object_put (metadata);
    
  ofstream of (filename, ios::binary);
  if (!of)
    {
      cerr << format(N_("buildid {} -- could not open '{}' for writing\n"), buildid, filename);
    }

  /* Write gmon header.  It and other headers mostly hold
     native-endian and fixed (or native) bitwidth values.  In
     principle, we should get the bitness/endianness from the
     particular executable associated with the buildid.  But, being a
     live profiler, we don't really have to deal with CROSS
     architecture work, and for now can just hard-code the bitness to
     match this host program. XXX
   */
  int wordsize = (sizeof (void *) == 8) ? 8 : 4;
  struct gmon_hdr ghdr;
  memcpy (&ghdr.cookie[0], GMON_MAGIC, 4);
  uint32_t version = GMON_VERSION;
  memcpy (&ghdr.version[0], reinterpret_cast<const char *>(&version), 4);
  memset (&ghdr.spare[0], 0, sizeof(ghdr.spare));
  /* TODO: Also include libpfm event info -- in a separate file? */
  of.write(reinterpret_cast<const char *>(&ghdr), sizeof(ghdr));

  if (m.histogram.size() > 0)
    {
      // write one histogram from low_pc ... high_pc
      
      // XXX: the histogram bucket counts are 16-bits wide, so if we have
      // collected more than 2**16 hits, we need additional histogram(s)
      // to accumulate those excess counts

      uint64_t first_pc = m.histogram.begin()->first;
      uint64_t last_pc = m.histogram.rbegin()->first;
      uint64_t alignment = (last_pc - first_pc + 1) / UINT_MAX + 1; // compute an alignment that fits 2**32 buckets
      uint32_t num_buckets = (last_pc-first_pc)/alignment + 1;

      // write histogram record header
      unsigned char tag = GMON_TAG_TIME_HIST;
      of.write(reinterpret_cast<const char *>(&tag), sizeof(tag));
      if (wordsize == 4) {
        uint32_t addr = first_pc;
        of.write(reinterpret_cast<const char *>(&addr), sizeof(addr));
        addr = last_pc;
        of.write(reinterpret_cast<const char *>(&addr), sizeof(addr));
      } else {
        of.write(reinterpret_cast<const char *>(&first_pc), sizeof(first_pc));
        of.write(reinterpret_cast<const char *>(&last_pc), sizeof(last_pc));
      }
      of.write(reinterpret_cast<const char *>(&num_buckets), sizeof(num_buckets));
      uint32_t prof_rate = attr.sample_freq;
      of.write(reinterpret_cast<const char *>(&prof_rate), sizeof(prof_rate));
      // dimension string is 15 chars long (not null terminated)
      char dimension_string[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
      if (libpfm_event != "")
        strncpy(dimension_string, libpfm_event.c_str(), 15);
      else
        strcpy(dimension_string, "ticks");
      of.write(reinterpret_cast<const char *>(dimension_string), 15);
      // dimension character abbreviation: just take the first char of above
      of.write(reinterpret_cast<const char *>(dimension_string), 1);

      // write histogram buckets
      uint64_t bucket_addr = first_pc;
      for (uint32_t bucket = 0; bucket < num_buckets; bucket++)
        {
          uint16_t count = 0;
          for (auto it = m.histogram.lower_bound(bucket_addr);
               it != m.histogram.upper_bound(bucket_addr+alignment-1);
               it ++)
            count += it->second; // XXX: check for overflow here!
          bucket_addr += alignment;
          of.write(reinterpret_cast<const char *>(&count), sizeof(count));
        }
    } // had a histogram

  /* Write call graph arcs. */
  for (auto& p : m.callgraph)
    {
      unsigned char tag = GMON_TAG_CG_ARC;
      of.write(reinterpret_cast<const char *>(&tag), sizeof(tag));
      if (wordsize == 4) {
        uint32_t addr = p.first.first;
        of.write(reinterpret_cast<const char *>(&addr), sizeof(addr));
        addr = p.first.second;
        of.write(reinterpret_cast<const char *>(&addr), sizeof(addr));
      } else {
        uint64_t addr = p.first.first;
        of.write(reinterpret_cast<const char *>(&addr), sizeof(addr));
        addr = p.first.second;
        of.write(reinterpret_cast<const char *>(&addr), sizeof(addr));
      }
      /* p is (from,to) -> count */
      uint32_t count = p.second;
      of.write(reinterpret_cast<const char *>(&count), sizeof(count));
    }

  of.close();
}

GprofUnwindSampleConsumer::~GprofUnwindSampleConsumer()
{
  if (show_summary)
    cout << endl << "=== buildid / sample counts ===" << endl;
  
  UnwindStatsTable::buildid_map_t m (this->stats->buildid_tab.begin(), this->stats->buildid_tab.end());
  for (auto& p : m) // traverse in sorted order
    {
      const string& buildid = p.first;
      UnwindModuleStats& m = p.second;
      /* TODO(REVIEW.4): Write the buildid-->path mapping to a secondary
         (json?) metadata file.  That makes for a reasonable hint;
         debuginfod-find can be used as a mostly-functional fallback
         (for packaged rather than locally built executables) if the
         results are moved to another system. */
      const char *mainfile = NULL;
      if (buildid_to_mainfile.count(buildid) != 0)
	mainfile = buildid_to_mainfile[buildid].c_str();
      const char *debugfile = NULL;
      if (buildid_to_debugfile.count(buildid) != 0)
	debugfile = buildid_to_debugfile[buildid].c_str();
      if (show_summary)
	clog << format(N_("buildid {} ({} {}{}) -- received {} distinct pcs, {} callgraph arcs\n"), /* TODO also count samples / estimated histogram size? */
		 buildid.c_str(),
		 mainfile == NULL ? "<unknown>" : mainfile,
		 debugfile == NULL ? "" : " +debugfile ",
		 debugfile == NULL ? "" : debugfile,
		 m.histogram.size(),
		 m.callgraph.size());
      this->record_gmon_out(buildid, m);
    }
  if (show_summary)
    {
      clog << "===\n";
      clog << format(N_("TOTAL -- received {} buildids\n"), this->stats->buildid_tab.size());
    }
  cout << endl;
}

void GprofUnwindSampleConsumer::process(const UnwindSample *sample)
{
  if (sample->addrs.size() < 2)
    return; /* no callgraph arc */ // XXX: accumulate at least histogram hit even without callgraph

  Dwarf_Addr pc = sample->addrs[0];
  Dwarf_Addr pc2 = sample->addrs[1];

  Dwfl_Module *mod = dwfl_addrmodule(sample->dwfl, pc);
  if (mod == NULL)
    return;
#if 0
  Dwarf_Addr bias;
  Elf *elf = dwfl_module_getelf (mod, &bias);
  (void)elf;
#endif

  Dwfl_Module *mod2 = dwfl_addrmodule(sample->dwfl, pc2);
  if (mod2 == NULL)
    return;
  // If caller & callee are in different modules, this is a cross-shared-library
  // call, so we can't track it as a call-graph arc.  XXX: at least count them 

  // extract buildid for pc (hit callee)
  const unsigned char *desc = nullptr;
  GElf_Addr vaddr;
  int build_id_len = dwfl_module_build_id(mod, &desc, &vaddr);
  if (build_id_len <= 0)
    return; // XXX: report/tabulate hit outside known modules

  /* TODO(REVIEW.5): Is it better to use the unconverted build_id_desc as hash key? */
  string buildid;
  for (int i = 0; i < build_id_len; ++i) {
    buildid += format("{:02x}", static_cast<int>(desc[i]));
  }

  const char *mainfile;
  const char *debugfile;
  dwfl_module_info (mod, NULL, NULL, NULL, NULL,
		    NULL, &mainfile, &debugfile);
  if (mainfile && !buildid_to_mainfile.count(buildid))
    buildid_to_mainfile[buildid] = mainfile;
  if (debugfile && !buildid_to_debugfile.count(buildid))
    buildid_to_debugfile[buildid] = debugfile;
  /* TODO(REVIEW.6): Also monitor for collisions. */

  UnwindModuleStats *buildid_ent = this->stats->buildid_find_or_create(buildid, mod);

  int i = dwfl_module_relocate_address (mod, &pc);
  (void) i;
  #if 0
  // XXX: for now, ignore relocation-basis section name or whatever
  const char *name;
  if (i >= 0)
    name = dwfl_module_relocation_info (mod, i, NULL);
  #endif
  buildid_ent->record_pc(pc);

  if (mod == mod2) // intra-module call
    {
      int j = dwfl_module_relocate_address (mod, &pc2); // map pc2 also
      (void) j;
      buildid_ent->record_callgraph_arc(pc2, pc);
    }
}
