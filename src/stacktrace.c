/* Process a stream of stack samples into stack traces.
   Copyright (C) 2023-2025 Red Hat, Inc.
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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   This file incorporates work covered by the following copyright and
   permission notice:

   Copyright 2016-2019 Christian Hergert <chergert@redhat.com>

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   Subject to the terms and conditions of this license, each copyright holder
   and contributor hereby grants to those receiving rights under this license
   a perpetual, worldwide, non-exclusive, no-charge, royalty-free,
   irrevocable (except for failure to satisfy the conditions of this license)
   patent license to make, have made, use, offer to sell, sell, import, and
   otherwise transfer this software, where such license applies only to those
   patent claims, already acquired or hereafter acquired, licensable by such
   copyright holder or contributor that are necessarily infringed by:

   (a) their Contribution(s) (the licensed copyrights of copyright holders
       and non-copyrightable additions of contributors, in source or binary
       form) alone; or

   (b) combination of their Contribution(s) with the work of authorship to
       which such Contribution(s) was added by such copyright holder or
       contributor, if, at the time the Contribution is added, such addition
       causes such combination to be necessarily infringed. The patent license
       shall not apply to any other combinations which include the
       Contribution.

   Except as expressly stated above, no rights or licenses from any copyright
   holder or contributor is granted under this license, whether expressly, by
   implication, estoppel or otherwise.

   DISCLAIMER

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include <config.h>
#include <assert.h>
#include <argp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <locale.h>

#include <system.h>

/***********************************
 * Includes: perf_events interface *
 ***********************************/

#include <linux/perf_event.h>

/* TODO: Need to generalize the code beyond x86 architectures. */
#include <asm/perf_regs.h>
#ifndef _ASM_X86_PERF_REGS_H
#error "eu-stacktrace is currently limited to x86 architectures"
#endif

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>

/*************************************
 * Includes: libdwfl data structures *
 *************************************/

#include ELFUTILS_HEADER(ebl)
/* #include ELFUTILS_HEADER(dwfl) */
#include "../libdwfl/libdwflP.h"
/* XXX: Private header needed for find_procfile. */
#include ELFUTILS_HEADER(dwfl_stacktrace)

/*************************************
 * Includes: sysprof data structures *
 *************************************/

#if HAVE_SYSPROF_6_HEADERS
#include <sysprof-6/sysprof-capture-types.h>
#define HAVE_SYSPROF_HEADERS 1
#elif HAVE_SYSPROF_4_HEADERS
#include <sysprof-4/sysprof-capture-types.h>
#define HAVE_SYSPROF_HEADERS 1
#else
#define HAVE_SYSPROF_HEADERS 0
#endif

/* tmp override to test perf_events */
#undef HAVE_SYSPROF_HEADERS
#define HAVE_SYSPROF_HEADERS 0

#if HAVE_SYSPROF_HEADERS

/* XXX: To be added to new versions of sysprof.  If a
   sysprof-capture-types.h with new capture frame is being used, this
   #if should guard against duplicate declarations. */
#if SYSPROF_CAPTURE_FRAME_LAST < 19

#undef SYSPROF_CAPTURE_FRAME_LAST
#define SYSPROF_CAPTURE_FRAME_STACK_USER 18
#define SYSPROF_CAPTURE_FRAME_LAST 19

SYSPROF_ALIGNED_BEGIN(1)
typedef struct
{
  SysprofCaptureFrame   frame;
  uint64_t              size;
  int32_t               tid;
  uint32_t              padding;
  uint8_t               data[0];
} SysprofCaptureStackUser
SYSPROF_ALIGNED_END(1);

/* Does not appear standalone; instead, appended to the end of a SysprofCaptureStackUser frame. */
SYSPROF_ALIGNED_BEGIN(1)
typedef struct
{
  uint32_t              n_regs;
  uint32_t              abi;
  uint64_t              regs[0];
} SysprofCaptureUserRegs
SYSPROF_ALIGNED_END(1);

#endif /* SYSPROF_CAPTURE_FRAME_STACK_USER */

#endif /* HAVE_SYSPROF_HEADERS */

/**************************
 * Global data structures *
 **************************/

/* TODO: Reduce repeated error messages in show_failures. */

static int maxframes = 256;

static char *input_path = NULL;
static char *output_path = NULL;

static int signal_count = 0;

#define MODE_OPTS "basic/passthru/none"
#define MODE_NONE 0x0
#define MODE_PASSTHRU 0x1
#define MODE_BASIC 0x2
static int processing_mode = MODE_BASIC;

#define SOURCE_OPTS "perf_events/sysprof"
#define SOURCE_PERF_EVENTS 0x1
#define SOURCE_SYSPROF 0x2
static int input_format = SOURCE_PERF_EVENTS;

#define DEST_OPTS "gmon_out/sysprof/none"
#define DEST_NONE 0x0
#define DEST_GMON_OUT 0x1
#define DEST_SYSPROF 0x2
static int output_format = DEST_GMON_OUT;

/* XXX Used to decide regs_mask for dwflst_perf_sample_getframes. */
Ebl *default_ebl = NULL;

/* non-printable argp options.  */
#define OPT_DEBUG	0x100

/* Diagnostic options. */
static bool show_buildid = false;
static bool show_frames = false;
static bool show_samples = false;
static bool show_failures = false;
static bool show_summary = true;

/* Environment vars to drive diagnostic options: */
#define ELFUTILS_STACKTRACE_VERBOSE_ENV_VAR "ELFUTILS_STACKTRACE_VERBOSE"
/* Valid values that turn on diagnostics: 'true', 'verbose', 'debug', 'buildid', '1', '2', '3'. */

/* Enables even more diagnostics on modules: */
/* #define DEBUG_MODULES */

/* Enables standard access to DWARF debuginfo, matching stack.c.
   This is of dubious benefit -- for profiling, we really should
   aim to resolve everything with minimal overhead using eh CFI. */
/* #define FIND_DEBUGINFO */

/* Program exit codes.  All samples processed without any errors is
   GOOD.  Some non-fatal errors during processing is an ERROR.  A
   fatal error or no samples processed at all is BAD.  A command line
   USAGE exit is generated by argp_error. */
#define EXIT_OK     0
#define EXIT_ERROR  1
#define EXIT_BAD    2
#define EXIT_USAGE 64

/***********************
 * Unwinder state data *
 ***********************/

/* Basic unwinder state structure. */
struct passthru_info
{
  void *input; /* SysprofReader* or PerfReader* */
  void *output; /* SysprofOutput* or GmonOutput* */
  void *last_frame; /* SysprofCaptureFrame* or PerfCaptureFrame* */
};

/* ... and with additional diagnostics. */
#define UNWIND_ADDR_INCREMENT 512
struct unwind_info
{
  void *input; /* SysprofReader* or PerfReader* */
  void *output; /* SysprofOutput* or GmonOutput* */
  void *last_frame; /* SysprofCaptureFrame* or PerfSample* */

  int n_addrs;
  Dwarf_Addr *addrs; /* allocate in blocks of UNWIND_ADDR_INCREMENT */
  int max_addrs; /* last allocated size */
  int last_elfclass;

  Dwarf_Addr last_base; /* for diagnostic purposes */
  Dwarf_Addr last_sp; /* for diagnostic purposes */
  Dwfl *last_dwfl; /* for diagnostic purposes */
  pid_t last_pid; /* to provide access to dwfltab */
};

void
unwind_info_init (struct unwind_info *ui)
{
  ui->n_addrs = 0;
  ui->max_addrs = UNWIND_ADDR_INCREMENT;
  ui->addrs = (Dwarf_Addr *)malloc (ui->max_addrs * sizeof(Dwarf_Addr));
  ui->last_elfclass = ELFCLASS64;

  ui->last_base = 0;
  ui->last_sp = 0;
  ui->last_dwfl = NULL;
  ui->last_pid = 0;

  /* TODO also implement a cleanup function */
}

/*****************************
 * perf_events input support *
 *****************************/

typedef struct
{
  int ncpus;
  int ncpus_online;

  uint64_t sample_regs_user;
  int sample_regs_count;

  /* Sized by number of CPUs: */
  int *perf_fds;
  struct perf_event_mmap_page **perf_headers;
  bool *cpu_online;

  int page_size;
  int page_count;
  int mmap_size;

  int group_fd;

  int n_samples; /* for diagnostic purposes */
} PerfReader;

/* TODO: Consider including PERF_SAMPLE_IDENTIFIER. */
#define EUS_PERF_SAMPLE_TYPE (PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME \
			      | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER)
typedef struct
{
  struct perf_event_header header;
  uint64_t ip;
  uint32_t pid, tid;
  uint64_t time;
  uint64_t abi;
  uint64_t *regs; /* XXX variable size */
  /* uint64_t size; */
  /* char *data; -- XXX variable size */
} PerfSample;

uint64_t
perf_sample_get_size (PerfReader *reader, PerfSample *sample)
{
  int nregs = reader->sample_regs_count;
  return (uint64_t)(sample->regs + nregs * sizeof(uint64_t));
}

char *
perf_sample_get_data (PerfReader *reader, PerfSample *sample)
{
  int nregs = reader->sample_regs_count;
  return (char *)(sample->regs + (nregs + 1) * sizeof(uint64_t));
}

/* forward decl */
void perf_reader_end (PerfReader *reader);

int
count_mask (uint64_t perf_regs_mask)
{
  /* TODO: Generalize PERF_REG_X86_64_MAX to other arches. */
  int k, count; uint64_t bit;
  for (k = 0, count = 0, bit = 1;
       k < PERF_REG_X86_64_MAX; k++, bit <<= 1)
    if ((bit & perf_regs_mask))
      count++;
  return count;
}

PerfReader *
perf_reader_begin ()
{
  PerfReader *reader = calloc(1, sizeof(PerfReader));
  if (reader == NULL)
    return NULL;

  reader->ncpus = sysconf(_SC_NPROCESSORS_CONF);
  if (reader->ncpus < 0)
    {
      free(reader);
      return NULL;
    }

  reader->perf_fds = calloc(reader->ncpus, sizeof(int));
  reader->perf_headers = calloc(reader->ncpus, sizeof(struct perf_event_mmap_page *));
  reader->cpu_online = calloc(reader->ncpus, sizeof(bool));
  if (reader->perf_fds == NULL || reader->perf_headers == NULL || reader->cpu_online == NULL)
    {
      perf_reader_end(reader);
      return NULL;
    }

  /* If perf_event_open() fails on any CPU, we will mark it as offline: */
  reader->ncpus_online = reader->ncpus;
  for (int i = 0; i < reader->ncpus; i++)
    {
      reader->cpu_online[i] = true;
      reader->perf_fds[i] = -1;
    }

  reader->page_size = getpagesize();
  reader->page_count = 64; /* TODO: Decide on a large-enough power-of-2. */
  reader->mmap_size = reader->page_size * (reader->page_count + 1);

  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.sample_freq = 1000;
  attr.sample_type = EUS_PERF_SAMPLE_TYPE;
  attr.disabled = 1;
  attr.exclude_kernel = 1; /* TODO: Probably don't care about this for our initial usecase. */
  /* TODO attr.mmap, attr.mmap2 */
  /* TODO?
     attr.exclude_hv = 1; */
  /* TODO? attr.precise_ip = 0;
     attr.wakeup_events = 1; */

  reader->sample_regs_user = ebl_perf_frame_regs_mask (default_ebl);
  reader->sample_regs_count = count_mask (reader->sample_regs_user);
  attr.sample_regs_user = reader->sample_regs_user;
  attr.sample_stack_user = 8192;
  /* TODO? attr.sample_stack_user = 65536; */

  int nheads = 0;
  for (int cpu = 0; cpu < reader->ncpus; cpu++)
    {
      int fd = syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
      if (fd < 0)
	{
	  fprintf(stderr, "DEBUG perf_event_open failed %d\n", cpu);
	  reader->cpu_online[cpu] = false;
	  reader->ncpus_online --;
	  continue;
	}
      reader->perf_fds[cpu] = fd;

      void *buf = mmap(NULL, reader->mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if (buf == MAP_FAILED)
	{
	  fprintf(stderr, "DEBUG mmap for perf_event_open failed %d\n", cpu);
	  close(fd);
	  reader->perf_fds[cpu] = -1;
	  reader->cpu_online[cpu] = false;
	}
      reader->perf_headers[nheads] = buf;
      nheads++;
    }
  if (reader->ncpus_online == 0)
    {
      fprintf(stderr, N_("WARNING: perf_event_open failed on all cpus\n"));
      perf_reader_end(reader);
      return NULL;
    }

  return reader;
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

int
perf_event_read_simple (PerfReader *reader,
			struct perf_event_mmap_page *header,
			void **copy_mem, size_t *copy_size,
			int (*callback) (void *), void *arg)
{
  size_t mmap_size = reader->page_count * reader->page_size;
  uint64_t data_head = ring_buffer_read_head (header);
  uint64_t data_tail = header->data_tail;
  void *base = ((uint8_t *) header) + reader->page_size;
  int ret = DWARF_CB_OK;

  struct perf_event_header *ehdr;
  size_t ehdr_size;

  /* passthru_info prefixes all valid arg structs */
  struct passthru_info *pi = (struct passthru_info *)arg;

  while (data_head != data_tail)
    {
      ehdr = base + (data_tail & (mmap_size - 1));
      ehdr_size = ehdr->size;

      if (((void *)ehdr) + ehdr_size > base + mmap_size)
	{
	  void *copy_start = ehdr;
	  size_t len_first = base + mmap_size - copy_start;
	  size_t len_secnd = ehdr_size - len_first;

	  if (*copy_size < ehdr_size)
	    {
	      fprintf(stderr, "DEBUG perf_event_copy_simple malloc %ld\n", ehdr_size);
	      free(*copy_mem);
	      *copy_mem = malloc(ehdr_size);
	      if (!*copy_mem)
		{
		  fprintf(stderr, "DEBUG copy_size gone\n");
		  *copy_size = 0;
		  ret = DWARF_CB_ABORT;
		  break;
		}
	      *copy_size = ehdr_size;
	    }

	  (void)len_first; (void)len_secnd;
	  memcpy(*copy_mem, copy_start, len_first);
	  memcpy(*copy_mem + len_first, copy_start, len_secnd);
	  ehdr = *copy_mem; 
	}

      /* TODO also handle mmap events */
      if (ehdr->type == PERF_RECORD_SAMPLE)
	{
	  pi->last_frame = (PerfSample *)ehdr;
	  ret = callback(arg);
	  reader->n_samples ++;
	}
      data_tail += ehdr_size;
      if (ret != DWARF_CB_OK)
	break;
    }

  ring_buffer_write_tail(header, data_tail);
  return ret;
}

int
perf_reader_getframes (PerfReader *reader,
		       int (*callback) (void *),
		       void *arg)
{
  int nfds = 0;
  struct pollfd *fds = calloc(reader->ncpus, sizeof(struct pollfd));
  if (fds == NULL)
    return -1;

  for (int cpu = 0; cpu < reader->ncpus; cpu++)
    if (reader->cpu_online[cpu])
      {
	ioctl(reader->perf_fds[cpu], PERF_EVENT_IOC_ENABLE, 0);
	fds[nfds].fd = reader->perf_fds[cpu];
	fds[nfds].events = POLLIN;
	nfds++;
      }

  int rc = 0;
  reader->n_samples = 0;
  void *copy_mem = NULL;
  size_t copy_size = 0;
  while (1)
    {
      fprintf (stderr, "DEBUG poll0 %d\n", reader->n_samples);
      int ready = poll(fds, nfds, -1);
      fprintf (stderr, "DEBUG poll0->ret\n");
      if (ready < 0)
	{
	  /* TODO: handle EINTR properly */
	  if (errno == EINTR)
	    break;
	  rc = -1;
	  break;
	}
      for (int i = 0; i < nfds; i++)
	{
	  if (fds[i].revents <= 0)
	    continue;
	  ready --;
	  if (fds[i].revents & POLLIN)
	    {
	      int ok = perf_event_read_simple (reader,
					       reader->perf_headers[i],
					       &copy_mem, &copy_size,
					       callback, arg);
	      if (ok != DWARF_CB_OK)
		{
		  rc = 1;
		  break;
		}
	    }
	}
    }
  fprintf(stderr, "total %d samples\n", reader->n_samples);

  if (copy_mem != NULL)
    free(copy_mem);
  free(fds);
  return rc;
}

void
perf_reader_end (PerfReader *reader)
{
  if (reader == NULL)
    return;
  if (reader->perf_fds != NULL)
    {
      for (int cpu = 0; cpu < reader->ncpus; cpu++)
	if (reader->perf_fds[cpu] != -1)
	  close(reader->perf_fds[cpu]);
      free(reader->perf_fds);
    }
  if (reader->perf_headers != NULL)
    free(reader->perf_headers);
  if (reader->cpu_online != NULL)
    free(reader->cpu_online);
}

/********************************
 * Sysprof input/output support *
 ********************************/

/* TODO: elfutils (internal) libraries use libNN_set_errno and _E_WHATEVER;
   this code sets errno variable directly and uses standard EWHATEVER. */

/* XXX based on sysprof src/libsysprof-capture/sysprof-capture-reader.c

   Note: BSD license attribution at the top of the file applies to this
   segment. Could split into a separate file or even a library,
   in which case the attribution notice will move along with it. */

#if HAVE_SYSPROF_HEADERS

/* A complete passthrough can be implemented based on the following 7 functions:
 - sysprof_reader_begin/sysprof_reader_end :: sysprof_capture_reader_new_from_fd
 - sysprof_reader_getheader :: sysprof_capture_reader_read_file_header
 - sysprof_reader_getframes :: sysprof_capture_reader_discover_end_time, an example main loop that doesn't handle every type of frame
 - sysprof_reader_next_frame :: sysprof_capture_reader_peek_frame + sysprof_capture_reader_skip + sysprof_capture_reader_read_basic
 - sysprof_reader_ensure_space_for :: sysprof_capture_reader_ensure_space_for
 - sysprof_reader_bswap_frame :: sysprof_capture_reader_bswap_frame
 */

/* Note DWARF_CB_* replaces SYSPROF_CB_*. */

typedef struct
{
  uint8_t *buf;
  size_t bufsz;
  size_t len;
  size_t pos;
  size_t fd_off; /* XXX track offset for debugging only */
  int fd;
  int endian;
  SysprofCaptureFileHeader header;
} SysprofReader;

typedef struct
{
  int fd;
  int pos; /* for diagnostic purposes */
} SysprofOutput;

/* forward decls */
SysprofReader *sysprof_reader_begin (int fd);
void sysprof_reader_end (SysprofReader *reader);
bool sysprof_reader_getheader (SysprofReader *reader,
			       SysprofCaptureFileHeader *header);
void sysprof_reader_bswap_frame (SysprofReader *reader,
				 SysprofCaptureFrame *frame);
bool sysprof_reader_ensure_space_for (SysprofReader *reader, size_t len);
SysprofCaptureFrame *sysprof_reader_next_frame (SysprofReader *reader);
int sysprof_reader_getframes (SysprofReader *reader,
			      int (*callback) (void *arg),
			      void *arg);

SysprofReader *
sysprof_reader_begin (int fd)
{
  SysprofReader *reader;

  assert (fd > -1);

  reader = malloc (sizeof (SysprofReader));
  if (reader == NULL)
    {
      errno = ENOMEM;
      return NULL;
    }

  reader->bufsz = USHRT_MAX * 2;
  reader->buf = malloc (reader->bufsz);
  if (reader->buf == NULL)
    {
      free (reader);
      errno = ENOMEM;
      return NULL;
    }

  reader->len = 0;
  reader->pos = 0;
  reader->fd = fd;
  reader->fd_off = 0;

  if (!sysprof_reader_getheader (reader, &reader->header))
    {
      int errsv = errno;
      sysprof_reader_end (reader);
      errno = errsv;
      return NULL;
    }

  if (reader->header.little_endian)
    reader->endian = __LITTLE_ENDIAN;
  else
    reader->endian = __BIG_ENDIAN;

  return reader;
}

void
sysprof_reader_end (SysprofReader *reader)
{
  if (reader != NULL)
    {
      free (reader->buf);
      free (reader);
    }
}

bool
sysprof_reader_getheader (SysprofReader *reader,
			  SysprofCaptureFileHeader *header)
{
  assert (reader != NULL);
  assert (header != NULL);

  if (sizeof *header != read (reader->fd, header, sizeof *header))
    {
      /* errno is propagated */
      return false;
    }
  reader->fd_off += sizeof *header;

  if (header->magic != SYSPROF_CAPTURE_MAGIC)
    {
      errno = EBADMSG;
      return false;
    }

  header->capture_time[sizeof header->capture_time - 1] = '\0';

  return true;
}

void
sysprof_reader_bswap_frame (SysprofReader *reader, SysprofCaptureFrame *frame)
{
  assert (reader != NULL);
  assert (frame  != NULL);

  if (unlikely (reader->endian != __BYTE_ORDER))
    {
      frame->len = bswap_16 (frame->len);
      frame->cpu = bswap_16 (frame->cpu);
      frame->pid = bswap_32 (frame->pid);
      frame->time = bswap_64 (frame->time);
    }
}

bool
sysprof_reader_ensure_space_for (SysprofReader *reader, size_t len)
{
  assert (reader != NULL);
  assert (reader->pos <= reader->len);
  assert (len > 0);

  /* Ensure alignment of length to read */
  len = (len + SYSPROF_CAPTURE_ALIGN - 1) & ~(SYSPROF_CAPTURE_ALIGN - 1);

  if ((reader->len - reader->pos) < len)
    {
      ssize_t r;

      if (reader->len > reader->pos)
	memmove (reader->buf,
		 &reader->buf[reader->pos],
		 reader->len - reader->pos);
      reader->len -= reader->pos;
      reader->pos = 0;

      while (reader->len < len)
	{
	  assert ((reader->pos + reader->len) < reader->bufsz);
	  assert (reader->len < reader->bufsz);

	  /* Read into our buffer */
	  r = read (reader->fd,
		    &reader->buf[reader->len],
		    reader->bufsz - reader->len);

	  if (r <= 0)
	    break;

	  reader->fd_off += r;
	  reader->len += r;
	}
    }

  return (reader->len - reader->pos) >= len;
}

/* XXX May want to signal errors in more detail with an rc. */
SysprofCaptureFrame *
sysprof_reader_next_frame (SysprofReader *reader)
{
  SysprofCaptureFrame frame_hdr;
  SysprofCaptureFrame *frame = NULL;

  assert (reader != NULL);
  assert ((reader->pos % SYSPROF_CAPTURE_ALIGN) == 0);
  assert (reader->pos <= reader->len);
  assert (reader->pos <= reader->bufsz);

  if (!sysprof_reader_ensure_space_for (reader, sizeof *frame))
    return NULL;

  assert ((reader->pos % SYSPROF_CAPTURE_ALIGN) == 0);

  frame = (SysprofCaptureFrame *)(void *)&reader->buf[reader->pos];
  frame_hdr = *frame;
  sysprof_reader_bswap_frame (reader, &frame_hdr);

  if (frame_hdr.len < sizeof (SysprofCaptureFrame))
    return NULL;

  if (!sysprof_reader_ensure_space_for (reader, frame_hdr.len))
    return NULL;

  frame = (SysprofCaptureFrame *)(void *)&reader->buf[reader->pos];
  sysprof_reader_bswap_frame (reader, frame);

  if (frame->len > (reader->len - reader->pos))
    return NULL;

  reader->pos += frame->len;

  if ((reader->pos % SYSPROF_CAPTURE_ALIGN) != 0)
    return NULL;

  /* if (frame->type < 0 || frame->type >= SYSPROF_CAPTURE_FRAME_LAST) */
  if (frame->type >= SYSPROF_CAPTURE_FRAME_LAST)
    return NULL;

  return frame;
}

int
sysprof_reader_getframes (SysprofReader *reader,
			  int (*callback) (void *),
			  void *arg)
{
  SysprofCaptureFrame *frame;

  /* passthru_info prefixes all valid arg structs: */
  struct passthru_info *pi = (struct passthru_info *)arg;

  assert (reader != NULL);

  while ((frame = sysprof_reader_next_frame (reader)))
    {
      pi->last_frame = frame;
      int ok = callback (arg);
      if (ok != DWARF_CB_OK)
	return -1;
    }
  return 0;
}

#endif /* HAVE_SYSPROF_HEADERS */

/****************************************************
 * Dwfl and statistics table for multiple processes *
 ****************************************************/

Dwflst_Process_Tracker *tracker = NULL;

/* This echoes lib/dynamicsizehash.* with some necessary modifications. */
typedef struct
{
  bool used;
  pid_t pid;
  Dwfl *dwfl;
  char *comm;
  int max_frames; /* for diagnostic purposes */
  int total_samples; /* for diagnostic purposes */
  int lost_samples; /* for diagnostic purposes */
  Dwfl_Unwound_Source last_unwound; /* track CFI source, for diagnostic purposes */
  Dwfl_Unwound_Source worst_unwound; /* track CFI source, for diagnostic purposes */
} dwfltab_ent;

typedef struct
{
  ssize_t size;
  ssize_t filled;
  dwfltab_ent *table;
} dwfltab;

/* XXX table size must be a prime */
#define DWFLTAB_DEFAULT_SIZE 1021
extern size_t next_prime (size_t); /* XXX from libeu.a lib/next_prime.c */
dwfltab_ent *dwfltab_find(pid_t pid); /* forward decl */

/* TODO: Could turn this into a field of sui instead of a global. */
dwfltab default_table;

/* XXX based on lib/dynamicsizehash.* *_init */
bool dwfltab_init(void)
{
  dwfltab *htab = &default_table;
  htab->size = DWFLTAB_DEFAULT_SIZE;
  htab->filled = 0;
  htab->table = calloc ((htab->size + 1), sizeof(htab->table[0]));
  return (htab->table != NULL);
}

/* XXX based on lib/dynamicsizehash.* insert_entry_2 */
bool dwfltab_resize(void)
{
  /* TODO: Also implement LRU eviction, especially given the number of
     extremely-short-lived processes seen on GNOME desktop. */
  dwfltab *htab = &default_table;
  ssize_t old_size = htab->size;
  dwfltab_ent *old_table = htab->table;
  htab->size = next_prime (htab->size * 2);
  htab->table = calloc ((htab->size + 1), sizeof(htab->table[0]));
  if (htab->table == NULL)
    {
      htab->size = old_size;
      htab->table = old_table;
      return false;
    }
  htab->filled = 0;
  /* Transfer the old entries to the new table. */
  for (ssize_t idx = 1; idx <= old_size; ++idx)
    if (old_table[idx].used)
      {
	dwfltab_ent *ent0 = &old_table[idx];
	dwfltab_ent *ent1 = dwfltab_find(ent0->pid);
	assert (ent1 != NULL);
	memcpy (ent1, ent0, sizeof(dwfltab_ent));
      }
  free (old_table);
  /* TODO: Need to decide log level for this message. For now, it's
     not a failure, and printing it by default seems harmless: */
  fprintf(stderr, N_("Resized Dwfl table from %ld to %ld, copied %ld entries\n"),
	  old_size, htab->size, htab->filled);
  return true;
}

/* XXX based on lib/dynamicsizehash.* *_find */
dwfltab_ent *dwfltab_find(pid_t pid)
{
  dwfltab *htab = &default_table;
  ssize_t idx = 1 + (htab->size > (ssize_t)pid ? (ssize_t)pid : (ssize_t)pid % htab->size);

  if (!htab->table[idx].used)
    goto found;
  if (htab->table[idx].pid == pid)
    goto found;

  int64_t hash = 1 + pid % (htab->size - 2);
  do
    {
      if (idx <= hash)
	idx = htab->size + idx - hash;
      else
	idx -= hash;

      if (!htab->table[idx].used)
	goto found;
      if (htab->table[idx].pid == pid)
	goto found;
    }
  while (true);

 found:
  if (htab->table[idx].pid == 0)
    {
      if (100 * htab->filled > 90 * htab->size)
	if (!dwfltab_resize())
	  return NULL;
      htab->table[idx].used = true;
      htab->table[idx].pid = pid;
      htab->filled += 1;
    }
  return &htab->table[idx];
}

Dwfl *
pid_find_dwfl (pid_t pid)
{
  dwfltab_ent *entry = dwfltab_find(pid);
  if (entry == NULL)
    return NULL;
  return entry->dwfl;
}

char *
pid_find_comm (pid_t pid)
{
  dwfltab_ent *entry = dwfltab_find(pid);
  if (entry == NULL)
    return "<unknown>";
  if (entry->comm != NULL)
    return entry->comm;
  char name[64];
  int i = snprintf (name, sizeof(name), "/proc/%ld/comm", (long) pid);
  FILE *procfile = fopen(name, "r");
  if (procfile == NULL)
    goto fail;
  size_t linelen = 0;
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
  snprintf (entry->comm, 16, "<unknown>");
 done:
  return entry->comm;
}

/* Cache dwfl structs in a basic hash table. */
void
pid_store_dwfl (pid_t pid, Dwfl *dwfl)
{
  dwfltab_ent *entry = dwfltab_find(pid);
  if (entry == NULL)
    return;
  entry->pid = pid;
  entry->dwfl = dwfl;
  pid_find_comm(pid);
  return;
}

/**************************
 * generic unwinding code *
 **************************/

/* TODO: Could be relocated to libdwfl/linux-pid-attach.c
   to remove a dependency on the libdwflP.h interface. */
int
find_procfile (Dwfl *dwfl, pid_t *pid, Elf **elf, int *elf_fd)
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
      if (dwfl->process == NULL && dwfl->attacherr == DWFL_E_NOERROR) /* XXX requires libdwflP.h */
	{
	  errno = err;
	  /* TODO: __libdwfl_canon_error not exported from libdwfl */
	  /* dwfl->attacherr = __libdwfl_canon_error (DWFL_E_ERRNO); */
	}
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
	  if (show_failures)
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

Dwfl *
init_dwfl_cb (Dwflst_Process_Tracker *cb_tracker,
	      pid_t pid,
	      void *arg __attribute__ ((unused)))
{
  Dwfl *dwfl = dwflst_tracker_dwfl_begin (cb_tracker);

  int err = dwfl_linux_proc_report (dwfl, pid);
  if (err < 0)
    {
      if (show_failures)
	fprintf(stderr, "dwfl_linux_proc_report pid %lld: %s",
		(long long) pid, dwfl_errmsg (-1));
      return NULL;
    }
  err = dwfl_report_end (dwfl, NULL, NULL);
  if (err != 0)
    {
      if (show_failures)
	fprintf(stderr, "dwfl_report_end pid %lld: %s",
		(long long) pid, dwfl_errmsg (-1));
      return NULL;
    }

  return dwfl;
}

Dwfl *
find_dwfl (struct unwind_info *ui, pid_t pid,
	   const Dwarf_Word *regs, uint32_t n_regs,
	   Elf **out_elf, bool *cached)
{
  /* XXX: Note that requesting the x86_64 register file from
     perf_events will result in an array of 17 regs even for 32-bit
     applications. */
  if (n_regs < ebl_frame_nregs(default_ebl)) /* XXX expecting everything except FLAGS */
    {
      if (show_failures)
	fprintf(stderr, N_("find_dwfl: n_regs=%d, expected %ld\n"),
		n_regs, ebl_frame_nregs(default_ebl));
      return NULL;
    }

  Elf *elf = NULL;
  Dwfl *dwfl = dwflst_tracker_find_pid (tracker, pid, init_dwfl_cb, NULL);
  if (dwfl != NULL && dwfl->process != NULL)
    {
      *cached = true;
      goto reuse;
    }

  int elf_fd = -1;
  int err = find_procfile (dwfl, &pid, &elf, &elf_fd);
  if (err < 0)
    {
      if (show_failures)
	fprintf(stderr, "find_procfile pid %lld: %s",
		(long long) pid, dwfl_errmsg (-1));
      return NULL;
    }

 reuse:
  /* TODO: Generalize to other architectures than x86. */
  ui->last_sp = regs[7];
  ui->last_base = ui->last_sp;

  if (!*cached)
    pid_store_dwfl (pid, dwfl);
  *out_elf = elf;
  return dwfl;
}

int
unwind_frame_cb (Dwfl_Frame *state, void *arg)
{
  Dwarf_Addr pc;
  bool isactivation;
  if (! dwfl_frame_pc (state, &pc, &isactivation))
    {
      if (show_failures)
	fprintf(stderr, "dwfl_frame_pc: %s\n",
		dwfl_errmsg(-1));
      return DWARF_CB_ABORT;
    }

  Dwarf_Addr pc_adjusted = pc - (isactivation ? 0 : 1);
  Dwarf_Addr sp;

  /* TODO: Generalize to other architectures than x86. */
  struct unwind_info *ui = (struct unwind_info *)arg;
  int is_abi32 = (ui->last_elfclass == ELFCLASS32);
  /* DWARF register order cf. elfutils backends/{x86_64,i386}_initreg.c: */
  int user_regs_sp = is_abi32 ? 4 : 7;
  int rc = dwfl_frame_reg (state, user_regs_sp, &sp);
  if (rc < 0)
    {
      if (show_failures)
	fprintf(stderr, "dwfl_frame_reg: %s\n",
		dwfl_errmsg(-1));
      return DWARF_CB_ABORT;
    }

#ifdef DEBUG_MODULES
  Dwfl_Module *mod = dwfl_addrmodule(ui->last_dwfl, pc);
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

  dwfltab_ent *dwfl_ent = dwfltab_find(ui->last_pid);
  if (dwfl_ent != NULL)
    {
      Dwfl_Unwound_Source unwound_source = dwfl_frame_unwound_source(state);
      if (unwound_source > dwfl_ent->worst_unwound)
	dwfl_ent->worst_unwound = unwound_source;
      dwfl_ent->last_unwound = unwound_source;
      if (show_frames)
	fprintf(stderr, "* frame %d: pc_adjusted=%lx sp=%lx+(%lx) [%s]\n",
		ui->n_addrs, pc_adjusted, ui->last_base, sp - ui->last_base,
		dwfl_unwound_source_str(unwound_source));
    }
  else
    {
      if (show_frames)
	fprintf(stderr, N_("* frame %d: pc_adjusted=%lx sp=%lx+(%lx) [dwfl_ent not found]\n"),
		ui->n_addrs, pc_adjusted, ui->last_base, sp - ui->last_base);
    }
  if (show_buildid)
    {
      Dwfl_Module *m = dwfl_addrmodule(ui->last_dwfl, pc);
      const unsigned char *desc;
      GElf_Addr vaddr;
      int build_id_len = dwfl_module_build_id (m, &desc, &vaddr);
      if (show_buildid)
	fprintf(stderr, "* pid %d build_id ", ui->last_pid);
      for (int i = 0; i < build_id_len; ++i)
	fprintf(stderr, "%02" PRIx8, (uint8_t) desc[i]);
      fprintf(stderr, "\n");
    }

  if (ui->n_addrs > maxframes)
    {
      /* XXX very rarely, the unwinder can loop infinitely; worth investigating? */
      if (show_failures)
	fprintf(stderr, N_("unwind_frame_cb: sample exceeded maxframes %d\n"),
		maxframes);
      return DWARF_CB_ABORT;
    }

  ui->last_sp = sp;
  if (ui->n_addrs >= ui->max_addrs)
    {
      ui->addrs = reallocarray (ui->addrs, ui->max_addrs + UNWIND_ADDR_INCREMENT, sizeof(Dwarf_Addr));
      ui->max_addrs = ui->max_addrs + UNWIND_ADDR_INCREMENT;
    }
  ui->addrs[ui->n_addrs] = pc;
  ui->n_addrs++;
  return DWARF_CB_OK;
}

/* forward decls */
int perf_unwind_cb (void *arg);
int sysprof_unwind_cb (void *arg);

void
choose_unwind_cb (int (**callback) (void *))
{
#if HAVE_SYSPROF_HEADERS
  if (input_format == SOURCE_SYSPROF)
    {
      *callback = &sysprof_unwind_cb;
    }
#endif
  if (input_format == SOURCE_PERF_EVENTS)
    {
      *callback = &perf_unwind_cb;
      return;
    }
  *callback = NULL;
}

int
reader_getframes (int (*callback) (void *), void *arg)
{
  /* passthru_info prefixes all valid arg structs: */
  struct passthru_info *pi = (struct passthru_info *) arg;
  int rc = 0;
  if (input_format == SOURCE_PERF_EVENTS)
    {
      PerfReader *reader = (PerfReader *)pi->input;
      rc = perf_reader_getframes (reader, callback, arg);
    }
#if HAVE_SYSPROF_HEADERS
  else if (input_format == SOURCE_SYSPROF)
    {
      SysprofReader *reader = (SysprofReader *)pi->input;
      rc = sysprof_reader_getframes (reader, callback, arg);
    }
#endif
  else
    rc = -1; /* TODO set errno? */
  return rc;
}

/************************************
 * basic none/passthrough callbacks *
 ************************************/

int
process_none_cb (void *arg __attribute__ ((unused)))
{
  return DWARF_CB_OK;
}

#if HAVE_SYSPROF_HEADERS

int
passthru_sysprof_cb (SysprofCaptureFrame *frame, void *arg)
{
  struct passthru_info *pi = (struct passthru_info *)arg;
  SysprofReader *reader = (SysprofReader *)pi->input;
  SysprofOutput *output = (SysprofOutput *)pi->output;
  sysprof_reader_bswap_frame (reader, frame); /* reverse the earlier bswap */
  ssize_t n_write = write (output->fd, frame, frame->len);
  output->pos += frame->len;
  assert ((output->pos % SYSPROF_CAPTURE_ALIGN) == 0);
  if (n_write < 0)
    error (EXIT_BAD, errno, N_("Write error to file or FIFO '%s'"), output_path);
  return DWARF_CB_OK;
}

int
passthru_perf_to_sysprof_cb (PerfCaptureFrame *frame, void *arg)
{
  /* TODO */
  return DWARF_CB_ABORT;
}

#endif /* HAVE_SYSPROF_HEADERS */

void
choose_passthru_cb (int (**callback) (void *))
{
#if HAVE_SYSPROF_HEADERS
  if (input_format == SOURCE_SYSPROF && output_format == DEST_SYSPROF)
    {
      *callback = &passthru_sysprof_cb;
      return;
    }
  if (input_format == SOURCE_PERF_EVENTS && output_format == DEST_SYSPROF)
    {
      *callback = &passthru_perf_to_sysprof_cb;
      return;
    }
#endif
  if (output_format == DEST_NONE)
    {
      *callback = &process_none_cb;
      return;
    }
  *callback = NULL;
}

/****************************
 * find_debuginfo callbacks *
 ****************************/

#ifdef FIND_DEBUGINFO

static char *debuginfo_path = NULL;

static const Dwfl_Callbacks sample_callbacks =
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

static const Dwfl_Callbacks sample_callbacks =
{
  .find_elf = dwflst_tracker_linux_proc_find_elf,
  .find_debuginfo = nop_find_debuginfo, /* work with CFI only */
};

#endif /* FIND_DEBUGINFO */

/*******************************************
 * perf_events backend: unwinding callback *
 *******************************************/

/* TODO */

int
perf_unwind_cb (void *arg)
{
  struct unwind_info *ui = (struct unwind_info *)arg;
  PerfSample *sample = (PerfSample *)(ui->last_frame);

  char *comm = NULL;
  comm = pid_find_comm(sample->pid);

  /* TODO extract n_regs */
  PerfReader *reader = (PerfReader *)(ui->input);
  int n_regs = reader->sample_regs_count;

  if (show_frames)
    fprintf(stderr, "\n"); /* extra newline for padding */

  Elf *elf = NULL;
  bool cached = false;
  Dwfl *dwfl = find_dwfl (ui, sample->pid, sample->regs, n_regs, &elf, &cached);
  if (dwfl == NULL)
    {
      if (show_summary)
	{
	  dwfltab_ent *dwfl_ent = dwfltab_find(sample->pid);
	  dwfl_ent->total_samples++;
	  dwfl_ent->lost_samples++;
	}
      if (show_failures)
	fprintf(stderr, "find_dwfl pid %lld (%s) (failed)\n",
		(long long)sample->pid, comm);
      return DWARF_CB_OK;
    }

  if (show_frames) {
    bool is_abi32 = (sample->abi == PERF_SAMPLE_REGS_ABI_32);
    fprintf(stderr, "find_dwfl pid %lld%s: size=%d%s pc=%lx sp=%lx+(%lx)\n",
	    (long long) sample->pid, cached ? " (cached)" : "",
	    sample->header.size /* TODO ?? */, is_abi32 ? " (32-bit)" : "",
	    sample->regs[8] /* TODO: Generalize beyond x86 */, ui->last_base, (long)0);
  }

  ui->n_addrs = 0;
  ui->last_elfclass = sample->abi == PERF_SAMPLE_REGS_ABI_32 ? ELFCLASS32 : ELFCLASS64;
  ui->last_dwfl = dwfl;
  ui->last_pid = sample->pid;
  uint64_t regs_mask = reader->sample_regs_user;
  uint64_t data_size = perf_sample_get_size (reader, sample);
  char *data = perf_sample_get_data (reader, sample);

  int rc = dwflst_perf_sample_getframes (dwfl, elf, sample->pid, sample->tid,
					 (uint8_t *)data, data_size,
					 sample->regs, n_regs,
					 regs_mask, sample->abi,
					 unwind_frame_cb, ui);
  if (rc < 0)
    {
      if (show_failures)
	fprintf(stderr, "dwflst_perf_sample_getframes pid %lld: %s\n",
		(long long)sample->pid, dwfl_errmsg(-1));
    }
  if (show_summary)
    {
      /* For final diagnostics. */
      dwfltab_ent *dwfl_ent = dwfltab_find(sample->pid);
      if (dwfl_ent != NULL && ui->n_addrs > dwfl_ent->max_frames)
	dwfl_ent->max_frames = ui->n_addrs;
      dwfl_ent->total_samples++;
      if (ui->n_addrs <= 2)
	dwfl_ent->lost_samples ++;
    }

  return DWARF_CB_OK;
}

/****************************************
 * Sysprof backend: unwinding callbacks *
 ****************************************/

#if HAVE_SYSPROF_HEADERS

#define UNWIND_ADDR_INCREMENT 512
struct sysprof_unwind_info
{
  int output_fd;
  SysprofReader *reader;
  int pos; /* for diagnostic purposes */
  int n_addrs;
  int max_addrs; /* for diagnostic purposes */
  uint64_t last_abi;
  Dwarf_Addr last_base; /* for diagnostic purposes */
  Dwarf_Addr last_sp; /* for diagnostic purposes */
  Dwfl *last_dwfl; /* for diagnostic purposes */
  pid_t last_pid; /* for diagnostic purposes, to provide access to dwfltab */
  Dwarf_Addr *addrs; /* allocate blocks of UNWIND_ADDR_INCREMENT */
  void *outbuf;
};

int
sysprof_unwind_cb
{
  struct unwind_info *ui = (struct unwind_info *)arg;
  SysprofCaptureFrame *frame = (SysprofCaptureFrame *)(arg->last_frame);
  ssize_t n_write;
}

int
sysprof_unwind_cb (SysprofCaptureFrame *frame, void *arg)
{
  struct sysprof_unwind_info *sui = (struct sysprof_unwind_info *)arg;
  ssize_t n_write;

  /* additional diagnostic to display process name */
  char *comm = NULL;
  if (frame->type == SYSPROF_CAPTURE_FRAME_SAMPLE || frame->type == SYSPROF_CAPTURE_FRAME_STACK_USER)
      comm = pid_find_comm(frame->pid);

  if (frame->type == SYSPROF_CAPTURE_FRAME_SAMPLE)
    {
      /* XXX additional diagnostics for comparing to eu-stacktrace unwind */
      SysprofCaptureSample *ev_sample = (SysprofCaptureSample *)frame;
      if (show_samples)
	fprintf(stderr, N_("sysprof_unwind_cb pid %lld (%s): callchain sample with %d frames\n"),
		(long long)frame->pid, comm, ev_sample->n_addrs);
      if (show_summary)
	{
	  /* For final diagnostics. */
	  dwfltab_ent *dwfl_ent = dwfltab_find(frame->pid);
	  if (dwfl_ent == NULL && show_failures)
	    fprintf(stderr, N_("sysprof_unwind_cb pid %lld (%s): could not create Dwfl table entry\n"),
		    (long long)frame->pid, comm);
	  else if (dwfl_ent != NULL)
	    {
	      if (ev_sample->n_addrs > dwfl_ent->max_frames)
		dwfl_ent->max_frames = ev_sample->n_addrs;
	      dwfl_ent->total_samples ++;
	      if (ev_sample->n_addrs <= 2)
		dwfl_ent->lost_samples ++;
	    }
	}
    }
  if (frame->type != SYSPROF_CAPTURE_FRAME_STACK_USER)
    {
      sysprof_reader_bswap_frame (sui->reader, frame); /* reverse the earlier bswap */
      n_write = write (sui->output_fd, frame, frame->len);
      sui->pos += frame->len;
      assert ((sui->pos % SYSPROF_CAPTURE_ALIGN) == 0);
      if (n_write < 0)
	error (EXIT_BAD, errno, N_("Write error to file or FIFO '%s'"), output_path);
      return DWARF_CB_OK;
    }
  SysprofCaptureStackUser *ev = (SysprofCaptureStackUser *)frame;
  uint8_t *tail_ptr = (uint8_t *)ev;
  tail_ptr += sizeof(SysprofCaptureStackUser) + ev->size;
  SysprofCaptureUserRegs *regs = (SysprofCaptureUserRegs *)tail_ptr;
  if (show_frames)
    fprintf(stderr, "\n"); /* extra newline for padding */
  Elf *elf = NULL;
  bool cached = false;
  Dwfl *dwfl = find_dwfl (sui, frame->pid, regs->regs, regs->n_regs, &elf, &cached);
  if (dwfl == NULL)
    {
      if (show_summary)
	{
	  dwfltab_ent *dwfl_ent = dwfltab_find(frame->pid);
	  dwfl_ent->total_samples++;
	  dwfl_ent->lost_samples++;
	}
      if (show_failures)
	fprintf(stderr, "find_dwfl pid %lld (%s) (failed)\n",
		(long long)frame->pid, comm);
      return DWARF_CB_OK;
    }
  if (show_frames) {
    bool is_abi32 = (regs->abi == PERF_SAMPLE_REGS_ABI_32);
    fprintf(stderr, "find_dwfl pid %lld%s: size=%ld%s pc=%lx sp=%lx+(%lx)\n",
	    (long long) frame->pid, cached ? " (cached)" : "",
	    ev->size, is_abi32 ? " (32-bit)" : "",
	    regs->regs[8] /* TODO: Generalize beyond x86 */, sui->last_base, (long)0);
  }

  sui->n_addrs = 0;
  sui->last_elfclass = regs->abi == PERF_SAMPLE_REGS_ABI_32 ? ELFCLASS32 : ELFCLASS64;
  sui->last_dwfl = dwfl;
  sui->last_pid = frame->pid;
  uint64_t regs_mask = ebl_perf_frame_regs_mask (default_ebl);
  int rc = dwflst_perf_sample_getframes (dwfl, elf, frame->pid, ev->tid,
					 (uint8_t *)&ev->data, ev->size,
					 regs->regs, regs->n_regs,
					 regs_mask, regs->abi,
					 sysprof_unwind_frame_cb, sui);
  if (rc < 0)
    {
      if (show_failures)
	fprintf(stderr, "dwflst_perf_sample_getframes pid %lld: %s\n",
		(long long)frame->pid, dwfl_errmsg(-1));
    }
  if (show_samples)
    {
      bool is_abi32 = (regs->abi == PERF_SAMPLE_REGS_ABI_32);
      fprintf(stderr, N_("sysprof_unwind_cb pid %lld (%s)%s: unwound %d frames\n"),
	      (long long)frame->pid, comm, is_abi32 ? " (32-bit)" : "", sui->n_addrs);
    }
  if (show_summary)
    {
      /* For final diagnostics. */
      dwfltab_ent *dwfl_ent = dwfltab_find(frame->pid);
      if (dwfl_ent != NULL && sui->n_addrs > dwfl_ent->max_frames)
	dwfl_ent->max_frames = sui->n_addrs;
      dwfl_ent->total_samples++;
      if (sui->n_addrs <= 2)
	dwfl_ent->lost_samples ++;
    }

  /* Assemble and output callchain frame. */
  /* XXX assert(sizeof(Dwarf_Addr) == sizeof(SysprofCaptureAddress)); */
  SysprofCaptureSample *ev_callchain;
  size_t len = sizeof *ev_callchain + (sui->n_addrs * sizeof(Dwarf_Addr));
  ev_callchain = (SysprofCaptureSample *)sui->outbuf;
  if (len > USHRT_MAX)
    {
      if (show_failures)
	fprintf(stderr, N_("sysprof_unwind_cb frame size %ld is too large (max %d)\n"),
		len, USHRT_MAX);
      return DWARF_CB_OK;
    }
  SysprofCaptureFrame *out_frame = (SysprofCaptureFrame *)ev_callchain;
  out_frame->len = len;
  out_frame->cpu = ev->frame.cpu;
  out_frame->pid = ev->frame.pid;
  out_frame->time = ev->frame.time;
  out_frame->type = SYSPROF_CAPTURE_FRAME_SAMPLE;
  out_frame->padding1 = 0;
  out_frame->padding2 = 0;
  ev_callchain->n_addrs = sui->n_addrs;
  ev_callchain->tid = ev->tid;
  memcpy (ev_callchain->addrs, sui->addrs, (sui->n_addrs * sizeof(SysprofCaptureAddress)));
  n_write = write (sui->output_fd, ev_callchain, len);
  if (n_write < 0)
    error (EXIT_BAD, errno, N_("Write error to file or FIFO '%s'"), output_path);
  return DWARF_CB_OK;
}

#endif /* HAVE_SYSPROF_HEADERS */

/****************
 * Main program *
 ****************/

/* TODO: eu-stacktrace --mode=sysprof --input=fifo --output=syscap */
/* TODO: eu-stacktrace --mode=perf --target=pid --output=perf.data */
/* TODO: cmdline for invoking eu-stacktrace with perf-tool? */

/* Required to match our signal handling with that of a sysprof parent process. */
static void sigint_handler (int /* signo */)
{
  if (signal_count >= 2)
    {
      exit(1);
    }

  if (signal_count == 0)
    {
      fprintf (stderr, "%s\n", N_("Waiting for input to finish. Press twice more ^C to force exit."));
    }

  signal_count ++;
}

static error_t
parse_opt (int key, char *arg __attribute__ ((unused)),
	   struct argp_state *state)
{
  switch (key)
    {
    case 'i':
      input_path = arg;
      break;

    case 'o':
      output_path = arg;
      break;

    case 'm':
      if (strcmp (arg, "none") == 0)
	{
	  processing_mode = MODE_NONE;
	}
      else if (strcmp (arg, "passthru") == 0)
	{
	  processing_mode = MODE_PASSTHRU;
	}
      else if (strcmp (arg, "basic") == 0 || strcmp (arg, "naive") == 0)
	{
	  processing_mode = MODE_BASIC;
	}
      else
	{
	  argp_error (state, N_("Unsupported -m '%s', should be " MODE_OPTS "."), arg);
	}
      break;

    case 's':
      if (strcmp (arg, "perf_events") == 0)
	{
	  input_format = SOURCE_PERF_EVENTS;
	}
      else if (strcmp (arg, "sysprof") == 0)
	{
	  input_format = SOURCE_SYSPROF;
	}
      else
	{
	  argp_error (state, N_("Unsupported -s '%s', should be " SOURCE_OPTS "."), arg);
	}
      break;

    case 'd':
      if (strcmp (arg, "gmon_out") == 0)
	{
	  output_format = DEST_GMON_OUT;
	}
      else if (strcmp (arg, "sysprof") == 0)
	{
	  output_format = DEST_SYSPROF;
	}
      else if (strcmp (arg, "none") == 0)
	{
	  output_format = DEST_NONE;
	}
      else
	{
	  argp_error (state, N_("Unsupported -d '%s', should be " DEST_OPTS "."), arg);
	}
      break;

    case 'w':
      show_buildid = true;
      FALLTHROUGH;
    case OPT_DEBUG:
      show_frames = true;
      FALLTHROUGH;
    case 'v':
      show_samples = true;
      show_failures = true;
      show_summary = true;
      break;

    case ARGP_KEY_END:
      if (processing_mode == 0)
	processing_mode = MODE_BASIC;

      if (input_format == 0)
	input_format = SOURCE_PERF_EVENTS;

      if (input_format == SOURCE_PERF_EVENTS && input_path != NULL)
	argp_error (state, N_("-s 'perf_events' does not use an input file"));

      if (input_format != SOURCE_PERF_EVENTS && input_path == NULL)
	input_path = "-"; /* default to stdin */

      if (output_format == DEST_NONE && output_path != NULL)
	argp_error (state, N_("-d 'none' does not use an output file"));

      if (output_format == DEST_GMON_OUT && output_path == NULL)
	output_path = "."; /* default to cwd */

      if (output_format != DEST_NONE && output_path == NULL)
	output_path = "-"; /* default to stdout */

      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

int
main (int argc, char **argv)
{
  /* Set locale. */
  (void) setlocale (LC_ALL, "");

  const struct argp_option options[] =
    {
      { NULL, 0, NULL, 0, N_("Input and output selection options:"), 0 },
      { "source", 's', SOURCE_OPTS, 0,
	N_("Source data format, default 'perf_events'"), 0 },
      { "dest", 'd', DEST_OPTS, 0,
	N_("Destination data format, default 'gmon_out'"), 0 },
      { "input", 'i', "PATH", 0,
	N_("Path to read stack samples from (file or FIFO; for 'sysprof' source only)"), 0 },
      /* TODO: Could also support taking an FD for fork/exec pipes? */
      { "output", 'o', "PATH", 0,
	N_("Path to send stack traces to (file, directory or FIFO)"), 0 },

      { NULL, 0, NULL, 0, N_("Processing options:"), 0 },
      { "mode", 'm', MODE_OPTS, 0,
	N_("Processing mode, default 'basic'"), 0 },
      /* TODO: Should also support 'caching' mode. */
      /* TODO: Add an option for stack-stitching. */
      { "verbose", 'v', NULL, 0,
	N_("Show additional information for each unwound sample"), 0 },
      { "debug", OPT_DEBUG, NULL, 0,
	N_("Show additional information for each unwound frame"), 0 },
      { "buildid", 'w', NULL, 0,
	N_("Show build-id for each unwound frame"), 0 },
      /* TODO: Add a 'quiet' option suppressing summaries + errors.
         Perhaps also allow -v, -vv, -vvv in SystemTap style? */
      { NULL, 0, NULL, 0, NULL, 0 }
    };

  const struct argp argp =
    {
      .options = options,
      .parser = parse_opt,
      /* TODO: Update with standalone application info. */
      .doc = N_("Process a stream of stack samples into stack traces.\n\
\n\
Experimental tool, see README.eu-stacktrace in the development branch:\n\
https://sourceware.org/cgit/elfutils/tree/README.eu-stacktrace?h=users/serhei/eu-stacktrace\n")
    };

  argp_parse(&argp, argc, argv, 0, NULL, NULL);

  /* Also handle ELFUTILS_STACKTRACE_VERBOSE_ENV_VAR: */
  char *env_verbose = getenv(ELFUTILS_STACKTRACE_VERBOSE_ENV_VAR);
  if (env_verbose == NULL || strlen(env_verbose) == 0)
    ; /* nop, use command line options */
  else if (strcmp(env_verbose, "false") == 0
	   || strcmp(env_verbose, "0") == 0)
    ; /* nop, use command line options */
  else if (strcmp(env_verbose, "true") == 0
	   || strcmp(env_verbose, "verbose") == 0
	   || strcmp(env_verbose, "1") == 0)
    {
      show_samples = true;
      show_failures = true;
      show_summary = true;
    }
  else if (strcmp(env_verbose, "debug") == 0
	   || strcmp(env_verbose, "2") == 0)
    {
      show_frames = true;
      show_samples = true;
      show_failures = true;
      show_summary = true;
    }
  else if (strcmp(env_verbose, "buildid") == 0
	   || strcmp(env_verbose, "3") == 0)
    {
      show_buildid = true;
      show_frames = true;
      show_samples = true;
      show_failures = true;
      show_summary = true;
    }
  else
    fprintf (stderr, N_("WARNING: Unknown value '%s' in environment variable %s, ignoring\n"),
	     env_verbose, ELFUTILS_STACKTRACE_VERBOSE_ENV_VAR);

#if !(HAVE_SYSPROF_HEADERS)
  if (input_format == SOURCE_SYSPROF || output_format == DEST_SYSPROF)
    /* TODO: Should hide corresponding command line options when this is the case? */
    error (EXIT_BAD, 0, N_("Sysprof support is not available in this version"));
#endif

  if (signal (SIGINT, sigint_handler) == SIG_ERR)
    error (EXIT_BAD, errno, N_("Cannot set signal handler for SIGINT"));
  /* TODO: sigint_handler cued for sysprof, SOURCE_PERF_EVENTS should use SIGINT to terminate cleanly? */

  fprintf(stderr, "\n=== starting eu-stacktrace ===\n");
  default_ebl = ebl_openbackend_machine(EM_X86_64);

  int input_fd = -1;
#if HAVE_SYSPROF_HEADERS
  SysprofReader *sysprof_reader;
  SysprofOutput sysprof_output;
  sysprof_output.fd = -1;
#endif
  PerfReader *perf_reader = NULL;
  void *input = NULL;
  void *output = NULL;

  if (input_format == SOURCE_PERF_EVENTS)
    {
      perf_reader = perf_reader_begin ();
      if (perf_reader == NULL)
	error (EXIT_BAD, errno, N_("Cannot set up perf_events interface"));
      input = (void *)perf_reader;
    }
  else if (input_format == SOURCE_SYSPROF)
    {
#if HAVE_SYSPROF_HEADERS
      /* TODO: Also handle common expansions e.g. ~/foo instead of /home/user/foo. */
      if (strcmp (input_path, "-") == 0)
	input_fd = STDIN_FILENO;
      else
	input_fd = open (input_path, O_RDONLY);
      if (input_fd < 0)
	error (EXIT_BAD, errno, N_("Cannot open input file or FIFO '%s'"), input_path);

      sysprof_reader = sysprof_reader_begin (input_fd);
      input = (void *)sysprof_reader;
#endif
    }

  if (output_format == DEST_GMON_OUT)
    {
      output = NULL; /* TODO: Implement in subsequent patch. */
      /* error (EXIT_BAD, 0, N_("gmon.out support is not available in this version")); */
    }
  else if (output_format == DEST_SYSPROF)
    {
#if HAVE_SYSPROF_HEADERS
      if (strcmp (output_path, "-") == 0)
	sysprof_output->fd = STDOUT_FILENO;
      else
	sysprof_output->fd = open (output_path, O_CREAT | O_WRONLY, 0640);
      if (sysprof_output->fd < 0)
	error (EXIT_BAD, errno, N_("Cannot open output file or FIFO '%s'"), output_path);

      ssize_t n_write = write (sysprof_output->fd, &sysprof_reader->header,
			       sizeof sysprof_reader->header);
      if (n_write < 0)
	error (EXIT_BAD, errno, N_("Write error to file or FIFO '%s'"), output_path);
      output = (void *)&sysprof_output;
#endif
    }
  /* otherwise output_format == NONE, output == NULL */

  int rc = 0;
  if (processing_mode == MODE_NONE)
    {
      struct passthru_info ni = { input, output, NULL };
      rc = reader_getframes (&process_none_cb, &ni);
    }
  else if (processing_mode == MODE_PASSTHRU)
    {
      int (*process_passthru_cb)(void *) = NULL;
      choose_passthru_cb(&process_passthru_cb);
      struct passthru_info pi = { input, output, NULL };
      rc = reader_getframes (process_passthru_cb, &pi);
    }
  else /* processing_mode == MODE_BASIC */
    {
      if (!dwfltab_init())
	error (EXIT_BAD, errno, N_("Could not initialize Dwfl table"));

      tracker = dwflst_tracker_begin (&sample_callbacks);
      /* TODO: Generalize to other architectures. */

      struct unwind_info ui;
      ui.input = input;
      ui.output = output;
      unwind_info_init(&ui);

      int (*process_unwind_cb)(void *) = NULL;
      choose_unwind_cb(&process_unwind_cb);
      rc = reader_getframes (process_unwind_cb, &ui);

      if (show_summary)
	{
	  /* Final diagnostics. */
#define PERCENT(x,tot) ((x+tot == 0)?0.0:((double)x)/((double)tot)*100.0)
	  int total_samples = 0;
	  int total_lost_samples = 0;
	  fprintf(stderr, "\n=== final summary ===\n");
	  for (unsigned idx = 1; idx < default_table.size; idx++)
	    {
	      dwfltab_ent *t = default_table.table;
	      if (!t[idx].used)
		continue;
	      /* XXX worst_unwound gives least preferred unwind method used for this process
		 (i.e. eh_frame is preferred to dwarf is preferred to ebl) */
	      fprintf(stderr, N_("%d %s -- max %d frames, received %d samples, lost %d samples (%.1f%%) (last %s, worst %s)\n"),
		      t[idx].pid, t[idx].comm, t[idx].max_frames,
		      t[idx].total_samples, t[idx].lost_samples,
		      PERCENT(t[idx].lost_samples, t[idx].total_samples),
		      dwfl_unwound_source_str(t[idx].last_unwound),
		      dwfl_unwound_source_str(t[idx].worst_unwound));
	      total_samples += t[idx].total_samples;
	      total_lost_samples += t[idx].lost_samples;
	    }
	  fprintf(stderr, "===\n");
	  fprintf(stderr, N_("TOTAL -- received %d samples, lost %d samples, loaded %ld processes\n"),
		  total_samples, total_lost_samples,
		  default_table.filled /* TODO: after implementing LRU eviction, need to maintain a separate count, e.g. htab->filled + htab->evicted */);
	}
    }

#if HAVE_SYSPROF_HEADERS
  if (output_format == DEST_SYSPROF
      && rc < 0 && sysprof_output.pos <= sizeof sysprof_reader->header)
    error (EXIT_BAD, errno, N_("No frames in file or FIFO '%s'"), input_path);
  if (input_format == SOURCE_SYSPROF && output_format == DEST_SYSPROF
      && rc < 0 && input_path != NULL)
    error (EXIT_BAD, errno, N_("Error processing file or FIFO '%s' at input offset %ld, output offset %ld"),
	   input_path, sysprof_reader->pos, sysprof_output.pos);
  if (input_format == SOURCE_SYSPROF
      && rc < 0 && input_path != NULL)
    error (EXIT_BAD, errno, N_("Error processing file or FIFO '%s' at input offset %ld"),
	   input_path, sysprof_reader->pos);
#endif
  if (rc < 0)
    error (EXIT_BAD, errno, N_("Error processing input"));

  if (input_fd != -1)
    close (input_fd);
#if HAVE_SYSPROF_HEADERS
  if (sysprof_reader != NULL)
    sysprof_reader_end(sysprof_reader);
  if (sysprof_output->fd != -1)
    close (sysprof_output->fd);
#endif
  if (perf_reader != NULL)
    perf_reader_end (perf_reader);
  if (tracker != NULL)
    dwflst_tracker_end (tracker);

  return EXIT_OK;
}
