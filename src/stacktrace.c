/* Process a stream of stack samples into stack traces.
   Copyright (C) 2023 Red Hat, Inc.
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

#include <system.h>

/* TODO: Make optional through configury.  The #ifdefs are included
   now so we don't miss any code that needs to be controlled with this
   option. */
#define HAVE_SYSPROF_4_HEADERS
#ifdef HAVE_SYSPROF_4_HEADERS

#include <sysprof-4/sysprof-capture-types.h>

/* XXX: To be added to new versions of sysprof. */
#ifndef SYSPROF_CAPTURE_FRAME_STACK_USER

#undef SYSPROF_CAPTURE_FRAME_LAST
#define SYSPROF_CAPTURE_FRAME_STACK_USER 18
#define SYSPROF_CAPTURE_FRAME_LAST 19

SYSPROF_ALIGNED_BEGIN(1)
typedef struct
{
  SysprofCaptureFrame   frame;
  uint64_t              size;
  int32_t               tid;
  unsigned char         data[0];
} SysprofCaptureStackUser
SYSPROF_ALIGNED_END(1);

#endif // ifndef SYSPROF_CAPTURE_FRAME_STACK_USER
#endif // ifdef HAVE_SYSPROF_4_HEADERS

static char *input_path = NULL;
static int input_fd = -1;
static char *output_path = NULL;
static int output_fd = -1;

#define MODE_OPTS "none/passthru"
#define MODE_NONE 0x0
#define MODE_PASSTHRU 0x1
#define MODE_NAIVE 0x2
#define MODE_CACHING 0x3
static int processing_mode;

#define FORMAT_OPTS "sysprof"
#define FORMAT_PERF 0x1
#define FORMAT_SYSPROF 0x2
static int input_format;
static int output_format = FORMAT_SYSPROF; /* TODO: add to cmdline args? */

/* Program exit codes.  All samples processed without any errors is
   GOOD.  Some non-fatal errors during processing is an ERROR.  A
   fatal error or no samples processed at all is BAD.  A command line
   USAGE exit is generated by argp_error. */
#define EXIT_OK     0
#define EXIT_ERROR  1
#define EXIT_BAD    2
#define EXIT_USAGE 64

/* Sysprof format support.
   TODO: Could split into a separate file or even a library. */

#ifdef HAVE_SYSPROF_4_HEADERS

/* XXX based on sysprof src/libsysprof-capture/sysprof-capture-reader.c

   Note: BSD license attribution at the top of the file applies to this
   segment. If moving the code to a separate library, feel free to
   move the notice together with it. */

/* A complete passthrough can be implemented based on the following 7 functions:
 - sysprof_reader_begin/sysprof_reader_end :: sysprof_capture_reader_new_from_fd
 - sysprof_reader_getheader :: sysprof_capture_reader_read_file_header
 - sysprof_reader_getframes :: sysprof_capture_reader_discover_end_time, an example main loop that doesn't handle every type of frame
 - sysprof_reader_next_frame :: sysprof_capture_reader_peek_frame + sysprof_capture_reader_skip + sysprof_capture_reader_read_basic
 - sysprof_reader_ensure_space_for :: sysprof_capture_reader_ensure_space_for
 - sysprof_reader_bswap_frame :: sysprof_capture_reader_bswap_frame
 */

/* Callback results */
enum
{
  SYSPROF_CB_OK = 0,
  SYSPROF_CB_ABORT
};

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

/* forward decls */
SysprofReader *sysprof_reader_begin (int fd);
void sysprof_reader_end (SysprofReader *reader);
bool sysprof_reader_getheader (SysprofReader *reader,
			       SysprofCaptureFileHeader *header);
void sysprof_reader_bswap_frame (SysprofReader *reader,
				 SysprofCaptureFrame *frame);
bool sysprof_reader_ensure_space_for (SysprofReader *reader, size_t len);
SysprofCaptureFrame *sysprof_reader_next_frame (SysprofReader *reader);
ptrdiff_t sysprof_reader_getframes (SysprofReader *reader,
				    int (*callback) (SysprofCaptureFrame *frame,
						     void *arg),
				    void *arg);

SysprofReader *
sysprof_reader_begin (int fd)
{
  SysprofReader *reader;

  assert (fd > -1);

  /* TODO elfutils style: libraries use __lib??_seterrno and ??_E_ENOMEM. */
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

ptrdiff_t
sysprof_reader_getframes (SysprofReader *reader,
			  int (*callback) (SysprofCaptureFrame *,
					   void *),
			  void *arg)
{
  SysprofCaptureFrame *frame;

  assert (reader != NULL);

  while ((frame = sysprof_reader_next_frame (reader)))
    {
      int ok = callback (frame, arg);
      if (ok != SYSPROF_CB_OK)
	return -1;
    }
  return 0;
}

#endif /* HAVE_SYSPROF4_HEADERS */

/* Main program. */

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
      else
	{
	  argp_error (state, N_("Unsupported -m '%s', should be " MODE_OPTS "."), arg); 
	}
      break;

    case 'f':
      if (strcmp (arg, "sysprof") == 0)
	{
	  input_format = FORMAT_SYSPROF;
	}
      else
	{
	  argp_error (state, N_("Unsupported -f '%s', should be " FORMAT_OPTS "."), arg); 
	}
      break;

    case ARGP_KEY_END:
      if (input_path == NULL)
	input_path = "-"; /* default to stdin */

      if (output_path == NULL)
	output_path = "-"; /* default to stdout */

      if (processing_mode == 0)
	processing_mode = MODE_PASSTHRU;

      if (input_format == 0)
	input_format = FORMAT_SYSPROF;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

struct sysprof_passthru_info
{
  int output_fd;
  SysprofReader *reader;
  int pos; /* TODO for debugging purposes */
};

#ifdef HAVE_SYSPROF_4_HEADERS
int
sysprof_none_cb (SysprofCaptureFrame *frame __attribute__ ((unused)),
		 void *arg __attribute__ ((unused)))
{
  return SYSPROF_CB_OK;
}

int
sysprof_passthru_cb (SysprofCaptureFrame *frame, void *arg)
{
  struct sysprof_passthru_info *spi = (struct sysprof_passthru_info *)arg;
  sysprof_reader_bswap_frame (spi->reader, frame); /* reverse the prior bswap */
  ssize_t n_write = write (spi->output_fd, frame, frame->len);
  spi->pos += frame->len;
  assert ((spi->pos % SYSPROF_CAPTURE_ALIGN) == 0);
  if (n_write < 0)
    error (EXIT_BAD, errno, N_("Write error to file or FIFO '%s'"), output_path);
  return SYSPROF_CB_OK;
}
#endif

int
main (int argc, char **argv)
{
  /* Set locale. */
  (void) setlocale (LC_ALL, "");

  const struct argp_option options[] =
    {
      { NULL, 0, NULL, 0, N_("Input and output selection options:"), 0 },
      { "input", 'i', "PATH", 0,
	N_("File or FIFO to read stack samples from"), 0 },
      /* TODO: Should also support taking an FD for fork/exec pipes. */
      { "output", 'o', "PATH", 0,
	N_("File or FIFO to send stack traces to"), 0 },

      { NULL, 0, NULL, 0, N_("Processing options:"), 0 },
      { "mode", 'm', MODE_OPTS, 0,
	N_("Processing mode, default 'passthru'"), 0 },
      /* TODO: Should also support 'naive', 'caching'. */
      /* TODO: Add an option to control stack-stitching. */
      { "format", 'f', FORMAT_OPTS, 0,
	N_("Input data format, default 'sysprof'"), 0 },
      /* TODO: Add an option to control output data format separately,
	 shift to I/O selection section. */
      { NULL, 0, NULL, 0, NULL, 0 }
    };

  const struct argp argp =
    {
      .options = options,
      .parser = parse_opt,
      .doc = N_("Process a stream of stack samples into stack traces.\n\
\n\
Utility is a work-in-progress, see README.eu-stacktrace in the source branch.")
    };

  argp_parse(&argp, argc, argv, 0, NULL, NULL);

  /* TODO Also handle common expansions e.g. ~/foo instead of /home/user/foo. */
  if (strcmp (input_path, "-") == 0)
    input_fd = STDIN_FILENO;
  else
    input_fd = open (input_path, O_RDONLY);
  if (input_fd < 0)
    error (EXIT_BAD, errno, N_("Cannot open input file or FIFO '%s'"), input_path);
  if (strcmp (output_path, "-") == 0)
    output_fd = STDOUT_FILENO;
  else
    output_fd = open (output_path, O_CREAT | O_WRONLY, 0640);
  if (output_fd < 0)
    error (EXIT_BAD, errno, N_("Cannot open output file or FIFO '%s'"), output_path);

#ifndef HAVE_SYSPROF_4_HEADERS
  /* TODO: Should hide corresponding command line options when this is the case. */
  error (EXIT_BAD, 0, N_("Sysprof support is not available in this version."));
#else
  /* TODO: For now, code the processing loop for sysprof only; generalize later. */
  assert (input_format == FORMAT_SYSPROF);
  assert (output_format == FORMAT_SYSPROF);
  SysprofReader *reader = sysprof_reader_begin (input_fd);
  ssize_t n_write = write (output_fd, &reader->header, sizeof reader->header);
  if (n_write < 0)
    error (EXIT_BAD, errno, N_("Write error to file or FIFO '%s'"), output_path);
  struct sysprof_passthru_info spi = { output_fd, reader, sizeof reader->header };
  ptrdiff_t offset = sysprof_reader_getframes (reader, &sysprof_passthru_cb, &spi);
  if (offset < 0)
    error (EXIT_BAD, errno, N_("No frames in file or FIFO '%s'"), input_path);
  sysprof_reader_end (reader);
#endif

  if (input_fd != -1)
    close (input_fd);
  if (output_fd != -1)
    close (output_fd);

  return EXIT_OK;
}
