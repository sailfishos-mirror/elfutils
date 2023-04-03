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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <config.h>
#include <argp.h>
#include <stdio.h>
#include <string.h>

static char *input_path = NULL;
static char *output_path = NULL;

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
	argp_error (state, N_("-i PATH needs an input file or FIFO."));

      if (output_path == NULL)
	argp_error (state, N_("-o PATH needs an output path or FIFO."));

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

  /* hello world */
}
