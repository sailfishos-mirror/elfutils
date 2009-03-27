/* Pedantic checking of DWARF files.
   Copyright (C) 2008,2009 Red Hat, Inc.
   This file is part of Red Hat elfutils.
   Written by Petr Machata <pmachata@redhat.com>, 2008.

   Red Hat elfutils is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by the
   Free Software Foundation; version 2 of the License.

   Red Hat elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with Red Hat elfutils; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301 USA.

   Red Hat elfutils is an included package of the Open Invention Network.
   An included package of the Open Invention Network is a package for which
   Open Invention Network licensees cross-license their patents.  No patent
   license is granted, either expressly or impliedly, by designation as an
   included package.  Should you wish to participate in the Open Invention
   Network licensing program, please visit www.openinventionnetwork.com
   <http://www.openinventionnetwork.com>.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <argp.h>
#include <assert.h>
#include <error.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <libintl.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <system.h>
#include <unistd.h>

#include "../libdw/dwarf.h"
#include "../libdw/libdwP.h"
#include "../libdw/known-dwarf.h"
#include "../libebl/libebl.h"
#include "dwarfstrings.h"
#include "dwarflint.h"

/* Bug report address.  */
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

#define ARGP_strict	300
#define ARGP_gnu	301
#define ARGP_tolerant	302
#define ARGP_ref        303
#define ARGP_nohl       304

#undef FIND_SECTION_HOLES

/* Definitions of arguments for argp functions.  */
static const struct argp_option options[] =
{
  { "strict", ARGP_strict, NULL, 0,
    N_("Be extremely strict, flag level 2 features."), 0 },
  { "quiet", 'q', NULL, 0, N_("Do not print anything if successful"), 0 },
  { "ignore-missing", 'i', NULL, 0,
    N_("Don't complain if files have no DWARF at all"), 0 },
  { "gnu", ARGP_gnu, NULL, 0,
    N_("Binary has been created with GNU toolchain and is therefore known to be \
broken in certain ways"), 0 },
  { "tolerant", ARGP_tolerant, NULL, 0,
    N_("Don't output certain common error messages"), 0 },
  { "ref", ARGP_ref, NULL, 0,
    N_("When validating .debug_loc and .debug_ranges, display information about \
the DIE referring to the entry in consideration"), 0 },
  { "nohl", ARGP_nohl, NULL, 0,
    N_("Don't run high-level tests"), 0 },
  { "verbose", 'v', NULL, 0,
    N_("Be verbose"), 0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

/* Short description of program.  */
static const char doc[] = N_("\
Pedantic checking of DWARF stored in ELF files.");

/* Strings for arguments in help texts.  */
static const char args_doc[] = N_("FILE...");

/* Prototype for option handler.  */
static error_t parse_opt (int key, char *arg, struct argp_state *state);

/* Data structure to communicate with argp functions.  */
static struct argp argp =
{
  options, parse_opt, args_doc, doc, NULL, NULL, NULL
};

/* If true, we accept silently files without debuginfo.  */
static bool tolerate_nodebug = false;

static void process_file (Dwarf *dwarf, const char *fname, bool only_one);

#define REALLOC(A, BUF)						\
  do {								\
    typeof ((A)) _a = (A);					\
    if (_a->size == _a->alloc)					\
      {								\
	if (_a->alloc == 0)					\
	  _a->alloc = 8;					\
	else							\
	  _a->alloc *= 2;					\
	_a->BUF = xrealloc (_a->BUF,				\
			    sizeof (*_a->BUF) * _a->alloc);	\
      }								\
  } while (0)

#define WIPE(OBJ) memset (&OBJ, 0, sizeof (OBJ))

struct message_term
{
  /* Given a term like A && !B && C && !D, we decompose it thus: */
  enum message_category positive; /* non-zero bits for plain predicates */
  enum message_category negative; /* non-zero bits for negated predicates */
};

struct message_criteria
{
  struct message_term *terms;
  size_t size;
  size_t alloc;
};

static bool
message_accept (struct message_criteria *cri, enum message_category cat)
{
  for (size_t i = 0; i < cri->size; ++i)
    {
      struct message_term *t = cri->terms + i;
      if ((t->positive & cat) == t->positive
	  && (t->negative & cat) == 0)
	return true;
    }
  return false;
}

static const char *
message_term_str (struct message_term *t)
{
  static char *names[] = {
#define MC(CAT, ID) [ID] = #CAT,
    MESSAGE_CATEGORIES
#undef MC
  };

  unsigned max = 0;
#define MC(CAT, ID) max = ID;
  MESSAGE_CATEGORIES
#undef MC

  static char buf[512];
  char *ptr = buf;
  ptr = stpcpy (ptr, "(");

  bool got = false;
  for (unsigned i = 0; i <= max; ++i)
    {
      unsigned mask = 1u << i;
      if ((t->positive & mask) != 0
	  || (t->negative & mask) != 0)
	{
	  if (got)
	    ptr = stpcpy (ptr, " & ");
	  if ((t->negative & (1u << i)) != 0)
	    ptr = stpcpy (ptr, "~");
	  ptr = stpcpy (ptr, names[i]);
	  got = true;
	}
    }

  if (ptr == buf + 1)
    ptr = stpcpy (ptr, "1");
  ptr = stpcpy (ptr, ")");
  return buf;
}

static const char *
message_cri_str (struct message_criteria *cri)
{
  static char buf[512];
  char *ptr = buf;
  *ptr = 0;

  for (size_t i = 0; i < cri->size; ++i)
    {
      struct message_term *t = cri->terms + i;
      if (i > 0)
	ptr = stpcpy (ptr, " | ");
      ptr = stpcpy (ptr, message_term_str (t));
    }

  return buf;
}

static void
message_cri_and (struct message_criteria *cri, struct message_term *term)
{
  assert ((term->positive & term->negative) == 0);
  for (size_t i = 0; i < cri->size; )
    {
      struct message_term *t = cri->terms + i;
      t->positive |= term->positive;
      t->negative |= term->negative;
      if ((t->positive & t->negative) != 0)
	/* A ^ ~A -> drop the term.  */
	cri->terms[i] = cri->terms[--cri->size];
      else
	++i;
    }
}

static void
message_cri_or (struct message_criteria *cri, struct message_term *term)
{
  assert ((term->positive & term->negative) == 0);
  REALLOC (cri, terms);
  cri->terms[cri->size++] = *term;
}

/* NEG(a&b&~c) -> (~a + ~b + c) */
static struct message_criteria
message_cri_neg (struct message_term *term)
{
  assert ((term->positive & term->negative) == 0);

  unsigned max = 0;
#define MC(CAT, ID) max = ID;
  MESSAGE_CATEGORIES
#undef MC

  struct message_criteria ret;
  WIPE (ret);
  for (size_t i = 0; i < max; ++i)
    {
      unsigned mask = 1u << i;
      if ((term->positive & mask) != 0)
	message_cri_or (&ret, &(struct message_term){1u << i, mc_none});
      else if ((term->negative & mask) != 0)
	message_cri_or (&ret, &(struct message_term){mc_none, 1u << i});
    }

  return ret;
}

/* MUL((a&b + c&d), (e&f + g&h)) -> (a&b&e&f + a&b&g&h + c&d&e&f + c&d&g&h) */
static void
message_cri_mul (struct message_criteria *cri, struct message_criteria *rhs)
{
  struct message_criteria ret;
  WIPE (ret);

  for (size_t i = 0; i < cri->size; ++i)
    for (size_t j = 0; j < rhs->size; ++j)
      {
	struct message_term t1 = cri->terms[i];
	struct message_term *t2 = rhs->terms + j;
	t1.positive |= t2->positive;
	t1.negative |= t2->negative;
	if (t1.positive & t1.negative)
	  /* A ^ ~A -> drop the term.  */
	  continue;
	message_cri_or (&ret, &t1);
      }

  free (cri->terms);
  *cri = ret;
}

/* Reject message if TERM passes.  */
static void
message_cri_and_not (struct message_criteria *cri, struct message_term *term)
{
  struct message_criteria tmp
    = message_cri_neg (&(struct message_term) {term->negative, term->positive});
  message_cri_mul (cri, &tmp);
  free (tmp.terms);
}

/* Messages that are accepted (and made into warning).  */
static struct message_criteria warning_criteria;

/* Accepted (warning) messages, that are turned into errors.  */
static struct message_criteria error_criteria;

static unsigned error_count = 0;

static bool
check_category (enum message_category cat)
{
  return message_accept (&warning_criteria, cat);
}

static void
wr_verror (const struct where *wh, const char *format, va_list ap)
{
  printf ("error: %s", where_fmt (wh, NULL));
  vprintf (format, ap);
  where_fmt_chain (wh, "error");
  ++error_count;
}

static void
wr_vwarning (const struct where *wh, const char *format, va_list ap)
{
  printf ("warning: %s", where_fmt (wh, NULL));
  vprintf (format, ap);
  where_fmt_chain (wh, "warning");
  ++error_count;
}

void
wr_error (const struct where *wh, const char *format, ...)
{
  va_list ap;
  va_start (ap, format);
  wr_verror (wh, format, ap);
  va_end (ap);
}

void
wr_warning (const struct where *wh, const char *format, ...)
{
  va_list ap;
  va_start (ap, format);
  wr_vwarning (wh, format, ap);
  va_end (ap);
}

void
wr_message (enum message_category category, const struct where *wh,
	    const char *format, ...)
{
  va_list ap;
  va_start (ap, format);
  if (message_accept (&warning_criteria, category))
    {
      if (message_accept (&error_criteria, category))
	wr_verror (wh, format, ap);
      else
	wr_vwarning (wh, format, ap);
    }
  va_end (ap);
}

void
wr_format_padding_message (enum message_category category,
			   struct where *wh,
			   uint64_t start, uint64_t end, char *kind)
{
  wr_message (category, wh,
	      ": 0x%" PRIx64 "..0x%" PRIx64 ": %s.\n", start, end, kind);
}

void
wr_format_leb128_message (struct where *where, const char *what,
			  const char *purpose,
			  const unsigned char *begin, const unsigned char *end)
{
  enum message_category category = mc_leb128 | mc_acc_bloat | mc_impact_3;
  char buf[(end - begin) * 3 + 1]; // 2 hexa digits+" " per byte, and term. 0
  char *ptr = buf;
  for (; begin < end; ++begin)
    ptr += sprintf (ptr, " %02x", *begin);
  wr_message (category, where,
	      ": %s: value %s encoded as `%s'.\n",
	      what, purpose, buf + 1);
}

void
wr_message_padding_0 (enum message_category category,
		      struct where *wh,
		      uint64_t start, uint64_t end)
{
  wr_format_padding_message (category | mc_acc_bloat | mc_impact_1,
			     wh, start, end,
			     "unnecessary padding with zero bytes");
}

void
wr_message_padding_n0 (enum message_category category,
		       struct where *wh,
		       uint64_t start, uint64_t end)
{
  wr_format_padding_message (category | mc_acc_bloat | mc_impact_1,
			     wh, start, end,
			     "unreferenced non-zero bytes");
}

/* True if no message is to be printed if the run is succesful.  */
static bool be_quiet = false; /* -q */
static bool be_verbose = false; /* -v */
static bool be_strict = false; /* --strict */
static bool be_gnu = false; /* --gnu */
static bool be_tolerant = false; /* --tolerant */
static bool show_refs = false; /* --ref */
static bool do_high_level = true; /* ! --nohl */

int
main (int argc, char *argv[])
{
  /* Set locale.  */
  setlocale (LC_ALL, "");

  /* Initialize the message catalog.  */
  textdomain (PACKAGE_TARNAME);

  /* Parse and process arguments.  */
  int remaining;
  argp_parse (&argp, argc, argv, 0, &remaining, NULL);

  /* Initialize warning & error criteria.  */
  message_cri_or (&warning_criteria,
		  &(struct message_term){mc_none, mc_none});

  message_cri_or (&error_criteria,
		  &(struct message_term){mc_impact_4, mc_none});
  message_cri_or (&error_criteria,
		  &(struct message_term){mc_error, mc_none});

  /* Configure warning & error criteria according to configuration.  */
  if (tolerate_nodebug)
    message_cri_and (&warning_criteria,
		     &(struct message_term){mc_none, mc_elf});

  if (be_gnu)
    {
      message_cri_and (&warning_criteria,
		       &(struct message_term){mc_none, mc_acc_bloat});
    }

  if (!be_strict)
    {
      message_cri_and (&warning_criteria,
		       &(struct message_term){mc_none, mc_strings});
      message_cri_and_not (&warning_criteria,
			   &(struct message_term)
			    {mc_line | mc_header | mc_acc_bloat, mc_none});
      message_cri_and (&warning_criteria,
		       &(struct message_term){mc_none, mc_pubtypes});
    }

  if (be_tolerant)
    {
      message_cri_and (&warning_criteria,
		       &(struct message_term){mc_none, mc_loc});
      message_cri_and (&warning_criteria,
		       &(struct message_term){mc_none, mc_ranges});
    }

  if (be_verbose)
    {
      printf ("warning criteria: %s\n", message_cri_str (&warning_criteria));
      printf ("error criteria:   %s\n", message_cri_str (&error_criteria));
    }

  /* Before we start tell the ELF library which version we are using.  */
  elf_version (EV_CURRENT);

  /* Now process all the files given at the command line.  */
  bool only_one = remaining + 1 == argc;
  do
    {
      /* Open the file.  */
      int fd = open (argv[remaining], O_RDONLY);
      if (fd == -1)
	{
	  error (0, errno, gettext ("cannot open input file"));
	  continue;
	}

      /* Create an `Elf' descriptor.  */
      Elf *elf = elf_begin (fd, ELF_C_READ_MMAP, NULL);
      if (elf == NULL)
	wr_error (NULL,
		  gettext ("cannot generate Elf descriptor: %s\n"),
		  elf_errmsg (-1));
      else
	{
	  unsigned int prev_error_count = error_count;
	  Dwarf *dwarf = dwarf_begin_elf (elf, DWARF_C_READ, NULL);
	  if (dwarf == NULL)
	    {
	      if (!tolerate_nodebug)
		wr_error (NULL,
			  gettext ("cannot generate Dwarf descriptor: %s\n"),
			  dwarf_errmsg (-1));
	    }
	  else
	    {
	      process_file (dwarf, argv[remaining], only_one);

	      if (dwarf_end (dwarf) != 0)
		wr_error (NULL,
			  gettext ("error while closing Dwarf descriptor: %s\n"),
			  dwarf_errmsg (-1));
	    }

	  if (elf_end (elf) != 0)
	    wr_error (NULL,
		      gettext ("error while closing Elf descriptor: %s\n"),
		      elf_errmsg (-1));

	  if (prev_error_count == error_count && !be_quiet)
	    puts (gettext ("No errors"));
	}

      close (fd);
    }
  while (++remaining < argc);

  return error_count != 0;
}

/* Handle program arguments.  */
static error_t
parse_opt (int key, char *arg __attribute__ ((unused)),
	   struct argp_state *state __attribute__ ((unused)))
{
  switch (key)
    {
    case ARGP_strict:
      be_strict = true;
      break;

    case ARGP_gnu:
      be_gnu = true;
      break;

    case ARGP_tolerant:
      be_tolerant = true;
      break;

    case ARGP_ref:
      show_refs = true;
      break;

    case ARGP_nohl:
      do_high_level = false;
      break;

    case 'i':
      tolerate_nodebug = true;
      break;

    case 'q':
      be_quiet = true;
      be_verbose = false;
      break;

    case 'v':
      be_quiet = false;
      be_verbose = true;
      break;

    case ARGP_KEY_NO_ARGS:
      fputs (gettext ("Missing file name.\n"), stderr);
      argp_help (&argp, stderr, ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR,
		 program_invocation_short_name);
      exit (1);

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

#define PRI_CU "CU 0x%" PRIx64
#define PRI_DIE "DIE 0x%" PRIx64
#define PRI_NOT_ENOUGH ": not enough data for %s.\n"
#define PRI_LACK_RELOCATION ": %s seems to lack a relocation.\n"

struct sec
{
  enum section_id id;
  GElf_Shdr shdr;
};

struct elf_file
{
  Dwarf *dwarf;
  Ebl *ebl;
  GElf_Ehdr ehdr;	/* Header of dwarf->elf.  */
  bool addr_64;

  struct sec *sec;	/* Array of sections.  */
  size_t size;
  size_t alloc;
};

struct relocation
{
  uint64_t offset;
  uint64_t addend;
  int symndx;
  int type;
  bool invalid;		/* Whether this one relocation should be
			   ignored.  Necessary so that we don't
			   double-report invalid & missing
			   relocation.  */
};

struct relocation_data
{
  struct elf_file *file;
  Elf_Data *symdata;	/* Symbol table associated with this
			   relocation section.  */
  size_t type;		/* SHT_REL or SHT_RELA.  */

  struct relocation *rel;	/* Array of relocations.  May be NULL
				   if there are no associated
				   relocation data.  */
  size_t size;
  size_t alloc;
  size_t index;		/* Current index. */
};

struct section_data
{
  struct elf_file *file;
  size_t secndx;	/* Index into file->sec.  */
  Elf_Data *data;
  struct relocation_data rel;
};

static struct sec *
data_get_sec (struct section_data *data)
{
  return data->file->sec + data->secndx;
}

/* Functions and data structures related to bounds-checked
   reading.  */

struct read_ctx
{
  Dwarf *dbg;
  Elf_Data *data;
  const unsigned char *ptr;
  const unsigned char *begin;
  const unsigned char *end;
};


static void read_ctx_init (struct read_ctx *ctx, Dwarf *dbg,
			   Elf_Data *data);
static bool read_ctx_init_sub (struct read_ctx *ctx,
			       struct read_ctx *parent,
			       const unsigned char *begin,
			       const unsigned char *end);
static uint64_t read_ctx_get_offset (struct read_ctx *ctx);
static bool read_ctx_need_data (struct read_ctx *ctx, size_t length);
static bool read_ctx_read_ubyte (struct read_ctx *ctx, unsigned char *ret);
static int read_ctx_read_uleb128 (struct read_ctx *ctx, uint64_t *ret);
static int read_ctx_read_sleb128 (struct read_ctx *ctx, int64_t *ret);
static bool read_ctx_read_2ubyte (struct read_ctx *ctx, uint16_t *ret);
static bool read_ctx_read_4ubyte (struct read_ctx *ctx, uint32_t *ret);
static bool read_ctx_read_8ubyte (struct read_ctx *ctx, uint64_t *ret);
static bool read_ctx_read_offset (struct read_ctx *ctx, bool dwarf64,
				  uint64_t *ret);
static bool read_ctx_read_var (struct read_ctx *ctx, int width, uint64_t *ret);
static const char *read_ctx_read_str (struct read_ctx *ctx);
static bool read_ctx_skip (struct read_ctx *ctx, uint64_t len);
static bool read_ctx_eof (struct read_ctx *ctx);


/* Functions and data structures related to raw (i.e. unassisted by
   libdw) Dwarf abbreviation handling.  */

struct abbrev
{
  uint64_t code;

  /* While ULEB128 can hold numbers > 32bit, these are not legal
     values of many enum types.  So just use as large type as
     necessary to cover valid values.  */
  uint16_t tag;
  bool has_children;

  /* Whether some DIE uses this abbrev.  */
  bool used;

  /* Attributes.  */
  struct abbrev_attrib
  {
    uint16_t name;
    uint8_t form;
    struct where where;
  } *attribs;
  size_t size;
  size_t alloc;
};

struct abbrev_table
{
  uint64_t offset;
  struct abbrev *abbr;
  size_t size;
  size_t alloc;
  struct abbrev_table *next;
};

static struct abbrev_table *abbrev_table_load (struct read_ctx *ctx);
static void abbrev_table_free (struct abbrev_table *abbr);
static struct abbrev *abbrev_table_find_abbrev (struct abbrev_table *abbrevs,
						uint64_t abbrev_code);


/* Functions and data structures for address record handling.  We use
   that to check that all DIE references actually point to an existing
   die, not somewhere mid-DIE, where it just happens to be
   interpretable as a DIE.  */

struct addr_record
{
  size_t size;
  size_t alloc;
  uint64_t *addrs;
};

static size_t addr_record_find_addr (struct addr_record *ar, uint64_t addr);
static bool addr_record_has_addr (struct addr_record *ar, uint64_t addr);
static void addr_record_add (struct addr_record *ar, uint64_t addr);
static void addr_record_free (struct addr_record *ar);


/* Functions and data structures for reference handling.  Just like
   the above, we use this to check validity of DIE references.  Unlike
   the above, this is not stored as sorted set, but simply as an array
   of records, because duplicates are unlikely.  */

struct ref
{
  uint64_t addr; // Referree address
  struct where who;  // Referrer
};

struct ref_record
{
  size_t size;
  size_t alloc;
  struct ref *refs;
};

static void ref_record_add (struct ref_record *rr, uint64_t addr, struct where *referrer);
static void ref_record_free (struct ref_record *rr);


/* Functions and data structures for CU handling.  */

struct cu
{
  uint64_t offset;
  uint64_t cudie_offset;
  uint64_t length;
  int address_size;             // Address size in bytes on the target machine.
  uint64_t base;                // DW_AT_low_pc value of CU DIE, 0 if not present.
  struct addr_record die_addrs; // Addresses where DIEs begin in this CU.
  struct ref_record die_refs;   // DIE references into other CUs from this CU.
  struct ref_record loc_refs;   // references into .debug_loc from this CU.
  struct ref_record range_refs; // references into .debug_ranges from this CU.
  struct ref_record line_refs;	// references into .debug_line from this CU.
  struct where where;           // Where was this section defined.
  bool has_arange;              // Whether we saw arange section pointing to this CU.
  bool has_pubnames;            // Likewise for pubnames.
  bool has_pubtypes;            // Likewise for pubtypes.
  struct cu *next;
};

static void cu_free (struct cu *cu_chain);
static struct cu *cu_find_cu (struct cu *cu_chain, uint64_t offset);


/* Functions for checking of structural integrity.  */

static struct cu * check_info_structural (struct section_data *data,
					  struct abbrev_table *abbrev_chain,
					  Elf_Data *strings);

static bool check_aranges_structural (struct section_data *data,
				      struct cu *cu_chain);

static bool check_pub_structural (struct section_data *data,
				  struct cu *cu_chain);

static bool check_location_expression (struct read_ctx *ctx,
				       uint64_t init_off,
				       struct relocation_data *reloc,
				       size_t length,
				       struct where *wh,
				       bool addr_64);

static bool check_loc_or_range_structural (struct section_data *data,
					   struct cu *cu_chain);

static bool read_rel (struct section_data *secdata,
		      Elf_Data *reldata,
		      bool elf_64);

static bool check_line_structural (struct section_data *data,
				   struct cu *cu_chain);

const char *
where_fmt (const struct where *wh, char *ptr)
{
  if (wh == NULL)
    return "";

  static char buf[256];

  struct section_info
  {
    const char *name;
    const char *addr1n;
    const char *addr1f;
    const char *addr2n;
    const char *addr2f;
    const char *addr3n;
    const char *addr3f;
  };

  static struct section_info section_names[] =
    {
      [sec_info] = {".debug_info", "CU", "%"PRId64,
		    "DIE", "%#"PRIx64, NULL, NULL},

      [sec_abbrev] = {".debug_abbrev", "section", "%"PRId64,
		      "abbreviation", "%"PRId64, "abbr. attribute", "%#"PRIx64},

      [sec_aranges] = {".debug_aranges", "table", "%"PRId64,
		       "arange", "%#"PRIx64, NULL, NULL},

      [sec_pubnames] = {".debug_pubnames", "pubname table", "%"PRId64,
			"pubname", "%#"PRIx64, NULL, NULL},

      [sec_pubtypes] = {".debug_pubtypes", "pubtype table", "%"PRId64,
			"pubtype", "%#"PRIx64, NULL, NULL},

      [sec_str] = {".debug_str", "offset", "%#"PRIx64,
		   NULL, NULL, NULL, NULL},

      [sec_line] = {".debug_line", "table", "%"PRId64,
		    "offset", "%#"PRIx64, NULL, NULL},

      [sec_loc] = {".debug_loc", "loclist", "%#"PRIx64,
		   "offset", "%#"PRIx64, NULL, NULL},

      [sec_mac] = {".debug_mac", NULL, NULL, NULL, NULL, NULL, NULL},

      [sec_ranges] = {".debug_ranges", "rangelist", "%#"PRIx64,
		      "offset", "%#"PRIx64, NULL, NULL},

      [sec_locexpr] = {"location expression", "offset", "%#"PRIx64,
		       NULL, NULL, NULL, NULL},

      [sec_rel] = {".rel", "relocation", "%"PRId64,
		   "offset", "%#"PRIx64, NULL, NULL},
      [sec_rela] = {".rela", "relocation", "%"PRId64,
		    "offset", "%#"PRIx64, NULL, NULL},

      [sec_text] = {"(exec data)", NULL, NULL, NULL, NULL, NULL, NULL},
    };

  static struct section_info special_formats[] =
    {
      [wf_cudie] = {".debug_info", "CU DIE", "%"PRId64, NULL, NULL, NULL, NULL}
    };

  assert (wh->section < sizeof (section_names) / sizeof (*section_names));
  struct section_info *inf
    = (wh->formatting == wf_plain)
    ? section_names + wh->section
    : special_formats + wh->formatting;

  assert (inf->name);

  assert ((inf->addr1n == NULL) == (inf->addr1f == NULL));
  assert ((inf->addr2n == NULL) == (inf->addr2f == NULL));
  assert ((inf->addr3n == NULL) == (inf->addr3f == NULL));

  assert ((wh->addr1 != (uint64_t)-1) ? inf->addr1n != NULL : true);
  assert ((wh->addr2 != (uint64_t)-1) ? inf->addr2n != NULL : true);
  assert ((wh->addr3 != (uint64_t)-1) ? inf->addr3n != NULL : true);

  assert ((wh->addr3 != (uint64_t)-1) ? (wh->addr2 != (uint64_t)-1) : true);
  assert ((wh->addr2 != (uint64_t)-1) ? (wh->addr1 != (uint64_t)-1) : true);

  /* GCC insists on checking format parameters and emits a warning
     when we don't use string literal.  With -Werror this ends up
     being hard error.  So instead we walk around this warning by
     using function pointer.  */
  int (*x_asprintf)(char **strp, const char *fmt, ...) = asprintf;

#define SETUP_ADDR(N)							\
  char *addr##N##s;							\
  if (wh->addr##N == (uint64_t)-1)					\
    addr##N##s = NULL;							\
  else if (x_asprintf (&addr##N##s, inf->addr##N##f, wh->addr##N) < 0)	\
    addr##N##s = "(fmt error)"

  SETUP_ADDR (1);
  SETUP_ADDR (2);
  SETUP_ADDR (3);
#undef SETUP_ADDR

  char *orig = ptr;
  bool is_reloc = wh->section == sec_rel || wh->section == sec_rela;
  if (ptr == NULL)
    {
      ptr = stpcpy (buf, inf->name);
      if (is_reloc)
	{
	  struct where *ref = wh->ref;
	  assert (ref != NULL);
	  if (ref->section == sec_locexpr)
	    {
	      ref = ref->next;
	      assert (ref != NULL);
	      assert (ref->section != sec_locexpr);
	    }
	  ptr = stpcpy (ptr, section_names[ref->section].name);
	}

      if (addr1s != NULL)
	ptr = stpcpy (ptr, ": ");
    }

  if (addr3s != NULL)
    ptr = stpcpy (stpcpy (stpcpy (ptr, inf->addr3n), " "), addr3s);
  else if (addr2s != NULL)
    ptr = stpcpy (stpcpy (stpcpy (ptr, inf->addr2n), " "), addr2s);
  else if (addr1s != NULL)
    ptr = stpcpy (stpcpy (stpcpy (ptr, inf->addr1n), " "), addr1s);

  if (wh->ref != NULL && !is_reloc)
    {
      ptr = stpcpy (ptr, " (");
      ptr = (char *)where_fmt (wh->ref, ptr);
      *ptr++ = ')';
      *ptr = 0;
    }

  if (orig == NULL)
    return buf;
  else
    return ptr;
}

void
where_fmt_chain (const struct where *wh, const char *severity)
{
  if (wh != NULL && show_refs)
    for (struct where *it = wh->next; it != NULL; it = it->next)
      printf ("%s: %s: caused by this reference.\n",
	      severity, where_fmt (it, NULL));
}

void
where_reset_1 (struct where *wh, uint64_t addr)
{
  wh->addr1 = addr;
  wh->addr2 = wh->addr3 = (uint64_t)-1;
}

void
where_reset_2 (struct where *wh, uint64_t addr)
{
  wh->addr2 = addr;
  wh->addr3 = (uint64_t)-1;
}

void
where_reset_3 (struct where *wh, uint64_t addr)
{
  wh->addr3 = addr;
}

#define WHERE_SECDATA(DATA, PARENT) (WHERE (data_get_sec (DATA)->id, PARENT))

static void
process_file (Dwarf *dwarf, const char *fname, bool only_one)
{
  if (!only_one)
    printf ("\n%s:\n", fname);

  struct elf_file file;
  WIPE (file);

  file.dwarf = dwarf;
  file.ebl = ebl_openbackend (dwarf->elf);
  if (file.ebl == NULL)
    goto invalid_elf;
  if (gelf_getehdr (dwarf->elf, &file.ehdr) == NULL)
    goto invalid_elf;
  file.addr_64 = file.ehdr.e_ident[EI_CLASS] == ELFCLASS64;

#define DEF_SECDATA(VAR, SEC)					\
  struct section_data VAR = {&file, (size_t)-1, NULL,		\
			     {&file, NULL, SHT_NULL, NULL, 0, 0, 0}}

  DEF_SECDATA (abbrev_data, sec_abbrev);
  DEF_SECDATA (aranges_data, sec_aranges);
  DEF_SECDATA (info_data, sec_info);
  DEF_SECDATA (line_data, sec_line);
  DEF_SECDATA (loc_data, sec_loc);
  DEF_SECDATA (pubnames_data, sec_pubnames);
  DEF_SECDATA (pubtypes_data, sec_pubtypes);
  DEF_SECDATA (ranges_data, sec_ranges);
  DEF_SECDATA (str_data, sec_str);

#undef DEF_SECDATA

  struct secinfo
  {
    const char *name;
    struct section_data *dataptr;
    Elf_Data *reldata;
    enum section_id sec;
  };
  struct secinfo secinfo[] = {
#define DEF_SECINFO(SEC) {".debug_" #SEC, &SEC##_data, NULL, sec_##SEC}
#define DEF_NOINFO(SEC)  {".debug_" #SEC, NULL, NULL, sec_##SEC}
    DEF_SECINFO (abbrev),
    DEF_SECINFO (aranges),
    DEF_SECINFO (info),
    DEF_SECINFO (line),
    DEF_SECINFO (loc),
    DEF_SECINFO (pubnames),
    DEF_SECINFO (pubtypes),
    DEF_SECINFO (ranges),
    DEF_SECINFO (str),
#undef DEF_NOINFO
#undef DEF_SECINFO
  };

  Elf_Scn *reloc_symtab = NULL;

  struct secinfo *find_secentry (const char *secname)
  {
    for (size_t i = 0; i < sizeof (secinfo) / sizeof (*secinfo); ++i)
      if (strcmp (secinfo[i].name, secname) == 0)
	return secinfo + i;
    return NULL;
  }

  struct section_data *find_secdata (const char *secname)
  {
    struct secinfo *info = find_secentry (secname);
    if (info != NULL)
      return info->dataptr;
    else
      return NULL;
  }

  /* Now find all necessary debuginfo sections and associated
     relocation sections.  */

  Elf_Scn *scn = NULL;

  /* Section 0 is special, skip it.  */
  REALLOC (&file, sec);
  file.sec[file.size++].id = sec_invalid;

  while ((scn = elf_nextscn (dwarf->elf, scn)) != NULL)
    {
      REALLOC (&file, sec);
      size_t curndx = file.size++;
      struct sec *cursec = file.sec + curndx;

      GElf_Shdr *shdr = gelf_getshdr (scn, &cursec->shdr);
      if (shdr == NULL)
	{
	invalid_elf:
	  /* A "can't happen".  libdw already managed to parse the Elf
	     file when constructing the Dwarf object.  */
	  wr_error (NULL, "Broken ELF.\n");
	  goto skip_rel;
	}

      const char *scnname = elf_strptr (dwarf->elf, file.ehdr.e_shstrndx,
					shdr->sh_name);
      if (scnname == NULL)
	goto invalid_elf;

      struct secinfo *secentry = find_secentry (scnname);
      struct section_data *secdata = secentry != NULL ? secentry->dataptr : NULL;
      cursec->id = secentry != NULL ? secentry->sec : sec_invalid;

      if (secdata != NULL)
	{
	  if (secdata->secndx == (size_t)-1)
	    {
	      secdata->data = elf_getdata (scn, NULL);
	      if (secdata->data == NULL || secdata->data->d_buf == NULL)
		wr_error (NULL, "Data-less section %s.\n", scnname);
	      secdata->secndx = curndx;
	    }
	  else
	    wr_error (NULL, "Multiple occurrences of section %s.\n", scnname);
	}
      else if ((shdr->sh_flags & SHF_ALLOC) && (shdr->sh_flags & SHF_EXECINSTR))
	cursec->id = sec_text;
      else if (shdr->sh_type == SHT_RELA || shdr->sh_type == SHT_REL)
	{
	  /* Get data of section that this REL(A) section relocates.  */
	  Elf_Scn *relocated_scn = elf_getscn (dwarf->elf, shdr->sh_info);
	  Elf_Scn *symtab_scn = elf_getscn (dwarf->elf, shdr->sh_link);
	  if (relocated_scn == NULL || symtab_scn == NULL)
	    goto invalid_elf;

	  GElf_Shdr relocated_shdr_mem;
	  GElf_Shdr *relocated_shdr = gelf_getshdr (relocated_scn,
						    &relocated_shdr_mem);
	  if (relocated_shdr == NULL)
	    goto invalid_elf;

	  const char *relocated_scnname
	    = elf_strptr (dwarf->elf, file.ehdr.e_shstrndx,
			  relocated_shdr->sh_name);

	  struct secinfo *relocated
	    = find_secentry (relocated_scnname);

	  if (relocated != NULL && relocated->dataptr != NULL)
	    {
	      if (relocated->reldata != NULL)
		wr_error (NULL,
			  "Several relocation sections for debug section %s."
			  "  Ignoring %s.\n",
			  relocated_scnname, scnname);
	      else
		{
		  relocated->reldata = elf_getdata (scn, NULL);
		  if (relocated->reldata == NULL)
		    wr_error (NULL,
			      "Data-less relocation section %s.\n", scnname);
		  relocated->dataptr->rel.type = shdr->sh_type;
		}

	      if (reloc_symtab == NULL)
		reloc_symtab = symtab_scn;
	      else if (reloc_symtab != symtab_scn)
		wr_error (NULL,
			  "Relocation sections use multiple symbol tables.\n");
	    }
	}
    }

  Elf_Data *reloc_symdata = NULL;
  if (reloc_symtab != NULL)
    {
      reloc_symdata = elf_getdata (reloc_symtab, NULL);
      if (reloc_symdata == NULL)
	{
	  wr_error (NULL,
		    "Couldn't obtain symtab data.\n");
	  /* But carry on, we can check a lot of stuff even without
	     symbol table.  */
	}
    }

  /* Check relocation sections that we've got.  */
  for (size_t i = 0; i < sizeof (secinfo) / sizeof (*secinfo); ++i)
    {
      struct secinfo *cur = secinfo + i;
      if (cur->dataptr != NULL
	  && cur->reldata != NULL)
	{
	  if (cur->dataptr->data == NULL)
	    wr_error (&WHERE_SECDATA (secinfo[i].dataptr, NULL),
		      ": this data-less section has a relocation section.\n");
	  else if (read_rel (cur->dataptr, cur->reldata, file.addr_64))
	    cur->dataptr->rel.symdata = reloc_symdata;
	}
    }

  if (str_data.rel.size > 0)
    wr_message (mc_impact_2 | mc_elf, &WHERE (sec_str, NULL),
		": there's a relocation section associated with this section.\n");

 skip_rel:;
  struct abbrev_table *abbrev_chain = NULL;
  struct cu *cu_chain = NULL;
  struct read_ctx ctx;
  struct hl_ctx *hlctx = hl_ctx_new (dwarf);

  /* If we got Dwarf pointer, .debug_abbrev and .debug_info are
     present inside the file.  But let's be paranoid.  */
  if (likely (abbrev_data.data != NULL))
    {
      read_ctx_init (&ctx, dwarf, abbrev_data.data);
      abbrev_chain = abbrev_table_load (&ctx);
    }
  else if (!tolerate_nodebug)
    /* Hard error, not a message.  We can't debug without this.  */
    wr_error (NULL, ".debug_abbrev data not found.\n");

  if (abbrev_chain != NULL)
    {
      if (info_data.data != NULL)
	{
	  cu_chain = check_info_structural (&info_data, abbrev_chain,
					    str_data.data);
	  if (cu_chain != NULL && do_high_level)
	    check_expected_trees (hlctx);
	}
      else if (!tolerate_nodebug)
	/* Hard error, not a message.  We can't debug without this.  */
	wr_error (NULL, ".debug_info data not found.\n");
    }

  bool ranges_sound;
  if (ranges_data.data != NULL && cu_chain != NULL)
    ranges_sound = check_loc_or_range_structural (&ranges_data, cu_chain);
  else
    ranges_sound = false;

  if (loc_data.data != NULL && cu_chain != NULL)
    check_loc_or_range_structural (&loc_data, cu_chain);

  if (aranges_data.data != NULL)
    {
      read_ctx_init (&ctx, dwarf, aranges_data.data);
      if (check_aranges_structural (&aranges_data, cu_chain)
	  && ranges_sound && do_high_level)
	check_matching_ranges (hlctx);
    }

  if (pubnames_data.data != NULL)
    check_pub_structural (&pubnames_data, cu_chain);
  else
    wr_message (mc_impact_4 | mc_acc_suboptimal | mc_elf,
		&WHERE (sec_pubnames, NULL), ": data not found.\n");

  if (pubtypes_data.data != NULL)
    check_pub_structural (&pubtypes_data, cu_chain);
  else
    wr_message (mc_impact_4 | mc_acc_suboptimal | mc_elf | mc_pubtypes,
		&WHERE (sec_pubtypes, NULL), ": data not found.\n");

  if (line_data.data != NULL)
    check_line_structural (&line_data, cu_chain);
  else
    wr_message (mc_impact_4 | mc_acc_suboptimal | mc_elf | mc_loc,
		&WHERE (sec_line, NULL), ": data not found.\n");

  cu_free (cu_chain);
  abbrev_table_free (abbrev_chain);
  if (file.ebl != NULL)
    ebl_closebackend (file.ebl);
  free (file.sec);
  hl_ctx_delete (hlctx);
}

static void
read_ctx_init (struct read_ctx *ctx, Dwarf *dbg, Elf_Data *data)
{
  if (data == NULL)
    abort ();

  ctx->dbg = dbg;
  ctx->data = data;
  ctx->begin = data->d_buf;
  ctx->end = data->d_buf + data->d_size;
  ctx->ptr = data->d_buf;
}

static bool
read_ctx_init_sub (struct read_ctx *ctx, struct read_ctx *parent,
		   const unsigned char *begin, const unsigned char *end)
{
  if (parent == NULL)
    abort ();

  if (begin < parent->begin
      || end > parent->end)
    return false;

  ctx->dbg = parent->dbg;
  ctx->data = parent->data;
  ctx->begin = begin;
  ctx->end = end;
  ctx->ptr = begin;
  return true;
}

static uint64_t
read_ctx_get_offset (struct read_ctx *ctx)
{
  assert (ctx->ptr >= ctx->begin);
  return (uint64_t)(ctx->ptr - ctx->begin);
}

static bool
read_ctx_need_data (struct read_ctx *ctx, size_t length)
{
  const unsigned char *ptr = ctx->ptr + length;
  return ptr <= ctx->end && (length == 0 || ptr > ctx->ptr);
}

static bool
read_ctx_read_ubyte (struct read_ctx *ctx, unsigned char *ret)
{
  if (!read_ctx_need_data (ctx, 1))
    return false;
  if (ret != NULL)
    *ret = *ctx->ptr;
  ctx->ptr++;
  return true;
}

static int
read_ctx_read_uleb128 (struct read_ctx *ctx, uint64_t *ret)
{
  uint64_t result = 0;
  int shift = 0;
  int size = 8 * sizeof (result);
  bool zero_tail = false;

  while (1)
    {
      uint8_t byte;
      if (!read_ctx_read_ubyte (ctx, &byte))
	return -1;

      uint8_t payload = byte & 0x7f;
      zero_tail = payload == 0 && shift > 0;
      result |= (uint64_t)payload << shift;
      shift += 7;
      if (shift > size && byte != 0x1)
	return -1;
      if ((byte & 0x80) == 0)
	break;
    }

  if (ret != NULL)
    *ret = result;
  return zero_tail ? 1 : 0;
}

static bool
checked_read_uleb128 (struct read_ctx *ctx, uint64_t *ret,
		      struct where *where, const char *what)
{
  const unsigned char *ptr = ctx->ptr;
  int st = read_ctx_read_uleb128 (ctx, ret);
  if (st < 0)
    wr_error (where, ": can't read %s.\n", what);
  else if (st > 0)
    {
      char buf[19]; // 16 hexa digits, "0x", terminating zero
      sprintf (buf, "%#" PRIx64, *ret);
      wr_format_leb128_message (where, what, buf, ptr, ctx->ptr);
    }
  return st >= 0;
}

static int
read_ctx_read_sleb128 (struct read_ctx *ctx, int64_t *ret)
{
  int64_t result = 0;
  int shift = 0;
  int size = 8 * sizeof (result);
  bool zero_tail = false;
  bool sign = false;

  while (1)
    {
      uint8_t byte;
      if (!read_ctx_read_ubyte (ctx, &byte))
	return -1;

      uint8_t payload = byte & 0x7f;
      zero_tail = shift > 0 && ((payload == 0x7f && sign)
				|| (payload == 0 && !sign));
      sign = (byte & 0x40) != 0; /* Set sign for rest of loop & next round.  */
      result |= (int64_t)payload << shift;
      shift += 7;
      if ((byte & 0x80) == 0)
	{
	  if (shift < size && sign)
	    result |= -((int64_t)1 << shift);
	  break;
	}
      if (shift > size)
	return -1;
    }

  if (ret != NULL)
    *ret = result;
  return zero_tail ? 1 : 0;
}

static bool
checked_read_sleb128 (struct read_ctx *ctx, int64_t *ret,
		      struct where *where, const char *what)
{
  const unsigned char *ptr = ctx->ptr;
  int st = read_ctx_read_sleb128 (ctx, ret);
  if (st < 0)
    wr_error (where, ": can't read %s.\n", what);
  else if (st > 0)
    {
      char buf[20]; // sign, "0x", 16 hexa digits, terminating zero
      int64_t val = *ret;
      sprintf (buf, "%s%#" PRIx64, val < 0 ? "-" : "", val < 0 ? -val : val);
      wr_format_leb128_message (where, what, buf, ptr, ctx->ptr);
    }
  return st >= 0;
}

static bool
read_ctx_read_2ubyte (struct read_ctx *ctx, uint16_t *ret)
{
  if (!read_ctx_need_data (ctx, 2))
    return false;
  uint16_t val = read_2ubyte_unaligned_inc (ctx->dbg, ctx->ptr);
  if (ret != NULL)
    *ret = val;
  return true;
}

static bool
read_ctx_read_4ubyte (struct read_ctx *ctx, uint32_t *ret)
{
  if (!read_ctx_need_data (ctx, 4))
    return false;
  uint32_t val = read_4ubyte_unaligned_inc (ctx->dbg, ctx->ptr);
  if (ret != NULL)
    *ret = val;
  return true;
}

static bool
read_ctx_read_8ubyte (struct read_ctx *ctx, uint64_t *ret)
{
  if (!read_ctx_need_data (ctx, 8))
    return false;
  uint64_t val = read_8ubyte_unaligned_inc (ctx->dbg, ctx->ptr);
  if (ret != NULL)
    *ret = val;
  return true;
}

static bool
read_ctx_read_offset (struct read_ctx *ctx, bool dwarf64, uint64_t *ret)
{
  if (dwarf64)
    return read_ctx_read_8ubyte (ctx, ret);

  uint32_t v;
  if (!read_ctx_read_4ubyte (ctx, &v))
    return false;

  if (ret != NULL)
    *ret = (uint64_t)v;
  return true;
}

static bool
read_ctx_read_var (struct read_ctx *ctx, int width, uint64_t *ret)
{
  switch (width)
    {
    case 4:
    case 8:
      return read_ctx_read_offset (ctx, width == 8, ret);
    case 2:
      {
	uint16_t val;
	if (!read_ctx_read_2ubyte (ctx, &val))
	  return false;
	*ret = val;
	return true;
      }
    case 1:
      {
	uint8_t val;
	if (!read_ctx_read_ubyte (ctx, &val))
	  return false;
	*ret = val;
	return true;
      }
    default:
      return false;
    };
}

/* The value passed back in uint64_t VALUEP may actually be
   type-casted int64_t.  WHAT and WHERE describe error message and
   context for LEB128 loading.  */
static bool
read_ctx_read_form (struct read_ctx *ctx, bool addr_64, uint8_t form,
		    uint64_t *valuep, struct where *where, const char *what)
{
  switch (form)
    {
    case DW_FORM_addr:
      return read_ctx_read_offset (ctx, addr_64, valuep);
    case DW_FORM_udata:
      return checked_read_uleb128 (ctx, valuep, where, what);
    case DW_FORM_sdata:
      return checked_read_sleb128 (ctx, (int64_t *)valuep, where, what);
    case DW_FORM_data1:
      {
	uint8_t v;
	if (!read_ctx_read_ubyte (ctx, &v))
	  return false;
	if (valuep != NULL)
	  *valuep = v;
	return true;
      }
    case DW_FORM_data2:
      {
	uint16_t v;
	if (!read_ctx_read_2ubyte (ctx, &v))
	  return false;
	if (valuep != NULL)
	  *valuep = v;
	return true;
      }
    case DW_FORM_data4:
      {
	uint32_t v;
	if (!read_ctx_read_4ubyte (ctx, &v))
	  return false;
	if (valuep != NULL)
	  *valuep = v;
	return true;
      }
    case DW_FORM_data8:
      return read_ctx_read_8ubyte (ctx, valuep);
    };

  return false;
}

static const char *
read_ctx_read_str (struct read_ctx *ctx)
{
  const char *ret = (const char *)ctx->ptr;
  uint8_t byte;
  do
    if (!read_ctx_read_ubyte (ctx, &byte))
      return NULL;
  while (byte != 0);
  return ret;
}

static bool
read_ctx_skip (struct read_ctx *ctx, uint64_t len)
{
  if (!read_ctx_need_data (ctx, len))
    return false;
  ctx->ptr += len;
  return true;
}

static bool
read_ctx_eof (struct read_ctx *ctx)
{
  return !read_ctx_need_data (ctx, 1);
}

static bool
attrib_form_valid (uint64_t form)
{
  return form > 0 && form <= DW_FORM_indirect;
}

static int
check_sibling_form (uint64_t form)
{
  switch (form)
    {
    case DW_FORM_indirect:
      /* Tolerate this in abbrev loading, even during the DIE loading.
	 We check that dereferenced indirect form yields valid form.  */
    case DW_FORM_ref1:
    case DW_FORM_ref2:
    case DW_FORM_ref4:
    case DW_FORM_ref8:
    case DW_FORM_ref_udata:
      return 0;

    case DW_FORM_ref_addr:
      return -1;

    default:
      return -2;
    };
}

/* Check that given form may in fact be valid in some CU.  */
static bool
check_abbrev_location_form (uint64_t form)
{
  switch (form)
    {
    case DW_FORM_indirect:

      /* loclistptr */
    case DW_FORM_data4:
    case DW_FORM_data8:

      /* block */
    case DW_FORM_block1:
    case DW_FORM_block2:
    case DW_FORM_block4:
    case DW_FORM_block:
      return true;

    default:
      return false;
    };
}

static bool
is_location_attrib (uint64_t name)
{
  switch (name)
    {
    case DW_AT_location:
    case DW_AT_frame_base:
    case DW_AT_data_location:
    case DW_AT_data_member_location:
      return true;
    default:
      return false;
    }
}

static struct abbrev_table *
abbrev_table_load (struct read_ctx *ctx)
{
  struct abbrev_table *section_chain = NULL;
  struct abbrev_table *section = NULL;
  uint64_t first_attr_off = 0;
  struct where where = WHERE (sec_abbrev, NULL);
  where.addr1 = 0;

  while (!read_ctx_eof (ctx))
    {
      uint64_t abbr_off;
      uint64_t abbr_code;
      {
	uint64_t prev_abbr_off = (uint64_t)-1;
	uint64_t prev_abbr_code = (uint64_t)-1;
	uint64_t zero_seq_off = (uint64_t)-1;

	while (!read_ctx_eof (ctx))
	  {
	    abbr_off = read_ctx_get_offset (ctx);
	    where_reset_2 (&where, abbr_off);

	    /* Abbreviation code.  */
	    if (!checked_read_uleb128 (ctx, &abbr_code, &where, "abbrev code"))
	      goto free_and_out;

	    if (abbr_code == 0 && prev_abbr_code == 0
		&& zero_seq_off == (uint64_t)-1)
	      zero_seq_off = abbr_off;

	    if (abbr_code != 0)
	      break;
	    else
	      section = NULL;

	    prev_abbr_code = abbr_code;
	    prev_abbr_off = abbr_off;
	  }

	if (zero_seq_off != (uint64_t)-1)
	  {
	    /* Don't report abbrev address, this is section-wide
	       padding.  */
	    struct where wh = WHERE (where.section, NULL);
	    wr_message_padding_0 (mc_abbrevs | mc_header, &wh,
				  zero_seq_off, abbr_off - 1);
	  }
      }

      if (read_ctx_eof (ctx))
	break;

      if (section == NULL)
	{
	  section = xcalloc (1, sizeof (*section));
	  section->offset = abbr_off;
	  section->next = section_chain;
	  section_chain = section;

	  where_reset_1 (&where, abbr_off);
	  where_reset_2 (&where, abbr_off);
	}
      REALLOC (section, abbr);

      struct abbrev *cur = section->abbr + section->size++;
      WIPE (*cur);

      cur->code = abbr_code;

      /* Abbreviation tag.  */
      uint64_t abbr_tag;
      if (!checked_read_uleb128 (ctx, &abbr_tag, &where, "abbrev tag"))
	goto free_and_out;

      if (abbr_tag > DW_TAG_hi_user)
	{
	  wr_error (&where, ": invalid abbrev tag 0x%" PRIx64 ".\n", abbr_tag);
	  goto free_and_out;
	}
      cur->tag = (typeof (cur->tag))abbr_tag;

      /* Abbreviation has_children.  */
      uint8_t has_children;
      if (!read_ctx_read_ubyte (ctx, &has_children))
	{
	  wr_error (&where, ": can't read abbrev has_children.\n");
	  goto free_and_out;
	}

      if (has_children != DW_CHILDREN_no
	  && has_children != DW_CHILDREN_yes)
	{
	  wr_error (&where,
		    ": invalid has_children value 0x%x.\n", cur->has_children);
	  goto free_and_out;
	}
      cur->has_children = has_children == DW_CHILDREN_yes;

      bool null_attrib;
      uint64_t sibling_attr = 0;
      do
	{
	  uint64_t attr_off = read_ctx_get_offset (ctx);
	  uint64_t attrib_name, attrib_form;
	  if (first_attr_off == 0)
	    first_attr_off = attr_off;
	  /* Shift to match elfutils reporting.  */
	  where_reset_3 (&where, attr_off - first_attr_off);

	  /* Load attribute name and form.  */
	  if (!checked_read_uleb128 (ctx, &attrib_name, &where,
				     "attribute name"))
	    goto free_and_out;

	  if (!checked_read_uleb128 (ctx, &attrib_form, &where,
				     "attribute form"))
	    goto free_and_out;

	  null_attrib = attrib_name == 0 && attrib_form == 0;

	  /* Now if both are zero, this was the last attribute.  */
	  if (!null_attrib)
	    {
	      /* Otherwise validate name and form.  */
	      if (attrib_name > DW_AT_hi_user)
		{
		  wr_error (&where,
			    ": invalid name 0x%" PRIx64 ".\n", attrib_name);
		  goto free_and_out;
		}

	      if (!attrib_form_valid (attrib_form))
		{
		  wr_error (&where,
			    ": invalid form 0x%" PRIx64 ".\n", attrib_form);
		  goto free_and_out;
		}
	    }

	  REALLOC (cur, attribs);

	  struct abbrev_attrib *acur = cur->attribs + cur->size++;
	  WIPE (*acur);

	  /* We do structural checking of sibling attribute, so make
	     sure our assumptions in actual DIE-loading code are
	     right.  We expect at most one DW_AT_sibling attribute,
	     with form from reference class, but only CU-local, not
	     DW_FORM_ref_addr.  */
	  if (attrib_name == DW_AT_sibling)
	    {
	      if (sibling_attr != 0)
		wr_error (&where,
			  ": Another DW_AT_sibling attribute in one abbreviation. "
			  "(First was 0x%" PRIx64 ".)\n", sibling_attr);
	      else
		{
		  assert (attr_off > 0);
		  sibling_attr = attr_off;

		  if (!cur->has_children)
		    wr_message (mc_die_rel | mc_acc_bloat | mc_impact_1,
				&where,
				": Excessive DW_AT_sibling attribute at childless abbrev.\n");
		}

	      switch (check_sibling_form (attrib_form))
		{
		case -1:
		  wr_message (mc_die_rel | mc_impact_2, &where,
			      ": DW_AT_sibling attribute with form DW_FORM_ref_addr.\n");
		  break;

		case -2:
		  wr_error (&where,
			    ": DW_AT_sibling attribute with non-reference form \"%s\".\n",
			    dwarf_form_string (attrib_form));
		};
	    }
	  /* Similar for DW_AT_location and friends.  */
	  else if (is_location_attrib (attrib_name))
	    {
	      if (!check_abbrev_location_form (attrib_form))
		wr_error (&where,
			  ": location attribute with invalid form \"%s\".\n",
			  dwarf_form_string (attrib_form));
	    }
	  /* Similar for DW_AT_ranges.  */
	  else if (attrib_name == DW_AT_ranges
		   || attrib_name == DW_AT_stmt_list)
	    {
	      if (attrib_form != DW_FORM_data4
		  && attrib_form != DW_FORM_data8
		  && attrib_form != DW_FORM_indirect)
		wr_error (&where,
			  ": %s with invalid form \"%s\".\n",
			  dwarf_attr_string (attrib_name),
			  dwarf_form_string (attrib_form));
	    }

	  acur->name = attrib_name;
	  acur->form = attrib_form;
	  acur->where = where;
	}
      while (!null_attrib);
    }

  for (section = section_chain; section != NULL; section = section->next)
    {
      int cmp_abbrs (const void *a, const void *b)
      {
	struct abbrev *aa = (struct abbrev *)a;
	struct abbrev *bb = (struct abbrev *)b;
	return aa->code - bb->code;
      }

      /* The array is most likely already sorted in the file, but just
	 to be sure...  */
      qsort (section->abbr, section->size, sizeof (*section->abbr), cmp_abbrs);
    }

  return section_chain;

 free_and_out:
  abbrev_table_free (section_chain);
  return NULL;
}

static void
abbrev_table_free (struct abbrev_table *abbr)
{
  for (struct abbrev_table *it = abbr; it != NULL; )
    {
      for (size_t i = 0; i < it->size; ++i)
	free (it->abbr[i].attribs);
      free (it->abbr);

      struct abbrev_table *temp = it;
      it = it->next;
      free (temp);
    }
}

static struct abbrev *
abbrev_table_find_abbrev (struct abbrev_table *abbrevs, uint64_t abbrev_code)
{
  size_t a = 0;
  size_t b = abbrevs->size;
  struct abbrev *ab = NULL;

  while (a < b)
    {
      size_t i = (a + b) / 2;
      ab = abbrevs->abbr + i;

      if (ab->code > abbrev_code)
	b = i;
      else if (ab->code < abbrev_code)
	a = i + 1;
      else
	return ab;
    }

  return NULL;
}

static size_t
addr_record_find_addr (struct addr_record *ar, uint64_t addr)
{
  size_t a = 0;
  size_t b = ar->size;

  while (a < b)
    {
      size_t i = (a + b) / 2;
      uint64_t v = ar->addrs[i];

      if (v > addr)
	b = i;
      else if (v < addr)
	a = i + 1;
      else
	return i;
    }

  return a;
}

static bool
addr_record_has_addr (struct addr_record *ar, uint64_t addr)
{
  if (ar->size == 0
      || addr < ar->addrs[0]
      || addr > ar->addrs[ar->size - 1])
    return false;

  size_t a = addr_record_find_addr (ar, addr);
  return a < ar->size && ar->addrs[a] == addr;
}

static void
addr_record_add (struct addr_record *ar, uint64_t addr)
{
  size_t a = addr_record_find_addr (ar, addr);
  if (a >= ar->size || ar->addrs[a] != addr)
    {
      REALLOC (ar, addrs);
      size_t len = ar->size - a;
      memmove (ar->addrs + a + 1, ar->addrs + a, len * sizeof (*ar->addrs));

      ar->addrs[a] = addr;
      ar->size++;
    }
}

static void
addr_record_free (struct addr_record *ar)
{
  if (ar != NULL)
    free (ar->addrs);
}


static void
ref_record_add (struct ref_record *rr, uint64_t addr, struct where *referrer)
{
  REALLOC (rr, refs);
  struct ref *ref = rr->refs + rr->size++;
  ref->addr = addr;
  ref->who = *referrer;
}

static void
ref_record_free (struct ref_record *rr)
{
  if (rr != NULL)
    free (rr->refs);
}


void
coverage_init (struct coverage *ar, uint64_t size)
{
  size_t ctemts = size / coverage_emt_bits + 1;
  ar->buf = xcalloc (ctemts, sizeof (ar->buf));
  ar->alloc = ctemts;
  ar->size = size;
}

void
coverage_add (struct coverage *ar, uint64_t begin, uint64_t end)
{
  assert (ar);
  assert (begin <= end);
  assert (end <= ar->size);

  uint64_t bi = begin / coverage_emt_bits;
  uint64_t ei = end / coverage_emt_bits;

  uint8_t bb = begin % coverage_emt_bits;
  uint8_t eb = end % coverage_emt_bits;

  coverage_emt_type bm = (coverage_emt_type)-1 >> bb;
  coverage_emt_type em = (coverage_emt_type)-1 << (coverage_emt_bits - 1 - eb);

  if (bi == ei)
    ar->buf[bi] |= bm & em;
  else
    {
      ar->buf[bi] |= bm;
      ar->buf[ei] |= em;
      memset (ar->buf + bi + 1, -1, coverage_emt_size * (ei - bi - 1));
    }
}

bool
coverage_is_covered (struct coverage *ar, uint64_t address)
{
  assert (ar);
  assert (address <= ar->size);

  uint64_t bi = address / coverage_emt_bits;
  uint8_t bb = address % coverage_emt_bits;
  coverage_emt_type bm = (coverage_emt_type)1 << (coverage_emt_bits - 1 - bb);
  return !!(ar->buf[bi] & bm);
}

bool
coverage_pristine (struct coverage *ar, uint64_t begin, uint64_t length)
{
  for (uint64_t i = 0; i < length; ++i)
    if (coverage_is_covered (ar, begin + i))
      return false;
  return true;
}

bool
coverage_find_holes (struct coverage *ar,
		     bool (*cb)(uint64_t begin, uint64_t end, void *user),
		     void *user)
{
  bool hole;
  uint64_t begin = 0;

  void hole_begin (uint64_t a)
  {
    begin = a;
    hole = true;
  }

  bool hole_end (uint64_t a)
  {
    assert (hole);
    if (a != begin)
      if (!cb (begin, a - 1, user))
	return false;
    hole = false;
    return true;
  }

  hole_begin (0);
  for (size_t i = 0; i < ar->alloc; ++i)
    {
      if (ar->buf[i] == (coverage_emt_type)-1)
	{
	  if (hole)
	    if (!hole_end (i * coverage_emt_bits))
	      return false;
	}
      else
	{
	  coverage_emt_type tmp = ar->buf[i];
	  for (uint8_t j = 1; j <= coverage_emt_bits; ++j)
	    {
	      coverage_emt_type mask
		= (coverage_emt_type)1 << (coverage_emt_bits - j);
	      uint64_t addr = i * coverage_emt_bits + j - 1;
	      if (addr > ar->size)
		break;
	      if (!hole && !(tmp & mask))
		hole_begin (addr);
	      else if (hole && (tmp & mask))
		if (!hole_end (addr))
		  return false;
	    }
	}
    }
  if (hole)
    if (!hole_end (ar->size))
      return false;

  return true;
}

bool
found_hole (uint64_t begin, uint64_t end, void *data)
{
  struct hole_info *info = (struct hole_info *)data;
  bool all_zeroes = true;
  for (uint64_t i = begin; i <= end; ++i)
    if (((char*)info->data)[i] != 0)
      {
	all_zeroes = false;
	break;
      }

  if (all_zeroes)
    {
      /* Zero padding is valid, if it aligns on the bounds of
	 info->align bytes, and is not excessive.  */
      if (!(info->align != 0 && info->align != 1
	    && ((end + 1) % info->align == 0) && (begin % 4 != 0)
	    && (end + 1 - begin < info->align)))
	wr_message_padding_0 (info->category, &WHERE (info->section, NULL),
			      begin, end);
    }
  else
    /* XXX: This actually lies when the unreferenced portion is
       composed of sequences of zeroes and non-zeroes.  */
    wr_message_padding_n0 (info->category, &WHERE (info->section, NULL),
			   begin, end);

  return true;
}

bool
coverage_map_found_hole (uint64_t begin, uint64_t end,
			 struct section_coverage *sco, void *user)
{
  struct coverage_map_hole_info *info = (struct coverage_map_hole_info *)user;

  struct where where = WHERE (info->info.section, NULL);

  GElf_Ehdr ehdr_mem, *ehdr = gelf_getehdr (info->elf, &ehdr_mem);
  if (ehdr == NULL)
    {
      wr_error (&where, ": invalid ELF, terminating coverage analysis.\n");
      return false;
    }
  const char *scnname = elf_strptr (info->elf, ehdr->e_shstrndx,
				    sco->shdr.sh_name) ?: "(unknown)";

  Elf_Data *data = elf_getdata (sco->scn, NULL);
  if (data == NULL)
    {
      wr_error (&where, ": couldn't read the data of section %s.\n", scnname);
      return false;
    }

  /* We don't expect some sections to be covered.  But if they
     are at least partially covered, we expect the same
     coverage criteria as for .text.  */
  if (!sco->hit
      && (strcmp (scnname, ".init") == 0
	  || strcmp (scnname, ".fini") == 0
	  || strcmp (scnname, ".plt") == 0))
    return true;

  uint64_t base = sco->shdr.sh_addr;
  /* If we get stripped debuginfo file, the data simply may not be
     available.  In that case simply report the hole.  */
  if (data->d_buf != NULL)
    {
      bool zeroes = true;
      for (uint64_t j = begin; j < end; ++j)
	/* XXX NOP run detection?  */
	if (((char *)data->d_buf)[j] != 0)
	  {
	    zeroes = false;
	    break;
	  }
      if (!zeroes)
	return true;
    }

  wr_message (info->info.category | mc_acc_suboptimal | mc_impact_4, &where,
	      ": addresses %#" PRIx64 "..%#" PRIx64
	      " of section %s are not covered.\n",
	      begin + base, end + base, scnname);
  return true;
}

void
coverage_free (struct coverage *ar)
{
  free (ar->buf);
}


void
section_coverage_init (struct section_coverage *sco, Elf_Scn *scn,
		       GElf_Shdr *shdr)
{
  assert (sco != NULL);
  assert (scn != NULL);
  assert (shdr != NULL);

  sco->scn = scn;
  sco->shdr = *shdr;
  coverage_init (&sco->cov, shdr->sh_size);
  sco->hit = false;
}

bool
coverage_map_init (struct coverage_map *coverage_map, Elf *elf,
		   Elf64_Xword mask, bool allow_overlap)
{
  assert (coverage_map != NULL);
  assert (elf != NULL);

  WIPE (*coverage_map);
  coverage_map->elf = elf;
  coverage_map->allow_overlap = allow_overlap;

  GElf_Ehdr ehdr_mem, *ehdr = gelf_getehdr (elf, &ehdr_mem);
  if (ehdr == NULL)
    return false;

  for (size_t i = 0; i < ehdr->e_shnum; ++i)
    {
      Elf_Scn *scn = elf_getscn (elf, i);
      if (scn == NULL)
	return false;

      GElf_Shdr shdr_mem, *shdr = gelf_getshdr (scn, &shdr_mem);
      if (shdr == NULL)
	return false;

      if ((shdr->sh_flags & mask) == mask)
	{
	  REALLOC (coverage_map, scos);
	  section_coverage_init (coverage_map->scos + coverage_map->size++,
				 scn, shdr);
	}
    }

  return true;
}

void
coverage_map_add (struct coverage_map *coverage_map,
		  uint64_t address,
		  uint64_t length,
		  struct where *where,
		  enum message_category cat)
{
  bool found = false;
  bool crosses_boundary = false;
  bool overlap = false;
  uint64_t end = address + length;

  /* This is for analyzing how much of the current range falls into
     sections in coverage map.  Whatever is left uncovered doesn't
     fall anywhere and is reported.  */
  struct coverage range_cov;
  coverage_init (&range_cov, length);

  for (size_t i = 0; i < coverage_map->size; ++i)
    {
      struct section_coverage *sco = coverage_map->scos + i;
      GElf_Shdr *shdr = &sco->shdr;
      struct coverage *cov = &sco->cov;

      Elf64_Addr s_end = shdr->sh_addr + shdr->sh_size;
      if (end < shdr->sh_addr || address >= s_end)
	/* no overlap */
	continue;

      if (found && !crosses_boundary)
	{
	  /* While probably not an error, it's very suspicious.  */
	  wr_message (cat | mc_impact_2, where,
		      ": the range %#" PRIx64 "..%#" PRIx64
		      " crosses section boundaries.\n",
		      address, end);
	  crosses_boundary = true;
	}

      found = true;

      uint64_t cov_begin
	= address < shdr->sh_addr ? 0 : address - shdr->sh_addr;
      uint64_t cov_end
	= (end < s_end ? end - shdr->sh_addr
	   : shdr->sh_size - 1); /* -1 because coverage
				    endpoint is inclusive.  */
      assert (cov_begin <= cov_end);

      uint64_t r_cov_begin = cov_begin + shdr->sh_addr - address;
      uint64_t r_cov_end = cov_end + shdr->sh_addr - address;

      if (!overlap && !coverage_map->allow_overlap
	  && !coverage_pristine (cov, cov_begin, cov_end - cov_begin))
	{
	  /* Not a show stopper, this shouldn't derail high-level.  */
	  wr_message (cat | mc_impact_2 | mc_error, where,
		      ": the range %#" PRIx64 "..%#" PRIx64
		      " overlaps with another one.\n",
		      address, end);
	  overlap = true;
	}

      /* Section coverage... */
      coverage_add (cov, cov_begin, cov_end);
      sco->hit = true;

      /* And range coverage... */
      coverage_add (&range_cov, r_cov_begin, r_cov_end);
    }

  if (!found)
    /* Not a show stopper.  */
    wr_error (where,
	      ": couldn't find a section that the range %#"
	      PRIx64 "..%#" PRIx64 " covers.\n", address, end);
  else
    {
      bool range_hole (uint64_t h_begin, uint64_t h_end,
		       void *user __attribute__ ((unused)))
      {
	wr_error (where,
		  ": portion %#" PRIx64 "..%#" PRIx64
		  ", of the range %#" PRIx64 "..%#" PRIx64
		  " doesn't fall into any ALLOC & EXEC section.\n",
		  h_begin + address, h_end + address,
		  address, end);
	return true;
      }
      coverage_find_holes (&range_cov, range_hole, NULL);
    }

  coverage_free (&range_cov);
}

bool
coverage_map_find_holes (struct coverage_map *coverage_map,
			 bool (*cb) (uint64_t, uint64_t,
				     struct section_coverage *, void *),
			 void *user)
{
  for (size_t i = 0; i < coverage_map->size; ++i)
    {
      struct section_coverage *sco = coverage_map->scos + i;

      bool wrap_cb (uint64_t h_begin, uint64_t h_end, void *h_user)
      {
	return cb (h_begin, h_end, sco, h_user);
      }

      if (!coverage_find_holes (&sco->cov, wrap_cb, user))
	return false;
    }

  return true;
}

void
coverage_map_free (struct coverage_map *coverage_map)
{
  for (size_t i = 0; i < coverage_map->size; ++i)
    coverage_free (&coverage_map->scos[i].cov);
  free (coverage_map->scos);
}


static void
cu_free (struct cu *cu_chain)
{
  for (struct cu *it = cu_chain; it != NULL; )
    {
      addr_record_free (&it->die_addrs);

      struct cu *temp = it;
      it = it->next;
      free (temp);
    }
}

static struct cu *
cu_find_cu (struct cu *cu_chain, uint64_t offset)
{
  for (struct cu *it = cu_chain; it != NULL; it = it->next)
    if (it->offset == offset)
      return it;
  return NULL;
}


static bool
check_die_references (struct cu *cu,
		      struct ref_record *die_refs)
{
  bool retval = true;
  for (size_t i = 0; i < die_refs->size; ++i)
    {
      struct ref *ref = die_refs->refs + i;
      if (!addr_record_has_addr (&cu->die_addrs, ref->addr))
	{
	  wr_error (&ref->who,
		    ": unresolved reference to " PRI_DIE ".\n", ref->addr);
	  retval = false;
	}
    }
  return retval;
}

static bool
check_global_die_references (struct cu *cu_chain)
{
  bool retval = true;
  for (struct cu *it = cu_chain; it != NULL; it = it->next)
    for (size_t i = 0; i < it->die_refs.size; ++i)
      {
	struct ref *ref = it->die_refs.refs + i;
	struct cu *ref_cu = NULL;
	for (struct cu *jt = cu_chain; jt != NULL; jt = jt->next)
	  if (addr_record_has_addr (&jt->die_addrs, ref->addr))
	    {
	      ref_cu = jt;
	      break;
	    }

	if (ref_cu == NULL)
	  {
	    wr_error (&ref->who,
		      ": unresolved (non-CU-local) reference to " PRI_DIE ".\n",
		      ref->addr);
	    retval = false;
	  }
	else if (ref_cu == it)
	  wr_message (mc_impact_2 | mc_acc_suboptimal | mc_die_rel,
		      &ref->who,
		      ": local reference to " PRI_DIE " formed as global.\n",
		      ref->addr);
      }

  return retval;
}

static bool
read_size_extra (struct read_ctx *ctx, uint32_t size32, uint64_t *sizep,
		 bool *dwarf_64p, struct where *wh)
{
  if (size32 == DWARF3_LENGTH_64_BIT)
    {
      if (!read_ctx_read_8ubyte (ctx, sizep))
	{
	  wr_error (wh, ": can't read 64bit CU length.\n");
	  return false;
	}

      *dwarf_64p = true;
    }
  else if (size32 >= DWARF3_LENGTH_MIN_ESCAPE_CODE)
    {
      wr_error (wh, ": unrecognized CU length escape value: "
		"%" PRIx32 ".\n", size32);
      return false;
    }
  else
    {
      *sizep = size32;
      *dwarf_64p = false;
    }

  return true;
}

static bool
check_zero_padding (struct read_ctx *ctx,
		    enum message_category category,
		    struct where *wh)
{
  assert (ctx->ptr != ctx->end);
  const unsigned char *save_ptr = ctx->ptr;
  while (!read_ctx_eof (ctx))
    if (*ctx->ptr++ != 0)
      {
	ctx->ptr = save_ptr;
	return false;
      }

  wr_message_padding_0 (category, wh,
			(uint64_t)(save_ptr - ctx->begin),
			(uint64_t)(ctx->end - ctx->begin));
  return true;
}

static struct where
where_from_reloc (struct relocation_data *reloc, struct where *ref)
{
  struct where where
    = WHERE (reloc->type == SHT_REL ? sec_rel : sec_rela, NULL);
  where_reset_1 (&where, reloc->rel[reloc->index].offset);
  where.ref = ref;
  return where;
}

enum skip_type
{
  skip_unref = 0,
  skip_mismatched = 1,
  skip_ok,
};

static struct relocation *
relocation_next (struct relocation_data *reloc, uint64_t offset,
		 struct where *where, enum skip_type st)
{
  if (reloc == NULL || reloc->rel == NULL)
    return NULL;

  while (reloc->index < reloc->size)
    {
      struct where reloc_where = where_from_reloc (reloc, where);

      struct relocation *rel = reloc->rel + reloc->index;
      where_reset_2 (&reloc_where, rel->offset);

      /* This relocation entry is ahead of us.  */
      if (rel->offset > offset)
	return NULL;

      reloc->index++;

      if (rel->offset < offset)
	{
	  if (st != skip_ok)
	    {
	      void (*w) (const struct where *, const char *, ...) = wr_error;
	      (*w) (&reloc_where,
		    ((const char *[])
		    {": relocation targets unreferenced portion of the section.\n",
		     ": relocation is mismatched.\n"})[st]);
	    }
	  continue;
	}

      return rel;
    }

  return NULL;
}

/* Skip all relocation up to offset, and leave cursor pointing at that
   relocation, so that next time relocation_next is called, relocation
   matching that offset is immediately yielded.  */
static void
relocation_skip (struct relocation_data *reloc, uint64_t offset,
		 struct where *where, enum skip_type st)
{
  if (reloc != NULL && reloc->rel != NULL)
    relocation_next (reloc, offset - 1, where, st);
}

/* Skip all the remaining relocations.  */
static void
relocation_skip_rest (struct section_data *data)
{
  if (data->rel.rel != NULL)
    relocation_next (&data->rel, (uint64_t)-1, &WHERE_SECDATA (data, NULL),
		     skip_mismatched);
}

/* SYMPTR may be NULL, otherwise (**SYMPTR) has to yield valid memory
   location.  When the function returns, (*SYMPTR) is either NULL, in
   which case we failed or didn't get around to obtain the symbol from
   symbol table, or non-NULL, in which case the symbol was initialized.  */
static void
relocate_one (struct relocation_data *reloc, struct relocation *rel,
	      unsigned width, uint64_t *value, struct where *where,
	      enum section_id offset_into, GElf_Sym **symptr)
{
  if (rel->invalid)
    return;

  struct where reloc_where = where_from_reloc (reloc, where);
  where_reset_2 (&reloc_where, rel->offset);
  struct where reloc_ref_where = reloc_where;
  reloc_ref_where.next = where;

  GElf_Sym symbol_mem, *symbol;
  if (symptr != NULL)
    {
      symbol = *symptr;
      *symptr = NULL;
    }
  else
    symbol = &symbol_mem;

  if (offset_into == sec_invalid)
    {
      wr_message (mc_impact_3 | mc_reloc, &reloc_ref_where,
		  ": relocates a datum that shouldn't be relocated.\n");
      return;
    }

  Elf_Type type = ebl_reloc_simple_type (reloc->file->ebl, rel->type);

  unsigned rel_width;
  switch (type)
    {
    case ELF_T_BYTE:
      rel_width = 1;
      break;

    case ELF_T_HALF:
      rel_width = 2;
      break;

    case ELF_T_WORD:
    case ELF_T_SWORD:
      rel_width = 4;
      break;

    case ELF_T_XWORD:
    case ELF_T_SXWORD:
      rel_width = 8;
      break;

    default:
      /* This has already been diagnosed during the isolated
	 validation of relocation section.  */
      return;
    };

  if (rel_width != width)
    wr_error (&reloc_ref_where,
	      ": %d-byte relocation relocates %d-byte datum.\n",
	      rel_width, width);

  /* Tolerate that we might have failed to obtain a symbol table.  */
  if (reloc->symdata != NULL)
    {
      symbol = gelf_getsym (reloc->symdata, rel->symndx, symbol);
      if (symptr != NULL)
	*symptr = symbol;
      if (symbol == NULL)
	{
	  wr_error (&reloc_where,
		    ": couldn't obtain symbol #%d: %s.\n",
		    rel->symndx, elf_errmsg (-1));
	  return;
	}

      *value = rel->addend + symbol->st_value;
      uint64_t section_index = symbol->st_shndx;
      /* XXX We should handle SHN_XINDEX here.  Or, instead, maybe it
	 would be possible to use dwfl, which already does XINDEX
	 translation.  */

      /* It's target value, not section offset.  */
      if (offset_into == rel_value
	  || offset_into == rel_address)
	{
	  /* If a target value is what's expected, then complain if
	     it's not either SHN_ABS, an SHF_ALLOC section, or
	     SHN_UNDEF.  For data forms of address_size, an SHN_UNDEF
	     reloc is acceptable, otherwise reject it.  */
	  if (!(section_index == SHN_ABS
		|| (offset_into == rel_address
		    && (section_index == SHN_UNDEF
			|| section_index == SHN_COMMON))))
	    {
	      Elf_Scn *scn;
	      GElf_Shdr shdr_mem, *shdr;
	      if (offset_into != rel_address && section_index == SHN_UNDEF)
		wr_error (&reloc_where,
			    ": relocation of an address is formed against SHN_UNDEF symbol"
			    " (symtab index %d).\n", rel->symndx);
	      else if ((scn = elf_getscn (reloc->file->dwarf->elf,
					  section_index)) == NULL)
		wr_error (&reloc_where,
			  ": couldn't obtain associated section #%" PRId64 ".\n",
			  section_index);
	      else if ((shdr = gelf_getshdr (scn, &shdr_mem)) == NULL)
		wr_error (&reloc_where,
			  ": couldn't obtain header of associated section #%" PRId64 ".\n",
			  section_index);
	      else if ((shdr->sh_flags & SHF_ALLOC) != SHF_ALLOC)
		wr_message (mc_reloc | mc_impact_3, &reloc_where,
			    ": associated section #%" PRId64 " isn't SHF_ALLOC.\n",
			    section_index);
	    }
	}
      else
	{
	  enum section_id id;
	  /* If symtab[symndx].st_shndx does not match the expected
	     debug section's index, complain.  */
	  if (section_index >= reloc->file->size)
	    wr_error (&reloc_where,
		      ": invalid associated section #%" PRId64 ".\n",
		      section_index);
	  else if ((id = reloc->file->sec[section_index].id) != offset_into)
	    {
	      char *wh1 = id != sec_invalid
		? strdup (where_fmt (&WHERE (id, NULL), NULL)) : "(?)";
	      char *wh2 = strdup (where_fmt (&WHERE (offset_into, NULL), NULL));
	      wr_error (&reloc_where,
			": relocation references section %s, but %s was expected"
			" (section index: %" PRId64 ").\n",
			wh1, wh2, section_index);
	      free (wh2);
	      if (id != sec_invalid)
		free (wh1);
	    }
	}
    }
}

static enum section_id
reloc_target (uint8_t form, struct abbrev_attrib *at)
{
  switch (form)
    {
    case DW_FORM_strp:
      return sec_str;

    case DW_FORM_addr:

      switch (at->name)
	{
	case DW_AT_low_pc:
	case DW_AT_high_pc:
	case DW_AT_entry_pc:
	  return sec_text;
	};

      break;

    case DW_FORM_ref_addr:
      return sec_info;

    case DW_FORM_data1:
    case DW_FORM_data2:
      /* While these are technically legal, they are never used in
	 DWARF sections.  So better mark them as illegal, and have
	 dwarflint flag them.  */
      return sec_invalid;

    case DW_FORM_data4:
    case DW_FORM_data8:

      switch (at->name)
	{
	case DW_AT_stmt_list:
	  return sec_line;

	case DW_AT_location:
	case DW_AT_string_length:
	case DW_AT_return_addr:
	case DW_AT_data_member_location:
	case DW_AT_frame_base:
	case DW_AT_segment:
	case DW_AT_static_link:
	case DW_AT_use_location:
	case DW_AT_vtable_elem_location:
	  return sec_loc;

	case DW_AT_mac_info:
	  return sec_mac;

	case DW_AT_ranges:
	  return sec_ranges;
	}

      break;

    case DW_FORM_string:
    case DW_FORM_ref1:
    case DW_FORM_ref2:
    case DW_FORM_ref4:
      /* Shouldn't be relocated.  */
      return sec_invalid;

    case DW_FORM_sdata:
    case DW_FORM_udata:
    case DW_FORM_flag:
    case DW_FORM_ref_udata:
      assert (!"Can't be relocated!");

    case DW_FORM_block1:
    case DW_FORM_block2:
    case DW_FORM_block4:
    case DW_FORM_block:
      assert (!"Should be handled specially!");
    };

  printf ("XXX don't know how to handle form=%s, at=%s\n",
	  dwarf_form_string (form), dwarf_attr_string (at->name));

  return rel_value;
}

static enum section_id
reloc_target_loc (uint8_t opcode)
{
  switch (opcode)
    {
    case DW_OP_call2:
    case DW_OP_call4:
      return sec_info;

    case DW_OP_addr:
      return rel_address;

    case DW_OP_call_ref:
      assert (!"Can't handle call_ref!");
    };

  printf ("XXX don't know how to handle opcode=%s\n",
	  dwarf_locexpr_opcode_string (opcode));

  return rel_value;
}

static bool
supported_version (unsigned version,
		   size_t num_supported, struct where *where, ...)
{
  bool retval = false;
  va_list ap;
  va_start (ap, where);
  for (size_t i = 0; i < num_supported; ++i)
    {
      unsigned v = va_arg (ap, unsigned);
      if (version == v)
	{
	  retval = true;
	  break;
	}
    }
  va_end (ap);

  if (!retval)
    wr_error (where, ": unsupported version %d.\n", version);

  return retval;
}

/*
  Returns:
    -1 in case of error
    +0 in case of no error, but the chain only consisted of a
       terminating zero die.
    +1 in case some dies were actually loaded
 */
static int
read_die_chain (struct read_ctx *ctx,
		struct cu *cu,
		struct abbrev_table *abbrevs,
		Elf_Data *strings,
		bool dwarf_64, bool addr_64,
		struct ref_record *die_refs,
		struct ref_record *local_die_refs,
		struct coverage *strings_coverage,
		struct relocation_data *reloc,
		struct elf_file *file)
{
  bool got_die = false;
  uint64_t sibling_addr = 0;
  uint64_t die_off, prev_die_off = 0;
  struct abbrev *abbrev, *prev_abbrev = NULL;
  struct where where = WHERE (sec_info, NULL);

  while (!read_ctx_eof (ctx))
    {
      where = cu->where;
      die_off = read_ctx_get_offset (ctx);
      /* Shift reported DIE offset by CU offset, to match the way
	 readelf reports DIEs.  */
      where_reset_2 (&where, die_off + cu->offset);

      uint64_t abbr_code;

      prev_die_off = die_off;
      if (!checked_read_uleb128 (ctx, &abbr_code, &where, "abbrev code"))
	return -1;

      /* Check sibling value advertised last time through the loop.  */
      if (sibling_addr != 0)
	{
	  if (abbr_code == 0)
	    wr_error (&where,
		      ": is the last sibling in chain, but has a DW_AT_sibling attribute.\n");
	  else if (sibling_addr != die_off)
	    wr_error (&where, ": This DIE should have had its sibling at 0x%"
		      PRIx64 ", but it's at 0x%" PRIx64 " instead.\n",
		      sibling_addr, die_off);
	  sibling_addr = 0;
	}
      else if (prev_abbrev != NULL && prev_abbrev->has_children)
	/* Even if it has children, the DIE can't have a sibling
	   attribute if it's the last DIE in chain.  That's the reason
	   we can't simply check this when loading abbrevs.  */
	wr_message (mc_die_rel | mc_acc_suboptimal | mc_impact_4, &where,
		    ": This DIE had children, but no DW_AT_sibling attribute.\n");

      /* The section ended.  */
      if (abbr_code == 0)
	break;
      if (read_ctx_eof (ctx))
	{
	  wr_error (&where, ": DIE chain not terminated with DIE with zero abbrev code.\n");
	  break;
	}

      prev_die_off = die_off;
      got_die = true;

      /* Find the abbrev matching the code.  */
      abbrev = abbrev_table_find_abbrev (abbrevs, abbr_code);
      if (abbrev == NULL)
	{
	  wr_error (&where,
		    ": abbrev section at 0x%" PRIx64
		    " doesn't contain code %" PRIu64 ".\n",
		    abbrevs->offset, abbr_code);
	  return -1;
	}
      abbrev->used = true;

      addr_record_add (&cu->die_addrs, cu->offset + die_off);

      /* Attribute values.  */
      for (struct abbrev_attrib *it = abbrev->attribs;
	   it->name != 0; ++it)
	{
	  where.ref = &it->where;

	  void record_ref (uint64_t addr, struct where *who, bool local)
	  {
	    struct ref_record *record = &cu->die_refs;
	    if (local)
	      {
		assert (ctx->end > ctx->begin);
		if (addr > (uint64_t)(ctx->end - ctx->begin))
		  {
		    wr_error (&where,
			      ": invalid reference outside the CU: 0x%" PRIx64 ".\n",
			      addr);
		    return;
		  }

		/* Address holds a CU-local reference, so add CU
		   offset to turn it into section offset.  */
		addr += cu->offset;
		record = local_die_refs;
	      }

	    if (record != NULL)
	      ref_record_add (record, addr, who);
	  }

	  uint8_t form = it->form;
	  bool indirect = form == DW_FORM_indirect;
	  if (indirect)
	    {
	      uint64_t value;
	      if (!checked_read_uleb128 (ctx, &value, &where,
					 "indirect attribute form"))
		return -1;

	      if (!attrib_form_valid (value))
		{
		  wr_error (&where,
			    ": invalid indirect form 0x%" PRIx64 ".\n", value);
		  return -1;
		}
	      form = value;

	      if (it->name == DW_AT_sibling)
		switch (check_sibling_form (form))
		  {
		  case -1:
		    wr_message (mc_die_rel | mc_impact_2, &where,
				": DW_AT_sibling attribute with (indirect) form DW_FORM_ref_addr.\n");
		    break;

		  case -2:
		    wr_error (&where,
			      ": DW_AT_sibling attribute with non-reference (indirect) form \"%s\".\n",
			      dwarf_form_string (value));
		  };
	    }

	  enum check_what_t
	  {
	    check_nothing = 0,
	    check_locptr,
	    check_lineptr,
	    check_rangeptr
	  };
	  static enum message_category mc_check[] =
	    {
	      [check_nothing] = mc_none,
	      [check_locptr] = mc_loc,
	      [check_lineptr] = mc_line,
	      [check_rangeptr] = mc_ranges
	    };

	  void do_check_ptr (enum check_what_t what, uint64_t value)
	  {
	    assert (what != check_nothing);

	    if (what == check_rangeptr && ((value % cu->address_size) != 0))
	      wr_message (mc_ranges | mc_impact_2, &where,
			  ": rangeptr value %#" PRIx64
			  " not aligned to CU address size.\n", value);

	    struct ref_record *ref = NULL;
	    switch (what)
	      {
	      case check_rangeptr:
		ref = &cu->range_refs;
	        break;
	      case check_lineptr:
		ref = &cu->line_refs;
		break;
	      case check_locptr:
		ref = &cu->loc_refs;
	      case check_nothing:
		break;
	      };

	    ref_record_add (ref, value, &where);
	  }

	  enum check_what_t check_ptr = check_nothing;

	  if (is_location_attrib (it->name))
	    {
	      switch (form)
		{
		case DW_FORM_data8:
		  if (!dwarf_64)
		    wr_error (&where,
			      ": location attribute with form \"%s\" in 32-bit CU.\n",
			      dwarf_form_string (form));
		  /* fall-through */
		case DW_FORM_data4:
		  check_ptr = check_locptr;
		  /* fall-through */
		case DW_FORM_block1:
		case DW_FORM_block2:
		case DW_FORM_block4:
		case DW_FORM_block:
		  break;

		default:
		  /* Only print error if it's indirect.  Otherwise we
		     gave diagnostic during abbrev loading.  */
		  if (indirect)
		    wr_error (&where,
			      ": location attribute with invalid (indirect) form \"%s\".\n",
			      dwarf_form_string (form));
		};
	    }
	  else if (it->name == DW_AT_ranges
		   || it->name == DW_AT_stmt_list)
	    switch (form)
	      {
	      case DW_FORM_data8:
		if (!dwarf_64)
		  wr_error (&where,
			    ": %s with form DW_FORM_data8 in 32-bit CU.\n",
			    dwarf_attr_string (it->name));
		/* fall-through */
	      case DW_FORM_data4:
		if (it->name == DW_AT_ranges)
		  check_ptr = check_rangeptr;
		else
		  {
		    assert (it->name == DW_AT_stmt_list);
		    check_ptr = check_lineptr;
		  }
		break;

	      default:
		/* Only print error if it's indirect.  Otherwise we
		   gave diagnostic during abbrev loading.  */
		if (indirect)
		  wr_error (&where,
			    ": %s with invalid (indirect) form \"%s\".\n",
			    dwarf_attr_string (it->name),
			    dwarf_form_string (form));
	      };

	  uint64_t ctx_offset = read_ctx_get_offset (ctx) + cu->offset;
	  struct relocation *rel;
	  bool type_is_rel = file->ehdr.e_type == ET_REL;

	  switch (form)
	    {
	    case DW_FORM_strp:
	      {
		uint64_t addr;
		if (!read_ctx_read_offset (ctx, dwarf_64, &addr))
		  {
		  cant_read:
		    wr_error (&where, ": can't read attribute value.\n");
		    return -1;
		  }

		if ((rel = relocation_next (reloc, ctx_offset,
					    &where, skip_mismatched)))
		  relocate_one (reloc, rel, dwarf_64 ? 8 : 4,
				&addr, &where, sec_str, NULL);
		else if (type_is_rel)
		  wr_message (mc_impact_2 | mc_die_other | mc_reloc | mc_strings,
			      &where, PRI_LACK_RELOCATION, "DW_FORM_strp");

		if (strings == NULL)
		  wr_error (&where,
			    ": strp attribute, but no .debug_str section.\n");
		else if (addr >= strings->d_size)
		  wr_error (&where,
			    ": Invalid offset outside .debug_str: 0x%" PRIx64 ".\n",
			    addr);
		else
		  {
		    /* Record used part of .debug_str.  */
		    const char *strp = (const char *)strings->d_buf + addr;
		    uint64_t end = addr + strlen (strp);

		    if (strings_coverage != NULL)
		      coverage_add (strings_coverage, addr, end);
		  }

		break;
	      }

	    case DW_FORM_string:
	      {
		if (!read_ctx_read_str (ctx))
		  goto cant_read;
		break;
	      }

	    case DW_FORM_addr:
	    case DW_FORM_ref_addr:
	      {
		uint64_t addr;
		if (!read_ctx_read_offset (ctx, addr_64, &addr))
		  goto cant_read;

		if ((rel = relocation_next (reloc, ctx_offset,
					    &where, skip_mismatched)))
		  relocate_one (reloc, rel, addr_64 ? 8 : 4, &addr, &where,
				reloc_target (form, it), NULL);
		else if ((type_is_rel
			  || form == DW_FORM_ref_addr)
			 && addr != 0)
		  wr_message (mc_impact_2 | mc_die_rel | mc_reloc, &where,
			      PRI_LACK_RELOCATION, dwarf_form_string (form));

		if (form == DW_FORM_ref_addr)
		  record_ref (addr, &where, false);
		else if ((abbrev->tag == DW_TAG_compile_unit
			  || abbrev->tag == DW_TAG_partial_unit)
			 && it->name == DW_AT_low_pc)
		  cu->base = addr;

		break;
	      }

	    case DW_FORM_udata:
	    case DW_FORM_ref_udata:
	      {
		uint64_t value;
		if (!checked_read_uleb128 (ctx, &value, &where,
					   "attribute value"))
		  return -1;

		if (it->name == DW_AT_sibling)
		  sibling_addr = value;
		else if (form == DW_FORM_ref_udata)
		  record_ref (value, &where, true);
		break;
	      }

	    case DW_FORM_flag:
	    case DW_FORM_data1:
	    case DW_FORM_ref1:
	      {
		/* Neither of these should be relocated.  */
		uint8_t value;
		if (!read_ctx_read_ubyte (ctx, &value))
		  goto cant_read;

		if (it->name == DW_AT_sibling)
		  sibling_addr = value;
		else if (form == DW_FORM_ref1)
		  record_ref (value, &where, true);
		break;
	      }

	    case DW_FORM_data2:
	    case DW_FORM_ref2:
	      {
		/* Neither of these should be relocated.  */
		uint16_t value;
		if (!read_ctx_read_2ubyte (ctx, &value))
		  goto cant_read;

		if (it->name == DW_AT_sibling)
		  sibling_addr = value;
		else if (form == DW_FORM_ref2)
		  record_ref (value, &where, true);
		break;
	      }

	    case DW_FORM_data4:
	    case DW_FORM_ref4:
	      {
		uint32_t raw_value;
		if (!read_ctx_read_4ubyte (ctx, &raw_value))
		  goto cant_read;

		/* DW_FORM_ref4 shouldn't be relocated.  */
		uint64_t value = raw_value;
		if (form == DW_FORM_data4)
		  {
		    if ((rel = relocation_next (reloc, ctx_offset,
						&where, skip_mismatched)))
		      relocate_one (reloc, rel, 4, &value, &where,
				    reloc_target (form, it), NULL);
		    else if (type_is_rel && check_ptr != check_nothing)
		      wr_message (mc_impact_2 | mc_die_other | mc_reloc
				  | mc_check[check_ptr],
				  &where, PRI_LACK_RELOCATION,
				  dwarf_form_string (form));
		  }

		if (it->name == DW_AT_sibling)
		  sibling_addr = value;
		else if (check_ptr != check_nothing)
		  do_check_ptr (check_ptr, value);
		else if (form == DW_FORM_ref4)
		  record_ref (value, &where, true);
		break;
	      }

	    case DW_FORM_data8:
	    case DW_FORM_ref8:
	      {
		uint64_t value;
		if (!read_ctx_read_8ubyte (ctx, &value))
		  goto cant_read;

		/* DW_FORM_ref8 shouldn't be relocated.  */
		if (form == DW_FORM_data8)
		  {
		    if ((rel = relocation_next (reloc, ctx_offset,
						&where, skip_mismatched)))
		      relocate_one (reloc, rel, 8, &value, &where,
				    reloc_target (form, it), NULL);
		    else if (type_is_rel
			     && (check_locptr || check_rangeptr))
		      wr_message (mc_impact_2 | mc_die_other | mc_reloc
				  | (check_rangeptr ? mc_ranges : mc_loc),
				  &where, PRI_LACK_RELOCATION,
				  dwarf_form_string (form));
		  }

		if (it->name == DW_AT_sibling)
		  sibling_addr = value;
		else if (check_ptr != check_nothing)
		  do_check_ptr (check_ptr, value);
		else if (form == DW_FORM_ref8)
		  record_ref (value, &where, true);
		break;
	      }

	    case DW_FORM_sdata:
	      {
		int64_t value;
		if (!checked_read_sleb128 (ctx, &value, &where,
					   "attribute value"))
		  return -1;
		break;
	      }

	    case DW_FORM_block:
	      {
		int width = 0;
		uint64_t length;
		goto process_DW_FORM_block;

	    case DW_FORM_block1:
		width = 1;
		goto process_DW_FORM_block;

	    case DW_FORM_block2:
		width = 2;
		goto process_DW_FORM_block;

	    case DW_FORM_block4:
		width = 4;

	      process_DW_FORM_block:
		if (width == 0)
		  {
		    if (!checked_read_uleb128 (ctx, &length, &where,
					       "attribute value"))
		      return -1;
		  }
		else if (!read_ctx_read_var (ctx, width, &length))
		  goto cant_read;

		if (is_location_attrib (it->name))
		  {
		    uint64_t expr_start = cu->offset + read_ctx_get_offset (ctx);
		    if (!check_location_expression (ctx, expr_start,
						    reloc, length,
						    &where, addr_64))
		      return -1;
		  }
		else
		  relocation_skip (reloc,
				   read_ctx_get_offset (ctx) + length,
				   &where, skip_mismatched);

		if (!read_ctx_skip (ctx, length))
		  goto cant_read;

		break;
	      }

	    case DW_FORM_indirect:
	      wr_error (&where, ": indirect form is again indirect.\n");
	      return -1;

	    default:
	      wr_error (&where,
			": internal error: unhandled form 0x%x\n", form);
	    }
	}

      if (abbrev->has_children)
	{
	  int st = read_die_chain (ctx, cu, abbrevs, strings,
				   dwarf_64, addr_64,
				   die_refs, local_die_refs,
				   strings_coverage, reloc, file);
	  if (st == -1)
	    return -1;
	  else if (st == 0)
	    wr_message (mc_impact_3 | mc_acc_suboptimal | mc_die_rel,
			&where,
			": abbrev has_children, but the chain was empty.\n");
	}
    }

  if (sibling_addr != 0)
    wr_error (&where,
	      ": this DIE should have had its sibling at 0x%"
	      PRIx64 ", but the DIE chain ended.\n", sibling_addr);

  return got_die ? 1 : 0;
}

static bool
check_cu_structural (struct read_ctx *ctx,
		     struct cu *const cu,
		     struct abbrev_table *abbrev_chain,
		     Elf_Data *strings,
		     bool dwarf_64,
		     struct ref_record *die_refs,
		     struct coverage *strings_coverage,
		     struct relocation_data *reloc,
		     struct elf_file *file)
{
  uint8_t address_size;
  bool retval = true;

  /* Version.  */
  uint16_t version;
  if (!read_ctx_read_2ubyte (ctx, &version))
    {
      wr_error (&cu->where, ": can't read version.\n");
      return false;
    }
  if (!supported_version (version, 2, &cu->where, 2, 3))
    return false;
  if (version == 2 && dwarf_64)
    /* Keep going.  It's a standard violation, but we may still be
       able to read the unit under consideration and do high-level
       checks.  */
    wr_error (&cu->where, ": invalid 64-bit unit in DWARF 2 format.\n");

  /* Abbrev offset.  */
  uint64_t abbrev_offset;
  uint64_t ctx_offset = read_ctx_get_offset (ctx) + cu->offset;
  if (!read_ctx_read_offset (ctx, dwarf_64, &abbrev_offset))
    {
      wr_error (&cu->where, ": can't read abbrev offset.\n");
      return false;
    }

  struct relocation *rel
    = relocation_next (reloc, ctx_offset, &cu->where, skip_mismatched);
  if (rel != NULL)
    relocate_one (reloc, rel, dwarf_64 ? 8 : 4,
		  &abbrev_offset, &cu->where, sec_abbrev, NULL);
  else if (file->ehdr.e_type == ET_REL)
    wr_message (mc_impact_2 | mc_info | mc_reloc, &cu->where,
		PRI_LACK_RELOCATION, "abbrev offset");

  /* Address size.  */
  if (!read_ctx_read_ubyte (ctx, &address_size))
    {
      wr_error (&cu->where, ": can't read address size.\n");
      return false;
    }
  if (address_size != 4 && address_size != 8)
    {
      wr_error (&cu->where,
		": invalid address size: %d (only 4 or 8 allowed).\n",
		address_size);
      return false;
    }
  cu->address_size = address_size;

  struct abbrev_table *abbrevs = abbrev_chain;
  for (; abbrevs != NULL; abbrevs = abbrevs->next)
    if (abbrevs->offset == abbrev_offset)
      break;

  if (abbrevs == NULL)
    {
      wr_error (&cu->where,
		": couldn't find abbrev section with offset 0x%" PRIx64 ".\n",
		abbrev_offset);
      return false;
    }

  struct ref_record local_die_refs;
  WIPE (local_die_refs);

  cu->cudie_offset = read_ctx_get_offset (ctx) + cu->offset;
  if (read_die_chain (ctx, cu, abbrevs, strings,
		      dwarf_64, address_size == 8,
		      die_refs, &local_die_refs, strings_coverage,
		      (reloc != NULL && reloc->size > 0) ? reloc : NULL,
		      file) >= 0)
    {
      for (size_t i = 0; i < abbrevs->size; ++i)
	if (!abbrevs->abbr[i].used)
	  wr_message (mc_impact_3 | mc_acc_bloat | mc_abbrevs, &cu->where,
		      ": abbreviation with code %" PRIu64 " is never used.\n",
		      abbrevs->abbr[i].code);

      if (!check_die_references (cu, &local_die_refs))
	retval = false;
    }
  else
    retval = false;

  ref_record_free (&local_die_refs);
  return retval;
}

static struct cu *
check_info_structural (struct section_data *data,
		       struct abbrev_table *abbrev_chain,
		       Elf_Data *strings)
{
  struct read_ctx ctx;
  read_ctx_init (&ctx, data->file->dwarf, data->data);

  struct ref_record die_refs;
  WIPE (die_refs);

  struct cu *cu_chain = NULL;

  bool success = true;

  struct coverage strings_coverage_mem, *strings_coverage = NULL;
  if (strings != NULL && check_category (mc_strings))
    {
      coverage_init (&strings_coverage_mem, strings->d_size);
      strings_coverage = &strings_coverage_mem;
    }

  struct relocation_data *reloc = data->rel.size > 0 ? &data->rel : NULL;
  while (!read_ctx_eof (&ctx))
    {
      const unsigned char *cu_begin = ctx.ptr;
      struct where where = WHERE (sec_info, NULL);
      where_reset_1 (&where, read_ctx_get_offset (&ctx));

      struct cu *cur = xcalloc (1, sizeof (*cur));
      cur->offset = where.addr1;
      cur->next = cu_chain;
      cur->where = where;
      cur->base = (uint64_t)-1;
      cu_chain = cur;

      uint32_t size32;
      uint64_t size;
      bool dwarf_64 = false;

      /* Reading CU header is a bit tricky, because we don't know if
	 we have run into (superfluous but allowed) zero padding.  */
      if (!read_ctx_need_data (&ctx, 4)
	  && check_zero_padding (&ctx, mc_info | mc_header, &where))
	break;

      /* CU length.  */
      if (!read_ctx_read_4ubyte (&ctx, &size32))
	{
	  wr_error (&where, ": can't read CU length.\n");
	  success = false;
	  break;
	}
      if (size32 == 0 && check_zero_padding (&ctx, mc_info | mc_header, &where))
	break;

      if (!read_size_extra (&ctx, size32, &size, &dwarf_64, &where))
	{
	  success = false;
	  break;
	}

      if (!read_ctx_need_data (&ctx, size))
	{
	  wr_error (&where,
		    ": section doesn't have enough data"
		    " to read CU of size %" PRIx64 ".\n", size);
	  ctx.ptr = ctx.end;
	  success = false;
	  break;
	}

      const unsigned char *cu_end = ctx.ptr + size;
      cur->length = cu_end - cu_begin; // Length including the length field.

      /* version + debug_abbrev_offset + address_size */
      uint64_t cu_header_size = 2 + (dwarf_64 ? 8 : 4) + 1;
      if (size < cu_header_size)
	{
	  wr_error (&where, ": claimed length of %" PRIx64
		    " doesn't even cover CU header.\n", size);
	  success = false;
	  break;
	}
      else
	{
	  /* Make CU context begin just before the CU length, so that DIE
	     offsets are computed correctly.  */
	  struct read_ctx cu_ctx;
	  if (!read_ctx_init_sub (&cu_ctx, &ctx, cu_begin, cu_end))
	    {
	    not_enough:
	      wr_error (&where, PRI_NOT_ENOUGH, "next CU");
	      success = false;
	      break;
	    }
	  cu_ctx.ptr = ctx.ptr;

	  if (!check_cu_structural (&cu_ctx, cur, abbrev_chain,
				    strings, dwarf_64, &die_refs,
				    strings_coverage, reloc, data->file))
	    {
	      success = false;
	      break;
	    }
	  if (cu_ctx.ptr != cu_ctx.end
	      && !check_zero_padding (&cu_ctx, mc_info, &where))
	    wr_message_padding_n0 (mc_info, &where,
				   read_ctx_get_offset (&ctx),
				   read_ctx_get_offset (&ctx) + size - 1);
	}

      if (!read_ctx_skip (&ctx, size))
	goto not_enough;
    }

  if (success)
    {
      if (ctx.ptr != ctx.end)
	/* Did we read up everything?  */
	wr_message (mc_die_other | mc_impact_4,
		    &WHERE (sec_info, NULL),
		    ": CU lengths don't exactly match Elf_Data contents.");
      else
	/* Did we consume all the relocations?  */
	relocation_skip_rest (data);
    }


  int address_size = 0;
  if (cu_chain != NULL)
    {
      uint64_t offset = 0;
      for (struct cu *it = cu_chain; it != NULL; it = it->next)
	if (address_size == 0)
	  {
	    address_size = it->address_size;
	    offset = it->where.addr1;
	  }
	else if (address_size != it->address_size)
	  {
	    /* XXX would be nice to check consistency of CU address
	       size declared in various other .debug_* sections.  */
	    wr_message (mc_info, &it->where,
			": has different address size than CU 0x%"
			PRIx64 ".\n", offset);
	    address_size = 0;
	    break;
	  }
    }

  bool references_sound = check_global_die_references (cu_chain);
  ref_record_free (&die_refs);

  if (strings_coverage != NULL)
    {
      if (success)
	coverage_find_holes (strings_coverage, found_hole,
			     &((struct hole_info)
			       {sec_str, mc_strings, 0, strings->d_buf}));
      coverage_free (strings_coverage);
    }

  if (!success || !references_sound)
    {
      cu_free (cu_chain);
      cu_chain = NULL;
    }

  /* Reverse the chain, so that it's organized "naturally".  Has
     significant impact on performance when handling loc_ref and
     range_ref fields in loc/range validation.  */
  struct cu *last = NULL;
  for (struct cu *it = cu_chain; it != NULL; )
    {
      struct cu *next = it->next;
      it->next = last;
      last = it;
      it = next;
    }
  cu_chain = last;

  return cu_chain;
}

static struct coverage_map *
coverage_map_alloc_XA (Elf *elf, bool allow_overlap)
{
  struct coverage_map *ret = xmalloc (sizeof (*ret));
  if (!coverage_map_init (ret, elf, SHF_ALLOC | SHF_EXECINSTR, allow_overlap))
    {
      free (ret);
      return NULL;
    }
  return ret;
}

static void
coverage_map_free_XA (struct coverage_map *coverage_map)
{
  if (coverage_map != NULL)
    {
      coverage_map_free (coverage_map);
      free (coverage_map);
    }
}

static bool
check_aranges_structural (struct section_data *data, struct cu *cu_chain)
{
  struct read_ctx ctx;
  read_ctx_init (&ctx, data->file->dwarf, data->data);

  bool retval = true;

  struct coverage_map *coverage_map;
  if ((coverage_map = coverage_map_alloc_XA (data->file->dwarf->elf,
					     false)) == NULL)
    {
      wr_error (&WHERE (sec_aranges, NULL),
		": couldn't read ELF, skipping coverage analysis.\n");
      retval = false;
    }

  while (!read_ctx_eof (&ctx))
    {
      struct where where = WHERE (sec_aranges, NULL);
      where_reset_1 (&where, read_ctx_get_offset (&ctx));
      const unsigned char *atab_begin = ctx.ptr;

      /* Size.  */
      uint32_t size32;
      uint64_t size;
      bool dwarf_64;
      if (!read_ctx_read_4ubyte (&ctx, &size32))
	{
	  wr_error (&where, ": can't read table length.\n");
	  return false;
	}
      if (!read_size_extra (&ctx, size32, &size, &dwarf_64, &where))
	return false;

      struct read_ctx sub_ctx;
      const unsigned char *atab_end = ctx.ptr + size;
      if (!read_ctx_init_sub (&sub_ctx, &ctx, atab_begin, atab_end))
	{
	not_enough:
	  wr_error (&where, PRI_NOT_ENOUGH, "next table");
	  return false;
	}

      sub_ctx.ptr = ctx.ptr;

      /* Version.  */
      uint16_t version;
      if (!read_ctx_read_2ubyte (&sub_ctx, &version))
	{
	  wr_error (&where, ": can't read version.\n");
	  retval = false;
	  goto next;
	}
      if (!supported_version (version, 1, &where, 2))
	{
	  retval = false;
	  goto next;
	}

      /* CU offset.  */
      uint64_t cu_offset;
      uint64_t ctx_offset = sub_ctx.ptr - ctx.begin;
      if (!read_ctx_read_offset (&sub_ctx, dwarf_64, &cu_offset))
	{
	  wr_error (&where, ": can't read debug info offset.\n");
	  retval = false;
	  goto next;
	}

      struct relocation *rel;
      if ((rel = relocation_next (&data->rel, ctx_offset,
				  &where, skip_mismatched)))
	relocate_one (&data->rel, rel, dwarf_64 ? 8 : 4,
		      &cu_offset, &where, sec_info, NULL);
      else if (data->file->ehdr.e_type == ET_REL)
	wr_message (mc_impact_2 | mc_aranges | mc_reloc | mc_header, &where,
		    PRI_LACK_RELOCATION, "debug info offset");

      struct cu *cu = NULL;
      if (cu_chain != NULL && (cu = cu_find_cu (cu_chain, cu_offset)) == NULL)
	wr_error (&where, ": unresolved reference to " PRI_CU ".\n", cu_offset);

      struct where where_cudie;
      if (cu != NULL)
	{
	  where_cudie = WHERE (sec_info, NULL);
	  where_reset_1 (&where_cudie, cu->cudie_offset);
	  where.ref = &where_cudie;
	  where_cudie.formatting = wf_cudie;
	  if (cu->has_arange)
	    wr_message (mc_impact_2 | mc_aranges | mc_header, &where,
			": there has already been arange section for this CU.\n");
	  else
	    cu->has_arange = true;
	}

      /* Address size.  */
      uint8_t address_size;
      if (!read_ctx_read_ubyte (&sub_ctx, &address_size))
	{
	  wr_error (&where, ": can't read address size.\n");
	  retval = false;
	  goto next;
	}
      if (cu != NULL)
	{
	  if (address_size != cu->address_size)
	    {
	      wr_error (&where,
			": address size %d doesn't match referred CU.\n",
			address_size);
	      retval = false;
	    }
	}
      /* Try to parse it anyway, unless the address size is wacky.  */
      else if (address_size != 4 && address_size != 8)
	{
	  wr_error (&where, ": invalid address size: %d.\n", address_size);
	  retval = false;
	  goto next;
	}

      /* Segment size.  */
      uint8_t segment_size;
      if (!read_ctx_read_ubyte (&sub_ctx, &segment_size))
	{
	  wr_error (&where, ": can't read unit segment size.\n");
	  retval = false;
	  goto next;
	}
      if (segment_size != 0)
	{
	  wr_warning (&where, ": dwarflint can't handle segment_size != 0.\n");
	  retval = false;
	  goto next;
	}


      /* 7.20: The first tuple following the header in each set begins
	 at an offset that is a multiple of the size of a single tuple
	 (that is, twice the size of an address). The header is
	 padded, if necessary, to the appropriate boundary.  */
      const uint8_t tuple_size = 2 * address_size;
      uint64_t off = read_ctx_get_offset (&sub_ctx);
      if ((off % tuple_size) != 0)
	{
	  uint64_t noff = ((off / tuple_size) + 1) * tuple_size;
	  for (uint64_t i = off; i < noff; ++i)
	    {
	      uint8_t c;
	      if (!read_ctx_read_ubyte (&sub_ctx, &c))
		{
		  wr_error (&where,
			    ": section ends after the header, but before the first entry.\n");
		  retval = false;
		  goto next;
		}
	      if (c != 0)
		wr_message (mc_impact_2 | mc_aranges | mc_header, &where,
			    ": non-zero byte at 0x%" PRIx64
			    " in padding before the first entry.\n",
			    read_ctx_get_offset (&sub_ctx));
	    }
	}
      assert ((read_ctx_get_offset (&sub_ctx) % tuple_size) == 0);

      while (!read_ctx_eof (&sub_ctx))
	{
	  where_reset_2 (&where, read_ctx_get_offset (&sub_ctx));

	  /* Record address.  */
	  uint64_t address;
	  ctx_offset = sub_ctx.ptr - ctx.begin;
	  bool address_relocated = false;
	  if (!read_ctx_read_var (&sub_ctx, address_size, &address))
	    {
	      wr_error (&where, ": can't read address field.\n");
	      retval = false;
	      goto next;
	    }

    	  if ((rel = relocation_next (&data->rel, ctx_offset,
				      &where, skip_mismatched)))
	    {
	      address_relocated = true;
	      relocate_one (&data->rel, rel, address_size,
			    &address, &where, sec_text, NULL);
	    }
	  else if (data->file->ehdr.e_type == ET_REL
		   && address != 0)
	    wr_message (mc_impact_2 | mc_aranges | mc_reloc, &where,
			PRI_LACK_RELOCATION, "address field");

	  /* Record length.  */
	  uint64_t length;
	  if (!read_ctx_read_var (&sub_ctx, address_size, &length))
	    {
	      wr_error (&where, ": can't read length field.\n");
	      retval = false;
	      goto next;
	    }

	  if (address == 0 && length == 0 && !address_relocated)
	    break;

	  /* Skip coverage analysis if we have errors.  */
	  if (retval)
	    coverage_map_add (coverage_map, address, length, &where,
			      mc_aranges);
	}

      if (sub_ctx.ptr != sub_ctx.end
	  && !check_zero_padding (&sub_ctx, mc_pubtables,
				  &WHERE (where.section, NULL)))
	{
	  wr_message_padding_n0 (mc_pubtables | mc_error,
				 &WHERE (where.section, NULL),
				 read_ctx_get_offset (&sub_ctx),
				 read_ctx_get_offset (&sub_ctx) + size - 1);
	  retval = false;
	}

    next:
      if (!read_ctx_skip (&ctx, size))
	/* A "can't happen" error.  */
	goto not_enough;
    }

  if (retval && coverage_map != NULL)
    coverage_map_find_holes (coverage_map, &coverage_map_found_hole,
			     &(struct coverage_map_hole_info)
			       {{sec_aranges, mc_aranges, 0, NULL},
				 coverage_map->elf});

  coverage_map_free_XA (coverage_map);

  return retval;
}

static bool
check_pub_structural (struct section_data *data,
		      struct cu *cu_chain)
{
  struct read_ctx ctx;
  read_ctx_init (&ctx, data->file->dwarf, data->data);
  bool retval = true;

  while (!read_ctx_eof (&ctx))
    {
      struct where where = WHERE_SECDATA (data, NULL);
      where_reset_1 (&where, read_ctx_get_offset (&ctx));
      const unsigned char *set_begin = ctx.ptr;

      /* Size.  */
      uint32_t size32;
      uint64_t size;
      bool dwarf_64;
      if (!read_ctx_read_4ubyte (&ctx, &size32))
	{
	  wr_error (&where, ": can't read table length.\n");
	  return false;
	}
      if (!read_size_extra (&ctx, size32, &size, &dwarf_64, &where))
	return false;

      struct read_ctx sub_ctx;
      const unsigned char *set_end = ctx.ptr + size;
      if (!read_ctx_init_sub (&sub_ctx, &ctx, set_begin, set_end))
	{
	not_enough:
	  wr_error (&where, PRI_NOT_ENOUGH, "next set");
	  return false;
	}
      sub_ctx.ptr = ctx.ptr;

      /* Version.  */
      uint16_t version;
      if (!read_ctx_read_2ubyte (&sub_ctx, &version))
	{
	  wr_error (&where, ": can't read set version.\n");
	  retval = false;
	  goto next;
	}
      if (!supported_version (version, 1, &where, 2))
	{
	  retval = false;
	  goto next;
	}

      /* CU offset.  */
      uint64_t cu_offset;  /* Offset of related CU.  */
      uint64_t ctx_offset = sub_ctx.ptr - ctx.begin;
      if (!read_ctx_read_offset (&sub_ctx, dwarf_64, &cu_offset))
	{
	  wr_error (&where, ": can't read debug info offset.\n");
	  retval = false;
	  goto next;
	}

      struct relocation *rel;
      if ((rel = relocation_next (&data->rel, ctx_offset,
				  &where, skip_mismatched)))
	relocate_one (&data->rel, rel, dwarf_64 ? 8 : 4,
		      &cu_offset, &where, sec_info, NULL);
      else if (data->file->ehdr.e_type == ET_REL)
	wr_message (mc_impact_2 | mc_pubtables | mc_reloc | mc_header, &where,
		    PRI_LACK_RELOCATION, "debug info offset");

      struct cu *cu = NULL;
      enum section_id sec = data_get_sec (data)->id;
      if (cu_chain != NULL && (cu = cu_find_cu (cu_chain, cu_offset)) == NULL)
	wr_error (&where, ": unresolved reference to " PRI_CU ".\n", cu_offset);
      if (cu != NULL)
	{
	  where.ref = &cu->where;
	  bool *has = sec == sec_pubnames
			? &cu->has_pubnames : &cu->has_pubtypes;
	  if (*has)
	    wr_message (mc_impact_2 | mc_pubtables | mc_header, &where,
			": there has already been section for this CU.\n");
	  else
	    *has = true;
	}

      /* Covered length.  */
      uint64_t cu_len;
      if (!read_ctx_read_offset (&sub_ctx, dwarf_64, &cu_len))
	{
	  wr_error (&where, ": can't read covered length.\n");
	  retval = false;
	  goto next;
	}
      if (cu != NULL && cu_len != cu->length)
	{
	  wr_error (&where,
		    ": the table covers length %" PRId64
		    " but CU has length %" PRId64 ".\n", cu_len, cu->length);
	  retval = false;
	  goto next;
	}

      /* Records... */
      while (!read_ctx_eof (&sub_ctx))
	{
	  ctx_offset = sub_ctx.ptr - ctx.begin;
	  where_reset_2 (&where, ctx_offset);

	  uint64_t offset;
	  if (!read_ctx_read_offset (&sub_ctx, dwarf_64, &offset))
	    {
	      wr_error (&where, ": can't read offset field.\n");
	      retval = false;
	      goto next;
	    }
	  if (offset == 0)
	    break;

	  if (cu != NULL
	      && !addr_record_has_addr (&cu->die_addrs, offset + cu->offset))
	    {
	      wr_error (&where,
			": unresolved reference to " PRI_DIE ".\n", offset);
	      retval = false;
	      goto next;
	    }

	  uint8_t c;
	  do
	    if (!read_ctx_read_ubyte (&sub_ctx, &c))
	      {
		wr_error (&where, ": can't read symbol name.\n");
		retval = false;
		goto next;
	      }
	  while (c);
	}

      if (sub_ctx.ptr != sub_ctx.end
	  && !check_zero_padding (&sub_ctx, mc_pubtables,
				  &WHERE (sec, NULL)))
	{
	  wr_message_padding_n0 (mc_pubtables | mc_error,
				 &WHERE (sec, NULL),
				 read_ctx_get_offset (&sub_ctx),
				 read_ctx_get_offset (&sub_ctx) + size - 1);
	  retval = false;
	}

    next:
      if (!read_ctx_skip (&ctx, size))
	goto not_enough;
    }

  if (retval)
    relocation_skip_rest (data);

  return retval;
}


/* Operands are passed back as attribute forms.  In particular,
   DW_FORM_dataX for X-byte operands, DW_FORM_[us]data for
   ULEB128/SLEB128 operands, and DW_FORM_addr for 32b/64b operands.
   If the opcode takes no operands, 0 is passed.

   Return value is false if we couldn't determine (i.e. invalid
   opcode).
 */
static bool
get_location_opcode_operands (uint8_t opcode, uint8_t *op1, uint8_t *op2)
{
  switch (opcode)
    {
#define DEF_DW_OP(OPCODE, OP1, OP2)  \
      case OPCODE: *op1 = OP1; *op2 = OP2; return true;
# include "expr_opcodes.h"
#undef DEF_DW_OP
    default:
      return false;
    };
}

static bool
check_location_expression (struct read_ctx *parent_ctx,
			   uint64_t init_off,
			   struct relocation_data *reloc,
			   size_t length,
			   struct where *wh,
			   bool addr_64)
{
  struct read_ctx ctx;
  if (!read_ctx_init_sub (&ctx, parent_ctx, parent_ctx->ptr,
			  parent_ctx->ptr + length))
    {
      wr_error (wh, PRI_NOT_ENOUGH, "location expression");
      return false;
    }

  struct ref_record oprefs;
  WIPE (oprefs);

  struct addr_record opaddrs;
  WIPE (opaddrs);

  while (!read_ctx_eof (&ctx))
    {
      struct where where = WHERE (sec_locexpr, wh);
      uint64_t opcode_off = read_ctx_get_offset (&ctx) + init_off;
      where_reset_1 (&where, opcode_off);
      addr_record_add (&opaddrs, opcode_off);

      uint8_t opcode;
      if (!read_ctx_read_ubyte (&ctx, &opcode))
	{
	  wr_error (&where, ": can't read opcode.\n");
	  break;
	}

      uint8_t op1, op2;
      if (!get_location_opcode_operands (opcode, &op1, &op2))
	{
	  wr_error (&where, ": can't decode opcode \"%s\".\n",
		    dwarf_locexpr_opcode_string (opcode));
	  break;
	}

#define READ_FORM(OP, STR, PTR)						\
      do {								\
	if (OP != 0)							\
	  {								\
	    uint64_t _off = read_ctx_get_offset (&ctx) + init_off;	\
	    uint64_t *_ptr = (PTR);					\
	    if (!read_ctx_read_form (&ctx, addr_64, (OP),		\
				     _ptr, &where, STR " operand"))	\
	      {								\
		wr_error (&where, ": opcode \"%s\""			\
			  ": can't read " STR " operand (form \"%s\").\n", \
			  dwarf_locexpr_opcode_string (opcode),		\
			  dwarf_form_string ((OP)));			\
		goto out;						\
	      }								\
	    struct relocation *_rel;					\
	    if ((_rel = relocation_next (reloc, _off,			\
					 &where, skip_mismatched)))	\
	      relocate_one (reloc, _rel,				\
			    addr_64 ? 8 : 4, _ptr, &where,		\
			    reloc_target_loc (opcode), NULL);		\
	  }								\
      } while (0)

      uint64_t value1, value2;
      READ_FORM (op1, "1st", &value1);
      READ_FORM (op2, "2st", &value2);
#undef READ_FORM

      switch (opcode)
	{
	case DW_OP_bra:
	case DW_OP_skip:
	  {
	    int16_t skip = (uint16_t)value1;

	    if (skip == 0)
	      wr_message (mc_loc | mc_acc_bloat | mc_impact_3, &where,
			  ": %s with skip 0.\n",
			  dwarf_locexpr_opcode_string (opcode));
	    else if (skip > 0 && !read_ctx_need_data (&ctx, (size_t)skip))
	      wr_error (&where, ": %s branches out of location expression.\n",
			dwarf_locexpr_opcode_string (opcode));
	    /* Compare with the offset after the two-byte skip value.  */
	    else if (skip < 0 && ((uint64_t)-skip) > read_ctx_get_offset (&ctx))
	      wr_error (&where,
			": %s branches before the beginning of location expression.\n",
			dwarf_locexpr_opcode_string (opcode));
	    else
	      ref_record_add (&oprefs, opcode_off + skip, &where);

	    break;
	  }

	case DW_OP_const8u:
	case DW_OP_const8s:
	  if (!addr_64)
	    wr_error (&where, ": %s on 32-bit machine.\n",
		      dwarf_locexpr_opcode_string (opcode));
	  break;

	default:
	  if (!addr_64
	      && (opcode == DW_OP_constu
		  || opcode == DW_OP_consts
		  || opcode == DW_OP_deref_size
		  || opcode == DW_OP_plus_uconst)
	      && (value1 > (uint64_t)(uint32_t)-1))
	    wr_error (&where, ": %s with operand %#" PRIx64 " on 32-bit machine.\n",
		      dwarf_locexpr_opcode_string (opcode), value1);
	};
    }

 out:
  for (size_t i = 0; i < oprefs.size; ++i)
    {
      struct ref *ref = oprefs.refs + i;
      if (!addr_record_has_addr (&opaddrs, ref->addr))
	wr_error (&ref->who,
		  ": unresolved reference to opcode at %#" PRIx64 ".\n",
		  ref->addr);
    }

  addr_record_free (&opaddrs);
  ref_record_free (&oprefs);

  return true;
}

static bool
check_loc_or_range_ref (const struct read_ctx *parent_ctx,
			struct cu *cu,
			struct section_data *data,
			struct coverage *coverage,
			struct coverage_map *coverage_map,
			uint64_t addr,
			bool addr_64,
			struct where *wh,
			enum message_category cat)
{
  struct read_ctx ctx;
  read_ctx_init (&ctx, parent_ctx->dbg, parent_ctx->data);

  enum section_id sec = data_get_sec (data)->id;

  assert (sec == sec_loc || sec == sec_ranges);
  assert (cat == mc_loc || cat == mc_ranges);
  assert ((sec == sec_loc) == (cat == mc_loc));
  assert (coverage != NULL);

  if (!read_ctx_skip (&ctx, addr))
    {
      wr_error (wh, ": invalid reference outside the section "
		"%#" PRIx64 ", size only %#tx.\n",
		addr, ctx.end - ctx.begin);
      return false;
    }

  bool retval = true;
  bool contains_locations = sec == sec_loc;

  if (coverage_is_covered (coverage, addr))
    {
      wr_error (wh, ": reference to 0x%" PRIx64
		" points at the middle of location or range list.\n", addr);
      retval = false;
    }

  uint64_t escape = addr_64 ? (uint64_t)-1 : (uint64_t)(uint32_t)-1;

  bool overlap = false;
  uint64_t base = cu->base;
  while (!read_ctx_eof (&ctx))
    {
      struct where where = WHERE (sec, wh);
      where_reset_1 (&where, read_ctx_get_offset (&ctx));

#define HAVE_OVERLAP						\
      do {							\
	wr_error (&where, ": range definitions overlap.\n");	\
	retval = false;						\
	overlap = true;						\
      } while (0)

      /* begin address */
      uint64_t begin_addr;
      uint64_t begin_off = read_ctx_get_offset (&ctx);
      GElf_Sym begin_symbol_mem, *begin_symbol = &begin_symbol_mem;
      bool begin_relocated = false;
      if (!overlap
	  && !coverage_pristine (coverage, begin_off, addr_64 ? 8 : 4))
	HAVE_OVERLAP;

      if (!read_ctx_read_offset (&ctx, addr_64, &begin_addr))
	{
	  wr_error (&where, ": can't read address range beginning.\n");
	  return false;
	}

      struct relocation *rel;
      if ((rel = relocation_next (&data->rel, begin_off,
				  &where, skip_mismatched)))
	{
	  begin_relocated = true;
	  relocate_one (&data->rel, rel, addr_64 ? 8 : 4,
			&begin_addr, &where, rel_value,	&begin_symbol);
	}

      /* end address */
      uint64_t end_addr;
      uint64_t end_off = read_ctx_get_offset (&ctx);
      GElf_Sym end_symbol_mem, *end_symbol = &end_symbol_mem;
      bool end_relocated = false;
      if (!overlap
	  && !coverage_pristine (coverage, end_off, addr_64 ? 8 : 4))
	HAVE_OVERLAP;

      if (!read_ctx_read_offset (&ctx, addr_64, &end_addr))
	{
	  wr_error (&where, ": can't read address range ending.\n");
	  return false;
	}

      if ((rel = relocation_next (&data->rel, end_off,
				  &where, skip_mismatched)))
	{
	  end_relocated = true;
	  relocate_one (&data->rel, rel, addr_64 ? 8 : 4,
			&end_addr, &where, rel_value, &end_symbol);
	  if (begin_addr != escape)
	    {
	      if (!begin_relocated)
		wr_message (cat | mc_impact_2, &where,
			    ": end of address range is relocated, but the beginning wasn't.\n");
	      else if (begin_symbol != NULL
		       && end_symbol != NULL
		       && begin_symbol->st_shndx != end_symbol->st_shndx)
		wr_message (cat | mc_impact_2, &where,
			    ": symbols of begin and end relocations reference"
			    " different sections (%d and %d).\n",
			    begin_symbol->st_shndx, end_symbol->st_shndx);
	    }
	}
      else if (begin_relocated)
	wr_message (cat | mc_impact_2, &where,
		    ": end of address range is not relocated, but the beginning was.\n");

      bool done = false;
      if (begin_addr == 0 && end_addr == 0 && !begin_relocated && !end_relocated)
	done = true;
      else if (begin_addr != escape)
	{
	  if (base == (uint64_t)-1)
	    {
	      wr_error (&where,
			": address range with no base address set (%#"
			PRIx64 "..%#" PRIx64 ").\n", begin_addr, end_addr);
	      /* This is not something that would derail high-level,
		 so carry on.  */
	    }

	  if (end_addr < begin_addr)
	    wr_message (cat | mc_error, &where,
			": has negative range 0x%" PRIx64 "..0x%" PRIx64 ".\n",
			begin_addr, end_addr);
	  else if (begin_addr == end_addr)
	    /* 2.6.6: A location list entry [...] whose beginning
	       and ending addresses are equal has no effect.  */
	    wr_message (cat | mc_acc_bloat | mc_impact_3, &where,
			": entry covers no range.\n");
	  /* Skip coverage analysis if we have errors or have no base
	     (or just don't do coverage analysis at all).  */
	  else if (base < (uint64_t)-2 && retval && coverage_map != NULL)
	    {
	      uint64_t address = begin_addr + base;
	      uint64_t length = end_addr - begin_addr;
	      coverage_map_add (coverage_map, address, length, &where, cat);
	    }

	  if (contains_locations)
	    {
	      /* location expression length */
	      uint16_t len;
	      if (!overlap
		  && !coverage_pristine (coverage,
					 read_ctx_get_offset (&ctx), 2))
		HAVE_OVERLAP;

	      if (!read_ctx_read_2ubyte (&ctx, &len))
		{
		  wr_error (&where, ": can't read length of location expression.\n");
		  return false;
		}

	      /* location expression itself */
	      uint64_t expr_start = read_ctx_get_offset (&ctx);
	      if (!check_location_expression (&ctx, expr_start, &data->rel,
					      len, &where, addr_64))
		return false;
	      uint64_t expr_end = read_ctx_get_offset (&ctx);
	      if (!overlap
		  && !coverage_pristine (coverage,
					 expr_start, expr_end - expr_start))
		HAVE_OVERLAP;

	      if (!read_ctx_skip (&ctx, len))
		{
		  /* "can't happen" */
		  wr_error (&where, PRI_NOT_ENOUGH, "location expression");
		  return false;
		}
	    }
	}
      else
	{
	  if (end_addr == base)
	    wr_message (cat | mc_acc_bloat | mc_impact_3, &where,
			": base address selection doesn't change base address"
			" (%#" PRIx64 ").\n", base);
	  else
	    base = end_addr;
	}
#undef HAVE_OVERLAP

      coverage_add (coverage, where.addr1, read_ctx_get_offset (&ctx) - 1);
      if (done)
	break;
    }

  return retval;
}

static bool
check_loc_or_range_structural (struct section_data *data,
			       struct cu *cu_chain)
{
  enum section_id sec = data_get_sec (data)->id;
  assert (sec == sec_loc || sec == sec_ranges);
  assert (cu_chain != NULL);

  struct read_ctx ctx;
  read_ctx_init (&ctx, data->file->dwarf, data->data);

  bool retval = true;

  struct coverage_map *coverage_map = NULL;
#ifdef FIND_SECTION_HOLES
  if ((coverage_map = coverage_map_alloc_XA (ctx.dbg->elf,
					     data->sec == sec_loc)) == NULL)
    {
      wr_error (&WHERE (data->sec, NULL),
		": couldn't read ELF, skipping coverage analysis.\n");
      retval = false;
    }
#endif

  struct coverage coverage;
  coverage_init (&coverage, ctx.data->d_size);

  enum message_category cat = sec == sec_loc ? mc_loc : mc_ranges;

  /* Relocation checking in the followings assumes that all the
     references are organized in monotonously increasing order.  That
     doesn't have to be the case.  So merge all the references into
     them into one sorted array.  */
  size_t size = 0;
  for (struct cu *cu = cu_chain; cu != NULL; cu = cu->next)
    {
      struct ref_record *rec
	= sec == sec_loc ? &cu->loc_refs : &cu->range_refs;
      size += rec->size;
    }
  struct ref_cu
  {
    struct ref ref;
    struct cu *cu;
  };
  struct ref_cu *refs = xmalloc (sizeof (*refs) * size);
  struct ref_cu *refptr = refs;
  for (struct cu *cu = cu_chain; cu != NULL; cu = cu->next)
    {
      struct ref_record *rec
	= sec == sec_loc ? &cu->loc_refs : &cu->range_refs;
      for (size_t i = 0; i < rec->size; ++i)
	*refptr++ = ((struct ref_cu){.ref = rec->refs[i], .cu = cu});
    }
  int compare_refs (const void *a, const void *b)
  {
    const struct ref_cu *ref_a = (const struct ref_cu *)a;
    const struct ref_cu *ref_b = (const struct ref_cu *)b;

    if (ref_a->ref.addr > ref_b->ref.addr)
      return 1;
    else if (ref_a->ref.addr < ref_b->ref.addr)
      return -1;
    else
      return 0;
  }
  qsort (refs, size, sizeof (*refs), compare_refs);

  uint64_t last_off = 0;
  for (size_t i = 0; i < size; ++i)
    {
      uint64_t off = refs[i].ref.addr;
      if (i > 0)
	{
	  if (off == last_off)
	    continue;
	  relocation_skip (&data->rel, off,
			   &WHERE (sec, NULL), skip_unref);
	}
      if (!check_loc_or_range_ref (&ctx, refs[i].cu, data,
				   &coverage, coverage_map,
				   off, refs[i].cu->address_size == 8,
				   &refs[i].ref.who, cat))
	retval = false;
      last_off = off;
    }

  if (retval)
    {
      relocation_skip_rest (data);

      /* We check that all CUs have the same address size when building
	 the CU chain.  So just take the address size of the first CU in
	 chain.  */
      coverage_find_holes (&coverage, found_hole,
			   &((struct hole_info)
			     {sec, cat, cu_chain->address_size,
			      ctx.data->d_buf}));

      if (coverage_map)
	coverage_map_find_holes (coverage_map, &coverage_map_found_hole,
				 &(struct coverage_map_hole_info)
				 {{sec, cat, 0, NULL},
				   coverage_map->elf});
    }


  coverage_free (&coverage);
  coverage_map_free_XA (coverage_map);

  return retval;
}

static GElf_Rela *
get_rel_or_rela (Elf_Data *data, int ndx,
		 GElf_Rela *dst, size_t type)
{
  if (type == SHT_RELA)
    return gelf_getrela (data, ndx, dst);
  else
    {
      assert (type == SHT_REL);
      GElf_Rel rel_mem;
      if (gelf_getrel (data, ndx, &rel_mem) == NULL)
	return NULL;
      dst->r_offset = rel_mem.r_offset;
      dst->r_info = rel_mem.r_info;
      dst->r_addend = 0;
      return dst;
    }
}

static bool
read_rel (struct section_data *secdata, Elf_Data *reldata, bool elf_64)
{
  assert (secdata->rel.type == SHT_REL
	  || secdata->rel.type == SHT_RELA);
  bool is_rela = secdata->rel.type == SHT_RELA;

  struct read_ctx ctx;
  read_ctx_init (&ctx, secdata->file->dwarf, secdata->data);

  size_t entrysize
    = elf_64
    ? (is_rela ? sizeof (Elf64_Rela) : sizeof (Elf64_Rel))
    : (is_rela ? sizeof (Elf32_Rela) : sizeof (Elf32_Rel));
  size_t count = reldata->d_size / entrysize;

  struct where parent = WHERE_SECDATA (secdata, NULL);
  struct where where = WHERE (is_rela ? sec_rela : sec_rel, NULL);
  where.ref = &parent;

  for (unsigned i = 0; i < count; ++i)
    {
      where_reset_1 (&where, i);

      REALLOC (&secdata->rel, rel);
      struct relocation *cur = secdata->rel.rel + secdata->rel.size++;
      WIPE (*cur);

      GElf_Rela rela_mem, *rela
	= get_rel_or_rela (reldata, i, &rela_mem, secdata->rel.type);
      if (rela == NULL)
	{
	  wr_error (&where, ": couldn't read relocation.\n");
	skip:
	  cur->invalid = true;
	  continue;
	}

      cur->offset = rela->r_offset;
      cur->symndx = GELF_R_SYM (rela->r_info);
      cur->type = GELF_R_TYPE (rela->r_info);

      where_reset_2 (&where, cur->offset);

      Elf_Type type = ebl_reloc_simple_type (secdata->file->ebl, cur->type);
      int width;

      switch (type)
	{
	case ELF_T_WORD:
	case ELF_T_SWORD:
	  width = 4;
	  break;

	case ELF_T_XWORD:
	case ELF_T_SXWORD:
	  width = 8;
	  break;

	case ELF_T_BYTE:
	case ELF_T_HALF:
	  /* Technically legal, but never used.  Better have dwarflint
	     flag them as erroneous, because it's more likely these
	     are a result of a bug than actually being used.  */
	  {
	    char buf[64];
	    wr_error (&where, ": 8 or 16-bit relocation type %s.\n",
		      ebl_reloc_type_name (secdata->file->ebl,
					   cur->type, buf, sizeof (buf)));
	    goto skip;
	  }

	default:
	  {
	    char buf[64];
	    wr_error (&where, ": invalid relocation %d (%s).\n",
		      cur->type,
		      ebl_reloc_type_name (secdata->file->ebl,
					   cur->type, buf, sizeof (buf)));
	    goto skip;
	  }
	};

      if (cur->offset + width >= secdata->data->d_size)
	{
	  wr_error (&where,
		    ": relocation doesn't fall into relocated section.\n");
	  goto skip;
	}

      uint64_t value;
      if (width == 4)
	value = read_4ubyte_unaligned (secdata->file->dwarf,
				       secdata->data->d_buf + cur->offset);
      else
	{
	  assert (width == 8);
	  value = read_8ubyte_unaligned (secdata->file->dwarf,
					 secdata->data->d_buf + cur->offset);
	}

      if (is_rela)
	{
	  if (value != 0)
	    wr_message (mc_impact_2 | mc_reloc, &where,
			": SHR_RELA relocates a place with non-zero value.\n");
	  cur->addend = rela->r_addend;
	}
      else
	cur->addend = value;
    }

  /* Sort the reloc section so that the applicable addresses of
     relocation entries are monotonously increasing.  */
  int compare (const void *a, const void *b)
  {
    return ((struct relocation *)a)->offset
      - ((struct relocation *)b)->offset;
  }

  qsort (secdata->rel.rel, secdata->rel.size,
	 sizeof (*secdata->rel.rel), &compare);
  return true;
}

static bool
check_line_structural (struct section_data *data,
		       struct cu *cu_chain)
{
  struct read_ctx ctx;
  read_ctx_init (&ctx, data->file->dwarf, data->data);
  bool retval = true;

  struct addr_record line_tables;
  WIPE (line_tables);

  while (!read_ctx_eof (&ctx))
    {
      struct where where = WHERE_SECDATA (data, NULL);
      uint64_t set_offset = read_ctx_get_offset (&ctx);
      where_reset_1 (&where, set_offset);
      addr_record_add (&line_tables, set_offset);
      const unsigned char *set_begin = ctx.ptr;

      /* Size.  */
      uint32_t size32;
      uint64_t size;
      bool dwarf_64;
      if (!read_ctx_read_4ubyte (&ctx, &size32))
	{
	  wr_error (&where, ": can't read table length.\n");
	  return false;
	}
      if (!read_size_extra (&ctx, size32, &size, &dwarf_64, &where))
	return false;

      struct read_ctx sub_ctx;
      const unsigned char *set_end = ctx.ptr + size;
      if (!read_ctx_init_sub (&sub_ctx, &ctx, set_begin, set_end))
	{
	not_enough:
	  wr_error (&where, PRI_NOT_ENOUGH, "next unit");
	  return false;
	}
      sub_ctx.ptr = ctx.ptr;
      sub_ctx.begin = ctx.begin;

      {
      /* Version.  */
      uint16_t version;
      if (!read_ctx_read_2ubyte (&sub_ctx, &version))
	{
	  wr_error (&where, ": can't read set version.\n");
	skip:
	  retval = false;
	  goto next;
	}
      if (!supported_version (version, 2, &where, 2, 3))
	goto skip;

      /* Header length.  */
      uint64_t header_length;
      if (!read_ctx_read_offset (&sub_ctx, dwarf_64, &header_length))
	{
	  wr_error (&where, ": can't read attribute value.\n");
	  goto skip;
	}
      const unsigned char *program_start = sub_ctx.ptr + header_length;

      /* Minimum instruction length.  */
      uint8_t minimum_i_length;
      if (!read_ctx_read_ubyte (&sub_ctx, &minimum_i_length))
	{
	  wr_error (&where, ": can't read minimum instruction length.\n");
	  goto skip;
	}

      /* Default value of is_stmt.  */
      uint8_t default_is_stmt;
      if (!read_ctx_read_ubyte (&sub_ctx, &default_is_stmt))
	{
	  wr_error (&where, ": can't read default_is_stmt.\n");
	  goto skip;
	}
      /* 7.21: The boolean values "true" and "false" used by the line
	 number information program are encoded as a single byte
	 containing the value 0 for "false," and a non-zero value for
	 "true."  [But give a notice if it's not 0 or 1.]  */
      if (default_is_stmt != 0
	  && default_is_stmt != 1)
	wr_message (mc_line | mc_impact_2 | mc_header, &where,
		    ": default_is_stmt should be 0 or 1, not %ud\n",
		    default_is_stmt);

      /* Line base.  */
      int8_t line_base;
      if (!read_ctx_read_ubyte (&sub_ctx, (uint8_t *)&line_base))
	{
	  wr_error (&where, ": can't read line_base.\n");
	  goto skip;
	}

      /* Line range.  */
      uint8_t line_range;
      if (!read_ctx_read_ubyte (&sub_ctx, &line_range))
	{
	  wr_error (&where, ": can't read line_range.\n");
	  goto skip;
	}

      /* Opcode base.  */
      uint8_t opcode_base;
      if (!read_ctx_read_ubyte (&sub_ctx, &opcode_base))
	{
	  wr_error (&where, ": can't read opcode_base.\n");
	  goto skip;
	}

      /* Standard opcode lengths.  */
      if (opcode_base == 0)
	{
	  wr_error (&where, ": opcode base set to 0.\n");
	  opcode_base = 1; // so that in following, our -1s don't underrun
	}
      uint8_t std_opc_lengths[opcode_base - 1]; /* -1, opcodes go from 1.  */
      for (unsigned i = 0; i < (unsigned)(opcode_base - 1); ++i)
	if (!read_ctx_read_ubyte (&sub_ctx, std_opc_lengths + i))
	  {
	    wr_error (&where,
		      ": can't read length of standard opcode #%d.\n", i);
	    goto skip;
	  }

      /* Include directories.  */
      struct include_directory_t
      {
	const char *name;
	bool used;
      };
      struct include_directories_t
      {
	size_t size;
	size_t alloc;
	struct include_directory_t *dirs;
      } include_directories;
      WIPE (include_directories);

      while (!read_ctx_eof (&sub_ctx))
	{
	  const char *name = read_ctx_read_str (&sub_ctx);
	  if (name == NULL)
	    {
	      wr_error (&where,
			": can't read name of include directory #%zd.\n",
			include_directories.size + 1); /* Numbered from 1.  */
	      goto skip;
	    }
	  if (*name == 0)
	    break;

	  REALLOC (&include_directories, dirs);
	  include_directories.dirs[include_directories.size++] =
	    (struct include_directory_t){name, false};
	}

      /* File names.  */
      struct file_t
      {
	const char *name;
	uint64_t dir_idx;
	bool used;
      };
      struct files_t
      {
	size_t size;
	size_t alloc;
	struct file_t *files;
      } files;
      WIPE (files);

      /* Directory index.  */
      bool read_directory_index (const char *name, uint64_t *ptr)
      {
	if (!checked_read_uleb128 (&sub_ctx, ptr,
				   &where, "directory index"))
	  return false;
	if (*name == '/' && *ptr != 0)
	  wr_message (mc_impact_2 | mc_line | mc_header, &where,
		      ": file #%zd has absolute pathname, but refers to directory != 0.\n",
		      files.size + 1);
	if (*ptr > include_directories.size) /* Not >=, dirs indexed from 1.  */
	  {
	    wr_message (mc_impact_4 | mc_line | mc_header, &where,
			": file #%zd refers to directory #%" PRId64 ", which wasn't defined.\n",
			files.size + 1, *ptr);
	    /* Consumer might choke on that.  */
	    retval = false;
	  }
	else if (*ptr != 0)
	  include_directories.dirs[*ptr - 1].used = true;
	return true;
      }

      while (1)
	{
	  const char *name = read_ctx_read_str (&sub_ctx);
	  if (name == NULL)
	    {
	      wr_error (&where,
			": can't read name of file #%zd.\n",
			files.size + 1); /* Numbered from 1.  */
	      goto skip;
	    }
	  if (*name == 0)
	    break;

	  uint64_t dir_idx;
	  if (!read_directory_index (name, &dir_idx))
	    goto skip;

	  /* Time of last modification.  */
	  uint64_t timestamp;
	  if (!checked_read_uleb128 (&sub_ctx, &timestamp,
				     &where, "timestamp of file entry"))
	    goto skip;

	  /* Size of the file.  */
	  uint64_t file_size;
	  if (!checked_read_uleb128 (&sub_ctx, &file_size,
				     &where, "file size of file entry"))
	    goto skip;

	  REALLOC (&files, files);
	  files.files[files.size++]
	    = (struct file_t){name, dir_idx, false};
	}

      /* Skip the rest of the header.  */
      if (sub_ctx.ptr > program_start)
	{
	  wr_error (&where,
		    ": header claims that it has a size of %#" PRIx64
		    ", but in fact it has a size of %#" PRIx64 ".\n",
		    header_length, sub_ctx.ptr - program_start + header_length);
	  /* Assume that the header lies, and what follows is in
	     fact line number program.  */
	  retval = false;
	}
      else if (sub_ctx.ptr < program_start)
	{
	  if (!check_zero_padding (&sub_ctx, mc_line | mc_header, &where))
	    wr_message_padding_n0 (mc_line | mc_header, &WHERE (sec_line, NULL),
				   read_ctx_get_offset (&sub_ctx),
				   program_start - sub_ctx.begin - 1);
	  sub_ctx.ptr = program_start;
	}

      bool terminated = false;
      bool first_file = true;
      bool seen_opcode = false;
      while (!read_ctx_eof (&sub_ctx))
	{
	  where_reset_2 (&where, read_ctx_get_offset (&sub_ctx));
	  uint8_t opcode;
	  if (!read_ctx_read_ubyte (&sub_ctx, &opcode))
	    {
	      wr_error (&where, ": can't read opcode.\n");
	      goto skip;
	    }

	  void use_file (uint64_t file_idx)
	  {
	    if (file_idx == 0 || file_idx > files.size)
	      {
		wr_error (&where,
			  ": DW_LNS_set_file: invalid file index %" PRId64 ".\n",
			  file_idx);
		retval = false;
	      }
	    else
	      files.files[file_idx - 1].used = true;
	  }

	  unsigned operands = 0;
	  uint8_t extended = 0;
	  switch (opcode)
	    {
	      /* Extended opcodes.  */
	    case 0:
	      {
		uint64_t skip_len;
		if (!checked_read_uleb128 (&sub_ctx, &skip_len, &where,
					   "length of extended opcode"))
		  goto skip;
		const unsigned char *next = sub_ctx.ptr + skip_len;
		if (!read_ctx_read_ubyte (&sub_ctx, &extended))
		  {
		    wr_error (&where, ": can't read extended opcode.\n");
		    goto skip;
		  }

		bool handled = true;
		switch (extended)
		  {
		  case DW_LNE_end_sequence:
		    terminated = true;
		    break;

		  case DW_LNE_set_address:
		    {
		      uint64_t ctx_offset = read_ctx_get_offset (&sub_ctx);
		      uint64_t addr;
		      if (!read_ctx_read_offset (&sub_ctx, data->file->addr_64, &addr))
			{
			  wr_error (&where, ": can't read operand of DW_LNE_set_address.\n");
			  goto skip;
			}

		      struct relocation *rel;
		      if ((rel = relocation_next (&data->rel, ctx_offset,
						  &where, skip_mismatched)))
			relocate_one (&data->rel, rel, data->file->addr_64 ? 8 : 4,
				      &addr, &where, sec_text, NULL);
		      else if (data->file->ehdr.e_type == ET_REL)
			wr_message (mc_impact_2 | mc_line | mc_reloc, &where,
				    PRI_LACK_RELOCATION, "DW_LNE_set_address");
		      break;
		    }

		  case DW_LNE_define_file:
		    {
		      const char *name;
		      if ((name = read_ctx_read_str (&sub_ctx)) == NULL)
			{
			  wr_error (&where,
				    ": can't read filename operand of DW_LNE_define_file.\n");
			  goto skip;
			}
		      uint64_t dir_idx;
		      if (!read_directory_index (name, &dir_idx))
			goto skip;
		      REALLOC (&files, files);
		      files.files[files.size++] =
			(struct file_t){name, dir_idx, false};
		      operands = 2; /* Skip mtime & size of the file.  */
		    }

		    /* See if we know about any other standard opcodes.  */
		  default:
		    handled = false;
		    switch (extended)
		      {
#define ONE_KNOWN_DW_LNE(NAME, CODE) case CODE: break;
			ALL_KNOWN_DW_LNE
#undef ONE_KNOWN_DW_LNE
		      default:
			/* No we don't, emit a warning.  */
			wr_message (mc_impact_2 | mc_line, &where,
				    ": unknown extended opcode #%d.\n", extended);
		      };
		  };

		if (sub_ctx.ptr > next)
		  {
		    wr_error (&where,
			      ": opcode claims that it has a size of %#" PRIx64
			      ", but in fact it has a size of %#" PRIx64 ".\n",
			      skip_len, skip_len + (next - sub_ctx.ptr));
		    retval = false;
		  }
		else if (sub_ctx.ptr < next)
		  {
		    if (handled
			&& !check_zero_padding (&sub_ctx, mc_line, &where))
		      wr_message_padding_n0 (mc_line, &WHERE (sec_line, NULL),
					     read_ctx_get_offset (&sub_ctx),
					     next - sub_ctx.begin - 1);
		    sub_ctx.ptr = next;
		  }
		break;
	      }

	      /* Standard opcodes that need validation or have
		 non-ULEB operands.  */
	    case DW_LNS_fixed_advance_pc:
	      {
		uint16_t a;
		if (!read_ctx_read_2ubyte (&sub_ctx, &a))
		  {
		    wr_error (&where, ": can't read operand of DW_LNS_fixed_advance_pc.\n");
		    goto skip;
		  }
		break;
	      }

	    case DW_LNS_set_file:
	      {
		uint64_t file_idx;
		if (!checked_read_uleb128 (&sub_ctx, &file_idx, &where,
					   "DW_LNS_set_file operand"))
		  goto skip;
		use_file (file_idx);
		first_file = false;
	      }
	      break;

	    case DW_LNS_set_isa:
	      // XXX is it possible to validate this?
	      operands = 1;
	      break;

	      /* All the other opcodes.  */
	    default:
	      if (opcode < opcode_base)
		operands = std_opc_lengths[opcode - 1];

    	      switch (opcode)
		{
#define ONE_KNOWN_DW_LNS(NAME, CODE) case CODE: break;
		  ALL_KNOWN_DW_LNS
#undef ONE_KNOWN_DW_LNS

		default:
		  if (opcode < opcode_base)
		    wr_message (mc_impact_2 | mc_line, &where,
				": unknown standard opcode #%d.\n", opcode);
		};
	    };

	  for (unsigned i = 0; i < operands; ++i)
	    {
	      uint64_t operand;
	      char buf[128];
	      if (opcode != 0)
		sprintf (buf, "operand #%d of DW_LNS_%s",
			 i, dwarf_locexpr_opcode_string (opcode));
	      else
		sprintf (buf, "operand #%d of extended opcode %d",
			 i, extended);
	      if (!checked_read_uleb128 (&sub_ctx, &operand, &where, buf))
		goto skip;
	    }

	  if (first_file)
	    {
	      use_file (1);
	      first_file = false;
	    }

	  if (opcode != 0 || extended != DW_LNE_end_sequence)
	    seen_opcode = true;
	}

      for (size_t i = 0; i < include_directories.size; ++i)
	if (!include_directories.dirs[i].used)
	  wr_message (mc_impact_3 | mc_acc_bloat | mc_line | mc_header,
		      &where, ": the include #%zd `%s' is not used.\n",
		      i + 1, include_directories.dirs[i].name);

      for (size_t i = 0; i < files.size; ++i)
	if (!files.files[i].used)
	  wr_message (mc_impact_3 | mc_acc_bloat | mc_line | mc_header,
		      &where, ": the file #%zd `%s' is not used.\n",
		      i + 1, files.files[i].name);

      if (!seen_opcode)
	wr_message (mc_line | mc_acc_bloat | mc_impact_3, &where,
		    ": empty line number program.\n");
      if (!terminated)
	{
	  if (seen_opcode)
	    wr_error (&where,
		      ": sequence of opcodes not terminated with DW_LNE_end_sequence.\n");
	}
      else if (sub_ctx.ptr != sub_ctx.end
	       && !check_zero_padding (&sub_ctx, mc_line,
				       &WHERE (sec_line, NULL)))
	wr_message_padding_n0 (mc_line, &WHERE (sec_line, NULL),
			       /*begin*/read_ctx_get_offset (&sub_ctx),
			       /*end*/sub_ctx.end - sub_ctx.begin - 1);
      }

      /* XXX overlaps in defined addresses are probably OK, one
	 instruction can be derived from several statements.  But
	 certain flags in table should be consistent in that case,
	 namely is_stmt, basic_block, end_sequence, prologue_end,
	 epilogue_begin, isa.  */

    next:
      if (!read_ctx_skip (&ctx, size))
	goto not_enough;
    }

  if (retval)
    {
      relocation_skip_rest (data);

      for (struct cu *cu = cu_chain; cu != NULL; cu = cu->next)
	for (size_t i = 0; i < cu->line_refs.size; ++i)
	  {
	    struct ref *ref = cu->line_refs.refs + i;
	    if (!addr_record_has_addr (&line_tables, ref->addr))
	      wr_error (&ref->who,
			": unresolved reference to .debug_line table %#" PRIx64 ".\n",
			ref->addr);
	  }
    }

  return retval;
}
