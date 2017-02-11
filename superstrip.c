/* superstrip - strip an ELF executable of all unmapped information */

/* Written by David Madore <david.madore@ens.fr> */
/* Modified by Laurent Bercot <ska-skaware@skarnet.org>
   for use with skalibs */

/* First version: 2002-09-03 */
/* This version:  2011-06-28 */

/* This file is in the Public Domain -- David Madore */

/* However, I kindly request that any copy of this program that is
 * modified by someone other than myself be clearly labeled as such in
 * the comments above, and use a distinguishing tag on the version
 * string above; or else be called by some other name than
 * "superstrip". */

/* This program comes with ABSOLUTELY NO WARRANTY.  Use at your own
 * risk. */

/* This version is still in ALPHA stage of development! */

/* Syntax is: superstrip [file] */

/* [file] must be a seekable ELF file, and this is only useful for an
 * executable, possibly only for a statically linked executable.  It
 * will be copied to a temporary file, but only those parts which are
 * mapped in memory upon loading will be kept: all other data, such as
 * symbol names, section names, section tables, debugging information,
 * etc, are discarded.  Thus, this is like the "strip" operation, but
 * even more radical.  The primary author advises you to use
 * this program only in situations where disk space is extremely
 * scarce (e.g. on a floppy).  Note that this will not gain you any
 * space in memory, by definition. */

/* Some important caveats: */
/* Do not use on object files, nor on dynamic libraries with which you
 * intend to link (I mean ld-link, not run-time link), this would make
 * them useless.  Use on dynamic libraries only intended for run-time
 * link, or on dynamically linked executable, appears to work in some
 * situations, but this is by no means guaranteed (of course, nothing
 * about this program is guaranteed anyway, see above) and strongly
 * discouraged. */
/* Only 32-bit ELF is supported at the moment.  Support for 64-bit ELF
 * is intended in a future version. */
/* Only native endianness is supported.  That is, the program will
 * only treat ELF files made for a machine with the same endianness as
 * that on which it runs. */
/* This has not been extensively tested yet and many bugs are probably
 * still lurking. */


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <elf.h>

#include "skalibs/skalibs.h"
#include "ulong.h"
#include "sysdeps.h"
#include "alloc.h"
#include "allreadwrite.h"
#include "bytestr.h"
#include "fmtscan.h"
#include "buffer.h"
#include "strerr2.h"
#include "stralloc.h"
#include "djbunix.h"
#include "random.h"

#define BUFSIZE 8192

char const *PROG = "superstrip" ;
#define USAGE "superstrip file"

#ifdef HASLITTLE_ENDIAN
#define ENDIAN 0
#else
#ifdef HASBIG_ENDIAN
#define ENDIAN 1
#else
#define ENDIAN (-1)
#endif
#endif

/* The default page size (4 kilobytes): this is for Intel - double as
 * necessary on other architectures (Sparc...) or if you get a warning
 * about alignment not being multiple of page size. */
#ifndef PAGESIZE
#define PAGESIZE 0x1000
#endif


/* FreeBSD lacks those in <elf.h> */
#ifndef ELFMAG
#define ELFMAG "\177ELF"
#endif
#ifndef SELFMAG
#define SELFMAG 4
#endif

static char const *oldname ;
static char const *tmpname ;

static Elf32_Ehdr ehdr ;           /* ELF header */
static Elf32_Phdr *phdr ;          /* Program header (table) */
static Elf32_Off ph_offset ;       /* Offset of the latter in file */
static Elf32_Word ph_filesz ;      /* Size of program header table */

static int cleanup ()
{
  return unlink(tmpname) ;
}

static void read_hdrs ()
     /* Read headers from ELF file. */
{
  if (allread(0, (char *)&ehdr, sizeof(ehdr)) < sizeof(ehdr))
    strerr_diefu2sys(111, "read ELF header in ", oldname) ;
  if (byte_diff(ehdr.e_ident, SELFMAG, ELFMAG))
    strerr_dief2x(100, oldname, " is not an ELF file") ;
  if (ehdr.e_ident[EI_CLASS] != ELFCLASS32)
  {
    char fmt[ULONG_FMT] ;
    fmt[uint_fmt(fmt, ehdr.e_ident[EI_CLASS])] = 0 ;
    strerr_dief4x(100, oldname, ": ELF class ", fmt, " not supported") ;
  }
  {
    char elfdata2[2] = { ELFDATA2LSB, ELFDATA2MSB } ;
    if (ENDIAN < 0) strerr_dief1x(100, "machine endianness not supported") ;
    if (ehdr.e_ident[EI_DATA] != elfdata2[ENDIAN])
    {
      char *what[2] = { "little", "big" } ;
      char fmt[ULONG_FMT] ;
      fmt[uint_fmt(fmt, ehdr.e_ident[EI_DATA])] = 0 ;
      strerr_dief6x(100, oldname, ": data encoding ", fmt, " not supported on this ", what[ENDIAN], "-endian machine") ;
    }
  }
  if (ehdr.e_ident[EI_VERSION] != EV_CURRENT)
  {
    char fmt[ULONG_FMT] ;
    fmt[uint_fmt(fmt, ehdr.e_ident[EI_VERSION])] = 0 ;
    strerr_dief4x(100, oldname, ": ELF file version ", fmt, " not supported") ;
  }
  if (ehdr.e_type != ET_EXEC)
    strerr_warnw2x(oldname, " is not an executable") ;
  if (ehdr.e_version != EV_CURRENT)
  {
    char fmt[ULONG_FMT] ;
    fmt[ulong_fmt(fmt, (unsigned long)ehdr.e_version)] = 0 ;
    strerr_dief4x(100, oldname, ": ELF version ", fmt, " not supported") ;
  }
  if (ehdr.e_phoff == 0)
    strerr_dief2x(100, oldname, " has no program header") ;
  if (ehdr.e_phentsize != sizeof(Elf32_Phdr))
  {
    char fmt[ULONG_FMT] ;
    fmt[ulong_fmt(fmt, (unsigned long)ehdr.e_phentsize)] = 0 ;
    strerr_dief3x(100, oldname, ": unexpected program header entries size: ", fmt) ;
  }
  if (ehdr.e_phnum == 0)
    strerr_dief2x(100, oldname, ": program header has no entries") ;
  phdr = (Elf32_Phdr *)alloc(ehdr.e_phnum * sizeof(Elf32_Phdr)) ;
  if (!phdr)
    strerr_diefu2sys(111, "map program header for ", oldname) ;
  if (seek_set(0, ehdr.e_phoff) == -1)
    strerr_diefu2sys(111, "seek to program header for ", oldname) ;
  if (allread(0, (char *)phdr, ehdr.e_phnum * sizeof(Elf32_Phdr)) < ehdr.e_phnum * sizeof(Elf32_Phdr))
    strerr_diefu2sys(111, "read program header for ", oldname) ;
  ph_offset = ehdr.e_phoff ;
  ph_filesz = ehdr.e_phentsize * ehdr.e_phnum ;
}

#ifdef DEBUG
static void debug_print_segments ()
     /* Print ELF mapped segments. */
{
  register unsigned long i = 0 ;

  buffer_putsalign(buffer_2, PROG) ;
  buffer_putalign(buffer_2, ": ", 2) ;
  buffer_putsalign(buffer_2, DEBUG) ;
  buffer_putalign(buffer_2, ": ", 2) ;
  buffer_putsalign(buffer_2, oldname) ;
  buffer_putalign(buffer_2, ": ", 2) ;
  buffer_putsalign(buffer_2, "segments are:\n") ;
  for (; i < (unsigned long)ehdr.e_phnum ; i++)
  {
    char fmt[ULONG_FMT] ;
    char type[ULONG_FMT] ;
    char offset[ULONG_FMT] ;
    char filesz[ULONG_FMT] ;
    char align[ULONG_FMT] ;
    fmt[ulong_fmt(fmt, i)] = 0 ;
    type[uint_fmt(type, (unsigned long)phdr[i].p_type)] = 0 ;
    offset[ulong_xfmt(offset, (unsigned long)phdr[i].p_offset)] = 0 ;
    filesz[ulong_xfmt(filesz, (unsigned long)phdr[i].p_filesz)] = 0 ;
    align[ulong_xfmt(align, (unsigned long)phdr[i].p_align)] = 0 ;
    buffer_putsalign(buffer_2, PROG) ;
    buffer_putalign(buffer_2, ": ", 2) ;
    buffer_putsalign(buffer_2, DEBUG) ;
    buffer_putalign(buffer_2, ": ", 2) ;
    buffer_putsalign(buffer_2, "segment ") ;
    buffer_putsalign(buffer_2, fmt) ;
    buffer_putsalign(buffer_2, " (type ") ;
    buffer_putsalign(buffer_2, type) ;
    buffer_putsalign(buffer_2, "): offset=0x") ;
    buffer_putsalign(buffer_2, offset) ;
    buffer_putsalign(buffer_2, ", filesz=0x") ;
    buffer_putsalign(buffer_2, filesz) ;
    buffer_putsalign(buffer_2, ", align=0x") ;
    buffer_putsalign(buffer_2, align) ;
    buffer_putalign(buffer_2, "\n", 1) ;
  }
  buffer_flush(buffer_2) ;
}
#endif

/* The regions in the file which are mapped in memory, _consecutive_
 * and _disjoint_. */

typedef struct region_s region, *region_ref ;
struct region_s
{
  region_ref next ;                      /* (linked list) */
  Elf32_Off offset ;                     /* Offset in input file */
  Elf32_Word filesz ;                    /* Region size (bytes) */
  Elf32_Word disp ;                      /* Input->output file displacement */
  Elf32_Off toffset ;                    /* (Target) offset in output file */
} ;

static region_ref first_region ;

static void compute_regions ()
     /* Determine which file regions are "important" (that is, contain
      * a segment or the ELF header or the program header). */
{
  long i ;

  /* i==-2 => ELF header */
  /* i==-1 => program header */
  /* i>=0 => section i */

  for (i = -2 ; i < (long)ehdr.e_phnum ; i++)
  {
    region_ref p = 0, q = first_region ;
    Elf32_Off s_offset ;
    Elf32_Word s_filesz ;

    if (i == -2)
    {
      s_offset = 0 ;
      s_filesz = sizeof(ehdr) ;
    }
    else if (i == -1)
    {
      s_offset = ph_offset ;
      s_filesz = ph_filesz ;
    }
    else
    {
      if (phdr[i].p_type == PT_NULL) continue ;
      if (phdr[i].p_align != 0 && PAGESIZE % phdr[i].p_align != 0)
        strerr_warnw2x(oldname, ": alignment not multiple of page size") ;
      s_offset = phdr[i].p_offset ;
      s_filesz = phdr[i].p_filesz ;
    }
    if (s_filesz == 0) continue ;

    /* s_offset and s_filesz contain the offset and size of a part
     * of the file that is important and should be added (if needed)
     * to the regions list. */

    while (q && (q->offset < s_offset))
    {
      p = q ;
      q = p->next ;
    }
    if (p && ((p->offset + p->filesz) >= s_offset))
    {
      /* Merge with previous region. */
      if ((s_offset + s_filesz) > (p->offset + p->filesz))
        p->filesz = s_offset - p->offset + s_filesz ;
    }
    else
    {
      region_ref t = (region_ref)alloc(sizeof(region)) ;
      if (!t) strerr_diefu2sys(111, "allocate region for ", oldname) ;
      if (p) p->next = t ;
      else first_region = t ;
      p = t ;
      p->next = q ;
      p->offset = s_offset ;
      p->filesz = s_filesz ;
    }
    while (q && (q->offset <= (p->offset + p->filesz)))
    {
      /* Merge with next region. */
      p->next = q->next ;
      if ((q->offset + q->filesz) > (p->offset + p->filesz))
        p->filesz = q->offset - p->offset + q->filesz ;
      alloc_free(q) ;
      q = p->next ;
    }
  }
}

static void compute_disps ()
     /* Now compute displacements from input file to output file: we
      * impose them to be multiple of PAGESIZE. */
     /* (Note: this whole displacement bit seems pretty much unused,
      * complicating the program immensely; but, who knows, we may
      * find an ELF with huge unmapped sections in the middle.) */
{
  region_ref p ;
  Elf32_Word curdisp ;
  Elf32_Off curoff = 0 ;

  for (p = first_region ; p ; p = p->next)
  {
    curdisp = ((p->offset - curoff)/PAGESIZE) * PAGESIZE ;
    p->disp = curdisp ;
    p->toffset = p->offset - curdisp ;
    curoff = p->toffset + p->filesz ;
  }
}

#ifdef DEBUG
static void debug_print_regions ()
{
  region_ref p ;

  buffer_putsalign(buffer_2, PROG) ;
  buffer_putalign(buffer_2, ": ", 2) ;
  buffer_putsalign(buffer_2, DEBUG) ;
  buffer_putalign(buffer_2, ": ", 2) ;
  buffer_putsalign(buffer_2, oldname) ;
  buffer_putalign(buffer_2, ": ", 2) ;
  buffer_putsalign(buffer_2, "computed regions are:\n") ;
  for (p = first_region ; p ; p = p->next)
  {
    char offset[FMT_ULONG] ;
    char filesz[FMT_ULONG] ;
    char disp[FMT_ULONG] ;
    char toffset[FMT_ULONG] ;
    offset[ulong_xfmt(filesz, (unsigned long)p->offset)] = 0 ;
    filesz[ulong_xfmt(filesz, (unsigned long)p->filesz)] = 0 ;
    disp[ulong_xfmt(filesz, (unsigned long)p->disp)] = 0 ;
    toffset[ulong_xfmt(filesz, (unsigned long)p->toffset)] = 0 ;
    buffer_putsalign(buffer_2, PROG) ;
    buffer_putalign(buffer_2, ": ", 2) ;
    buffer_putsalign(buffer_2, DEBUG) ;
    buffer_putalign(buffer_2, ": ", 2) ;
    buffer_putsalign(buffer_2, "offset=0x") ;
    buffer_putsalign(buffer_2, offset) ;
    buffer_putsalign(buffer_2, ", filesz=0x") ;
    buffer_putsalign(buffer_2, filesz) ;
    buffer_putsalign(buffer_2, ", displace by -0x") ;
    buffer_putsalign(buffer_2, disp) ;
    buffer_putsalign(buffer_2, " to 0x") ;
    buffer_putsalign(buffer_2, toffset) ;
    buffer_putalign(buffer_2, "\n", 1) ;
  }
  buffer_flush(buffer_2) ;
}
#endif

static void modify_hdrs ()
     /* Modify ELF headers to take account of the displacement of
      * segments (and possibly the program header) and the removal of
      * section header table. */
{
  long i ;

  ehdr.e_shoff = 0 ;
  ehdr.e_shentsize = 0 ;
  ehdr.e_shnum = 0 ;
  ehdr.e_shstrndx = 0 ;
  for (i = -1 ; i < (long)ehdr.e_phnum ; i++)
  {
    region_ref p ;

    if ((i >= 0) && ((phdr[i].p_type == PT_NULL) || (phdr[i].p_filesz == 0))) continue ;
    for (p = first_region ; p ; p = p->next)
      if ((i == -1) ? ((ph_offset >= p->offset) && ((ph_offset + ph_filesz) <= (p->offset + p->filesz))) : ((phdr[i].p_offset >= p->offset) && (((phdr[i].p_offset + phdr[i].p_filesz) <= (p->offset + p->filesz)))))
        break ;
    if (!p)
    {
      char fmt[ULONG_FMT] ;
      fmt[ulong_fmt(fmt, i)] = 0 ;
      strerr_dief4x(101, "internal error: unable to find region for segment ", fmt, " in ", oldname) ;
    }
    if (i == -1) ehdr.e_phoff -= p->disp ;
    else phdr[i].p_offset -= p->disp ;
  }
}

static void process_file ()
     /* Now that all preliminary information has been gathered, do the
      * actual processing, copying input file to output file,
      * performing necessary skips and replacements along the way. */
{
  region_ref p ;

  /* Copy region by region... */
  for (p = first_region ; p ; p = p->next)
  {
    size_t thisoff, thisendoff ;
    size_t toread, thisread ;
    char buf[BUFSIZE] ;

    if (seek_set(0, p->offset) == -1)
    {
      cleanup() ;
      strerr_diefu2sys(111, "seek input for ", oldname) ;
    }
    if (seek_set(1, p->toffset) == -1)
    {
      cleanup() ;
      strerr_diefu2sys(111, "seek output for ", oldname) ;
    }

    thisoff = p->offset ;
    toread = p->filesz ;
      /* ...and block by block in each region. */
    while (toread > 0)
    {
      if (toread > BUFSIZE) thisread = BUFSIZE ;
      else thisread = toread ;
      if (allread(0, buf, thisread) < thisread)
      {
        cleanup() ;
        strerr_diefu2sys(111, "read from ", oldname) ;
      }
      thisendoff = thisoff + thisread ;
      /* Adjust for modified ELF header if necessary. */
      if (thisoff < sizeof(ehdr))
      {
        size_t posa, posb ;
        size_t len ;

        posa = thisoff ;
        posb = 0 ;
        len = sizeof(ehdr) - posa ;
        if (len > (thisread - posb)) len = thisread - posb ;
        byte_copy(buf + posb, len, ((char *)&ehdr) + posa) ;
#ifdef DEBUG
        {
          char a[UINT_XFMT] ;
          char b[UINT_XFMT] ;
          char l[UINT_FMT] ;
          a[uint_xfmt(a, posa)] = 0 ;
          b[uint_xfmt(a, posb)] = 0 ;
          l[uint_fmt(a, len)] = 0 ;
          buffer_putsalign(buffer_2, PROG) ;
          buffer_putalign(buffer_2, ": ", 2) ;
          buffer_putsalign(buffer_2, DEBUG) ;
          buffer_putalign(buffer_2, ": ", 2) ;
          buffer_putsalign(buffer_2, oldname) ;
          buffer_putalign(buffer_2, ": ", 2) ;
          buffer_putsalign(buffer_2, "ELF header posa=0x") ;
          buffer_putsalign(buffer_2, a) ;
          buffer_putsalign(buffer_2, ", posb=0x") ;
          buffer_putsalign(buffer_2, b) ;
          buffer_putsalign(buffer_2, ", len=") ;
          buffer_putsalign(buffer_2, l) ;
          buffer_putflush(buffer_2, "\n", 1) ;
        }
#endif
      }
      /* Adjust for modified program header if necessary. */
      if ((thisoff < (ph_offset + ph_filesz)) && (ph_offset < thisendoff))
      {
        size_t posa, posb ;
        size_t len ;

        if (thisoff < ph_offset)
        {
          posa = 0 ;
          posb = ph_offset - thisoff ;
        }
        else
        {
          posa = thisoff - ph_offset ;
          posb = 0 ;
        }
        len = ph_filesz - posa ;
        if (len > thisread - posb) len = thisread - posb ;
        byte_copy(buf + posb, len, ((char *)phdr) + posa) ;
#ifdef DEBUG
        {
          char a[UINT_XFMT] ;
          char b[UINT_XFMT] ;
          char l[UINT_FMT] ;
          a[uint_xfmt(a, posa)] = 0 ;
          b[uint_xfmt(a, posb)] = 0 ;
          l[uint_fmt(a, len)] = 0 ;
          buffer_putsalign(buffer_2, PROG) ;
          buffer_putalign(buffer_2, ": ", 2) ;
          buffer_putsalign(buffer_2, DEBUG) ;
          buffer_putalign(buffer_2, ": ", 2) ;
          buffer_putsalign(buffer_2, oldname) ;
          buffer_putalign(buffer_2, ": ", 2) ;
          buffer_putsalign(buffer_2, "section header posa=0x") ;
          buffer_putsalign(buffer_2, a) ;
          buffer_putsalign(buffer_2, ", posb=0x") ;
          buffer_putsalign(buffer_2, b) ;
          buffer_putsalign(buffer_2, ", len=") ;
          buffer_putsalign(buffer_2, l) ;
          buffer_putflush(buffer_2, "\n", 1) ;
        }
#endif
      }
      if (allwrite(1, buf, thisread) < thisread)
      {
        cleanup() ;
        strerr_diefu2sys(111, "write to temp file for ", oldname) ;
      }
      toread -= thisread ;
      thisoff += thisread ;
    }
  }
}

int main (int argc, char const *const *argv)
{
  if (argc < 2) strerr_dieusage(100, USAGE) ;
  oldname = argv[1] ;

  {
    register int fdr = open_readb(argv[1]) ;
    if (fdr == -1)
      strerr_diefu3sys(111, "open ", oldname, " for reading") ;
    if (fd_move(0, fdr) == -1)
      strerr_diefu2sys(111, "move fd for ", oldname) ;
  }

  read_hdrs() ;

#ifdef DEBUG
  debug_print_segments() ;
#endif

  compute_regions() ;

  compute_disps() ;

#ifdef DEBUG
  debug_print_regions() ;
#endif

  modify_hdrs() ;

#ifdef DEBUG
  debug_print_segments() ;
#endif

  {
    stralloc sa = STRALLOC_ZERO ;
    if (!stralloc_cats(&sa, oldname)
     || !stralloc_cats(&sa, ":superstrip:"))
      strerr_diefu2sys(111, "make temp file for ", oldname) ;
    if (random_sauniquename(&sa, 9) == -1)
      strerr_diefu2sys(111, "make temp file for ", oldname) ;
    sa.s[sa.len-1] = 0 ;
    tmpname = sa.s ;

    {
      struct stat st ;
      register int fdw ;
      if (fstat(0, &st) == -1)
        strerr_diefu2sys(111, "stat ", oldname) ;
      fdw = open3(tmpname, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, st.st_mode & 0777) ;
      if (fdw == -1)
        strerr_diefu3sys(111, "open temp file ", tmpname, " for writing") ;
      if (fd_move(1, fdw) == -1)
        strerr_diefu2sys(111, "move fd for ", tmpname) ;
    }

    process_file() ;
    fd_close(0) ; fd_close(1) ;

    if (rename(tmpname, oldname) == -1)
    {
      cleanup() ;
      strerr_diefu4sys(111, "atomically rename ", tmpname, " into ", oldname) ;
    }
   /* stralloc_free(&sa) ; */
  }
  return 0 ;
}
