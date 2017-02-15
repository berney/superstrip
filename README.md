# superstrip

superstrip - strip an ELF executable of all unmapped information

David Madore's superstrip, as a single C file suitable for compilation with skalibs. 
superstrip is a very aggressive ELF stripping utility.


## History

- Written by David Madore <david.madore@ens.fr>
- Modified by Laurent Bercot <ska-skaware@skarnet.org>
  - for use with skalibs
- Modified by Berney to compile against current skalibs
  - Added a Makefile

- First version: 2002-09-03
- Laurent's version:  2011-06-28
- This version: 2017-02-15


## License and No Warranty

- This project is in the Public Domain -- David Madore, Laurent Bercot, Berney
- However, I kindly request that any copy of this program that is
 modified by someone other than myself be clearly labeled as such in
 the comments above, and use a distinguishing tag on the version
 string above; or else be called by some other name than
 "superstrip".

- This program comes with ABSOLUTELY NO WARRANTY.  Use at your own risk.

- This version is still in ALPHA stage of development!


## How to Use

Syntax is: `superstrip [file]`

`[file]` must be a seekable ELF file, and this is only useful for an
executable, possibly only for a statically linked executable.  It
will be copied to a temporary file, but only those parts which are
mapped in memory upon loading will be kept: all other data, such as
symbol names, section names, section tables, debugging information,
etc, are discarded.  Thus, this is like the "strip" operation, but
even more radical.  The primary author advises you to use
this program only in situations where disk space is extremely
scarce (e.g. on a floppy).  Note that this will not gain you any
space in memory, by definition.

### Some important caveats:
Do not use on object files, nor on dynamic libraries with which you
intend to link (I mean ld-link, not run-time link), this would make
them useless.  Use on dynamic libraries only intended for run-time
link, or on dynamically linked executable, appears to work in some
situations, but this is by no means guaranteed (of course, nothing
about this program is guaranteed anyway, see above) and strongly
discouraged.
Only 32-bit ELF is supported at the moment.  Support for 64-bit ELF
is intended in a future version.
Only native endianness is supported.  That is, the program will
only treat ELF files made for a machine with the same endianness as
that on which it runs.
This has not been extensively tested yet and many bugs are probably
still lurking.
