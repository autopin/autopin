#
# Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
# Contributed by Stephane Eranian <eranian@hpl.hp.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
# 02111-1307 USA
#

#
# This file defines the global compilation settings.
# It is included by every Makefile
#
#
ARCH := $(shell uname -m)
ifeq (i686,$(findstring i686,$(ARCH)))
override ARCH=ia32
endif
ifeq (i586,$(findstring i586,$(ARCH)))
override ARCH=ia32
endif
ifeq (i486,$(findstring i486,$(ARCH)))
override ARCH=ia32
endif
ifeq (i386,$(findstring i386,$(ARCH)))
override ARCH=ia32
endif
ifeq (sparc64,$(findstring sparc64,$(ARCH)))
override ARCH=sparc
endif

#
# Cell Broadband Engine is reported as PPC but needs special handling.
#
MACHINE := $(shell grep -q 'Cell Broadband Engine' /proc/cpuinfo && echo cell)
ifeq (cell,$(MACHINE))
override ARCH=cell
endif

#
# Where should things go in the end. This follows GNU conventions of 
# destdir, prefix and the rest
#
install_prefix=/usr/local
PREFIX=$(install_prefix)
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man
DATADIR=$(PREFIX)/share/pfmon

#
# The root directory where to find the perfmon header files and the library (libpfm-3.0).
# Must be an absolute path.
#
PFMROOTDIR ?=/usr/local
PFMLIBDIR=$(PFMROOTDIR)/lib
PFMINCDIR=$(PFMROOTDIR)/include

# Where to find libelf
# pfmon needs libelf either from the old libelf package or from elfutils-devel
# elfutils-devel has libelf.h in /usr/include, whereas the old libelf has it
# in /usr/include/libelf. To make sure we can compile, we always add the
# include path to /usr/include/libelf. This is extraneous if using elfutils but
# harmless
#
# Define ELFLIBDIR if libelf is non-standard location
#
ELFINCDIR ?= /usr/include/libelf

#
# pfmon debugging option
# 
# CONFIG_PFMON_DEBUG: enables extraneous debug print
# CONFIG_PFMON_STATIC: produces a statically linked binary
# CONFIG_PFMON_LIBUNWIND: if you have libunwind installed, 
# then you can enable this option for call stack on segv
# CONFIG_PFMON_DEBUG_MEM: pfmon memory debugging with dmalloc (development package must be present)
#
CONFIG_PFMON_DEBUG=y
CONFIG_PFMON_STATIC=n
CONFIG_PFMON_DEBUG_MEM=n

#ifeq ($(ARCH),ia64)
#CONFIG_PFMON_LIBUNWIND=y
#else
#CONFIG_PFMON_LIBUNWIND=n
#endif

#
# optimization settings
#
OPTIM= -ggdb

#
# linker specific flags
#
# It is not recommended to link with -statis as this
# may causes issues with pthreads on certain systems.
# 
#LDFLAGS=-static

#
# you shouldn't have to touch anything beyond this point
#

ifeq ($(CONFIG_PFMON_DEBUG_MEM),y)
LDFLAGS+=-ldmalloc
OPTIM+=-DCONFIG_DEBUG_MEM
endif

#
# The entire package can be compiled using 
# the Intel Itanium Compiler
#
#CC=icc -Wall
CC=gcc
PFMINCDIR=$(PFMROOTDIR)/include
PFMLIBDIR=$(PFMROOTDIR)/lib
DBG=-g -Wall -Werror
CFLAGS=$(OPTIM) $(DBG) -D_REENTRANT -I$(PFMINCDIR)
MKDEP=makedepend
LIBS=
INSTALL=install

ifeq ($(ARCH),ia64)
CFLAGS += -DCONFIG_PFMON_IA64
endif

ifeq ($(ARCH),x86_64)
CFLAGS += -DCONFIG_PFMON_AMD_X86_64
endif

ifeq ($(CONFIG_PFMON_DEBUG),y)
CFLAGS += -DPFMON_DEBUG
endif
