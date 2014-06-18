#
# Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
# Contributed by Stephane Eranian <eranian@hpl.hp.com>
#
# This file is part of pfmon, a sample tool to measure performance 
# of applications on Linux.
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

include config.mk
include rules.mk

CFLAGS += -DDATADIR=\"$(DATADIR)\" -I.

#
# Try NPTL explicitly (required for safe static link on Redhat)
#
#
ifeq ($(CONFIG_PFMON_STATIC),y)
LDFLAGS += -static
endif

LIBS += -L/usr/lib/nptl -lpthread -lm -lrt -lnuma


#
# libelf is always linked in statically to minimize dependencies
#
ifneq ($(ELFLIBDIR),)
  LIBS += $(ELFLIBDIR)/libelf.a
else
ifeq ($(CONFIG_PFMON_STATIC),y)
  LIBS += -lelf
else
  LIBS += -Wl,-Bstatic -lelf -Wl,-Bdynamic
endif
endif

ifeq ($(CONFIG_PFMON_STATIC),y)
  LIBS += $(PFMLIBDIR)/libpfm.a
else
  LIBS += -L$(PFMLIBDIR) -lpfm 
endif

ifneq ($(ELFINCDIR),)
CFLAGS +=-I$(ELFINCDIR)
endif

ifeq ($(CONFIG_PFMON_LIBUNWIND),y)
CFLAGS += -DCONFIG_PFMON_LIBUNWIND
LIBS += -lunwind-generic -lunwind
endif

#
# required to access fcntl(F_SETSIG)
#
CFLAGS += -D_GNU_SOURCE

#
# This is kind of broken because it assumes that if the static library
# has changed then the shared library must have also changed. But this 
# should cover our needs.
#

SRCS=autopin.c pfmon_smpl.c pfmon_util.c pfmon_system.c pfmon_task.c pfmon_symbols.c \
     pfmon_results.c pfmon_hash.c pfmon_smpl_dfl.c pfmon_os.c

ifeq ($(ARCH),ia64)
SRCS += pfmon_util_ia64.c \
	pfmon_gen_ia64.c \
	pfmon_itanium.c \
	pfmon_itanium2.c \
	pfmon_montecito.c
CFLAGS += -DCONFIG_PFMON_IA64
endif 

ifeq ($(ARCH),x86_64)
SRCS += pfmon_util_x86.c \
	pfmon_gen_ia32.c \
	pfmon_amd64.c \
	pfmon_core.c \
	pfmon_pentium4.c
CFLAGS += -DCONFIG_PFMON_X86_64
endif 

ifeq ($(ARCH),ia32)
SRCS += pfmon_util_x86.c \
	pfmon_i386_p6.c \
	pfmon_gen_ia32.c \
	pfmon_amd64.c \
	pfmon_core.c \
	pfmon_pentium4.c
CFLAGS += -DCONFIG_PFMON_I386
endif 

ifeq ($(ARCH),mips64)
SRCS += pfmon_util_mips64.c pfmon_mips64.c
CFLAGS += -DCONFIG_PFMON_MIPS64
endif 

ifeq ($(ARCH),cell)
SRCS += pfmon_cell.c pfmon_util_cell.c
CFLAGS += -DCONFIG_PFMON_CELL
endif

ifeq ($(ARCH),sparc)
SRCS += pfmon_sparc.c pfmon_util_sparc.c
CFLAGS += -DCONFIG_PFMON_SPARC
endif

DIRS=smpl_mod 
SMPL_MOD_LIB=smpl_mod/libsmplfmt.a
TARGET=autopin

ifeq ($(CONFIG_PFMON_DEBUG),y)
CFLAGS += -DPFMON_DEBUG -g
endif

OBJS=$(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS) $(SMPL_MOD_LIB) pfmon.h pfmon_support.h pfmon_smpl.h
	$(CC) -o $@ $(OBJS) $(CFLAGS) $(LDFLAGS) $(SMPL_MOD_LIB) $(LIBS) 

$(OBJS) : config.mk rules.mk Makefile

clean: clean_subdirs
	rm -f $(OBJS) $(TARGET) 

distclean: clean clean_subdirs
	rm -f $(ALL_SUPPORT)
depend:
	$(MKDEP) $(SRCS)

install: subdirs $(TARGET)
	-mkdir -p $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 autopin $(DESTDIR)$(BINDIR)/autopin
	-ln -sf $(DESTDIR)$(BINDIR)/autopin $(DESTDIR)$(BINDIR)/autopin_gen

$(SMPL_MOD_LIB) subdirs: 
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d all; done

clean_subdirs: 
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d clean; done

tags:
	ctags $(SRCS)
