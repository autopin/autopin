#
# Copyright (c) 2003-2006 Hewlett-Packard Development Company, L.P.
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

include ../config.mk
include ../rules.mk

CFLAGS += -D_GNU_SOURCE -I. -I..

#
# modules supporting any PMU models
#
OBJS=inst_hist_smpl.o compact_smpl.o raw_smpl.o detailed_smpl.o

ifeq ($(ARCH),ia64)
OBJS  += detailed_itanium.o detailed_itanium2.o detailed_montecito.o \
         dear_hist_ia64.o dear_itanium.o dear_itanium2.o dear_montecito.o \
	 pfmon_smpl_ia64_old.o \
	 inst_hist_ia64_old_smpl.o \
	 detailed_ia64_old_smpl.o \
         dear_hist_ia64_old_smpl.o \
	 compact_ia64_old_smpl.o \
	 raw_ia64_old_smpl.o
endif

ifeq ($(ARCH),ia32)
OBJS   += pebs_smpl.o
endif
ifeq ($(ARCH),x86_64)
OBJS   += pebs_smpl.o
endif

TARGET=libsmplfmt.a

all: $(TARGET)

$(TARGET):  $(OBJS)
	rm -f $@
	$(AR) rv $@ $(OBJS)

$(OBJS) : ../config.mk ../config.mk Makefile

clean: 
	rm -f $(OBJS) $(TARGET) 

distclean: clean

depend:
	$(MKDEP) $(SRCS)

.PHONY: install
