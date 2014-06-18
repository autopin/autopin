/*
 * pfmon_support.h
 *
 * Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *
 * This file is part of pfmon, a sample tool to measure performance 
 * of applications on Linux.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 */
#ifndef __PFMON_SUPPORT_H__
#define PFMON_SUPPORT_H__

#include "pfmon.h"

extern pfmon_support_t pfmon_itanium;
extern pfmon_support_t pfmon_itanium2;
extern pfmon_support_t pfmon_montecito;
extern pfmon_support_t pfmon_generic_ia64;
extern pfmon_support_t pfmon_amd64;
extern pfmon_support_t pfmon_i386_pm;
extern pfmon_support_t pfmon_i386_pii;
extern pfmon_support_t pfmon_i386_ppro;
extern pfmon_support_t pfmon_i386_p6;
extern pfmon_support_t pfmon_pentium4;
extern pfmon_support_t pfmon_gen_ia32;
extern pfmon_support_t pfmon_coreduo;
extern pfmon_support_t pfmon_core;
extern pfmon_support_t pfmon_mips64_20kc;
extern pfmon_support_t pfmon_mips64_25kf;
extern pfmon_support_t pfmon_mips64_ice9a;
extern pfmon_support_t pfmon_mips64_ice9b;
extern pfmon_support_t pfmon_cell;
extern pfmon_support_t pfmon_ultra12;
extern pfmon_support_t pfmon_ultra3;
extern pfmon_support_t pfmon_ultra3i;
extern pfmon_support_t pfmon_ultra3plus;
extern pfmon_support_t pfmon_ultra4plus;
extern pfmon_support_t pfmon_niagara1;
extern pfmon_support_t pfmon_niagara2;

#endif /* __PFMON_SUPPORT_H__ */

