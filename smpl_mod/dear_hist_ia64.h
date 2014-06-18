/*
 * dear_hist_ia64.h - D-EAR histograms for all IA-64 PMU models (with D-EAR)
 *
 * Copyright (c) 2005-2006 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
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
#ifndef __PFMON_SMPL_MOD_DEAR_HIST_IA64_H__
#define __PFMON_SMPL_MOD_DEAR_HIST_IA64_H__

typedef enum {
	DEAR_IS_CACHE,
	DEAR_IS_TLB,
	DEAR_IS_ALAT
} dear_mode_t;

typedef struct {
	unsigned long iaddr;
	unsigned long daddr;
	unsigned int  latency;
	unsigned int  tlb_lvl;
} dear_sample_t;


extern unsigned long dear_ita_extract(unsigned long *pmd, dear_sample_t *smpl);
extern int  dear_ita_info(int event, dear_mode_t *mode);
extern unsigned long dear_ita2_extract(unsigned long *pmd, dear_sample_t *smpl);
extern int  dear_ita2_info(int event, dear_mode_t *mode);
extern unsigned long dear_mont_extract(unsigned long *pmd, dear_sample_t *smpl);
extern int  dear_mont_info(int event, dear_mode_t *mode);

#endif /* __PFMON_SMPL_MOD_DEAR_HIST_IA64_H__ */
