/*
 * pfmon_mips64.h
 *
 * By Philip Mucci, based on pfmon_i386.h, <mucci@cs.utk.edu>
 *
 * Copyright (c) 2005-2006 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *
 * This file is part of pfmon, a sample tool to measure performance 
 * of applications for Linux.
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
#ifndef __PFMON_MIPS64_H__
#define __PFMON_MIPS64_H__ 1

static __inline__ unsigned int
bit_weight(unsigned long x)
{
	unsigned int cnt = 0;
	for(; x; x>>=1) if (x & 0x1) cnt++;
	return cnt;
}

/*
 * return -1 when value of x is zero
 */
static inline unsigned long
find_last_bit_set(unsigned long x)
{
	unsigned int bit, last_bit = ~0;

	for(bit=0;x; bit++,x>>=1)
		if (x & 0x1) last_bit = bit;

	return last_bit;
}

/*
 * instr/data caches
 * cache sizes
 * 3 levels of caches, load/store latencies
 * lat = 0, means cache not implemented
 */
typedef struct {
	unsigned long	d_size[4];
	unsigned long	i_size[4];
	unsigned int d_latency[4][2];
	unsigned int i_latency[4][2];
} pfmon_cache_info_t; 

typedef struct {
	int dummy;
} pfmon_mips64_options_t;

typedef struct {
	char *cnt_mask_arg;
} pfmon_mips64_args_t;

#endif /* __PFMON_MIPS64_H__ */
