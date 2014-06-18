/*
 * pfmon_ia64.h
 *
 * Copyright (c) 2003-2006 Hewlett-Packard Development Company, L.P.
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
#if defined(__ECC) && defined(__INTEL_COMPILER)
#define PFMON_USING_INTEL_ECC_COMPILER	1
/* if you do not have this file, your compiler is too old */
#include <ia64intrin.h>
#endif

static __inline__ unsigned int
bit_weight(unsigned long x)
{
	unsigned long result;
#if defined(PFMON_USING_INTEL_ECC_COMPILER)
	result = _m64_popcnt(x);
#elif defined(__GNUC__)
	__asm__ ("popcnt %0=%1" : "=r" (result) : "r" (x));
#else
#error "you need to provide inline assembly from your compiler"
#endif
	return (unsigned int)result;
}

static inline unsigned long
find_last_bit_set(unsigned long x)
{
	long double d = x;
	long exp;

#if defined(PFMON_USING_INTEL_ECC_COMPILER)
	exp = __getf_exp(d);
#elif defined(__GNUC__)
	__asm__ ("getf.exp %0=%1" : "=r"(exp) : "f"(d));
#else
#error "you need to provide inline assembly from your compiler"
#endif
	return exp - 0xffff;
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


