/*
 * Sparc PMU support for pfmon.
 *
 * This file is part of pfmon, a sample tool to measure performance
 * of applications for Linux.
 *
 * Copyright (C) 2007 David S. Miller (davem@davemloft.net)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of the License.
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

#ifndef __PFMON_SPARC_H__
#define __PFMON_SPARC_H__ 1

static __inline__ unsigned int bit_weight(unsigned long x)
{
	unsigned int cnt = 0;

	for (; x; x >>= 1)
		if (x & 0x1)
			cnt++;
	return cnt;
}

static inline unsigned long find_last_bit_set(unsigned long x)
{
	unsigned int bit, last_bit = ~0;

	for (bit = 0; x; bit++, x >>= 1)
		if (x & 0x1)
			last_bit = bit;

	return last_bit;
}

typedef struct {
	int dummy;
} pfmon_cache_info_t;

#endif /* __PFMON_SPARC_H__ */
