/*
 * pfmon_pentium4.h
 *
 * Copyright (c) 2005-2006 Hewlett-Packard Development Company, L.P.
 * Copyright (c) 2006 IBM Corp.
 * Contributed by Kevin Corry <kevcorry@us.ibm.com>
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
#ifndef __PFMON_PENTIUM4_H__
#define __PFMON_PENTIUM4_H__

typedef struct {
	int dummy;
} pfmon_pentium4_options_t;

typedef struct {
	char *cnt_mask_arg;
	char *inv_mask_arg;
	char *edge_mask_arg;
} pfmon_pentium4_args_t;

#endif /* __PFMON_PENTIUM4_H__ */
