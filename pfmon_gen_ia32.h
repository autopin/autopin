/*
 * pfmon_gen_ia32.h
 *
 * Copyright (c) 2006 Hewlett-Packard Development Company, L.P.
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
#ifndef __PFMON_GEN_IA32_H__
#define __PFMON_GEN_IA32_H__ 1

typedef struct {
	int dummy;
} pfmon_gen_ia32_options_t;

typedef struct {
	char *cnt_mask_arg;
	char *inv_mask_arg;
	char *edge_mask_arg;
} pfmon_gen_ia32_args_t;

#endif /* __PFMON_GEN_IA32_H__ */
