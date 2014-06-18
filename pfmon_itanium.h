/*
 * pfmon_itanium.h 
 *
 * Copyright (c) 2002-2006 Hewlett-Packard Development Company, L.P.
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
#ifndef __PFMON_ITANIUM_H__
#define __PFMON_ITANIUM_H__

#include <perfmon/pfmlib_itanium.h>

typedef struct {
	struct {
		int opt_no_qual_check;	/* do not check qualifier constraints on events */
		int opt_insecure;	/* allow rum/sum in task mode */
	} pfmon_ita_opt_flags;
	char	*drange_arg;
	char	*irange_arg;
	char	*chkp_func_arg;
} pfmon_ita_options_t;

/*
 * event-set private options
 */
typedef struct {
	char	*instr_set_arg;	/* per set instruction set */
	char	*threshold_arg;	/* per set thresholds */
	char	*opcm8_arg;
	char	*opcm9_arg;
	int 	opt_btb_notar;	
	int 	opt_btb_notac;	
	int 	opt_btb_tm;	
	int 	opt_btb_ptm;	
	int 	opt_btb_ppm;	
	int 	opt_btb_bpt;	
	int 	opt_btb_nobac;	
	int 	opt_ia64;
	int 	opt_ia32;
} pfmon_ita_args_t;

#define opt_no_qual_check	pfmon_ita_opt_flags.opt_no_qual_check
#define opt_insecure		pfmon_ita_opt_flags.opt_insecure

#endif /* __PFMON_ITANIUM_H__ */

