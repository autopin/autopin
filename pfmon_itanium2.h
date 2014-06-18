/*
 * pfmon_itanium2.h 
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
#ifndef __PFMON_ITANIUM2_H__
#define __PFMON_ITANIUM2_H__

#include <perfmon/pfmlib_itanium2.h>

typedef struct {
	struct {
		int opt_no_qual_check;	/* do not check qualifier constraints on events */
		int opt_insecure;	/* allow rum/sum in task mode */
		int opt_inv_rr;		/* inverse range restriction on IBRP0 */
	} pfmon_ita2_opt_flags;
	char	*drange_arg;
	char	*irange_arg;
	char	*chkp_func_arg;
} pfmon_ita2_options_t;

#define opt_no_qual_check	pfmon_ita2_opt_flags.opt_no_qual_check
#define opt_insecure		pfmon_ita2_opt_flags.opt_insecure
#define opt_inv_rr		pfmon_ita2_opt_flags.opt_inv_rr

/*
 * event-set private options
 */
typedef struct {
	char	*instr_set_arg;	/* per set instruction set */
	char	*threshold_arg;	/* per set thresholds */
	char	*opcm8_arg;
	char	*opcm9_arg;
	int opt_btb_ds;		/* capture branch predictions instead of targets */
	int opt_btb_tm;		/* taken/not-taken branches only */
	int opt_btb_ptm;	/* predicted target address mask: correct/incorrect */
	int opt_btb_ppm;	/* predicted path: correct/incorrect */
	int opt_btb_brt;	/* branch type mask */
	int opt_ia64;
	int opt_ia32;
} pfmon_ita2_args_t;

#endif /* __PFMON_ITANIUM2_H__ */
