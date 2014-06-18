/*
 * pfmon_montecito.h 
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
#ifndef __PFMON_MONTECITO_H__
#define __PFMON_MONTECITO_H__

#include <perfmon/pfmlib_montecito.h>

/*
 * options to apply to all sets
 */
typedef struct {
	struct {
		int opt_no_qual_check;	/* do not check qualifier constraints on events */
		int opt_insecure;	/* allow rum/sum in task mode */
		int opt_inv_rr;	/* inverse range restriction on IBRP0 */
		int opt_demand_fetch;	/* for specific event and irange */
		int opt_fetch_match;	/* for specific event and irange */
	} pfmon_mont_opt_flags;
	char	*drange_arg;
	char	*irange_arg;
	char	*chkp_func_arg;
} pfmon_mont_options_t;

/*
 * event-set private options
 */
typedef struct {
	char	*instr_set_arg;	/* per set instruction set */
	char	*threshold_arg;	/* per set thresholds */
	char	*opcm32_arg;
	char	*opcm34_arg;
	int 	opt_etb_ds;	/* capture branch predictions instead of targets */
	int 	opt_etb_tm;	/* taken/not-taken branches only */
	int 	opt_etb_ptm;	/* predicted target address mask: correct/incorrect */
	int 	opt_etb_ppm;	/* predicted path: correct/incorrect */
	int 	opt_etb_brt;	/* branch type mask */
} pfmon_mont_args_t;

#define opt_no_qual_check	pfmon_mont_opt_flags.opt_no_qual_check
#define opt_insecure		pfmon_mont_opt_flags.opt_insecure
#define opt_inv_rr		pfmon_mont_opt_flags.opt_inv_rr
#define opt_demand_fetch	pfmon_mont_opt_flags.opt_demand_fetch
#define opt_fetch_match		pfmon_mont_opt_flags.opt_fetch_match

#endif /* __PFMON_MONTECITO_H__ */
