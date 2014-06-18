/*
 * pfmon_itanium2.c - Itanium2 PMU support for pfmon
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
#include "pfmon.h"

#include <ctype.h>
#include <limits.h>
#include <perfmon/pfmlib_itanium2.h>

#include "pfmon_itanium2.h"

#define DEAR_REGS_MASK		(M_PMD(2)|M_PMD(3)|M_PMD(17))
#define DEAR_ALAT_REGS_MASK	(M_PMD(3)|M_PMD(17))
#define IEAR_REGS_MASK		(M_PMD(0)|M_PMD(1))
#define BTB_REGS_MASK		(M_PMD(8)|M_PMD(9)|M_PMD(10)|M_PMD(11)|M_PMD(12)|M_PMD(13)|M_PMD(14)|M_PMD(15)|M_PMD(16))

#define PFMON_ITA2_MAX_IBRS	8
#define PFMON_ITA2_MAX_DBRS	8

static pfmon_ita2_options_t pfmon_ita2_opt;	/* keep track of global program options */

static void
pfmon_ita2_setup_thresholds(pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	pfmon_ita2_args_t *args;
	char *thres_str;
	char *p;
	unsigned int thres, maxincr;
	unsigned int cnt=0;
	unsigned int i;

	args = set->mod_args;

	thres_str = args->threshold_arg;

	/*
	 * the default value for the threshold is 0: this means at least once 
	 * per cycle.
	 */
	if (thres_str == NULL) {
		for (i=0; i < set->event_count; i++) param->pfp_ita2_counters[i].thres = 0;
		return;
	}

	while (thres_str) {

		if (cnt == options.max_counters || cnt == set->event_count) goto too_many;

		p = strchr(thres_str,',');

		if ( p ) *p++ = '\0';

		thres = atoi(thres_str);

		/*
		 *  threshold = multi-occurence -1
		 * this is because by setting threshold to n, one counts only
		 * when n+1 or more events occurs per cycle.
	 	 */
		pfm_ita2_get_event_maxincr(set->inp.pfp_events[cnt].event, &maxincr);
		if (thres > (maxincr-1)) goto too_big;

		param->pfp_ita2_counters[cnt++].thres = thres;

		thres_str = p;
	}
	return;
too_big:
	fatal_error("event %d: threshold must be in [0-%d)\n", cnt, maxincr);
too_many:
	fatal_error("too many thresholds specified\n");
}

static char *retired_events[]={
	"IA64_TAGGED_INST_RETIRED_IBRP0_PMC8",
	"IA64_TAGGED_INST_RETIRED_IBRP1_PMC9",
	"IA64_TAGGED_INST_RETIRED_IBRP2_PMC8",
	"IA64_TAGGED_INST_RETIRED_IBRP3_PMC9",
	NULL
};

static void
check_ibrp_events(pfmon_event_set_t *set)
{
	pfmlib_ita2_output_param_t *param = set->mod_outp;
	unsigned long umasks_retired[4];
	unsigned long umask;
	unsigned int j, i, seen_retired, ibrp, idx;
	int code;
	int retired_code, incr;
	
	/*
	 * in fine mode, it is enough to use the event
	 * which only monitors the first debug register
	 * pair. The two pairs making up the range
	 * are guaranteed to be consecutive in rr_br[].
	 */
	incr = pfm_ita2_irange_is_fine(&set->outp, param) ? 4 : 2;

	for (i=0; retired_events[i]; i++) {
		pfm_find_event(retired_events[i], &idx);
		pfm_ita2_get_event_umask(idx, umasks_retired+i);
	}

	pfm_get_event_code(idx, &retired_code);

	/*
	 * print a warning message when the using IA64_TAGGED_INST_RETIRED_IBRP* which does
	 * not completely cover the all the debug register pairs used to make up the range.
	 * This could otherwise lead to misinterpretation of the results.
	 */
	for (i=0; i < param->pfp_ita2_irange.rr_nbr_used; i+= incr) {

		ibrp = param->pfp_ita2_irange.rr_br[i].reg_num >>1;

		seen_retired = 0;
		for(j=0; j < set->event_count; j++) {
			pfm_get_event_code(set->inp.pfp_events[j].event, &code);
			if (code != retired_code) continue;
			seen_retired = 1;
			pfm_ita2_get_event_umask(set->inp.pfp_events[j].event, &umask);
			if (umask == umasks_retired[ibrp]) break;
		}
		if (seen_retired && j == set->event_count)
			warning("warning: code range uses IBR pair %d which is not monitored using %s\n", ibrp, retired_events[ibrp]);
	}
}

static int
install_irange(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_ita2_output_param_t *param = set->mod_outp;
	pfarg_pmc_t dbreg[PFMON_ITA2_MAX_IBRS];
	unsigned int i, used_dbr;
	int r, error;

	memset(dbreg, 0, sizeof(dbreg));

	check_ibrp_events(set);

	used_dbr = param->pfp_ita2_irange.rr_nbr_used;

	for(i=0; i < used_dbr; i++) {
		dbreg[i].reg_num   = 256+param->pfp_ita2_irange.rr_br[i].reg_num; 
		dbreg[i].reg_set   = set->id;
		dbreg[i].reg_value = param->pfp_ita2_irange.rr_br[i].reg_value; 
	}
	r = pfmon_write_ibrs(sdesc->ctxid, dbreg, used_dbr, &error);
	if (r == -1)
		warning("cannot install code range restriction: %s\n", strerror(error));
	return r;
}

static int
install_drange(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_ita2_output_param_t *param = set->mod_outp;
	pfarg_pmc_t dbreg[PFMON_ITA2_MAX_DBRS];
	unsigned int i, used_dbr;
	int r, error;

	memset(dbreg, 0, sizeof(dbreg));

	used_dbr = param->pfp_ita2_drange.rr_nbr_used;

	for(i=0; i < used_dbr; i++) {
		dbreg[i].reg_num   = 264+param->pfp_ita2_drange.rr_br[i].reg_num; 
		dbreg[i].reg_set   = set->id;
		dbreg[i].reg_value = param->pfp_ita2_drange.rr_br[i].reg_value; 
	}

	r = pfmon_write_dbrs(sdesc->ctxid, dbreg, used_dbr, &error);
	if (r == -1)
		warning("cannot install data range restriction: %s\n", strerror(error));

	return r;
}

static int
install_btb(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	/* 
	 * we do not really need to clear PMD16, because the kernel 
	 * clears pmd16 for each newly created context
	 */
	return 0;
}

static int
install_iears(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	/*
	 * we do not reaaly need to clear PMD) because the kernel
	 * clears pmd0 for each newly created context
	 */
	return 0;
}

static int
prepare_btb(pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	unsigned int i;
	int found_btb = -1;

	for(i=0; i < set->event_count; i++) {
		if (pfm_ita2_is_btb(set->inp.pfp_events[i].event)) {
			found_btb = i;
			goto found;
		}
	}
	/*
	 * check for no BTB event, but just BTB options.
	 */
	if (param->pfp_ita2_btb.btb_used == 0) return 0;
found:
	/*
	 * in case of no BTB event found OR BTB event does not have a sampling period, 
	 * we are in free running mode (no BTB sampling) therefore we include the BTB 
	 * PMD in all samples
	 */
	if (found_btb != -1 && (set->short_rates[i].flags & PFMON_RATE_VAL_SET)) {
		set->smpl_pmds[i][0]  |=  BTB_REGS_MASK;
		set->common_reset_pmds[0] |=  M_PMD(16);
	} else {
		set->common_smpl_pmds[0]  |=  BTB_REGS_MASK;
		set->common_reset_pmds[0] |=  BTB_REGS_MASK;
	}
	return 0;
}

static int
prepare_ears(pfmon_event_set_t *set)
{
	unsigned int i;
	int ev, is_iear;

	/*
	 * search for an EAR event
	 */
	for(i=0; i < set->event_count; i++) {

		ev = set->inp.pfp_events[i].event;

		/* look for EAR event */
		if (pfm_ita2_is_ear(ev) == 0) continue;

		is_iear = pfm_ita2_is_iear(ev);

		/*
		 * when used as sampling period, then just setup the bitmask
		 * of PMDs to record in each sample
		 */
		if (set->short_rates[i].flags & PFMON_RATE_VAL_SET) {
			if (is_iear) {
				set->smpl_pmds[i][0]  |=  IEAR_REGS_MASK;
				set->common_reset_pmds[0] |= M_PMD(0);
			} else {
				set->smpl_pmds[i][0]  |=  pfm_ita2_is_dear_alat(ev) ? DEAR_ALAT_REGS_MASK : DEAR_REGS_MASK;
			}
			continue;
		}

		/*
		 * for D-EAR, we must clear PMD3.stat and PMD17.vl to make
		 * sure we do not interpret the register in the wrong manner.
		 *
		 * for I-EAR, we must clear PMD0.stat to avoid interpreting stale
		 * entries
		 *
		 * This is ONLY necessary when the events are not used as sampling
		 * periods.
		 */
		if (is_iear) {
			set->common_reset_pmds[0] |= M_PMD(0);
			set->common_smpl_pmds[0]  |= IEAR_REGS_MASK;
		} else {
			set->common_reset_pmds[0] |= M_PMD(17);

			/* DEAR-ALAT only needs PMD17 */
			if (pfm_ita2_is_dear_alat(ev) == 0) {
				set->common_reset_pmds[0] |= M_PMD(3);
				set->common_smpl_pmds[0]  |= DEAR_REGS_MASK;
			} else {
				set->common_smpl_pmds[0]  |= DEAR_ALAT_REGS_MASK;
			}
		} 
	}
	return 0;
}

/*
 * Executed in the context of the child, this is the last chance to modify programming
 * before the PMC and PMD register are written.
 */
static int
pfmon_ita2_prepare_registers(pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	int r = 0;
	
	if (param == NULL) return 0;

	if (param->pfp_ita2_btb.btb_used) r = prepare_btb(set);

	if (r == 0) r = prepare_ears(set);

	return r;
}

static int
pfmon_ita2_install_pmc_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	int r = 0;

	if (param == NULL) return 0;

	if (param->pfp_ita2_irange.rr_used) r = install_irange(sdesc, set);

	if (r == 0 && param->pfp_ita2_drange.rr_used) r = install_drange(sdesc, set);

	return r;
}

static int
pfmon_ita2_install_pmd_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	int r = 0;

	if (param == NULL) return 0;

	if (r == 0 && param->pfp_ita2_iear.ear_used) install_iears(sdesc, set);

	if (r == 0 && param->pfp_ita2_btb.btb_used) install_btb(sdesc, set);

	return r;
}

static void
pfmon_ita2_usage(void)
{
	printf( "--event-thresholds=thr1,thr2,...\tSet event thresholds (no space).\n"
		"--opc-match8=[mifb]:match:mask\t\tSet opcode match for pmc8.\n"
		"--opc-match9=[mifb]:match:mask\t\tSet opcode match for pmc9.\n"
		"--btb-tm-tk\t\t\t\tCapture taken IA-64 branches only.\n"
		"--btb-tm-ntk\t\t\t\tCapture not taken IA-64 branches only.\n"
		"--btb-ptm-correct\t\t\tCapture branch if target predicted\n"
		"\t\t\t\t\tcorrectly.\n"
		"--btb-ptm-incorrect\t\t\tCapture branch if target is\n"
		"\t\t\t\t\tmispredicted.\n"
		"--btb-ppm-correct\t\t\tCapture branch if path is predicted\n"
		"\t\t\t\t\tcorrectly.\n"
		"--btb-ppm-incorrect\t\t\tCapture branch if path is mispredicted.\n"
		"--btb-brt-iprel\t\t\t\tCapture IP-relative branches only.\n"
		"--btb-brt-ret\t\t\t\tCapture return branches only.\n"
		"--btb-brt-ind\t\t\t\tCapture non-return indirect branches\n"
		"\t\t\t\t\tonly.\n"
		"--irange=start-end\t\t\tSpecify an instruction address range\n"
		"\t\t\t\t\tconstraint.\n"
		"--drange=start-end\t\t\tSpecify a data address range constraint.\n"
		"--checkpoint-func=addr\t\t\tA bundle address to use as checkpoint.\n"
		"--ia32\t\t\t\t\tMonitor IA-32 execution only.\n"
		"--ia64\t\t\t\t\tMonitor IA-64 execution only.\n"
		"--insn-sets=set1,set2,...\t\tSet per event instruction set\n"
		"\t\t\t\t\t(setX=[ia32|ia64|both]).\n"
		"--inverse-irange\t\t\tInverse instruction range restriction.\n"
		"--no-qual-check\t\t\t\tDo not check qualifier constraints on\n"
		"\t\t\t\t\tevents.\n"
		"--insecure\t\t\t\tAllow rum/sum in monitored task\n"
		"--exclude-idle\t\t\t\tStop monitoring in the idle loop\n"
		"\t\t\t\t\t(default: off)\n"
		"\t\t\t\t\t(per-thread mode only).\n"
		"--excl-intr\t\t\t\tExclude interrupt-triggered execution\n"
		"\t\t\t\t\tfrom system-wide measurement.\n"
		"--intr-only\t\t\t\tInclude only interrupt-triggered\n"
		"\t\t\t\t\texecution from system-wide measurement.\n"
	);
}

static void
pfmon_ita2_setup_ears(pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	unsigned int i, done_iear = 0, done_dear = 0;
	pfmlib_ita2_ear_mode_t dear_mode, iear_mode;
	unsigned int ev;

	for (i=0; i < set->event_count; i++) {

		ev = set->inp.pfp_events[i].event;

		if (pfm_ita2_is_ear(ev) == 0) continue;

		if (pfm_ita2_is_dear(ev)) {

			if (done_dear) {
				fatal_error("cannot specify more than one D-EAR event at the same time\n");
			}

			pfm_ita2_get_ear_mode(ev, &dear_mode);

			param->pfp_ita2_dear.ear_used   = 1;
			param->pfp_ita2_dear.ear_mode   = dear_mode;
			param->pfp_ita2_dear.ear_plm    = set->inp.pfp_events[i].plm; /* use plm from event */
			param->pfp_ita2_dear.ear_ism    = param->pfp_ita2_counters[i].ism;
			pfm_ita2_get_event_umask(ev, &param->pfp_ita2_dear.ear_umask);
			
			done_dear = 1;

			continue;
		}

		if (pfm_ita2_is_iear(ev)) {

			if (done_iear) {
				fatal_error("cannot specify more than one D-EAR event at the same time\n");
			}

			pfm_ita2_get_ear_mode(ev, &iear_mode);

			param->pfp_ita2_iear.ear_used   = 1;
			param->pfp_ita2_iear.ear_mode   = iear_mode;
			param->pfp_ita2_iear.ear_plm    = set->inp.pfp_events[i].plm; /* use plm from event */
			param->pfp_ita2_iear.ear_ism    = param->pfp_ita2_counters[i].ism;
			pfm_ita2_get_event_umask(ev, &param->pfp_ita2_iear.ear_umask);

			done_iear = 1;
		}
	}	
}

static void
pfmon_ita2_setup_btb(pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	pfmon_ita2_args_t *ita2_args;
	unsigned int i, ev;
	int found_alat = 0, found_btb = -1, found_dear = 0;

	ita2_args = set->mod_args;

	for (i=0; i < set->event_count; i++) {
		ev = set->inp.pfp_events[i].event;
		if (found_btb == -1 && pfm_ita2_is_btb(ev)) found_btb = i;
		if (pfm_ita2_is_dear_alat(ev)) found_alat = 1;
		if (pfm_ita2_is_dear_tlb(ev)) found_dear = 1;
	}

	/*
	 * no BTB event, no BTB specific options: BTB is not used
	 */
	if (found_btb == -1 &&
           !ita2_args->opt_btb_tm &&
           !ita2_args->opt_btb_ptm &&
           !ita2_args->opt_btb_ppm &&
           !ita2_args->opt_btb_brt) {
		return;
	}

	/*
	 * PMC12 must be zero when D-EAR ALAT is configured
	 * The library does the check but here we can print a more detailed error message
	 */
	if (found_btb != -1 && found_alat) fatal_error("cannot use BTB and D-EAR ALAT at the same time\n");
	if (found_btb != -1 && found_dear) fatal_error("cannot use BTB and D-EAR TLB at the same time\n");

	/*
	 * set the use bit, such that the library will program PMC12
	 */
	param->pfp_ita2_btb.btb_used = 1;

	/* by default, the registers are setup to 
	 * record every possible branch.
	 *
	 * The data selector is set to capture branch target rather than prediction.
	 *
	 * The record nothing is not available because it simply means
	 * don't use a BTB event.
	 *
	 * So the only thing the user can do is:
	 * 	- narrow down the type of branches to record. 
	 * 	  This simplifies the number of cases quite substantially.
	 * 	- change the data selector
	 */
	param->pfp_ita2_btb.btb_ds  = 0;
	param->pfp_ita2_btb.btb_tm  = 0x3;
	param->pfp_ita2_btb.btb_ptm = 0x3;
	param->pfp_ita2_btb.btb_ppm = 0x3;
	param->pfp_ita2_btb.btb_brt = 0x0;
	param->pfp_ita2_btb.btb_plm = set->inp.pfp_events[i].plm; /* use the plm from the BTB event */

	if (ita2_args->opt_btb_tm)  param->pfp_ita2_btb.btb_tm  = ita2_args->opt_btb_tm & 0x3;
	if (ita2_args->opt_btb_ptm) param->pfp_ita2_btb.btb_ptm = ita2_args->opt_btb_ptm & 0x3;
	if (ita2_args->opt_btb_ppm) param->pfp_ita2_btb.btb_ppm = ita2_args->opt_btb_ppm & 0x3;
	if (ita2_args->opt_btb_brt) param->pfp_ita2_btb.btb_brt = ita2_args->opt_btb_brt & 0x3;

	vbprintf("btb options: ds=%d tm=%d ptm=%d ppm=%d brt=%d\n",
		param->pfp_ita2_btb.btb_ds,
		param->pfp_ita2_btb.btb_tm,
		param->pfp_ita2_btb.btb_ptm,
		param->pfp_ita2_btb.btb_ppm,
		param->pfp_ita2_btb.btb_brt);
}

/*
 * Itanium2-specific options
 *
 * 000-255   reserved for generic options
 * 400-499   reserved for PMU specific options
 * 500-599   reserved for format specific options
 */
static struct option cmd_ita2_options[]={
	{ "event-thresholds", 1, 0, 400 },
	{ "opc-match8", 1, 0, 401},
	{ "opc-match9", 1, 0, 402},
	/* slot 403, used to be --btb-all-mispredicted */
	{ "checkpoint-func", 1, 0, 404},
	{ "irange", 1, 0, 405},
	{ "drange", 1, 0, 406},
	{ "insn-sets", 1, 0, 407},
	{ "ia32", 0, 0, 408},
	{ "ia64", 0, 0, 409},
	{ "btb-tm-tk", 0, 0, 411},
	{ "btb-tm-ntk", 0, 0, 412}, 
	{ "btb-ptm-correct", 0, 0, 413},
	{ "btb-ptm-incorrect", 0, 0, 414}, 
	{ "btb-ppm-correct", 0, 0, 415},
	{ "btb-ppm-incorrect", 0, 0, 416}, 
	{ "btb-brt-iprel", 0,  0, 417}, 
	{ "btb-brt-ret", 0, 0, 418}, 
	{ "btb-brt-ind", 0, 0, 419},
	{ "excl-intr", 0, 0, 420},
	{ "intr-only", 0, 0, 421},
	{ "exclude-idle", 0, 0, 422 },
	{ "inverse-irange", 0, &pfmon_ita2_opt.opt_inv_rr, 1},
	{ "no-qual-check", 0, &pfmon_ita2_opt.opt_no_qual_check, 0x1},
	{ "insecure", 0, &pfmon_ita2_opt.opt_insecure, 0x1},
	{ 0, 0, 0, 0}
};

static int
pfmon_ita2_initialize(void)
{
	int r;

	r = pfmon_register_options(cmd_ita2_options, sizeof(cmd_ita2_options));
	if (r == -1) return -1;

	/* connect pfmon model specific options */
	options.model_options = &pfmon_ita2_opt;

	return 0;
}

static void
pfmon_ita2_setup_insn(pfmon_event_set_t *set)
{
	static const struct {
		char *name;
		pfmlib_ita2_ism_t val;
	} insn_sets[]={
		{ "ia32", PFMLIB_ITA2_ISM_IA32 },
		{ "ia64", PFMLIB_ITA2_ISM_IA64 },
		{ "both", PFMLIB_ITA2_ISM_BOTH },
		{ NULL  , PFMLIB_ITA2_ISM_BOTH }
	};
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	char *p, *arg;
	pfmon_ita2_args_t *ita2_args;
	pfmlib_ita2_ism_t dfl_ism;
	unsigned int i, cnt=0;

	ita2_args = set->mod_args;

	/* 
	 * set default instruction set 
	 */
	if (ita2_args->opt_ia32  && ita2_args->opt_ia64)
		dfl_ism = PFMLIB_ITA2_ISM_BOTH;
	else if (ita2_args->opt_ia64)
		dfl_ism = PFMLIB_ITA2_ISM_IA64;
	else if (ita2_args->opt_ia32)
		dfl_ism = PFMLIB_ITA2_ISM_IA32;
	else
		dfl_ism = PFMLIB_ITA2_ISM_BOTH;

	/*
	 * propagate default instruction set to all events
	 */
	for(i=0; i < set->event_count; i++) param->pfp_ita2_counters[i].ism = dfl_ism;

	/*
	 * apply correction for per-event instruction set
	 */
	for (arg = ita2_args->instr_set_arg; arg; arg = p) {
		if (cnt == set->event_count) goto too_many;

		p = strchr(arg,',');
			
		if (p) *p = '\0';

		if (*arg) {
			for (i=0 ; insn_sets[i].name; i++) {
				if (!strcmp(insn_sets[i].name, arg)) goto found;
			}
			goto error;
found:
			param->pfp_ita2_counters[cnt++].ism = insn_sets[i].val;
		}
		/* place the comma back so that we preserve the argument list */
		if (p) *p++ = ',';
	}
	return;
error:
	fatal_error("unknown per-event instruction set %s (choices are ia32, ia64, or both)\n", arg);
	/* no return */
too_many:
	fatal_error("too many per-event instruction sets specified, max=%d\n", set->event_count);
}

/*
 * 0  means we understood the option
 * -1 unknown option
 */
static int
pfmon_ita2_parse_options(int code, char *optarg)
{
	pfmon_ita2_args_t *ita2_args;
	pfmon_event_set_t *set;

	set = options.last_set;

	ita2_args = set->mod_args;

	switch(code) {
		case  400:
			if (ita2_args->threshold_arg) fatal_error("thresholds already defined\n");
			ita2_args->threshold_arg = optarg;
			break;
		case  401:
			if (ita2_args->opcm8_arg) fatal_error("opcode matcher pmc8 is specified twice\n");
			ita2_args->opcm8_arg = optarg;
			break;
		case  402:
			if (ita2_args->opcm9_arg) fatal_error("opcode matcher pmc9 is specified twice\n");
			ita2_args->opcm9_arg = optarg;
			break;
		case  404:
			if (pfmon_ita2_opt.irange_arg) {
				fatal_error("cannot use checkpoints and instruction range at the same time\n");
			}
			if (pfmon_ita2_opt.chkp_func_arg) {
				fatal_error("checkpoint already  defined for %s\n", pfmon_ita2_opt.chkp_func_arg);
			}
			pfmon_ita2_opt.chkp_func_arg = optarg;
			break;

		case  405:
			if (pfmon_ita2_opt.chkp_func_arg) {
				fatal_error("cannot use instruction range and checkpoints at the same time\n");
			}
			if (pfmon_ita2_opt.irange_arg) {
				fatal_error("cannot specify more than one instruction range\n");
			}
			pfmon_ita2_opt.irange_arg = optarg;
			break;
		case  406:
			if (pfmon_ita2_opt.drange_arg) {
				fatal_error("cannot specify more than one data range\n");
			}
			pfmon_ita2_opt.drange_arg = optarg;
			break;
		case  407:
			if (ita2_args->instr_set_arg) fatal_error("per-event instruction sets already defined");
			ita2_args->instr_set_arg = optarg;
			break;
		case 408:
			ita2_args->opt_ia32 = 1;
			break;
		case 409:
			ita2_args->opt_ia64 = 1;
			break;
		case 411:
			ita2_args->opt_btb_tm = 0x2;
			break;
		case 412:
			ita2_args->opt_btb_tm = 0x1;
			break;
		case 413:
			ita2_args->opt_btb_ptm = 0x2;
			break;
		case 414:
			ita2_args->opt_btb_ptm = 0x1;
			break;
		case 415:
			ita2_args->opt_btb_ppm = 0x2;
			break;
		case 416:
			ita2_args->opt_btb_ppm = 0x1;
			break;
		case 417:
			ita2_args->opt_btb_brt = 0x1;
			break;
		case 418:
			ita2_args->opt_btb_brt = 0x2;
			break;
		case 419:
			ita2_args->opt_btb_brt = 0x3;
			break;
		case 420 :
			if (set->set_flags & PFM_ITA_SETFL_INTR_ONLY)
				fatal_error("cannot combine --excl-intr with --intr-only\n");
			set->set_flags |= PFM_ITA_SETFL_EXCL_INTR;
			break;
		case 421 :
			if (set->set_flags & PFM_ITA_SETFL_EXCL_INTR)
				fatal_error("cannot combine --excl-intr with --intr-only\n");
			set->set_flags |= PFM_ITA_SETFL_INTR_ONLY;
			break;
		case 422 :
			set->set_flags |= PFM_ITA_SETFL_IDLE_EXCL;
			break;

		default:
			return -1;
	}
	return 0;
}

static void
pfmon_ita2_parse_opcm(char *str, unsigned long*mifb, unsigned long *match, unsigned long *mask)
{
	unsigned long val;
	char *endptr;
	char *p;

	p = strchr(str, ':');
	if (p == NULL)
		fatal_error("malformed --opc-match-*. Must be [mifb]:match:mask\n");

	val = 0xf;
	if (p != str) {
		val = 0;
		while(*str != ':') {
			switch(*str) {
				case 'M':
				case 'm': val |= 8;
					  break;
				case 'I':
				case 'i': val |= 4;
					  break;
				case 'F':
				case 'f': val |= 2;
					 break;
				case 'B':
				case 'b': val |= 1;
					  break;
				default:
					fatal_error("unknown slot type %c for --opc-match*\n", *str);
			}
			str++;
		}
	}
	/* skip ':' */
	str++;

	*mifb = val;

	val = strtoul(str, &endptr, 0);
	if (val == ULONG_MAX && errno == ERANGE)
		fatal_error("invalid match field for --opcm-match*\n");

	if (*endptr != ':')
		fatal_error("malformed --opc-match*. Must be [mifb]:match:mask 2\n");

	*match = val;

	str = endptr+1;

	val = strtoul(str, &endptr, 0);
	if (val == ULONG_MAX && errno == ERANGE)
		fatal_error("invalid match field for --opcm-match*\n");

	if (*endptr != '\0')
		fatal_error("malformed --opc-match*. Must be [mifb]:match:mask 1\n");

	*mask = val;
}

static void
pfmon_ita2_setup_opcm(pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	pfmon_ita2_args_t *ita2_args;
	unsigned long mifb, match, mask;

	ita2_args = set->mod_args;

	if (ita2_args->opcm8_arg) {
		pfmon_ita2_parse_opcm(ita2_args->opcm8_arg,
				      &mifb,
				      &match,
				      &mask);

		/*
		 * truncate to relevant part (27 bits)
		 */
		match &= (1UL<<27)-1;
		mask  &= (1UL<<27)-1;

		param->pfp_ita2_pmc8.pmc_val = (mifb << 60) | (match <<33) | (mask<<3);
		param->pfp_ita2_pmc8.opcm_used = 1;
	}

	if (ita2_args->opcm9_arg) {
		pfmon_ita2_parse_opcm(ita2_args->opcm9_arg,
				      &mifb,
				      &match,
				      &mask);
		/*
		 * truncate to relevant part (27 bits)
		 */
		match &= (1UL<<27)-1;
		mask  &= (1UL<<27)-1;

		param->pfp_ita2_pmc9.pmc_val = (mifb << 60) | (match <<33) | (mask<<3);
		param->pfp_ita2_pmc9.opcm_used = 1;
	}
}

static void
pfmon_ita2_setup_rr(pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	pfmon_ita2_args_t *ita2_args;
	uintptr_t start, end;

	ita2_args = set->mod_args;

	/*
	 * we cannot have function checkpoint and irange
	 */
	if (pfmon_ita2_opt.chkp_func_arg) {
		if (set->priv_lvl_str)
			fatal_error("cannot use both a checkpoint function and per-event privilege level masks\n");

		gen_code_range(pfmon_ita2_opt.chkp_func_arg, &start, &end);

		/* just one bundle for this one */
		end = start + 0x10;

		vbprintf("checkpoint function at %p\n", start);

	} else if (pfmon_ita2_opt.irange_arg) {

		if (set->priv_lvl_str)
			fatal_error("cannot use both a code range function and per-event privilege level masks\n");

		gen_code_range(pfmon_ita2_opt.irange_arg, &start, &end); 

		if ((unsigned long)start & 0xf) fatal_error("code range does not start on bundle boundary : %p\n", start);
		if ((unsigned long)end & 0xf) fatal_error("code range does not end on bundle boundary : %p\n", end);

		vbprintf("irange is [%p-%p)=%ld bytes\n", start, end, end-start);
	}

	/*
	 * now finalize irange/chkp programming of the range
	 */
	if (pfmon_ita2_opt.irange_arg || pfmon_ita2_opt.chkp_func_arg) { 

		/*
		 * inverse range should be per set!
		 */
		param->pfp_ita2_irange.rr_used   = 1;
		param->pfp_ita2_irange.rr_flags |= pfmon_ita2_opt.opt_inv_rr ? PFMLIB_ITA2_RR_INV : 0;

		/*
		 * Fine mode does not work for small ranges (less than
		 * 2 bundles), so we force non-fine mode to work around the problem
		 */
		if (pfmon_ita2_opt.chkp_func_arg)
			param->pfp_ita2_irange.rr_flags |= PFMLIB_ITA2_RR_NO_FINE_MODE;

		param->pfp_ita2_irange.rr_limits[0].rr_start = (unsigned long)start;
		param->pfp_ita2_irange.rr_limits[0].rr_end   = (unsigned long)end;
		param->pfp_ita2_irange.rr_limits[0].rr_plm   = set->inp.pfp_dfl_plm; /* use default */
	}
	
	if (pfmon_ita2_opt.drange_arg) {
		if (set->priv_lvl_str)
			fatal_error("cannot use both a data range and  per-event privilege level masks\n");

		gen_data_range(pfmon_ita2_opt.drange_arg, &start, &end);

		vbprintf("drange is [%p-%p)=%lu bytes\n", start, end, end-start);
		
		param->pfp_ita2_drange.rr_used = 1;

		param->pfp_ita2_drange.rr_limits[0].rr_start = (unsigned long)start;
		param->pfp_ita2_drange.rr_limits[0].rr_end   = (unsigned long)end;
		param->pfp_ita2_drange.rr_limits[0].rr_plm   = set->inp.pfp_dfl_plm; /* use default */
	}
}

/*
 * It is not possible to measure more than one of the
 * L2_OZQ_CANCELS0_*, L2_OZQ_CANCELS1_*, or
 * L2_OZQ_CANCELS2_* at the same time.
 */
static char *cancel_events[]=
{
	"L2_OZQ_CANCELS0_ANY",
	"L2_OZQ_CANCELS1_REL",
	"L2_OZQ_CANCELS2_ACQ"
};
#define NCANCEL_EVENTS	sizeof(cancel_events)/sizeof(char *)

static void
check_cancel_events(pfmon_event_set_t *set)
{
	unsigned int i, j, tmp;
	int code, seen_first = 0, ret;
	int cancel_codes[NCANCEL_EVENTS];
	unsigned int idx = 0;
	char name[PFMON_MAX_EVTNAME_LEN], name2[PFMON_MAX_EVTNAME_LEN];

	for(i=0; i < NCANCEL_EVENTS; i++) {
		ret = pfm_find_event(cancel_events[i], &tmp);
		if (ret != PFMLIB_SUCCESS)
			fatal_error("pfmon bug: cannot find CANCEL events to check\n");
		pfm_get_event_code(tmp, &code);
		cancel_codes[i] = code;
	}
	for(i=0; i < set->event_count; i++) {
		for (j=0; j < NCANCEL_EVENTS; j++) {
			pfm_get_event_code(set->inp.pfp_events[i].event, &code);
			if (code == cancel_codes[j]) {
				if (seen_first) {
					pfm_get_event_name(idx, name, PFMON_MAX_EVTNAME_LEN);
					pfm_get_event_name(set->inp.pfp_events[i].event, name2, PFMON_MAX_EVTNAME_LEN);
					fatal_error("%s and %s cannot be measured at the same time\n", name, name2);
				}
				idx = set->inp.pfp_events[i].event;
				seen_first = 1;
			}
		}
	}
}

static void
check_cross_groups_and_set_umask(pfmon_event_set_t *set)
{
	unsigned long ref_umask, umask;
	int g, g2, s, s2;
	unsigned int cnt = set->event_count;
	pfmlib_event_t *e= set->inp.pfp_events;
	char name1[PFMON_MAX_EVTNAME_LEN], name2[PFMON_MAX_EVTNAME_LEN];
	unsigned int i, j;

	for (i=0; i < cnt; i++) {

		pfm_ita2_get_event_group(e[i].event, &g);
		pfm_ita2_get_event_set(e[i].event, &s);

		if (g == PFMLIB_ITA2_EVT_NO_GRP) continue;

		pfm_ita2_get_event_umask(e[i].event, &ref_umask);

		for (j=i+1; j < cnt; j++) {
			pfm_ita2_get_event_group(e[j].event, &g2);
			if (g2 != g) continue;

			pfm_ita2_get_event_set(e[j].event, &s2);
			if (s2 != s) goto error;

			/* only care about L2 cache group */
			if (g != PFMLIB_ITA2_EVT_L2_CACHE_GRP || (s == 1 || s == 2)) continue;

			pfm_ita2_get_event_umask(e[j].event, &umask);
			/*
			 * there is no assignment valid if more than one event of 
			 * the set has a umask
			 */
			if (umask && ref_umask != umask) goto error;
		}
	}
	return;
error:
	pfm_get_event_name(e[i].event, name1, PFMON_MAX_EVTNAME_LEN);
	pfm_get_event_name(e[j].event, name2, PFMON_MAX_EVTNAME_LEN);
	fatal_error("event %s and %s cannot be measured at the same time\n", name1, name2);
}

static void 
check_counter_conflict(pfmon_event_set_t *set)
{
	pfmlib_event_t *e = set->inp.pfp_events;
	pfmlib_regmask_t cnt1, cnt2, all_counters;
	unsigned int weight;
	unsigned int cnt = set->event_count;
	unsigned int i, j;
	char name1[PFMON_MAX_EVTNAME_LEN], name2[PFMON_MAX_EVTNAME_LEN];

	pfm_get_impl_counters(&all_counters);

	for (i=0; i < cnt; i++) {
		pfm_get_event_counters(e[i].event, &cnt1);
		if (pfm_regmask_eq(&cnt1, &all_counters)) continue;
		for(j=i+1; j < cnt; j++) {
			pfm_get_event_counters(e[j].event, &cnt2);
			weight = 0;
			pfm_regmask_weight(&cnt1, &weight);
			if (pfm_regmask_eq(&cnt2, &cnt1) && weight == 1) goto error;
		}
	}
	return;
error:
	pfm_get_event_name(e[i].event, name1, PFMON_MAX_EVTNAME_LEN);
	pfm_get_event_name(e[j].event, name2, PFMON_MAX_EVTNAME_LEN);
	fatal_error("event %s and %s cannot be measured at the same time, trying using different event sets\n", name1, name2);
}

static void
check_ita2_event_combinations(pfmon_event_set_t *set)
{
	unsigned int i, use_opcm, inst_retired_idx, ev;
	int code, inst_retired_code;
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	pfmon_ita2_args_t *ita2_args;
	char name[PFMON_MAX_EVTNAME_LEN];

	ita2_args = set->mod_args;

	/*
	 * here we repeat some of the tests done by the library
	 * to provide more detailed feedback (printf()) to the user.
	 *
	 * XXX: not all tests are duplicated, so we will not get detailed
	 * error reporting for all possible cases.
	 */
	check_counter_conflict(set);
	check_cancel_events(set);
	check_cross_groups_and_set_umask(set);

	use_opcm = param->pfp_ita2_pmc8.opcm_used || param->pfp_ita2_pmc9.opcm_used; 

	pfm_find_event("IA64_INST_RETIRED", &inst_retired_idx);
	pfm_get_event_code(inst_retired_idx, &inst_retired_code);

	for (i=0; i < set->event_count; i++) {

		ev = set->inp.pfp_events[i].event;

		pfm_get_event_name(ev, name, PFMON_MAX_EVTNAME_LEN);
		pfm_get_event_code(ev, &code);

		if (use_opcm && pfm_ita2_support_opcm(ev) == 0)
			fatal_error("event %s does not support opcode matching\n", name);

		if (param->pfp_ita2_pmc9.opcm_used && code != inst_retired_code) 
			fatal_error("pmc9 can only be used to qualify the IA64_INST_RETIRED events\n");

		if (param->pfp_ita2_irange.rr_used && pfm_ita2_support_iarr(ev) == 0)
			fatal_error("event %s does not support instruction address range restrictions\n", name);

		if (param->pfp_ita2_drange.rr_used && pfm_ita2_support_darr(ev) == 0)
			fatal_error("event %s does not support data address range restrictions\n", name);

		/*
		 * opt_ia32, opt_ia64  are set only if user explicitely requested
		 * default values 0,0 but ia32/ia64 is default mode
		 */
		if (ita2_args->opt_ia32 && ita2_args->opt_ia64 == 0 && pfm_ita2_is_btb(ev))
			fatal_error("cannot use BTB event (%s) when only monitoring IA-32 execution\n", name);
	}
}

static void
pfmon_ita2_no_qual_check(pfmon_event_set_t *set)
{
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	unsigned int i;

	/*
	 * set the "do not check constraint" flags for all events 
	 */
	for (i=0; i < set->event_count; i++) {
		param->pfp_ita2_counters[i].flags |= PFMLIB_ITA2_FL_EVT_NO_QUALCHECK;
	}
}

static int
pfmon_ita2_setup(pfmon_event_set_t *set)
{
	pfmon_ita2_args_t *ita2_args;

	ita2_args = set->mod_args;

	if (ita2_args == NULL) return 0;

	
	if (options.code_trigger_start || options.code_trigger_stop || options.data_trigger_start || options.data_trigger_stop) {
		if (pfmon_ita2_opt.irange_arg)
			fatal_error("cannot use a trigger address with instruction range restrictions\n");
		if (pfmon_ita2_opt.drange_arg)
			fatal_error("cannot use a trigger address with data range restrictions\n");
		if (pfmon_ita2_opt.chkp_func_arg)
			fatal_error("cannot use a trigger address with function checkpoint\n");
	}
	/*
	 * setup the instruction set support
	 *
	 * and reject any invalid feature combination for IA-32 only monitoring
	 *
	 * We do not warn of the fact that IA-32 execution will be ignored
	 * when used with incompatible features unless the user requested IA-32
	 * ONLY monitoring. 
	 */
	if (ita2_args->opt_ia32 == 1 && ita2_args->opt_ia64 == 0) {

		/*
		 * Code & Data range restrictions are ignored for IA-32
		 */
		if (pfmon_ita2_opt.irange_arg || pfmon_ita2_opt.drange_arg) 
			fatal_error("you cannot use range restrictions when monitoring IA-32 execution only\n");

		/*
		 * Code range restriction (used by checkpoint) is ignored for IA-32
		 */
		if (pfmon_ita2_opt.chkp_func_arg) 
			fatal_error("you cannot use function checkpoint when monitoring IA-32 execution only\n");
	}

	pfmon_ita2_setup_insn(set);
	pfmon_ita2_setup_rr(set);
	pfmon_ita2_setup_opcm(set);
	pfmon_ita2_setup_btb(set);
	pfmon_ita2_setup_ears(set);

	/*
	 * BTB is only valid in IA-64 mode (captures error in session without BTB event)
	 */
	if (ita2_args->opt_ia32 && ita2_args->opt_ia64 == 0 &&
            (ita2_args->opt_btb_tm  ||
            ita2_args->opt_btb_ptm ||
            ita2_args->opt_btb_ppm ||
            ita2_args->opt_btb_brt)) {
			fatal_error("cannot use BTB when only monitoring IA-32 execution\n");
	}

	/* 
	 * we systematically initialize thresholds to their minimal value
	 * or requested value
	 */
	pfmon_ita2_setup_thresholds(set);

	if (pfmon_ita2_opt.opt_no_qual_check) 
		pfmon_ita2_no_qual_check(set);
	else
		check_ita2_event_combinations(set);

	return 0;
}

static int
pfmon_ita2_print_header(FILE *fp)
{
	pfmon_event_set_t *set;
	pfmlib_ita2_input_param_t *mod_in;
	unsigned int i,k;
	int isn;
	size_t l;
	char *name;
	static const char *insn_str[]={
		"ia32/ia64",
		"ia32", 
		"ia64"
	};
	l = 1 + options.max_event_name_len;
	name = malloc(l);
	if (!name)
		fatal_error("cannot allocate string buffer");

	for(k=0, set = options.sets; set; k++, set = set->next) {
		mod_in = (pfmlib_ita2_input_param_t *)set->mod_inp;
		fprintf(fp, "#\n#\n# instruction sets for set%u:\n", k);
		for(i=0; i < set->event_count; i++) {

			pfm_get_event_name(set->inp.pfp_events[i].event, name, l);

			isn =mod_in->pfp_ita2_counters[i].ism;
			fprintf(fp, "#\tPMD%d: %-*s = %s\n", 
					set->outp.pfp_pmcs[i].reg_num,
					(int)options.max_event_name_len,
					name,
					insn_str[isn]);
		} 
		fprintf(fp, "#\n");
	}
	free(name);
	return 0;
}

static void
pfmon_ita2_detailed_event_name(unsigned int evt)
{
	unsigned long umask;
	unsigned int maxincr;
	char *grp_str;
	int grp, set;

	pfm_ita2_get_event_umask(evt, &umask);
	pfm_ita2_get_event_maxincr(evt, &maxincr);
	pfm_ita2_get_event_group(evt, &grp);

	printf("umask=0x%02lx incr=%u iarr=%c darr=%c opcm=%c ", 
		umask, 
		maxincr,
		pfm_ita2_support_iarr(evt) ? 'Y' : 'N',
		pfm_ita2_support_darr(evt) ? 'Y' : 'N',
		pfm_ita2_support_opcm(evt) ? 'Y' : 'N');

	if (grp != PFMLIB_ITA2_EVT_NO_GRP) {
		pfm_ita2_get_event_set(evt, &set);
		grp_str = grp == PFMLIB_ITA2_EVT_L1_CACHE_GRP ? "l1_cache" : "l2_cache";

		printf("grp=%s set=%d", grp_str, set);
	}
}

static int
pfmon_ita2_setup_ctx_flags(pfmon_ctx_t *ctx)
{
	if (pfmon_ita2_opt.opt_insecure) {
		if (options.opt_syst_wide) {
			warning("option --insecure does not support system-wide mode\n");
			return -1;
		}
		ctx->ctx_flags |= PFM_ITA_FL_INSECURE;
	}
	return 0;
}

static void
pfmon_ita2_verify_event_sets(void)
{
	pfmon_event_set_t *set;
	int has = 0;

	for(set = options.sets; set; set = set->next) {
		if (set->set_flags & PFM_ITA_SETFL_EXCL_INTR)
			has |= 1;
		if (set->set_flags & PFM_ITA_SETFL_INTR_ONLY)
			has |= 2;
		if (set->set_flags & PFM_ITA_SETFL_IDLE_EXCL)
			has |= 4;
	}
	if (options.opt_is22 == 0) { 
		if (has & 1)
			fatal_error("--excl-intr requires at least perfmon v2.2\n");
		if (has & 2)
			fatal_error("--intr-only requires at least perfmon v2.2\n");
		if (has & 4)
			fatal_error("--exclude-idle requires at least perfmon v2.4\n");
	} else {
		if (has & 4 && options.pfm_version < PERFMON_VERSION_24)
			fatal_error("--exclude-idle requires at least perfmon v2.4\n");
	}
	if (has && options.opt_syst_wide == 0) {
		if (has & 1)
			fatal_error("--excl-intr option is not available for per-task measurement\n");
		if (has & 2) 
			fatal_error("--intr-only option is not available for per-task measurement\n");
		if (has & 4)
			fatal_error("--exclude-idle option is not available for per-task measurement\n");
	}
}

static void
pfmon_ita2_verify_cmdline(int argc, char **argv)
{
	if (pfmon_ita2_opt.opt_insecure && options.opt_is22 == 0)
		fatal_error("the --insecure option requires at least perfmon v2.2\n");
}

static void
pfmon_ita2_show_event_info(unsigned int idx)
{
	unsigned long umask;
	unsigned int maxincr;
	int grp, set, n = 0;

	pfm_ita2_get_event_umask(idx, &umask);
	pfm_ita2_get_event_maxincr(idx, &maxincr);

	printf("Umask    : 0x%lx\n", umask);

	if (pfm_ita2_is_dear(idx)) {
		printf("EAR      : Data (%s)\n",
			pfm_ita2_is_dear_tlb(idx) ?
				"TLB Mode": (pfm_ita2_is_dear_alat(idx) ? "ALAT Mode": "Cache Mode"));
	} else if (pfm_ita2_is_iear(idx)) {
		printf("EAR      : Code (%s)\n",
			pfm_ita2_is_iear_tlb(idx) ?
				"TLB Mode": "Cache Mode");
	} else
		puts("EAR      : None");

	printf("BTB      : %s\n", pfm_ita2_is_btb(idx) ? "Yes" : "No");

	if (maxincr > 1)
		printf("MaxIncr  : %u  (Threshold [0-%u])\n", maxincr,  maxincr-1);
 	else
		printf("MaxIncr  : %u  (Threshold 0)\n", maxincr);

	printf("Qual     : ");

	if (pfm_ita2_support_opcm(idx)) {
		printf("[Opcode Match] ");
		n++;
	}

	if (pfm_ita2_support_iarr(idx)) {
		printf("[Instruction Address Range] ");
		n++;
	}

	if (pfm_ita2_support_darr(idx)) {
		printf("[Data Address Range] ");
		n++;
	}

	if (n == 0)
		puts("None");
	else
		putchar('\n');

	pfm_ita2_get_event_group(idx, &grp);
	pfm_ita2_get_event_set(idx, &set);

	switch(grp) {
		case PFMLIB_ITA2_EVT_NO_GRP:
			puts("Group    : None");
			break;
		case PFMLIB_ITA2_EVT_L1_CACHE_GRP:
			puts("Group    : L1D Cache");
			break;
		case PFMLIB_ITA2_EVT_L2_CACHE_GRP:
			puts("Group    : L2 Cache");
			break;
		default:
			puts("unknown");
	}
	if (set == PFMLIB_ITA2_EVT_NO_SET)
		puts("Set      : None");
	else
		printf("Set      : %d\n", set);
}

pfmon_support_t pfmon_itanium2={
	.name				="Itanium2",
	.pmu_type			= PFMLIB_ITANIUM2_PMU,
	.generic_pmu_type		= PFMLIB_GEN_IA64_PMU,
	.pfmon_initialize		= pfmon_ita2_initialize,		
	.pfmon_usage			= pfmon_ita2_usage,	
	.pfmon_parse_options		= pfmon_ita2_parse_options,
	.pfmon_setup			= pfmon_ita2_setup,
	.pfmon_prepare_registers	= pfmon_ita2_prepare_registers,
	.pfmon_install_pmc_registers	= pfmon_ita2_install_pmc_registers,
	.pfmon_install_pmd_registers	= pfmon_ita2_install_pmd_registers,
	.pfmon_print_header		= pfmon_ita2_print_header,
	.pfmon_detailed_event_name	= pfmon_ita2_detailed_event_name,
	.pfmon_setup_ctx_flags		= pfmon_ita2_setup_ctx_flags,
	.pfmon_verify_event_sets	= pfmon_ita2_verify_event_sets,
	.pfmon_verify_cmdline		= pfmon_ita2_verify_cmdline,
	.pfmon_show_event_info		= pfmon_ita2_show_event_info,
	.sz_mod_args			= sizeof(pfmon_ita2_args_t),
	.sz_mod_inp			= sizeof(pfmlib_ita2_input_param_t),
	.sz_mod_outp			= sizeof(pfmlib_ita2_output_param_t)
};
