/*
 * pfmon_montecito.c - Dual-core Itanium 2 PMU support for pfmon
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
#include "pfmon.h"

#include <ctype.h>
#include <limits.h>

#include "pfmon_montecito.h"

#define DEAR_REGS_MASK		(M_PMD(32)|M_PMD(33)|M_PMD(36))
#define DEAR_ALAT_REGS_MASK	(M_PMD(33)|M_PMD(36))
#define IEAR_REGS_MASK		(M_PMD(34)|M_PMD(35))
#define ETB_REGS_MASK		(M_PMD(38)| M_PMD(39)| \
		                 M_PMD(48)|M_PMD(49)|M_PMD(50)|M_PMD(51)|M_PMD(52)|M_PMD(53)|M_PMD(54)|M_PMD(55)|\
				 M_PMD(56)|M_PMD(57)|M_PMD(58)|M_PMD(59)|M_PMD(60)|M_PMD(61)|M_PMD(62)|M_PMD(63))

#define PFMON_MONT_MAX_IBRS	8
#define PFMON_MONT_MAX_DBRS	8

static pfmon_mont_options_t pfmon_mont_opt;	/* keep track of global program options */

static void
pfmon_mont_setup_thresholds(pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	pfmon_mont_args_t *args;
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
		for (i=0; i < set->event_count; i++) param->pfp_mont_counters[i].thres = 0;
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
		pfm_mont_get_event_maxincr(set->inp.pfp_events[cnt].event, &maxincr);
		if (thres > (maxincr-1)) goto too_big;

		param->pfp_mont_counters[cnt++].thres = thres;

		thres_str = p;
	}
	return;
too_big:
	fatal_error("event %d: threshold must be in [0-%d)\n", cnt, maxincr);
too_many:
	fatal_error("too many thresholds specified\n");
}

static char *retired_events[]={
	"IA64_TAGGED_INST_RETIRED_IBRP0_PMC32",
	"IA64_TAGGED_INST_RETIRED_IBRP1_PMC33",
	"IA64_TAGGED_INST_RETIRED_IBRP2_PMC32",
	"IA64_TAGGED_INST_RETIRED_IBRP3_PMC33",
	NULL
};

static void
check_ibrp_events(pfmon_event_set_t *set)
{
	pfmlib_mont_output_param_t *param = set->mod_outp;
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
	incr = pfm_mont_irange_is_fine(&set->outp, param) ? 4 : 2;

	for (i=0; retired_events[i]; i++) {
		pfm_find_event(retired_events[i], &idx);
		pfm_mont_get_event_umask(idx, umasks_retired+i);
	}

	pfm_get_event_code(idx, &retired_code);

	/*
	 * print a warning message when the using IA64_TAGGED_INST_RETIRED_IBRP* which does
	 * not completely cover the all the debug register pairs used to make up the range.
	 * This could otherwise lead to misinterpretation of the results.
	 */
	for (i=0; i < param->pfp_mont_irange.rr_nbr_used; i+= incr) {

		ibrp = param->pfp_mont_irange.rr_br[i].reg_num >>1;

		seen_retired = 0;
		for(j=0; j < set->event_count; j++) {
			pfm_get_event_code(set->inp.pfp_events[j].event, &code);
			if (code != retired_code) continue;
			seen_retired = 1;
			pfm_mont_get_event_umask(set->inp.pfp_events[j].event, &umask);
			if (umask == umasks_retired[ibrp]) break;
		}
		if (seen_retired && j == set->event_count)
			warning("warning: code range uses IBR pair %d which is not monitored using %s\n", ibrp, retired_events[ibrp]);
	}
}

static int
install_irange(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_mont_output_param_t *param = set->mod_outp;
	pfarg_pmc_t dbreg[PFMON_MONT_MAX_IBRS];
	unsigned int i, used_dbr;
	int r, error;

	check_ibrp_events(set);

	memset(dbreg, 0, sizeof(dbreg));

	used_dbr = param->pfp_mont_irange.rr_nbr_used;

	for(i=0; i < used_dbr; i++) {
		dbreg[i].reg_num   = 256+param->pfp_mont_irange.rr_br[i].reg_num; 
		dbreg[i].reg_set   = set->id;
		dbreg[i].reg_value = param->pfp_mont_irange.rr_br[i].reg_value; 
	}

	r = pfmon_write_ibrs(sdesc->ctxid, dbreg, used_dbr, &error);
	if (r == -1)
		warning("cannot install code range restriction: %s\n", strerror(error));
	return r;
}

static int
install_drange(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_mont_output_param_t *param = set->mod_outp;
	pfarg_pmc_t dbreg[PFMON_MONT_MAX_DBRS];
	unsigned int i, used_dbr;
	int r, error;

	memset(dbreg, 0, sizeof(dbreg));

	used_dbr = param->pfp_mont_drange.rr_nbr_used;

	for(i=0; i < used_dbr; i++) {
		dbreg[i].reg_num   = 264+param->pfp_mont_drange.rr_br[i].reg_num; 
		dbreg[i].reg_set   = set->id;
		dbreg[i].reg_value = param->pfp_mont_drange.rr_br[i].reg_value; 
	}

	r = pfmon_write_dbrs(sdesc->ctxid, dbreg, used_dbr, &error);
	if (r == -1)
		warning("cannot install data range restriction: %s\n", strerror(error));

	return r;
}

static int
install_etb(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	/* 
	 * we do not really need to clear PMD38, because the kernel 
	 * clears pmd38 for each newly created context
	 */
	return 0;
}

static int
install_iears(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	/* 
	 * we do not really need to clear PMD34, because the kernel 
	 * clears pmd34 for each newly created context
	 */
	return 0;
}

static int
prepare_etb(pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	unsigned int i;
	int found_etb = -1;

	for(i=0; i < set->event_count; i++) {
		if (pfm_mont_is_etb(set->inp.pfp_events[i].event)) {
			found_etb = i;
			goto found;
		}
	}
	/*
	 * check for no BTB event, but just BTB options.
	 */
	if (param->pfp_mont_etb.etb_used == 0) return 0;
found:
	/*
	 * in case of no BTB event found OR BTB event does not have a sampling period, 
	 * we are in free running mode (no BTB sampling) therefore we include the BTB 
	 * PMD in all samples
	 */
	if (found_etb != -1 && (set->short_rates[i].flags & PFMON_RATE_VAL_SET)) {
		set->smpl_pmds[i][0]  |=  ETB_REGS_MASK;
		set->common_reset_pmds[0] |=  M_PMD(38);
	} else {
		set->common_smpl_pmds[0]  |=  ETB_REGS_MASK;
		set->common_reset_pmds[0] |=  ETB_REGS_MASK;
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
		if (pfm_mont_is_ear(ev) == 0) continue;

		is_iear = pfm_mont_is_iear(ev);

		/*
		 * when used as sampling period, then just setup the bitmask
		 * of PMDs to record in each sample
		 */
		if (set->short_rates[i].flags & PFMON_RATE_VAL_SET) {
			if (is_iear) {
				set->smpl_pmds[i][0]  |=  IEAR_REGS_MASK;
				set->common_reset_pmds[0] |= M_PMD(34);
			} else {
				set->smpl_pmds[i][0]  |=  pfm_mont_is_dear_alat(ev) ? DEAR_ALAT_REGS_MASK : DEAR_REGS_MASK;
			}
			continue;
		}

		/*
		 * for D-EAR, we must clear PMD33.stat and PMD36.vl to make
		 * sure we do not interpret the register in the wrong manner.
		 *
		 * for I-EAR, we must clear PMD34.stat to avoid interpreting stale
		 * entries
		 *
		 * This is ONLY necessary when the events are not used as sampling
		 * periods.
		 */
		if (is_iear) {
			set->common_reset_pmds[0] |= M_PMD(34);
			set->common_smpl_pmds[0]  |= IEAR_REGS_MASK;
		} else {
			set->common_reset_pmds[0] |= M_PMD(33);

			/* DEAR-ALAT only needs to clear PMD33 */
			if (pfm_mont_is_dear_alat(ev) == 0) {
				set->common_reset_pmds[0] |= M_PMD(36);
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
pfmon_mont_prepare_registers(pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	int r = 0;
	
	if (param == NULL) return 0;

	if (param->pfp_mont_etb.etb_used) r = prepare_etb(set);

	if (r == 0) r = prepare_ears(set);

	return r;
}

static int
pfmon_mont_install_pmc_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	int r = 0;

	if (param == NULL) return 0;

	if (param->pfp_mont_irange.rr_used) r = install_irange(sdesc, set);

	if (r == 0 && param->pfp_mont_drange.rr_used) r = install_drange(sdesc, set);

	return r;
}

static int
pfmon_mont_install_pmd_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	int r = 0;

	if (param == NULL) return 0;

	if (r == 0 && param->pfp_mont_iear.ear_used) install_iears(sdesc, set);

	if (r == 0 && param->pfp_mont_etb.etb_used) install_etb(sdesc, set);

	return r;
}

static void
pfmon_mont_usage(void)
{
	printf( "--event-thresholds=thr1,thr2,...\tSet event thresholds (no space).\n"
		"--opc-match32=mifb:match:mask\t\tSet opcode match for pmc32.\n"
		"--opc-match34=mifb:match:mask\t\tSet opcode match for pmc34.\n"
		"--etb-tm-tk\t\t\t\tCapture taken IA-64 branches only.\n"
		"--etb-tm-ntk\t\t\t\tCapture not taken IA-64 branches only.\n"
		"--etb-ptm-correct\t\t\tCapture branch if target predicted\n"
		"\t\t\t\t\tcorrectly.\n"
		"--etb-ptm-incorrect\t\t\tCapture branch if target is\n"
		"\t\t\t\t\tmispredicted.\n"
		"--etb-ppm-correct\t\t\tCapture branch if path is predicted\n"
		"\t\t\t\t\tcorrectly.\n"
		"--etb-ppm-incorrect\t\t\tCapture branch if path is mispredicted.\n"
		"--etb-brt-iprel\t\t\t\tCapture IP-relative branches only.\n"
		"--etb-brt-ret\t\t\t\tCapture return branches only.\n"
		"--etb-brt-ind\t\t\t\tCapture non-return indirect branches\n"
		"\t\t\t\t\tonly.\n"
		"--irange=start-end\t\t\tSpecify an instruction address range\n"
		"\t\t\t\t\tconstraint.\n"
		"--drange=start-end\t\t\tSpecify a data address range constraint.\n"
		"--checkpoint-func=addr\t\t\tA bundle address to use as checkpoint.\n"
		"--inverse-irange\t\t\tInverse instruction range restriction.\n"
		"--no-qual-check\t\t\t\tDo not check qualifier constraints on\n"
		"\t\t\t\t\tevents.\n"
		"--insecure\t\t\t\tAllow rum/sum in monitored task\n"
		"\t\t\t\t\t(per-thread mode only).\n"
		"--exclude-idle\t\t\t\tDo not stop monitoring in the idle loop\n"
		"\t\t\t\t\t(default: off)\n"
		"--excl-intr\t\t\t\tExclude interrupt-triggered execution\n"
		"\t\t\t\t\tfrom system-wide measurement.\n"
		"--intr-only\t\t\t\tInclude only interrupt-triggered\n"
		"\t\t\t\t\texecution from system-wide measurement.\n"
		"--irange-demand-fetch\t\t\tLimit irange to demand fetched cache\n"
		"\t\t\t\t\tlines for specific prefetch events.\n"
		"--irange-prefetch-match\t\t\tLimit irange to explicitly prefetched\n"
		"\t\t\t\t\tcache lines for specific prefetch\n"
		"\t\t\t\t\tevents.\n"
	);
}

static void
pfmon_mont_setup_ears(pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	unsigned int i, done_iear = 0, done_dear = 0;
	pfmlib_mont_ear_mode_t dear_mode, iear_mode;
	unsigned int ev;

	for (i=0; i < set->event_count; i++) {

		ev = set->inp.pfp_events[i].event;

		if (pfm_mont_is_ear(ev) == 0) continue;

		if (pfm_mont_is_dear(ev)) {

			if (done_dear) {
				fatal_error("cannot specify more than one D-EAR event at the same time\n");
			}

			pfm_mont_get_ear_mode(ev, &dear_mode);

			param->pfp_mont_dear.ear_used   = 1;
			param->pfp_mont_dear.ear_mode   = dear_mode;
			param->pfp_mont_dear.ear_plm    = set->inp.pfp_events[i].plm; /* use plm from event */
			pfm_mont_get_event_umask(ev, &param->pfp_mont_dear.ear_umask);
			
			done_dear = 1;

			continue;
		}

		if (pfm_mont_is_iear(ev)) {

			if (done_iear) {
				fatal_error("cannot specify more than one D-EAR event at the same time\n");
			}

			pfm_mont_get_ear_mode(ev, &iear_mode);

			param->pfp_mont_iear.ear_used   = 1;
			param->pfp_mont_iear.ear_mode   = iear_mode;
			param->pfp_mont_iear.ear_plm    = set->inp.pfp_events[i].plm; /* use plm from event */
			pfm_mont_get_event_umask(ev, &param->pfp_mont_iear.ear_umask);

			done_iear = 1;
		}
	}	
}

static void
pfmon_mont_setup_etb(pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	pfmon_mont_args_t *mont_args;
	unsigned int i, ev;
	int found_alat = 0, found_etb = -1, found_dear = 0;

	mont_args = set->mod_args;

	for (i=0; i < set->event_count; i++) {
		ev = set->inp.pfp_events[i].event;
		if (found_etb == -1 && pfm_mont_is_etb(ev)) found_etb = i;
		if (pfm_mont_is_dear_alat(ev)) found_alat = 1;
		if (pfm_mont_is_dear_tlb(ev)) found_dear = 1;
	}

	/*
	 * no BTB event, no BTB specific options: BTB is not used
	 */
	if (found_etb == -1 &&
           !mont_args->opt_etb_tm &&
           !mont_args->opt_etb_ptm &&
           !mont_args->opt_etb_ppm &&
           !mont_args->opt_etb_brt) {
		return;
	}

	/*
	 * PMC39 must be zero when D-EAR ALAT is configured
	 * The library does the check but here we can print a more detailed error message
	 */
	if (found_etb != -1 && found_alat) fatal_error("cannot use ETB and D-EAR ALAT at the same time\n");
	if (found_etb != -1 && found_dear) fatal_error("cannot use ETB and D-EAR TLB at the same time\n");
	if (found_etb != -1 && found_dear) fatal_error("cannot use ETB and D-EAR TLB at the same time\n");

	/*
	 * set the use bit, such that the library will program PMC12
	 */
	param->pfp_mont_etb.etb_used = 1;

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
	param->pfp_mont_etb.etb_tm  = 0x3;
	param->pfp_mont_etb.etb_ptm = 0x3;
	param->pfp_mont_etb.etb_ppm = 0x3;
	param->pfp_mont_etb.etb_brt = 0x0;
	param->pfp_mont_etb.etb_plm = set->inp.pfp_events[i].plm; /* use the plm from the ETB event */

	if (mont_args->opt_etb_tm)  param->pfp_mont_etb.etb_tm  = mont_args->opt_etb_tm  & 0x3;
	if (mont_args->opt_etb_ptm) param->pfp_mont_etb.etb_ptm = mont_args->opt_etb_ptm & 0x3;
	if (mont_args->opt_etb_ppm) param->pfp_mont_etb.etb_ppm = mont_args->opt_etb_ppm & 0x3;
	if (mont_args->opt_etb_brt) param->pfp_mont_etb.etb_brt = mont_args->opt_etb_brt & 0x3;

	vbprintf("etb options: ds=0 tm=%d ptm=%d ppm=%d brt=%d\n",
		param->pfp_mont_etb.etb_tm,
		param->pfp_mont_etb.etb_ptm,
		param->pfp_mont_etb.etb_ppm,
		param->pfp_mont_etb.etb_brt);
}

/*
 * Montecito-specific options
 *
 * 000-255   reserved for generic options
 * 400-499   reserved for PMU specific options
 * 500-599   reserved for format specific options
 */
static struct option cmd_mont_options[]={
	{ "event-thresholds", 1, 0, 400 },
	{ "opc-match32", 1, 0, 401},
	{ "opc-match34", 1, 0, 402},
	/* 403 available */
	{ "checkpoint-func", 1, 0, 404},
	{ "irange", 1, 0, 405},
	{ "drange", 1, 0, 406},
	/*
	 * 407, 408, 409 are available
	 */
	{ "etb-tm-tk", 0, 0, 411},
	{ "etb-tm-ntk", 0, 0, 412}, 
	{ "etb-ptm-correct", 0, 0, 413},
	{ "etb-ptm-incorrect", 0, 0, 414}, 
	{ "etb-ppm-correct", 0, 0, 415},
	{ "etb-ppm-incorrect", 0, 0, 416}, 
	{ "etb-brt-iprel", 0,  0, 417}, 
	{ "etb-brt-ret", 0, 0, 418}, 
	{ "etb-brt-ind", 0, 0, 419},
	{ "excl-intr", 0, 0, 420},
	{ "intr-only", 0, 0, 421},
	{ "exclude-idle", 0, 0, 422 },
	{ "inverse-irange", 0, &pfmon_mont_opt.opt_inv_rr, 1},
	{ "no-qual-check", 0, &pfmon_mont_opt.opt_no_qual_check, 0x1},
	{ "insecure", 0, &pfmon_mont_opt.opt_insecure, 0x1},
	{ "irange-demand-fetch", 0, &pfmon_mont_opt.opt_demand_fetch, 0x1},
	{ "irange-prefetch-match", 0, &pfmon_mont_opt.opt_fetch_match, 0x1},
	{ 0, 0, 0, 0}
};

static int
pfmon_mont_initialize(void)
{
	int r;

	r = pfmon_register_options(cmd_mont_options, sizeof(cmd_mont_options));
	if (r == -1) return -1;

	/* connect pfmon model specific options */
	options.model_options = &pfmon_mont_opt;

	return 0;
}

/*
 * 0  means we understood the option
 * -1 unknown option
 */
static int
pfmon_mont_parse_options(int code, char *optarg)
{
	pfmon_mont_args_t *mont_args;
	pfmon_event_set_t *set;

	set = options.last_set;

	mont_args = set->mod_args;

	switch(code) {
		case  400:
			if (mont_args->threshold_arg) fatal_error("thresholds already defined\n");
			mont_args->threshold_arg = optarg;
			break;
		case  401:
			if (mont_args->opcm32_arg) fatal_error("opcode matcher pmc32 is specified twice\n");
			mont_args->opcm32_arg = optarg;
			break;
		case  402:
			if (mont_args->opcm34_arg) fatal_error("opcode matcher pmc34 is specified twice\n");
			mont_args->opcm34_arg = optarg;
			break;
		case  404:
			if (pfmon_mont_opt.irange_arg) {
				fatal_error("cannot use checkpoints and instruction range at the same time\n");
			}
			if (pfmon_mont_opt.chkp_func_arg) {
				fatal_error("checkpoint already  defined for %s\n", pfmon_mont_opt.chkp_func_arg);
			}
			pfmon_mont_opt.chkp_func_arg = optarg;
			break;

		case  405:
			if (pfmon_mont_opt.chkp_func_arg) {
				fatal_error("cannot use instruction range and checkpoints at the same time\n");
			}
			if (pfmon_mont_opt.irange_arg) {
				fatal_error("cannot specify more than one instruction range\n");
			}
			pfmon_mont_opt.irange_arg = optarg;
			break;
		case  406:
			if (pfmon_mont_opt.drange_arg) {
				fatal_error("cannot specify more than one data range\n");
			}
			pfmon_mont_opt.drange_arg = optarg;
			break;
		case 411:
			mont_args->opt_etb_tm = 0x2;
			break;
		case 412:
			mont_args->opt_etb_tm = 0x1;
			break;
		case 413:
			mont_args->opt_etb_ptm = 0x2;
			break;
		case 414:
			mont_args->opt_etb_ptm = 0x1;
			break;
		case 415:
			mont_args->opt_etb_ppm = 0x2;
			break;
		case 416:
			mont_args->opt_etb_ppm = 0x1;
			break;
		case 417:
			mont_args->opt_etb_brt = 0x1;
			break;
		case 418:
			mont_args->opt_etb_brt = 0x2;
			break;
		case 419:
			mont_args->opt_etb_brt = 0x3;
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
pfmon_mont_parse_opcm(char *str, unsigned long*mifb, unsigned long *match, unsigned long *mask)
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
pfmon_mont_setup_opcm(pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	pfmon_mont_args_t *mont_args;
	unsigned long mifb;

	mont_args = set->mod_args;

	if (mont_args->opcm32_arg) {
		param->pfp_mont_opcm1.opcm_used = 1;

		pfmon_mont_parse_opcm(mont_args->opcm32_arg,
				      &mifb,
				      &param->pfp_mont_opcm1.opcm_match,
				      &param->pfp_mont_opcm1.opcm_mask);

		param->pfp_mont_opcm1.opcm_b = mifb & 0x1 ? 1 : 0;
		param->pfp_mont_opcm1.opcm_f = mifb & 0x2 ? 1 : 0;
		param->pfp_mont_opcm1.opcm_i = mifb & 0x4 ? 1 : 0;
		param->pfp_mont_opcm1.opcm_m = mifb & 0x8 ? 1 : 0;
	}


	if (mont_args->opcm34_arg) {
		param->pfp_mont_opcm2.opcm_used = 1;

		pfmon_mont_parse_opcm(mont_args->opcm34_arg,
				      &mifb,
				      &param->pfp_mont_opcm2.opcm_match,
				      &param->pfp_mont_opcm2.opcm_mask);

		param->pfp_mont_opcm2.opcm_b = mifb & 0x1 ? 1 : 0;
		param->pfp_mont_opcm2.opcm_f = mifb & 0x2 ? 1 : 0;
		param->pfp_mont_opcm2.opcm_i = mifb & 0x4 ? 1 : 0;
		param->pfp_mont_opcm2.opcm_m = mifb & 0x8 ? 1 : 0;
	}
}

static void
pfmon_mont_setup_rr(pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	pfmon_mont_args_t *mont_args;
	uintptr_t start, end;

	mont_args = set->mod_args;

	/*
	 * we cannot have function checkpoint and irange
	 */
	if (pfmon_mont_opt.chkp_func_arg) {
		if (set->priv_lvl_str)
			fatal_error("cannot use both a checkpoint function and per-event privilege level masks\n");

		gen_code_range(pfmon_mont_opt.chkp_func_arg, &start, &end);

		/* just one bundle for this one */
		end = start + 0x10;

		vbprintf("checkpoint function at %p\n", start);

	} else if (pfmon_mont_opt.irange_arg) {

		if (set->priv_lvl_str)
			fatal_error("cannot use both a code range function and per-event privilege level masks\n");

		gen_code_range(pfmon_mont_opt.irange_arg, &start, &end); 

		if ((unsigned long)start & 0xf) fatal_error("code range does not start on bundle boundary : %p\n", start);
		if ((unsigned long)end & 0xf) fatal_error("code range does not end on bundle boundary : %p\n", end);

		vbprintf("irange is [%p-%p)=%ld bytes\n", start, end, end-start);
	}

	/*
	 * now finalize irange/chkp programming of the range
	 */
	if (pfmon_mont_opt.irange_arg || pfmon_mont_opt.chkp_func_arg) { 

		/*
		 * inverse range should be per set!
		 */
		param->pfp_mont_irange.rr_used   = 1;
		param->pfp_mont_irange.rr_flags |= pfmon_mont_opt.opt_inv_rr ? PFMLIB_MONT_RR_INV : 0;

		/*
		 * Fine mode does not work for small ranges (less than
		 * 2 bundles), so we force non-fine mode to work around the problem
		 */
		if (pfmon_mont_opt.chkp_func_arg)
			param->pfp_mont_irange.rr_flags |= PFMLIB_MONT_RR_NO_FINE_MODE;

		if (pfmon_mont_opt.opt_demand_fetch)
			param->pfp_mont_irange.rr_flags |= PFMLIB_MONT_IRR_DEMAND_FETCH;

		if (pfmon_mont_opt.opt_fetch_match)
			param->pfp_mont_irange.rr_flags |= PFMLIB_MONT_IRR_PREFETCH_MATCH;

		param->pfp_mont_irange.rr_limits[0].rr_start = (unsigned long)start;
		param->pfp_mont_irange.rr_limits[0].rr_end   = (unsigned long)end;
		param->pfp_mont_irange.rr_limits[0].rr_plm   = set->inp.pfp_dfl_plm; /* use default */
	}
	
	if (pfmon_mont_opt.drange_arg) {
		if (set->priv_lvl_str)
			fatal_error("cannot use both a data range and  per-event privilege level masks\n");

		gen_data_range(pfmon_mont_opt.drange_arg, &start, &end);

		vbprintf("drange is [%p-%p)=%lu bytes\n", start, end, end-start);
		
		param->pfp_mont_drange.rr_used = 1;

		param->pfp_mont_drange.rr_limits[0].rr_start = (unsigned long)start;
		param->pfp_mont_drange.rr_limits[0].rr_end   = (unsigned long)end;
		param->pfp_mont_drange.rr_limits[0].rr_plm   = set->inp.pfp_dfl_plm; /* use default */
	}
}

/*
 * It is not possible to measure more than one of the
 * L2D_OZQ_CANCELS0_* OR L2D_OZQ_CANCELS1_* events
 * at the same time.
 */
static char *cancel_events[]=
{
	"L2D_OZQ_CANCELS0_ACQ",
	"L2D_OZQ_CANCELS1_ANY"
};
#define NCANCEL_EVENTS	sizeof(cancel_events)/sizeof(char *)

static void
check_cancel_events(pfmon_event_set_t *set)
{
	unsigned int i, j, tmp;
	int code, seen_first = 0, ret;
	int cancel_codes[NCANCEL_EVENTS];
	unsigned int idx = 0;
	char *name1, *name2;

	name1 = options.ev_name1;
	name2 = options.ev_name2;

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
					pfm_get_event_name(idx, name1, options.max_event_name_len+1);
					pfm_get_event_name(set->inp.pfp_events[i].event, name2, options.max_event_name_len+1);
					fatal_error("%s and %s cannot be measured at the same time\n", name1, name2);
				}
				idx = set->inp.pfp_events[i].event;
				seen_first = 1;
			}
		}
	}
}

static void
check_cross_groups(pfmon_event_set_t *set)
{
	int s, s1, s2;
	int g1, g2;
	pfmlib_event_t *e= set->inp.pfp_events;
	unsigned int cnt = set->event_count;
	unsigned int i, j;

	/*
	 * Let check the L1D constraint first
	 *
	 * There is no umask restriction for this group
	 */
	for (i=0; i < cnt; i++) {
		pfm_mont_get_event_group(e[i].event, &g1);
		pfm_mont_get_event_set(e[i].event, &s1);

		if (g1 != PFMLIB_MONT_EVT_L1D_CACHE_GRP) continue;

		for (j=i+1; j < cnt; j++) {
			pfm_mont_get_event_group(e[j].event, &g2);
			if (g2 != g1) continue;
			/*
			 * if there is another event from the same group
			 * but with a different set, then we return an error
			 */
			pfm_mont_get_event_set(e[j].event, &s2);
			if (s2 != s1) goto error;
		}
	}

	/*
	 * Check that we have only up to two distinct 
	 * sets for L2D
	 */
	s1 = s2 = -1;
	for (i=0; i < cnt; i++) {
		pfm_mont_get_event_group(e[i].event, &g1);

		if (g1 != PFMLIB_MONT_EVT_L2D_CACHE_GRP) continue;

		pfm_mont_get_event_set(e[i].event, &s);

		/*
		 * we have seen this set before, continue
		 */
		if (s1 == s || s2 == s) continue;

		/*
		 * record first of second set seen
		 */
		if (s1 == -1) {
			s1 = s;
		} else if (s2 == -1) {
			s2 = s;
		} else {
			goto error2;
		}
	}
	return;
error:
	pfm_get_event_name(e[i].event, options.ev_name1, options.max_event_name_len+1);
	pfm_get_event_name(e[j].event, options.ev_name2, options.max_event_name_len+1);
	fatal_error("event %s and %s cannot be measured at the same time\n", options.ev_name1, options.ev_name2);
error2:
	fatal_error("you are using more L2D events from more than two sets at the same time\n");
}

static void 
check_counter_conflict(pfmon_event_set_t *set)
{
	pfmlib_event_t *e = set->inp.pfp_events;
	pfmlib_regmask_t cnt1, cnt2, all_counters;
	unsigned int weight;
	unsigned int cnt = set->event_count;
	unsigned int i, j;

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
	pfm_get_event_name(e[i].event, options.ev_name1, options.max_event_name_len+1);
	pfm_get_event_name(e[j].event, options.ev_name2, options.max_event_name_len+1);
	fatal_error("event %s and %s cannot be measured at the same time, trying using"
		    " different event sets\n",
		    options.ev_name1,
		    options.ev_name2);
}

static void
check_mont_event_combinations(pfmon_event_set_t *set)
{
	unsigned int i, use_opcm, inst_retired_idx, ev;
	int code, inst_retired_code;
	pfmlib_mont_input_param_t *param = set->mod_inp;
	pfmon_mont_args_t *mont_args;
	char *name;

	mont_args = set->mod_args;

	/*
	 * here we repeat some of the tests done by the library
	 * to provide more detailed feedback (printf()) to the user.
	 *
	 * XXX: not all tests are duplicated, so we will not get detailed
	 * error reporting for all possible cases.
	 */
	check_counter_conflict(set);
	check_cancel_events(set);
	check_cross_groups(set);

	use_opcm = param->pfp_mont_opcm1.opcm_used || param->pfp_mont_opcm2.opcm_used; 

	pfm_find_event("IA64_INST_RETIRED", &inst_retired_idx);
	pfm_get_event_code(inst_retired_idx, &inst_retired_code);

	name = options.ev_name1;

	for (i=0; i < set->event_count; i++) {

		ev = set->inp.pfp_events[i].event;

		pfm_get_event_name(ev, name, options.max_event_name_len+1);
		pfm_get_event_code(ev, &code);

		if (use_opcm && pfm_mont_support_opcm(ev) == 0)
			fatal_error("event %s does not support opcode matching\n", name);

		if (param->pfp_mont_irange.rr_used && pfm_mont_support_iarr(ev) == 0)
			fatal_error("event %s does not support instruction address range restrictions\n", name);

		if (param->pfp_mont_drange.rr_used && pfm_mont_support_darr(ev) == 0)
			fatal_error("event %s does not support data address range restrictions\n", name);
	}
}

static void
pfmon_mont_no_qual_check(pfmon_event_set_t *set)
{
	pfmlib_mont_input_param_t *param = set->mod_inp;
	unsigned int i;

	/*
	 * set the "do not check constraint" flags for all events 
	 */
	for (i=0; i < set->event_count; i++) {
		param->pfp_mont_counters[i].flags |= PFMLIB_MONT_FL_EVT_NO_QUALCHECK;
	}
}

static int
pfmon_mont_setup(pfmon_event_set_t *set)
{
	pfmon_mont_args_t *mont_args;

	mont_args = set->mod_args;

	if (mont_args == NULL) return 0;
	
	if (options.code_trigger_start || options.code_trigger_stop || options.data_trigger_start || options.data_trigger_stop) {
		if (pfmon_mont_opt.irange_arg)
			fatal_error("cannot use a trigger address with instruction range restrictions\n");
		if (pfmon_mont_opt.drange_arg)
			fatal_error("cannot use a trigger address with data range restrictions\n");
		if (pfmon_mont_opt.chkp_func_arg)
			fatal_error("cannot use a trigger address with function checkpoint\n");
	}
	pfmon_mont_setup_rr(set);
	pfmon_mont_setup_opcm(set);
	pfmon_mont_setup_etb(set);
	pfmon_mont_setup_ears(set);

	/* 
	 * we systematically initialize thresholds to their minimal value
	 * or requested value
	 */
	pfmon_mont_setup_thresholds(set);

	if (pfmon_mont_opt.opt_no_qual_check) 
		pfmon_mont_no_qual_check(set);
	else
		check_mont_event_combinations(set);

	return 0;
}

static int
pfmon_mont_print_header(FILE *fp)
{
	fprintf(fp, "#\n#\n# instruction set : ia64\n");
	return 0;
}

static void
pfmon_mont_detailed_event_name(unsigned int evt)
{
	unsigned long umask;
	unsigned int maxincr;
	char *grp_str;
	int grp, set, type;

	pfm_mont_get_event_umask(evt, &umask);
	pfm_mont_get_event_maxincr(evt, &maxincr);
	pfm_mont_get_event_group(evt, &grp);
	pfm_mont_get_event_type(evt, &type);

	printf("type=%c umask=0x%02lx incr=%u iarr=%c darr=%c opcm=%c ", 
		type == PFMLIB_MONT_EVT_ACTIVE ?
			'A' :
			(type == PFMLIB_MONT_EVT_FLOATING ? 'F' :
			 type == PFMLIB_MONT_EVT_CAUSAL ? 'C' : 'S'),
		umask, 
		maxincr,
		pfm_mont_support_iarr(evt) ? 'Y' : 'N',
		pfm_mont_support_darr(evt) ? 'Y' : 'N',
		pfm_mont_support_opcm(evt) ? 'Y' : 'N');

	if (grp != PFMLIB_MONT_EVT_NO_GRP) {
		pfm_mont_get_event_set(evt, &set);
		grp_str = grp == PFMLIB_MONT_EVT_L1D_CACHE_GRP ? "l1_cache" : "l2_cache";

		printf("grp=%s set=%d", grp_str, set);
	}
}

static int
pfmon_mont_setup_ctx_flags(pfmon_ctx_t *ctx)
{
	if (pfmon_mont_opt.opt_insecure) {
		if (options.opt_syst_wide) {
			warning("option --insecure does not support system-wide mode\n");
			return -1;
		}
		ctx->ctx_flags |= PFM_ITA_FL_INSECURE;
	}
	return 0;
}

static void
pfmon_mont_verify_event_sets(void)
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
pfmon_mont_verify_cmdline(int argc, char **argv)
{
	if (pfmon_mont_opt.opt_insecure && options.opt_is22 == 0)
		fatal_error("the --insecure option requires at least perfmon v2.2\n");
}

static void
pfmon_mont_show_event_info(unsigned int idx)
{
	unsigned long umask;
	unsigned int maxincr;
	int grp, set, n = 0, type;
	char *str;

	pfm_mont_get_event_umask(idx, &umask);
	pfm_mont_get_event_maxincr(idx, &maxincr);

	printf("Umask    : 0x%lx\n", umask);

	if (pfm_mont_is_dear(idx)) {
		printf("EAR      : Data (%s)\n",
			pfm_mont_is_dear_tlb(idx) ?
				"TLB Mode": (pfm_mont_is_dear_alat(idx) ? "ALAT Mode": "Cache Mode"));
	} else if (pfm_mont_is_iear(idx)) {
		printf("EAR      : Code (%s)\n",
			pfm_mont_is_iear_tlb(idx) ?
				"TLB Mode": "Cache Mode");
	} else
		puts("EAR      : None");

	printf("ETB      : %s\n", pfm_mont_is_etb(idx) ? "Yes" : "No");

	if (maxincr > 1)
		printf("MaxIncr  : %u  (Threshold [0-%u])\n", maxincr,  maxincr-1);
 	else
		printf("MaxIncr  : %u  (Threshold 0)\n", maxincr);

	printf("Qual     : ");

	if (pfm_mont_support_opcm(idx)) {
		printf("[Opcode Match] ");
		n++;
	}

	if (pfm_mont_support_iarr(idx)) {
		printf("[Instruction Address Range] ");
		n++;
	}

	if (pfm_mont_support_darr(idx)) {
		printf("[Data Address Range] ");
		n++;
	}

	if (n == 0)
		puts("None");
	else
		putchar('\n');

	pfm_mont_get_event_type(idx, &type);
	switch(type) {
		case PFMLIB_MONT_EVT_ACTIVE:
			str = "Active";
			break;
		case PFMLIB_MONT_EVT_FLOATING:
			str = "Floating";
			break;
		case PFMLIB_MONT_EVT_CAUSAL:
			str = "Causal";
			break;
		case PFMLIB_MONT_EVT_SELF_FLOATING:
			str = "Self-Floating";
			break;
		default:
			str = "??";
	}
	printf("Type     : %s\n", str);

	pfm_mont_get_event_group(idx, &grp);
	pfm_mont_get_event_set(idx, &set);

	switch(grp) {
		case PFMLIB_MONT_EVT_NO_GRP:
			puts("Group    : None");
			break;
		case PFMLIB_MONT_EVT_L1D_CACHE_GRP:
			puts("Group    : L1D Cache");
			break;
		case PFMLIB_MONT_EVT_L2D_CACHE_GRP:
			puts("Group    : L2 Cache");
			break;
	}
	if (set == PFMLIB_MONT_EVT_NO_SET)
		puts("Set      : None");
	else
		printf("Set      : %d\n", set);
}

pfmon_support_t pfmon_montecito={
	.name				="dual-core Itanium 2",
	.pmu_type			= PFMLIB_MONTECITO_PMU,
	.generic_pmu_type		= PFMLIB_GEN_IA64_PMU,
	.pfmon_initialize		= pfmon_mont_initialize,		
	.pfmon_usage			= pfmon_mont_usage,	
	.pfmon_parse_options		= pfmon_mont_parse_options,
	.pfmon_setup			= pfmon_mont_setup,
	.pfmon_prepare_registers	= pfmon_mont_prepare_registers,
	.pfmon_install_pmc_registers	= pfmon_mont_install_pmc_registers,
	.pfmon_install_pmd_registers	= pfmon_mont_install_pmd_registers,
	.pfmon_print_header		= pfmon_mont_print_header,
	.pfmon_detailed_event_name	= pfmon_mont_detailed_event_name,
	.pfmon_setup_ctx_flags		= pfmon_mont_setup_ctx_flags,
	.pfmon_verify_event_sets	= pfmon_mont_verify_event_sets,
	.pfmon_verify_cmdline		= pfmon_mont_verify_cmdline,
	.pfmon_show_event_info		= pfmon_mont_show_event_info,
	.sz_mod_args			= sizeof(pfmon_mont_args_t),
	.sz_mod_inp			= sizeof(pfmlib_mont_input_param_t),
	.sz_mod_outp			= sizeof(pfmlib_mont_output_param_t)
};
