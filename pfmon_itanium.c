/*
 * pfmon_itanium.c - Itanium PMU support for pfmon
 *
 * Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
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

#include "pfmon_itanium.h"

#define DEAR_REGS_MASK		(M_PMD(2)|M_PMD(3)|M_PMD(17))
#define IEAR_REGS_MASK		(M_PMD(0)|M_PMD(1))
#define BTB_REGS_MASK		(M_PMD(8)|M_PMD(9)|M_PMD(10)|M_PMD(11)|M_PMD(12)|M_PMD(13)|M_PMD(14)|M_PMD(15)|M_PMD(16))

#define PFMON_ITA_MAX_IBRS	8
#define PFMON_ITA_MAX_DBRS	8

static pfmon_ita_options_t pfmon_ita_opt;	/* keep track of global program options */

static void
pfmon_ita_setup_thresholds(pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	pfmon_ita_args_t *args;
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
		for (i=0; i < set->event_count; i++) param->pfp_ita_counters[i].thres = 0;
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
		pfm_ita_get_event_maxincr(set->inp.pfp_events[cnt].event, &maxincr);
		if (thres > (maxincr-1)) goto too_big;

		param->pfp_ita_counters[cnt++].thres = thres;

		thres_str = p;
	}
	return;
too_big:
	fatal_error("event %d: threshold must be in [0-%d)\n", cnt, maxincr);
too_many:
	fatal_error("too many thresholds specified\n");
}

static int
install_irange(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_ita_output_param_t *param = set->mod_outp;
	pfmon_pmc_t dbreg[PFMON_ITA_MAX_IBRS];
	unsigned int i, used_dbr;
	int r, error;

	memset(dbreg, 0, sizeof(dbreg));

	used_dbr = param->pfp_ita_irange.rr_nbr_used;

	for(i=0; i < used_dbr; i++) {
		dbreg[i].reg_num   = 256+param->pfp_ita_irange.rr_br[i].reg_num; 
		dbreg[i].reg_set   = set->id;
		dbreg[i].reg_value = param->pfp_ita_irange.rr_br[i].reg_value; 
		dbreg[i].reg_flags = 0UL;
	}

	r = pfmon_write_ibrs(sdesc->ctxid, dbreg, used_dbr, &error);
	if (r == -1)
		warning("cannot install code range restriction: %s\n", strerror(error));
	return r;
}

static int
install_drange(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_ita_output_param_t *param = set->mod_outp;
	pfmon_pmc_t dbreg[PFMON_ITA_MAX_DBRS];
	unsigned int i, used_dbr;
	int r, error;

	memset(dbreg, 0, sizeof(dbreg));

	used_dbr = param->pfp_ita_drange.rr_nbr_used;

	for(i=0; i < used_dbr; i++) {
		dbreg[i].reg_num   = 264+param->pfp_ita_drange.rr_br[i].reg_num; 
		dbreg[i].reg_set   = set->id;
		dbreg[i].reg_value = param->pfp_ita_drange.rr_br[i].reg_value; 
		dbreg[i].reg_flags = 0UL;
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
	 * clear pmd16 for each newly created context
	 */
	return 0;
}

static int
prepare_btb(pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	unsigned int i;
	int found_btb = -1;

	for(i=0; i < set->event_count; i++) {
		if (pfm_ita_is_btb(set->inp.pfp_events[i].event)) {
			found_btb = i;
			goto found;
		}
	}
	/*
	 * check for no BTB event, but just BTB options.
	 */
	if (param->pfp_ita_btb.btb_used == 0) return 0;
found:
	/*
	 * in case of no BTB event found, we are in free running mode (no BTB sampling)
	 * therefore we include the BTB PMD in all samples
	 */
	if (found_btb != -1 && (set->short_rates[i].flags & PFMON_RATE_VAL_SET)) {
		set->smpl_pmds[i][0]  	  |=  BTB_REGS_MASK;
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
		if (pfm_ita_is_ear(ev) == 0) continue;

		is_iear = pfm_ita_is_iear(ev);

		/*
		 * when used as sampling period, then just setup the bitmask
		 * of PMDs to record in each sample
		 */
		if (set->short_rates[i].flags & PFMON_RATE_VAL_SET) {
			set->smpl_pmds[i][0]  |=  is_iear ? IEAR_REGS_MASK : DEAR_REGS_MASK;
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
		set->common_reset_pmds[0] |= is_iear ? M_PMD(0) : M_PMD(17) | M_PMD(3);
	}
	return 0;
}

/*
 * executed once for the entire session (does not make any perfmonctl() calls)
 */
static int
pfmon_ita_prepare_registers(pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	int r = 0;

	if (param->pfp_ita_btb.btb_used) r = prepare_btb(set);

	if (r == 0) r = prepare_ears(set);

	return r;
}

static int
pfmon_ita_install_pmc_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	int r = 0;

	if (param == NULL) return 0;

	if (param->pfp_ita_irange.rr_used) r = install_irange(sdesc, set);

	if (r == 0 && param->pfp_ita_drange.rr_used) r = install_drange(sdesc, set);

	if (r == 0 && param->pfp_ita_btb.btb_used) r = install_btb(sdesc, set);

	return r;
}

static int
pfmon_ita_install_pmd_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	int r = 0;

	if (param == NULL) return 0;

	if (r == 0 && param->pfp_ita_btb.btb_used) r = install_btb(sdesc, set);

	return r;
}

static void
pfmon_ita_usage(void)
{
	printf( "--event-thresholds=thr1,thr2,...\tSet event thresholds (no space).\n"
		"--opc-match8=[mifb]:match:mask\t\tSet opcode match for pmc8.\n"
		"--opc-match9=[mifb]:match:mask\t\tSet opcode match for pmc9.\n"
		"--btb-no-tar\t\t\t\tDon't capture TAR predictions.\n"
		"--btb-no-bac\t\t\t\tDon't capture BAC predictions.\n"
		"--btb-no-tac\t\t\t\tDon't capture TAC predictions.\n"
		"--btb-tm-tk\t\t\t\tCapture taken IA-64 branches only.\n"
		"--btb-tm-ntk\t\t\t\tCapture not taken IA-64 branches only.\n"
		"--btb-ptm-correct\t\t\tCapture branch if target predicted\n"
		"\t\t\t\t\tcorrectly.\n"
		"--btb-ptm-incorrect\t\t\tCapture branch if target is\n"
		"\t\t\t\t\tmispredicted.\n"
		"--btb-ppm-correct\t\t\tCapture branch if path is predicted\n"
		"\t\t\t\t\tcorrectly.\n"
		"--btb-ppm-incorrect\t\t\tCapture branch if path is mispredicted.\n"
		"--btb-all-mispredicted\t\t\tCapture all mispredicted branches.\n"
		"--irange=start-end\t\t\tSpecify an instruction address range\n"
		"\t\t\t\t\tconstraint.\n"
		"--drange=start-end\t\t\tSpecify a data address range constraint.\n"
		"--checkpoint-func=addr\t\t\tA bundle address to use as checkpoint.\n"
		"--ia32\t\t\t\t\tMonitor IA-32 execution only.\n"
		"--ia64\t\t\t\t\tMonitor IA-64 execution only.\n"
		"--insn-sets=set1,set2,...\t\tSet per event instruction set\n"
		"\t\t\t\t\t(setX=[ia32|ia64|both]).\n"
		"--no-qual-check\t\t\t\tDo not check qualifier constraints on\n"
		"\t\t\t\t\tevents.\n"
		"--insecure\t\t\t\tAllow rum/sum in monitored task\n"
		"\t\t\t\t\t(per-thread mode and root only).\n"
		"--excl-intr\t\t\t\tExclude interrupt-triggered execution\n"
		"\t\t\t\t\tfrom system-wide measurement.\n"
		"--intr-only\t\t\t\tInclude only interrupt-triggered\n"
		"\t\t\t\t\texecution from system-wide measurement.\n"
		"--exclude-idle\t\t\t\tNot stop monitoring in the idle loop\n"
		"\t\t\t\t\t(default: off)\n"
	);
}

static void
pfmon_ita_setup_ears(pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	pfmlib_ita_ear_mode_t mode;
	int done_iear = 0, done_dear = 0;
	unsigned int i, ev;

	for (i=0; i < set->event_count; i++) {

		ev = set->inp.pfp_events[i].event;

		if (pfm_ita_is_ear(ev) == 0) continue;

		pfm_ita_get_ear_mode(ev, &mode);

		if (pfm_ita_is_dear(ev)) {

			if (done_dear) {
				fatal_error("cannot specify more than one D-EAR event at the same time\n");
			}

			param->pfp_ita_dear.ear_used = 1;
			param->pfp_ita_dear.ear_mode = mode;
			param->pfp_ita_dear.ear_plm  = set->inp.pfp_events[i].plm; /* use plm from event */
			param->pfp_ita_dear.ear_ism  = param->pfp_ita_counters[i].ism;
			pfm_ita_get_event_umask(ev, &param->pfp_ita_dear.ear_umask);

			done_dear = 1;
		}

		if (pfm_ita_is_iear(ev)) {

			if (done_iear) {
				fatal_error("cannot specify more than one D-EAR event at the same time\n");
			}

			param->pfp_ita_iear.ear_used = 1;
			param->pfp_ita_iear.ear_mode = mode;
			param->pfp_ita_iear.ear_plm  = set->inp.pfp_events[i].plm; /* use plm from event */
			param->pfp_ita_iear.ear_ism  = param->pfp_ita_counters[i].ism;

			pfm_ita_get_event_umask(ev, &param->pfp_ita_iear.ear_umask);

			done_iear = 1;
		}
	}
}

static void
pfmon_ita_setup_btb(pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	pfmon_ita_args_t *ita_args;
	unsigned int i;

	ita_args = set->mod_args;

	/*
	 * For pfmon, we do not activate the BTB registers unless a BRANCH_EVENT
	 * is specified in the event list. The libpfm library does not have this restriction.
	 *
	 * XXX: must make sure BRANCH_EVENT shows up only once
	 */
	for (i=0; i < set->event_count; i++) {
		if (pfm_ita_is_btb(set->inp.pfp_events[i].event)) {
			goto found;
		}
	}
	/*
	 * if the user specified a BTB option (but not the event) 
	 * then we program the BTB as a free running config.
	 *
	 * XXX: cannot record ALL branches
	 */
	if (  !ita_args->opt_btb_notar
	   && !ita_args->opt_btb_notac
	   && !ita_args->opt_btb_nobac
	   && !ita_args->opt_btb_tm
	   && !ita_args->opt_btb_ptm
	   && !ita_args->opt_btb_ppm) return;
found:

	/*
	 * set the use bit, such that the library will program PMC12
	 */
	param->pfp_ita_btb.btb_used = 1;

	/* by default, the registers are setup to 
	 * record every possible branch.
	 * The record nothing is not available because it simply means
	 * don't use a BTB event.
	 * So the only thing the user can do is narrow down the type of
	 * branches to record. This simplifies the number of cases quite
	 * substantially.
	 */
	param->pfp_ita_btb.btb_tar = 1;
	param->pfp_ita_btb.btb_tac = 1;
	param->pfp_ita_btb.btb_bac = 1;
	param->pfp_ita_btb.btb_tm  = 0x3;
	param->pfp_ita_btb.btb_ptm = 0x3;
	param->pfp_ita_btb.btb_ppm = 0x3;
	param->pfp_ita_btb.btb_plm = set->inp.pfp_events[i].plm; /* use the plm from the BTB event */

	if (ita_args->opt_btb_notar) param->pfp_ita_btb.btb_tar = 0;
	if (ita_args->opt_btb_notac) param->pfp_ita_btb.btb_tac = 0;
	if (ita_args->opt_btb_nobac) param->pfp_ita_btb.btb_bac = 0;
	if (ita_args->opt_btb_tm)    param->pfp_ita_btb.btb_tm  = (unsigned char)ita_args->opt_btb_tm  & 0x3;
	if (ita_args->opt_btb_ptm)   param->pfp_ita_btb.btb_ptm = (unsigned char)ita_args->opt_btb_ptm & 0x3;
	if (ita_args->opt_btb_ppm)   param->pfp_ita_btb.btb_ppm = (unsigned char)ita_args->opt_btb_ppm & 0x3;

	vbprintf("btb options:\n\tplm=%d tar=%c tac=%c bac=%c tm=%d ptm=%d ppm=%d\n",
		param->pfp_ita_btb.btb_plm,
		param->pfp_ita_btb.btb_tar ? 'Y' : 'N',
		param->pfp_ita_btb.btb_tac ? 'Y' : 'N',
		param->pfp_ita_btb.btb_bac ? 'Y' : 'N',
		param->pfp_ita_btb.btb_tm,
		param->pfp_ita_btb.btb_ptm,
		param->pfp_ita_btb.btb_ppm);
}

/*
 * Itanium-specific options
 *
 * 000-255   reserved for generic options
 * 400-499   reserved for PMU specific options
 * 500-599   reserved for format specific options
 */
static struct option cmd_ita_options[]={
	{ "event-thresholds", 1, 0, 400 },
	{ "opc-match8", 1, 0, 401},
	{ "opc-match9", 1, 0, 402},
	{ "btb-all-mispredicted", 0, 0, 403},
	{ "checkpoint-func", 1, 0, 404},
	{ "irange", 1, 0, 405},
	{ "drange", 1, 0, 406},
	{ "insn-sets", 1, 0, 407},
	{ "btb-no-tar", 0, 0, 408},
	{ "btb-no-bac", 0, 0, 409},
	{ "btb-no-tac", 0, 0, 410},
	{ "btb-tm-tk", 0, 0, 411},
	{ "btb-tm-ntk", 0, 0, 412},
	{ "btb-ptm-correct", 0, 0, 413},
	{ "btb-ptm-incorrect", 0, 0, 414},
	{ "btb-ppm-correct", 0, 0, 415},
	{ "btb-ppm-incorrect", 0, 0, 416},
	{ "ia32", 0, 0, 417},
	{ "ia64", 0, 0, 418},
	{ "excl-intr", 0, 0, 419},
	{ "intr-only", 0, 0, 420},
	{ "exclude-idle", 0, 0, 421 },
	{ "no-qual-check", 0, &pfmon_ita_opt.opt_no_qual_check, 0x1},
	{ "insecure", 0, &pfmon_ita_opt.opt_insecure, 0x1},
	{ 0, 0, 0, 0}
};

static int
pfmon_ita_initialize(void)
{
	int r;

	r = pfmon_register_options(cmd_ita_options, sizeof(cmd_ita_options));
	if (r == -1) return -1;


	/* connect pfmon model specific options */
	options.model_options = &pfmon_ita_opt;

	return 0;
}

static int
pfmon_ita_parse_options(int code, char *optarg)
{
	pfmon_ita_args_t *ita_args;
	pfmon_event_set_t *set;

	set = options.last_set;

	ita_args = set->mod_args;

	switch(code) {
		case  400:
			if (ita_args->threshold_arg) fatal_error("thresholds already defined\n");
			ita_args->threshold_arg = optarg;
			break;
		case  401:
			if (ita_args->opcm8_arg) fatal_error("opcode matcher pmc8 is specified twice\n");
			ita_args->opcm8_arg = optarg;
			break;
		case  402:
			if (ita_args->opcm9_arg) fatal_error("opcode matcher pmc9 is specified twice\n");
			ita_args->opcm9_arg = optarg;
			break;
		case  403:
			/* shortcut to the following options
			 * must not be used with other btb options
			 */
			ita_args->opt_btb_notar = 0;
			ita_args->opt_btb_nobac = 0;
			ita_args->opt_btb_notac = 0;
			ita_args->opt_btb_tm    = 0x3;
			ita_args->opt_btb_ptm   = 0x1;
			ita_args->opt_btb_ppm   = 0x1;
			break;
		case  404:
			if (pfmon_ita_opt.irange_arg) {
				fatal_error("cannot use checkpoints and instruction range at the same time\n");
			}
			if (pfmon_ita_opt.chkp_func_arg) {
				fatal_error("checkpoint already  defined for %s\n", pfmon_ita_opt.chkp_func_arg);
			}
			pfmon_ita_opt.chkp_func_arg = optarg;
			break;

		case  405:
			if (pfmon_ita_opt.chkp_func_arg) {
				fatal_error("cannot use instruction range and checkpoints at the same time\n");
			}
			if (pfmon_ita_opt.irange_arg) {
				fatal_error("cannot specify more than one instruction range\n");
			}
			pfmon_ita_opt.irange_arg = optarg;
			break;

		case  406:
			if (pfmon_ita_opt.drange_arg) {
				fatal_error("cannot specify more than one data range\n");
			}
			pfmon_ita_opt.drange_arg = optarg;
			break;
		case  407:
			if (ita_args->instr_set_arg) fatal_error("per event instruction sets already defined");
			ita_args->instr_set_arg = optarg;
			break;
		case 408:
			ita_args->opt_btb_notar = 1;
			break;
		case 409:
			ita_args->opt_btb_nobac = 1;
			break;
		case 410:
			ita_args->opt_btb_notac = 1;
			break;
		case 411:
			ita_args->opt_btb_tm = 2;
			break;
		case 412:
			ita_args->opt_btb_tm = 1;
			break;
		case 413:
			ita_args->opt_btb_ptm = 2;
			break;
		case 414:
			ita_args->opt_btb_ptm = 1;
			break;
		case 415:
			ita_args->opt_btb_ppm = 2;
			break;
		case 416:
			ita_args->opt_btb_ppm = 1;
			break;
		case 417:
			ita_args->opt_ia32 = 1;
			break;
		case 418:
			ita_args->opt_ia64 = 1;
			break;
		case 419 :
			if (set->set_flags & PFM_ITA_SETFL_INTR_ONLY)
				fatal_error("cannot combine --excl-intr with --intr-only\n");
			set->set_flags |= PFM_ITA_SETFL_EXCL_INTR;
			break;
		case 420 :
			if (set->set_flags & PFM_ITA_SETFL_INTR_ONLY)
				fatal_error("cannot combine --excl-intr with --intr-only\n");
			set->set_flags |= PFM_ITA_SETFL_INTR_ONLY;
			break;
		case 421 :
			set->set_flags |= PFM_ITA_SETFL_IDLE_EXCL;
			break;
		default:
			return -1;
	}
	return 0;
}

static void
pfmon_ita_parse_opcm(char *str, unsigned long *mifb, unsigned long *match, unsigned long *mask)
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
pfmon_ita_setup_opcm(pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	pfmon_ita_args_t *ita_args;
	unsigned long mifb, match, mask;

	ita_args = set->mod_args;

	if (ita_args->opcm8_arg) {
		pfmon_ita_parse_opcm(ita_args->opcm8_arg,
				      &mifb,
				      &match,
				      &mask);

		/*
		 * truncate to relevant part (27 bits)
		 */
		match &= (1UL<<27)-1;
		mask  &= (1UL<<27)-1;

		param->pfp_ita_pmc8.pmc_val = (mifb << 60) | (match <<33) | (mask<<3);
		param->pfp_ita_pmc8.opcm_used = 1;
	}

	if (ita_args->opcm9_arg) {
		pfmon_ita_parse_opcm(ita_args->opcm9_arg,
				      &mifb,
				      &match,
				      &mask);
		/*
		 * truncate to relevant part (27 bits)
		 */
		match &= (1UL<<27)-1;
		mask  &= (1UL<<27)-1;

		param->pfp_ita_pmc9.pmc_val = (mifb << 60) | (match <<33) | (mask<<3);
		param->pfp_ita_pmc9.opcm_used = 1;
	}
}

/*
 * XXX: fix to propagate to all sets
 */
static void
pfmon_ita_setup_rr(pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	pfmon_ita_args_t *ita_args;
	uintptr_t start, end;

	ita_args = set->mod_args;

	if (pfmon_ita_opt.chkp_func_arg) {
		if (set->priv_lvl_str)
			fatal_error("cannot use both a checkpoint function and per-event privilege level masks\n");

		gen_code_range(pfmon_ita_opt.chkp_func_arg, &start, &end);
		
		/* just one bundle for this one */
		end = start + 0x10;

		vbprintf("checkpoint function at %p\n", start);
	} else if (pfmon_ita_opt.irange_arg) {

		if (set->priv_lvl_str)
			fatal_error("cannot use both a code range function and per-event privilege level masks\n");

		gen_code_range(pfmon_ita_opt.irange_arg, &start, &end); 

		if ((unsigned long)start & 0xf) fatal_error("code range does not start on bundle boundary : %p\n", start);
		if ((unsigned long)end & 0xf) fatal_error("code range does not end on bundle boundary : %p\n", end);

		vbprintf("irange is [%p-%p)=%ld bytes\n", start, end, end-start);
	}

	/*
	 * now finalize irange/chkp programming of the range
	 */
	if (pfmon_ita_opt.irange_arg || pfmon_ita_opt.chkp_func_arg) { 

		param->pfp_ita_irange.rr_used = 1;

		param->pfp_ita_irange.rr_limits[0].rr_start = (unsigned long)start;
		param->pfp_ita_irange.rr_limits[0].rr_end   = (unsigned long)end;
		param->pfp_ita_irange.rr_limits[0].rr_plm   = set->inp.pfp_dfl_plm; /* use default */
	}

	if (pfmon_ita_opt.drange_arg) {
		if (set->priv_lvl_str)
			fatal_error("cannot use both a data range and  per-event privilege level masks\n");

		gen_data_range(pfmon_ita_opt.drange_arg, &start, &end);

		vbprintf("drange is [%p-%p)=%lu bytes\n", start, end, end-start);
		
		param->pfp_ita_drange.rr_used = 1;

		param->pfp_ita_drange.rr_limits[0].rr_start = (unsigned long)start;
		param->pfp_ita_drange.rr_limits[0].rr_end   = (unsigned long)end;
		param->pfp_ita_drange.rr_limits[0].rr_plm   = set->inp.pfp_dfl_plm; /* use default */
	}

}

/*
 * This function checks the configuration to verify
 * that the user does not try to combine features with
 * events that are incompatible.The library does this also
 * but it's hard to then detail the cause of the error.
 */
static void
check_ita_event_combinations(pfmon_event_set_t *set)
{
	unsigned int i, use_opcm, ev;
	pfmlib_ita_input_param_t *param = set->mod_inp;
	pfmon_ita_args_t *ita_args;
	char *name;

	ita_args = set->mod_args;

	name = options.ev_name1;

	use_opcm = param->pfp_ita_pmc8.opcm_used || param->pfp_ita_pmc9.opcm_used; 
	for (i=0; i < set->event_count; i++) {

		ev = set->inp.pfp_events[i].event;

		pfm_get_event_name(ev, name, options.max_event_name_len+1);

		if (use_opcm && pfm_ita_support_opcm(ev) == 0)
			fatal_error("event %s does not support opcode matching\n", name);

		if (param->pfp_ita_irange.rr_used && pfm_ita_support_iarr(ev) == 0)
			fatal_error("event %s does not support instruction address range restrictions\n", name);

		if (param->pfp_ita_drange.rr_used && pfm_ita_support_darr(ev) == 0)
			fatal_error("event %s does not support data address range restrictions\n", name);

		if (ita_args->opt_ia32 && ita_args->opt_ia64 == 0 && pfm_ita_is_btb(ev))
			fatal_error("cannot use BTB event (%s) when only monitoring IA-32 execution\n", name);
	}

	/*
	 * we do not call check_counter_conflict() because Itanium does not have events
	 * which can only be measured on one counter, therefore this routine would not
	 * catch anything at all.
	 */
}

static void
pfmon_ita_setup_insn(pfmon_event_set_t *set)
{
	static const struct {
		char *name;
		pfmlib_ita_ism_t val;
	} insn_sets[]={
		{ "ia32", PFMLIB_ITA_ISM_IA32 },
		{ "ia64", PFMLIB_ITA_ISM_IA64 },
		{ "both", PFMLIB_ITA_ISM_BOTH },
		{ NULL  , PFMLIB_ITA_ISM_BOTH }
	};
	pfmlib_ita_input_param_t *param = set->mod_inp;
	char *p, *arg;
	pfmon_ita_args_t *ita_args;
	pfmlib_ita_ism_t dfl_ism;
	unsigned int i, cnt=0;

	ita_args = set->mod_args;

	/* 
	 * set default instruction set 
	 */
	if (ita_args->opt_ia32  && ita_args->opt_ia64)
		dfl_ism = PFMLIB_ITA_ISM_BOTH;
	else if (ita_args->opt_ia64)
		dfl_ism = PFMLIB_ITA_ISM_IA64;
	else if (ita_args->opt_ia32)
		dfl_ism = PFMLIB_ITA_ISM_IA32;
	else
		dfl_ism = PFMLIB_ITA_ISM_BOTH;

	/*
	 * propagate default instruction set to all events
	 */
	for(i=0; i < set->event_count; i++) param->pfp_ita_counters[i].ism = dfl_ism;

	/*
	 * apply correction for per-event instruction set
	 */
	for (arg = ita_args->instr_set_arg; arg; arg = p) {
		if (cnt == set->event_count) goto too_many;

		p = strchr(arg,',');
			
		if (p) *p = '\0';

		if (*arg) {
			for (i=0 ; insn_sets[i].name; i++) {
				if (!strcmp(insn_sets[i].name, arg)) goto found;
			}
			goto error;
found:
			param->pfp_ita_counters[cnt++].ism = insn_sets[i].val;
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

static void
pfmon_ita_set_no_qual_check(pfmon_event_set_t *set)
{
	pfmlib_ita_input_param_t *param = set->mod_inp;
	unsigned int i;

	/*
	 * set the "do not check constraint" flags for all events 
	 */
	for (i=0; i < set->event_count; i++) {
		param->pfp_ita_counters[i].flags |= PFMLIB_ITA_FL_EVT_NO_QUALCHECK;
	}
}

static int
pfmon_ita_setup(pfmon_event_set_t *set)
{
	pfmon_ita_args_t *ita_args;

	ita_args = set->mod_args;

	if (ita_args == NULL) return 0;

	if (options.code_trigger_start || options.code_trigger_stop || options.data_trigger_start || options.data_trigger_stop) {
		if (pfmon_ita_opt.irange_arg)
			fatal_error("cannot use a trigger address with instruction range restrictions\n");
		if (pfmon_ita_opt.drange_arg)
			fatal_error("cannot use a trigger address with data range restrictions\n");
		if (pfmon_ita_opt.chkp_func_arg)
			fatal_error("cannot use a trigger address with function checkpoint\n");
	}

	/*
	 * setup the instruction set support
	 *
	 * and reject any invalid combination for IA-32 only monitoring
	 *
	 * We do not warn of the fact that IA-32 execution will be ignored
	 * when used with incompatible features unless the user requested IA-32
	 * ONLY monitoring. 
	 */
	if (ita_args->opt_ia32 == 1 && ita_args->opt_ia64 == 0) {

		/*
		 * Code & Data range restrictions are ignored for IA-32
		 */
		if (pfmon_ita_opt.irange_arg || pfmon_ita_opt.drange_arg) 
			fatal_error("you cannot use range restrictions when monitoring IA-32 execution only\n");

		/*
		 * Code range restriction (used by checkpoint) is ignored for IA-32
		 */
		if (pfmon_ita_opt.chkp_func_arg) 
			fatal_error("you cannot use function checkpoint when monitoring IA-32 execution only\n");

		/*
		 * opcode matcher are ignored for IA-32
		 */
		if (ita_args->opcm8_arg || ita_args->opcm9_arg)
			fatal_error("you cannot use the opcode matcher(s) when monitoring IA-32 execution only\n");

	}
	pfmon_ita_setup_insn(set);
	pfmon_ita_setup_rr(set);
	pfmon_ita_setup_opcm(set);
	pfmon_ita_setup_btb(set);
	pfmon_ita_setup_ears(set);

	/*
	 * BTB is only valid in IA-64 mode
	 */
	if ( ita_args->opt_ia32 && ita_args->opt_ia64 == 0&& 
	    (ita_args->opt_btb_notar || 
	     ita_args->opt_btb_notac || 
	     ita_args->opt_btb_nobac || 
	     ita_args->opt_btb_tm    || 
	     ita_args->opt_btb_ptm   || 
	     ita_args->opt_btb_ppm)) {
		fatal_error("cannot use the BTB when only monitoring IA-32 execution\n");
	}


	/* 
	 * we systematically initialize thresholds to their minimal value
	 * or requested value
	 */
	pfmon_ita_setup_thresholds(set);

	if (pfmon_ita_opt.opt_no_qual_check) 
		pfmon_ita_set_no_qual_check(set);
	else
		check_ita_event_combinations(set);

	return 0;
}

static int
pfmon_ita_print_header(FILE *fp)
{
	pfmon_event_set_t *set;
	pfmlib_ita_input_param_t *mod_in;
	unsigned int i, k, l;
	int isn;
	char *name;
	size_t len;
	static const char *insn_str[]={
		"ia32/ia64",
		"ia32", 
		"ia64"
	};
	len = 1 + options.max_event_name_len;
	name = malloc(len);
	if (!name)
		fatal_error("cannot allocate string buffer");

	for(k=0, set = options.sets; set; k++, set = set->next) {
		mod_in = (pfmlib_ita_input_param_t *)set->mod_inp;
		fprintf(fp, "#\n#\n# instruction sets for set%u:\n", k);
		for(i=0; i < set->event_count; i++) {
			pfm_get_event_name(set->inp.pfp_events[i].event, name, len);

			isn =mod_in->pfp_ita_counters[i].ism;
			fprintf(fp, "#\tPMD%d: %-*s = %s\n", 
					set->outp.pfp_pmcs[i].reg_num,
					(int)options.max_event_name_len,
					name,
					insn_str[isn]);
			l--;
		} 
		fprintf(fp, "#\n");
	}
	free(name);
	return 0;
}

static void
pfmon_ita_detailed_event_name(unsigned int evt)
{
	unsigned long umask;
	unsigned int maxincr;

	pfm_ita_get_event_umask(evt, &umask);
	pfm_ita_get_event_maxincr(evt, &maxincr);

	printf("umask=0x%02lx incr=%u iarr=%c darr=%c opcm=%c ", 
			umask, 
			maxincr,
			pfm_ita_support_iarr(evt) ? 'Y' : 'N',
			pfm_ita_support_darr(evt) ? 'Y' : 'N',
			pfm_ita_support_opcm(evt) ? 'Y' : 'N');
}

static int
pfmon_ita_setup_ctx_flags(pfmon_ctx_t *ctx)
{
	if (pfmon_ita_opt.opt_insecure)
		ctx->ctx_flags |= PFM_ITA_FL_INSECURE;
	return 0;
}

static void
pfmon_ita_verify_cmdline(int argc, char **argv)
{
	if (pfmon_ita_opt.opt_insecure && options.opt_is22 == 0)
		fatal_error("the --insecure option requires at least perfmon v2.2\n");
}

static void
pfmon_ita_verify_event_sets(void)
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
pfmon_ita_show_event_info(unsigned int idx)
{
	unsigned long umask;
	unsigned int maxincr;
	int n = 0;

	pfm_ita_get_event_umask(idx, &umask);
	pfm_ita_get_event_maxincr(idx, &maxincr);

	printf("Umask    : 0x%lx\n", umask);

	if (pfm_ita_is_dear(idx)) {
		printf("EAR      : Data (%s)\n",
			pfm_ita_is_dear_tlb(idx) ?  "TLB Mode": "Cache Mode");
	} else if (pfm_ita_is_iear(idx)) {
		printf("EAR      : Code (%s)\n",
			pfm_ita_is_iear_tlb(idx) ?
				"TLB Mode": "Cache Mode");
	} else
		puts("EAR      : None");

	printf("BTB      : %s\n", pfm_ita_is_btb(idx) ? "Yes" : "No");

	if (maxincr > 1)
		printf("MaxIncr  : %u  (Threshold [0-%u])\n", maxincr,  maxincr-1);
 	else
		printf("MaxIncr  : %u  (Threshold 0)\n", maxincr);

	printf("Qual     : ");

	if (pfm_ita_support_opcm(idx)) {
		printf("[Opcode Match] ");
		n++;
	}

	if (pfm_ita_support_iarr(idx)) {
		printf("[Instruction Address Range] ");
		n++;
	}

	if (pfm_ita_support_darr(idx)) {
		printf("[Data Address Range] ");
		n++;
	}

	if (n == 0)
		puts("None");
	else
		putchar('\n');
}

pfmon_support_t pfmon_itanium = {
	.name				= "Itanium",
	.pmu_type			= PFMLIB_ITANIUM_PMU,
	.generic_pmu_type		= PFMLIB_GEN_IA64_PMU,
	.pfmon_initialize		= pfmon_ita_initialize,
	.pfmon_usage			= pfmon_ita_usage,
	.pfmon_parse_options		= pfmon_ita_parse_options,
	.pfmon_setup			= pfmon_ita_setup,
	.pfmon_prepare_registers	= pfmon_ita_prepare_registers,
	.pfmon_install_pmc_registers	= pfmon_ita_install_pmc_registers,
	.pfmon_install_pmd_registers	= pfmon_ita_install_pmd_registers,
	.pfmon_print_header		= pfmon_ita_print_header,
	.pfmon_detailed_event_name	= pfmon_ita_detailed_event_name,
	.pfmon_setup_ctx_flags		= pfmon_ita_setup_ctx_flags,
	.pfmon_verify_cmdline		= pfmon_ita_verify_cmdline,
	.pfmon_verify_event_sets	= pfmon_ita_verify_event_sets,
	.pfmon_show_event_info		= pfmon_ita_show_event_info,
	.sz_mod_args			= sizeof(pfmon_ita_args_t),
	.sz_mod_inp			= sizeof(pfmlib_ita_input_param_t),
	.sz_mod_outp			= sizeof(pfmlib_ita_output_param_t)
};
