/*
 * pfmon.c 
 *
 * Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *
 * This file is part of pfmon, a sample tool to measure performance 
 * of applications on Linux.
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
#include <ctype.h>
#include <regex.h>
#include <math.h> /* for lroundf */
#include <limits.h>

#include "pfmon_support.h"

static pfmon_support_t *pfmon_cpus[]={
#ifdef CONFIG_PFMON_IA64
	&pfmon_itanium,
	&pfmon_itanium2,
	&pfmon_montecito,
	&pfmon_generic_ia64,		/* must always be last of IA-64 choices */
#endif
#ifdef CONFIG_PFMON_X86_64
	&pfmon_amd64,
	&pfmon_pentium4,
	&pfmon_core,
	&pfmon_gen_ia32,	/* must always be last of X86 choices */
#endif
#ifdef CONFIG_PFMON_I386
	&pfmon_amd64,
	&pfmon_pentium4,
	&pfmon_core,
	&pfmon_i386_p6,
	&pfmon_i386_pii,
	&pfmon_i386_ppro,
	&pfmon_i386_pm,
	&pfmon_coreduo,
	&pfmon_gen_ia32,	/* must always be last of X86 choices */
#endif
#ifdef CONFIG_PFMON_MIPS64
 	&pfmon_mips64_20kc,
 	&pfmon_mips64_25kf,
 	&pfmon_mips64_ice9a,
 	&pfmon_mips64_ice9b,
#endif
#ifdef CONFIG_PFMON_CELL
	&pfmon_cell,
#endif
#ifdef CONFIG_PFMON_SPARC
	&pfmon_ultra12,
	&pfmon_ultra3,
	&pfmon_ultra3i,
	&pfmon_ultra3plus,
	&pfmon_ultra4plus,
	&pfmon_niagara1,
	&pfmon_niagara2,
#endif
	NULL
};

#define PFMON_FORCED_GEN	"pfmon_gen"

pfmon_support_t		*pfmon_current;	/* current pfmon support */
program_options_t	options;	/* keep track of global program options */

/*
 * parsing of the --extra-smpl-pmds option
 */
static void
parse_xtra_smpl_pmds(pfmon_event_set_t *set)
{
	char *smpl_pmds, *p;
	int start_pmd, end_pmd = 0;

	smpl_pmds = set->xtra_smpl_pmds_args;

	if (smpl_pmds == NULL)
		return;

	while(isdigit(*smpl_pmds)) { 
		p = NULL;
		start_pmd = strtoul(smpl_pmds, &p, 0); /* auto-detect base */

		if (start_pmd == ULONG_MAX || (*p != '\0' && *p != ',' && *p != '-'))
			goto invalid;

		if (*p == '-') {
			smpl_pmds = ++p;
			p = NULL;

			end_pmd = strtoul(smpl_pmds, &p, 0); /* auto-detect base */
			
			if (end_pmd == ULONG_MAX || (*p != '\0' && *p != ','))
				goto invalid;
			if (end_pmd < start_pmd)
				goto invalid_range; 
		} else {
			end_pmd = start_pmd;
		}

		if (start_pmd >= PFM_MAX_PMDS || end_pmd >= PFM_MAX_PMDS)
			goto too_big;

		/*
		 * we do not check validity of the PMD because some
		 * virtual PMD may be unknown to libpfm. The kernel
		 * will do the check
		 */
		for (; start_pmd <= end_pmd; start_pmd++) {
			pfmon_bv_set(set->common_smpl_pmds, start_pmd);
		}

		if (*p) ++p;

		smpl_pmds = p;
	}
	return;

invalid:
	fatal_error("invalid extra sampling pmd list argument: %s\n", smpl_pmds);
	/* no return */
invalid_range:
	fatal_error("sampling pmd range %lu - %lu is invalid\n", start_pmd, end_pmd);
	/* no return */
too_big:
	fatal_error("extra sampling PMD range contains unimplemented PMDS\n", PFMON_MAX_CPUS);
	/* no return */
}

/*
 * return 1 if j corresponds to a PMD register used by
 * an event specified by the user, 0 otherwise
 */
static int is_event_pmd(pfmon_event_set_t *set, int j)
{
	int i;
	for(i=0; i < set->event_count; i++) {
		if (set->master_pd[i].reg_num == j)
			return 1;
	}
	return 0;
}

/*
 * does the final preparation on the pmc arguments
 * and also initializes the pmds arguments.
 *
 * the function does not make the perfmonctl() call to
 * install pmcs or pmds.
 *
 * As such this function is supposed to be called only once.
 */
static int
prepare_pmd_smpl(pfmon_event_set_t *set)
{
	uint32_t reg_flags;
	uint64_t tmp_smpl_pmds[PFM_PMD_BV];
	unsigned int i, j, k, l, m, n, o;

	/*
	 * nothing special to do if not sampling
	 */
	if (options.opt_use_smpl == 0) return 0;

	parse_xtra_smpl_pmds(set);

	memset(tmp_smpl_pmds, 0, sizeof(tmp_smpl_pmds));
	for(i=0; i < set->event_count; i++) {
		reg_flags = 0;
		/*
		 * The counters for which a sampling period has been
		 * set must have their notify flag set unless requested
		 * otherwise by user in which case the
		 * buffer will saturate: you stop when the buffer becomes
		 * full, i.e., collect the first samples only.
		 *
		 * Counters for which no sampling period is set are
		 * considered part of the set of PMC/PMD to store
		 * in each sample.
		 */
		if (set->long_rates[i].flags & PFMON_RATE_VAL_SET) {
			if (options.opt_no_ovfl_notify == 0) 
				reg_flags |= PFM_REGFL_OVFL_NOTIFY;
			/*
			 * set randomization flag
			 */
			if (set->long_rates[i].flags & PFMON_RATE_MASK_SET) {
				reg_flags |= PFM_REGFL_RANDOM;
			}
		} else {
			/*
			 * event/counter not used as sampling periods are 
			 * recorded in the samples as reg_smpl_pmds
			 */
			pfmon_bv_set(tmp_smpl_pmds, set->master_pd[i].reg_num);
			pfmon_bv_or(tmp_smpl_pmds, set->smpl_pmds[i]);
		}
		/*
		 * take care of compatibility problems on IA-64 with perfmon
		 * v2.0
		 */
		if (options.opt_is22)
			set->master_pd[i].reg_flags = reg_flags;
		else
			set->master_pc[i].reg_flags = reg_flags;

	}
	/*
	 * some common PMDs may have already been requested by model specific
	 * code (prepare_registers) or via --extra-smpl-pmds option
	 */
	pfmon_bv_or(set->common_smpl_pmds, tmp_smpl_pmds);

	/*
	 * update smpl_pmds for all sampling periods
	 * we need to wait until we know all the pmds involved
	 */
	for(i=0; i < set->event_count; i++) {

		if ((set->long_rates[i].flags & PFMON_RATE_VAL_SET) == 0) continue;

		/* pmd-specific smampling pmds */
		pfmon_bv_copy(set->master_pd[i].reg_smpl_pmds, set->smpl_pmds[i]);

		/* common sampling pmds */
		pfmon_bv_or(set->master_pd[i].reg_smpl_pmds, set->common_smpl_pmds);
		

		memset(tmp_smpl_pmds, 0, sizeof(tmp_smpl_pmds));
		k = 0;
		/*
		 * put explicit events first
		 */
		pfmon_bv_copy(tmp_smpl_pmds, set->master_pd[i].reg_smpl_pmds);
		o = pfmon_bv_weight(set->master_pd[i].reg_smpl_pmds);
		for(j=0; j < set->event_count; j++) {
			if ((set->long_rates[j].flags & PFMON_RATE_VAL_SET))
				continue;
			l = o;
			for(m=0, n=0; l; m++) {
				if (!pfmon_bv_isset(tmp_smpl_pmds, m))
					continue;
				vbprintf("j=%d m=%d reg=%d k=%d\n", j, m, set->master_pd[j].reg_num, k);
				if (m == set->master_pd[j].reg_num) {
					set->rev_smpl_pmds[set->master_pd[i].reg_num].map_pmd_evt[k].pd = m;
					set->rev_smpl_pmds[set->master_pd[i].reg_num].map_pmd_evt[k].off = n;
					k++;
				}
				n++;
				l--;
			}
		}
		for(j=0; j < k; j++)
			DPRINT(("1.%d map[%d]=%d\n", set->master_pd[i].reg_num, j, set->rev_smpl_pmds[set->master_pd[i].reg_num].map_pmd_evt[j]));

		l = o;
		for(j=0, m=0; l ; j++) {
			if (!pfmon_bv_isset(tmp_smpl_pmds, j))
				continue;
			if (!is_event_pmd(set, j)) {
				set->rev_smpl_pmds[set->master_pd[i].reg_num].map_pmd_evt[k].pd = j;
				set->rev_smpl_pmds[set->master_pd[i].reg_num].map_pmd_evt[k].off = m;
				k++;
			}
			l--;
			m++;
		}

		for(j=0; j < k; j++)
			DPRINT(("2.%d map[%d]=%d\n", set->master_pd[i].reg_num, j, set->rev_smpl_pmds[set->master_pd[i].reg_num].map_pmd_evt[j]));

		set->rev_smpl_pmds[set->master_pd[i].reg_num].num_smpl_pmds = k;
		set->rev_smpl_pmds[set->master_pd[i].reg_num].pd_idx = i; /* which event */

		pfmon_bv_copy(set->smpl_pmds[i], set->master_pd[i].reg_smpl_pmds);

		pfmon_bv_copy(set->master_pd[i].reg_reset_pmds, set->common_reset_pmds);

		if (options.opt_reset_non_smpl)
			pfmon_bv_or(set->master_pd[i].reg_reset_pmds, set->common_smpl_pmds);

		vbprintf("[pmd%u set=%u smpl_pmds=0x%lx reset_pmds=0x%lx]\n",
			set->master_pd[i].reg_num,
			set->master_pd[i].reg_set,
			set->master_pd[i].reg_smpl_pmds[0],
			set->master_pd[i].reg_reset_pmds[0]);
	}
	DPRINT(("common_smpl_pmds=0x%"PRIx64" common_reset_pmds=0x%"PRIx64"\n", 
		set->common_smpl_pmds[0],
		set->common_reset_pmds[0]));

	return 0;
}

static int
prepare_pmd_registers(pfmon_event_set_t *set)
{
	unsigned int i;
	int ret;

	/*
	 * install initial value, long and short overflow rates
	 *
	 * Mapping from PMC -> PMD:
	 * The logic is that each user-specified event corresponds to one counter (PMD).
	 * On some PMU models, it is necessary to configure several PMC registers per PMD.
	 */
	for(i=0; i < set->event_count; i++) {
		set->master_pd[i].reg_num	  = set->outp.pfp_pmds[i].reg_num;
		set->master_pd[i].reg_set         = set->id;
		set->master_pd[i].reg_value       = set->long_rates[i].value;
		set->master_pd[i].reg_short_reset = set->short_rates[i].value;
		set->master_pd[i].reg_long_reset  = set->long_rates[i].value;
		set->master_pd[i].reg_random_mask = set->long_rates[i].mask;	/* mask is per monitor */
		set->master_pd[i].reg_random_seed = set->long_rates[i].seed;	/* seed is per monitor */
		set->tmp_pd[i].reg_num            = set->outp.pfp_pmds[i].reg_num;
		set->tmp_pd[i].reg_set            = set->id;

	}
	ret = prepare_pmd_smpl(set);
	if (ret)
		return ret;
	for(i=0; i < set->event_count; i++) {
		vbprintf("[pmd%u set=%u ival=0x%"PRIx64
			" long_rate=0x%"PRIx64
			" short_rate=0x%"PRIx64
			" mask=0x%"PRIx64
			" seed=%u randomize=%c]\n",
			set->master_pd[i].reg_num,
			set->master_pd[i].reg_set,
			set->master_pd[i].reg_value,
			set->master_pd[i].reg_long_reset,
			set->master_pd[i].reg_short_reset,
			set->master_pd[i].reg_random_mask,
			set->master_pd[i].reg_random_seed,
			set->master_pd[i].reg_flags & PFM_REGFL_RANDOM ? 'y' : 'n');
	}
	return 0;
}

int
install_pmd_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	int error;
	/*
	 * and the PMD registers
	 */
	if (pfmon_write_pmds(sdesc->ctxid, set, set->master_pd, set->event_count,&error) == -1) {
		warning( "cannot write PMDs: %s\n", strerror(error));
		return -1;
	}
	DPRINT(("sdesc->id=%u installed registers\n", sdesc->id));	
	/*
	 * Give the PMU specific code a chance to install specific registers
	 */
	if (pfmon_current->pfmon_install_pmd_registers) {
		if (pfmon_current->pfmon_install_pmd_registers(sdesc, set) == -1) {
			warning("model specific install_pmd_registers failed\n");
			return -1;
		}
	}
	return 0;
}

int
install_pmc_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	int error;
	/*
	 * now program the PMC registers
	 */
	if (pfmon_write_pmcs(sdesc->ctxid, set, set->master_pc, set->pc_count,&error) == -1) {
		warning("cannot write PMCs: %s\n", strerror(error));
		return -1;
	}
	/*
	 * Give the PMU specific code a chance to install specific registers
	 */
	if (pfmon_current->pfmon_install_pmc_registers) {
		if (pfmon_current->pfmon_install_pmc_registers(sdesc, set) == -1) {
			warning("model specific install_pmc_registers failed\n");
			return -1;
		}
	}
	return 0;
}


int
install_event_sets(pfmon_sdesc_t *sdesc)
{
	pfmon_event_set_t *set;
	pfarg_setdesc_t sd;
	int ret, ctxid, error;

	ctxid = sdesc->ctxid;

	if (options.opt_is22) {
		for (set = sdesc->sets; set ; set = set->next) {
			memset(&sd, 0, sizeof(sd));
			sd.set_id      = set->id;
			sd.set_flags   = set->set_flags;
			sd.set_timeout = options.switch_timeout;
			if (sdesc->nsets > 1)
				sd.set_flags |= PFM_SETFL_TIME_SWITCH;

			if (pfmon_create_evtsets(ctxid, &sd, 1, &error) == -1) {
				warning("cannot create event sets: %s\n", strerror(error));
				return -1;
			}
		}
	}
	for (set = sdesc->sets; set ; set = set->next) {
		ret = install_pmc_registers(sdesc, set);
		if (ret) return ret;

		ret = install_pmd_registers(sdesc, set);
		if (ret) return ret;
	}
	return 0;
}

/*
 * Prepare measurement, setup PMC/PMD values, setup context and sampling module
 */
static int
run_measurements(char **argv)
{
	pfmon_event_set_t *set;
	pfmon_ctx_t     ctx;	/* master perfmon context */
	unsigned int 	i, reg_num;
	unsigned int	n, max_pmds_sample = 0; /* max number of PMD for a sample */
	int 		ret;

	memset(&ctx, 0, sizeof(ctx));

	for (set = options.sets; set; set = set->next) {

		if (options.opt_syst_wide) set->inp.pfp_flags = PFMLIB_PFP_SYSTEMWIDE;

		pfmon_detect_unavail_pmcs(&set->inp.pfp_unavail_pmcs);

		DPRINT(("library dispatch for set%u\n", set->id));
		/*
		 * assign events to counters, configure additional PMCs
		 * count may be greater than pfp_count when non trivial features are used
		 * We are guaranteed that the first n entries contains the n counters
		 * specified on the command line. The optional PMCs always come after.
		 */
		ret = pfm_dispatch_events(&set->inp, set->mod_inp, &set->outp, set->mod_outp);
		if (ret != PFMLIB_SUCCESS) {
			fatal_error("cannot configure events: %s\n", pfm_strerror(ret));
		}

		set->pc_count = set->outp.pfp_pmc_count;

		for(i=0; i < set->pc_count; i++) {
			if (pfmon_current->pfmon_pmc_map && pfmon_current->pfmon_pmc_map(set->outp.pfp_pmcs[i].reg_num, &reg_num)) {
				fatal_error("cannot map libpfm pmc%u\n",set->outp.pfp_pmcs[i].reg_num);
			} else {
				reg_num = set->outp.pfp_pmcs[i].reg_num;
			}
			set->master_pc[i].reg_num   = reg_num;
			set->master_pc[i].reg_set   = set->id;
			set->master_pc[i].reg_value = set->outp.pfp_pmcs[i].reg_value;
		}
	}

	/*
	 * in case we just want to check for a valid event combination, we
	 * exit here
	 */
	if (options.opt_check_evt_only) exit(0);

	/*
	 * final model-specific chance to setup for PMCs and PMDs.
	 * we use the master copies.
	 */
	for (set = options.sets; set; set = set->next) {
		ret = 0;
		if (pfmon_current->pfmon_prepare_registers) 
			ret = pfmon_current->pfmon_prepare_registers(set);
		if (ret) return ret;

		vbprintf("pmd setup for event set%u:\n", set->id);

		ret = prepare_pmd_registers(set);
		if (ret) return ret;
	}

	/*
	 * we are guaranteed only one set when sampling is enabled
	 */
	if (options.opt_use_smpl) {

		/*
		 * point to first (and only) set
		 */
		set = options.sets;

		/*
		 * find the monitor which has the largest number of PMDs to record
		 * for each overflow. This determines the maximum size of an entry.
		 */
		for(i=0; i < set->event_count; i++) {
			if ((set->long_rates[i].flags & PFMON_RATE_VAL_SET) == 0) continue;
			n = bit_weight(set->master_pd[i].reg_smpl_pmds[0]);
			if (n > max_pmds_sample) max_pmds_sample = n;
		}
		DPRINT(("ctx_arg_size=%lu max_pmds_samples=%u\n", options.ctx_arg_size, max_pmds_sample));
	}

	/*
	 * initialize various context flags
	 */
	if (options.opt_syst_wide)
		ctx.ctx_flags  = PFM_FL_SYSTEM_WIDE;

	if (options.opt_block)
		ctx.ctx_flags |= PFM_FL_NOTIFY_BLOCK;

	/*
	 * extra work to do when sampling
	 */
	if (options.opt_use_smpl) {

		set = options.sets;

		/*
		 * give the sampling module a chance to review PMC/PMD programming
		 */
		if (options.smpl_mod->validate_events) {
			ret = (*options.smpl_mod->validate_events)(set);
			if (ret) return ret;
		}

		/*
		 * initialize module specific context arguments
		 * (must be done after generic). 
		 */
		if (pfmon_smpl_init_ctx_arg(&ctx, max_pmds_sample) == -1) {
			return -1;
		}
	}

	/*
	 * install model specific flags
	 */
	if (   pfmon_current->pfmon_setup_ctx_flags
	    && (ret=pfmon_current->pfmon_setup_ctx_flags(&ctx))) {
		return ret;
	}

	if (options.opt_syst_wide) {
		ret = measure_system_wide(&ctx, argv);
	} else {
		ret = measure_task(&ctx, argv);
	}
	return ret;
}

static void
show_event_name(unsigned int idx, const char *name, int mode)
{
	size_t l;
	unsigned int n, i;
	char *mask_name;

	pfm_get_max_event_name_len(&l);
	mask_name = malloc(l+1);
	if (!mask_name)
		fatal_error("cannot allocate memory for mask name\n");

	pfm_get_num_event_masks(idx, &n);
	if (n == 0 || mode == 0) {
		printf("%s\n", name);
		return;
	}
	for (i = 0; n; n--, i++) {
		pfm_get_event_mask_name(idx, i, mask_name, l);
		printf("%s:%s\n", name, mask_name);
	}
	free(mask_name);
}

/*
 * mode=0 : just print event name
 * mode=1 : print name + other information (some of which maybe model specific)
 */
static void
pfmon_list_all_events(char *pattern, int mode)
{
	regex_t preg;
	unsigned int i, count;
	char *name;
	size_t len;

	pfm_get_max_event_name_len(&len);
	pfm_get_num_events(&count);
	len++; /* accomodate null character */
	name = malloc(len);
	if (!name)
		fatal_error("cannot allocate memory for event name\n");

	if (pattern) {
		int done = 0;

		if (regcomp(&preg, pattern, REG_ICASE|REG_NOSUB))
			fatal_error("error in regular expression for event \"%s\"\n", pattern);

		for(i=0; i < count; i++) {
			pfm_get_event_name(i, name, len);

			if (regexec(&preg, name, 0, NULL, 0) == 0) {
				show_event_name(i, name, mode);
				done = 1;
			}
		}
		if (done == 0)
			fatal_error("event not found\n");
	} else {
		for(i=0; i < count; i++) {
			pfm_get_event_name(i, name, len);
			show_event_name(i, name, mode);
		}
	}
	free(name);
}

/*
 * 000-255   reserved for generic options
 * 400-499   reserved for PMU specific options
 * 500-599   reserved for format specific options
 */
static struct option pfmon_common_options[]={
	{ "event-info", 1, 0, 1},
	{ "show-events", 2, 0, 2 },
	{ "kernel-level", 0, 0, 3 },
	{ "user-level", 0, 0, 4 },
	{ "events", 1, 0, 5 },
	{ "help", 0, 0, 6 },
	{ "version", 0, 0, 7 },
	{ "outfile", 1, 0, 8 },
	{ "long-show-events", 2, 0, 9 },
	{ "info", 0, 0, 10},
	{ "smpl-entries", 1, 0, 11},
	{ "smpl-outfile", 1, 0, 12},
	{ "long-smpl-periods", 1, 0, 13},
	{ "short-smpl-periods", 1, 0, 14},
	{ "cpu-mask", 1, 0, 15}, /* obsolete */
	{ "session-timeout", 1, 0, 16},
	{ "trigger-address", 1, 0, 17}, /* obsolete */
	{ "priv-levels", 1, 0, 18},
	{ "symbol-file", 1, 0, 19},
	{ "smpl-module", 1, 0, 20},
	{ "smpl-module-info", 1, 0, 21},
	{ "sysmap-file", 1, 0, 22},
	{ "smpl-periods-random", 1, 0, 23},
	{ "trigger-code-start-addresses", 1, 0, 24},
	{ "trigger-start-delay", 1, 0, 25},
	{ "attach-task", 1, 0, 26},
	{ "follow-exec", 2, 0, 27 },
	{ "follow-exec-exclude", 2, 0, 28 },
	{ "trigger-code-stop-addresses", 1, 0, 29},
	{ "cpu-list", 1, 0, 30},
	{ "trigger-data-start-addresses", 1, 0, 31},
	{ "trigger-data-stop-addresses", 1, 0, 32},
	{ "print-interval", 1, 0, 33},
	{ "switch-timeout", 1, 0, 35},
	{ "smpl-show-top", 1, 0, 36},
	{ "extra-smpl-pmds", 1, 0, 37},
	{ "smpl-cum-threshold", 1, 0, 38},
	{ "warmup", 1, 0, 39},
	{ "init-time", 1, 0, 40},
	{ "verbose", 0, &options.opt_verbose, 1 },
	{ "append", 0, &options.opt_append, 1},
	{ "overflow-block",0, &options.opt_block, 1},
	{ "system-wide", 0, &options.opt_syst_wide, 1},
	{ "debug", 0, &options.opt_debug, 1 },
	{ "aggregate-results", 0, &options.opt_aggr, 1 },

	{ "with-header", 0, &options.opt_with_header, 1},
	{ "us-counter-format",0, &options.opt_print_cnt_mode, 1},
	{ "eu-counter-format",0, &options.opt_print_cnt_mode, 2},
	{ "hex-counter-format",0, &options.opt_print_cnt_mode, 3},
	{ "show-time",0, &options.opt_show_rusage, 1},
	{ "check-events-only",0, &options.opt_check_evt_only, 1},
	{ "smpl-print-counts",0, &options.opt_smpl_print_counts, 1},
	{ "reset-non-smpl-periods", 0, &options.opt_reset_non_smpl, 1 },
	{ "follow-fork", 0, &options.opt_follow_fork, 1 },
	{ "follow-vfork", 0, &options.opt_follow_vfork, 1 },
	{ "follow-pthread", 0, &options.opt_follow_pthread, 1 },
	{ "follow-all", 0, &options.opt_follow_all, 1 },
	{ "no-cmd-output", 0, &options.opt_cmd_no_verbose, 1 },
	{ "trigger-code-repeat", 0, &options.opt_code_trigger_repeat, 1},
	{ "trigger-code-follow", 0, &options.opt_code_trigger_follow, 1},
	{ "trigger-data-repeat", 0, &options.opt_data_trigger_repeat, 1},
	{ "trigger-data-follow", 0, &options.opt_data_trigger_follow, 1},
	{ "trigger-data-ro", 0, &options.opt_data_trigger_ro, 1},
	{ "trigger-data-wo", 0, &options.opt_data_trigger_wo, 1},
	{ "restart-wait", 0, &options.opt_block_restart, 1}, /* for debug only */
	{ "exec-split-results", 0, &options.opt_split_exec, 1},
	{ "resolve-addresses", 0, &options.opt_addr2sym, 1},
	{ "saturate-smpl-buffer", 0, &options.opt_no_ovfl_notify, 1},
	{ "dont-start", 0, &options.opt_dont_start, 1},
	{ "pin-command", 0, &options.opt_pin_cmd, 1},
	{ "print-syms", 0, &options.opt_print_syms, 1},
	{ "cpu-set-relative", 0, &options.opt_vcpu, 1},
	{ "demangle-cpp", 0, &options.opt_dem_type, 1},
	{ "demangle-java", 0, &options.opt_dem_type, 2},
	{ "smpl-per-function", 0, &options.opt_smpl_per_func, 1},
	{ "smpl-ignore-pids", 0, &options.opt_smpl_nopid, 1},
	{ 0, 0, 0, 0}
};

static struct option *pfmon_cmd_options = pfmon_common_options;
static size_t pfmon_option_base_size	= sizeof(pfmon_common_options);

static void
usage(char **argv)
{
	printf("usage: %s [OPTIONS]... COMMAND\n", argv[0]);

	/*                1         2         3         4         5         6         7         8  */
	/*       12345678901234567890123456789012345678901234567890123456789012345678901234567890  */
	printf(	"-h, --help\t\t\t\tDisplay this help and exit.\n"
		"-V, --version\t\t\t\tOutput version information and exit.\n"
		"-l[regex], --show-events[=regex]\tDisplay all or a matching subset of\n"
		"\t\t\t\t\tthe events.\n"
		"-L, --long-show-events[=regex]\t\tdisplay matching events names and "
		"unit masks\n"
		"-i event, --event-info=event\t\tDisplay information about an event\n"
		"\t\t\t\t\t(numeric code or regex).\n"
		"-u, -3 --user-level\t\t\tMonitor at the user level for all\n"
		"\t\t\t\t\tevents (default: on).\n"
		"-k, -0 --kernel-level\t\t\tMonitor at the kernel level for all\n"
		"\t\t\t\t\tevents (default: off).\n"
		"-1\t\t\t\t\tMonitor execution at privilege level 1\n"
		"\t\t\t\t\t(default: off).\n"
		"-2\t\t\t\t\tMonitor execution at privilege level 2\n"
		"\t\t\t\t\t(default: off).\n"
		"-e, --events=ev1[:u1:u2],ev2,...\tSelect events to monitor.\n"
		"-I,--info\t\t\t\tList supported PMU models and compiled\n"
		"\t\t\t\t\tin sampling output formats.\n"
		"-t secs, --session-timeout=secs\t\tDuration of the system wide session in\n"
		"\t\t\t\t\tseconds.\n"
		"-S format, --smpl-module-info=format\tDisplay information about a sampling\n"
		"\t\t\t\t\toutput format.\n"
		"--debug\t\t\t\t\tEnable debug prints.\n"
		"--verbose\t\t\t\tPrint more information during execution.\n"
		"--outfile=filename\t\t\tPrint results in a file.\n"
		"--append\t\t\t\tAppend results to outfile.\n"
		"--overflow-block\t\t\tBlock the task when sampling buffer is\n"
		"\t\t\t\t\tfull (default: off).\n"
		"--system-wide\t\t\t\tCreate a system wide monitoring session\n"
		"\t\t\t\t\t(default: per-task).\n"
		"--smpl-outfile=filename\t\t\tFile to save the sampling results.\n"
		"--long-smpl-periods=val1,val2,...\tSet sampling period after user\n"
		"\t\t\t\t\tnotification.\n"
		"--short-smpl-periods=val1,val2,...\tSet sampling period.\n"
		"--smpl-entries=n\t\t\tNumber of entries in sampling buffer.\n"
		"--with-header\t\t\t\tGenerate a header for results.\n"
		"--cpu-list=num,num1-num2,...\t\tSpecify list, via numbers, of CPUs for\n"
		"\t\t\t\t\t system-wide session (default: all).\n"
		"--aggregate-results\t\t\tAggregate counts and sampling buffer\n"
		"\t\t\t\t\toutputs for multi CPU monitoring\n"
		"\t\t\t\t\t(default: off).\n"
		"--trigger-code-start-address=addr\tStart monitoring only when code address\n"
		"\t\t\t\t\tis executed.\n"
		"--trigger-code-stop-address=addr\tStop monitoring when code address is\n"
		"\t\t\t\t\texecuted.\n"
		"--trigger-data-start-address=addr\tStart monitoring only when data address\n"
		"\t\t\t\t\tis accessed.\n"
		"--trigger-data-stop-address=addr\tStop monitoring when data address code\n"
		"\t\t\t\t\tis accessed.\n"
		"--trigger-code-repeat\t\t\tStart/stop monitoring each time trigger\n"
		"\t\t\t\t\tstart/stop are executed.\n"
		"--trigger-code-follow\t\t\tStart/stop code trigger applied to all\n"
		"\t\t\t\t\tmonitored task (default first only).\n"
		"--trigger-data-repeat\t\t\tStart/stop monitoring each time trigger\n"
		"\t\t\t\t\tstart/stop are accessed.\n"
		"--trigger-data-follow\t\t\tStart/stop data trigger applied to all\n"
		"\t\t\t\t\tmonitored task (default first only).\n"
		"--trigger-data-ro\t\t\tData trigger activated on read access\n"
		"\t\t\t\t\t(default read-write).\n"
		"--trigger-data-wo\t\t\tData trigger activated on write access\n"
		"\t\t\t\t\t(default read-write).\n"
		"--trigger-start-delay=secs\t\tNumber of seconds before activating\n"
		"\t\t\t\t\tmonitoring.\n"
		"--priv-levels=lvl1,lvl2,...\t\tSet privilege level per event (any\n"
		"\t\t\t\t\tcombination of [0123uk]).\n"
		"--us-counter-format\t\t\tPrint counters using commas\n"
		"\t\t\t\t\t(e.g., 1,024).\n"
		"--eu-counter-format\t\t\tPrint counters using points\n"
		"\t\t\t\t\t(e.g., 1.024).\n"
		"--hex-counter-format\t\t\tPrint counters in hexadecimal\n"
		"\t\t\t\t\t(e.g., 0x400).\n"
		"--smpl-module=name\t\t\tSelect sampling module, use -I to list\n"
		"\t\t\t\t\tmodules.\n"
		"--show-time\t\t\t\tShow real,user, and system time for the\n"
		"\t\t\t\t\tcommand executed.\n"
		"--symbol-file=filename\t\t\tELF image containing a symbol table.\n"
		"--sysmap-file=filename\t\t\tSystem.map-format file containing a\n"
		"\t\t\t\t\tsymbol table.\n"
		"--check-events-only\t\t\tVerify combination of events and exit\n"
		"\t\t\t\t\t(no measurement).\n"
		"--smpl-periods-random=mask1:seed1,...\tApply randomization to long and short\n"
		"\t\t\t\t\tperiods.\n"
		"--smpl-print-counts\t\t\tPrint counters values when sampling\n"
		"\t\t\t\t\tsession ends (default: no).\n"
		"--attach-task pid\t\t\tMonitor process identified by pid.\n"
		"--reset-non-smpl-periods\t\tOn overflow reset counters not used as\n"
		"\t\t\t\t\tsampling periods.\n"
		"--follow-fork\t\t\t\tMonitoring continues across fork.\n"
		"--follow-vfork\t\t\t\tMonitoring continues across vfork.\n"
		"--follow-pthread\t\t\tMonitoring continues across\n"
		"\t\t\t\t\tpthread_create.\n"
		"--follow-exec[=pattern]\t\t\tFollow exec with optional command\n"
		"\t\t\t\t\tpattern.\n"
		"--follow-exec-exclude=pattern\t\tFollow exec but exclude commands\n"
		"\t\t\t\t\tmatching the pattern.\n"
		"--follow-all\t\t\t\tFollow fork, vfork, exec, pthreads.\n"
		"--no-cmd-output\t\t\t\tRedirect all output of executed commands\n"
		"\t\t\t\t\tto /dev/null.\n"
		"--exec-split-results\t\t\tGenerate separate results output on\n"
		"\t\t\t\t\texecve().\n"
		"--resolve-addresses\t\t\tTry to resolve code/data addresses to\n"
		"\t\t\t\t\tsymbols.\n"
		"--extra-smpl-pmds=num,num1-num2,...\tSpecify a list of extra PMD register to\n"
		"\t\t\t\t\tinclude in samples.\n"
		"--demangle-cpp\t\t\t\tC++ symbol demangling (OBSOLETE).\n"
		"--demangle-java\t\t\t\tJava symbol demangling (OBSOLETE).\n"
		"--saturate-smpl-buffer\t\t\tOnly collect samples until buffer\n"
		"\t\t\t\t\tbecomes full.\n"
		"--print-interval=n\t\t\tnumber of milliseconds between prints of count deltas\n"
		"--pin-command\t\t\t\tPin executed command on --cpu-list\n"
		"\t\t\t\t\t (system-wide only).\n"
		"--switch-timeout=milliseconds\t\tThe number of milliseconds before\n"
		"\t\t\t\t\t switching to the next event set.\n"
		"--dont-start\t\t\t\tDo not activate monitoring in pfmon\n"
		"\t\t\t\t\t(per-thread only).\n"
		"\t\t\t\t\tmeasurement.\n"
		"--cpu-set-relative\t\t\tCPU identifications relative to cpu_set\n"
		"\t\t\t\t\taffinity (default: off).\n"
		"--smpl-show-top=n\t\t\tshow only the top n entries in the\n"
		"\t\t\t\t\tprofile (default: all entries).\n"
		"--smpl-per-function\t\t\tshow per-function samples (default\n"
		"\t\t\t\t\tper address).\n"
		"--smpl-ignore-pids\t\t\tIgnore pids in system-wide sampling \n"
		"(default: off)\n"
		"--smpl-cum-threshold=n\t\t\tshow entries until cumulative\n"
		"\t\t\t\t\t%% of samples reaches n (default: 100%%)\n"
		);

	if (pfmon_current->pfmon_usage) pfmon_current->pfmon_usage();

	pfmon_smpl_mod_usage();
}

int
pfmon_register_options(struct option *cmd, size_t new_sz)
{
	size_t prev_sz;
	char *o;

	if (cmd == NULL || new_sz == 0) return 0;

	/* don't account for last (null) element */
	prev_sz = pfmon_option_base_size - sizeof(struct option);

	o = (char *)malloc(prev_sz + new_sz);
	if (o == NULL) return -1;

	/* do not copy null element at the end */
	memcpy(o, pfmon_cmd_options, prev_sz);

	/* copy starting at the previous last null element slot */
	memcpy(o+prev_sz, cmd, new_sz);

	/* 
	 * every new set of commands MUST be NULL terminated
	 */

	pfmon_cmd_options  = (struct option *)o;
	/*
	 * size of generic+pmu-specific options
	 * this is the base size for smpl module options
	 */
	pfmon_option_base_size = prev_sz + new_sz;

	//printf("added %ld pmu-specific options\n", (new_sz/sizeof(struct option))-1);
	//
	return 0;
}

static void
pfmon_detect(void)
{
	pfmon_support_t **p = pfmon_cpus;
	int type;

	pfm_get_pmu_type(&type);

	while (*p) {
		if ((*p)->pmu_type == type) break;
		p++;
	}

	if (*p == NULL) fatal_error("no detected PMU support type=%d\n", type);

	pfmon_current = *p;

	vbprintf("pfmon will use %s PMU support\n", (*p)->name);
}

/*
 * We use the command name as the hint for forced generic
 * mode. We cannot use an option because, the command line 
 * options depends on the detected support.
 */
static int
check_forced_generic(char *cmd)
{
	char *p;

	p = strrchr(cmd, '/');
	if (p) cmd = p + 1;

	return strcmp(cmd, PFMON_FORCED_GEN) ? 0 : 1;
}

/*
 * sym_type: PFMON_TEXT_SYMBOL, PFMON_DATA_SYMBOL
 */
static void 
parse_trigger_list(char *list, pfmon_sym_type_t sym_type,
		   pfmon_trigger_t *trg, pfmon_trigger_type_t brk_type,
		   unsigned int max, unsigned int *used)
{
	unsigned long addr;
	char *endptr, *p;
	unsigned int count = 0;
	int ret;

	while (list && count < max) {
		p = strchr(list, ',');
		if (p) *p = '\0';

		if (isdigit(*list)) {
			endptr = NULL;
			addr   = (uintptr_t)strtoul(list, &endptr, 0);
			if (*endptr != '\0') goto error_address;
		} else {
			ret = find_sym_addr(list, options.primary_syms, sym_type, &addr, NULL);
			if (ret) goto error_symbol;
		}
		if (p) *p++ = ',';

		trg->brk_address    = addr;
		trg->brk_type = brk_type;
		trg->brk_stop_idx = -1;

		trg++;

		count++;

		list = p;
	}

	if (list && count == max) goto error_many;

	*used = count;

	return;

error_symbol:
	fatal_error("cannot find address of symbol %s\n", list);
	/* no return */
error_address:
	fatal_error("invalid address %s\n", list);
	/* no return */
error_many:
	fatal_error("too many triggers defined, cannot use %s\n", list);
	/* no return */
}

/*
 * parse command line for --trigger options and stores in options
 * no symbol name resolution possible at this stage
 */
void
setup_trigger_addresses(void)
{
	pfmon_trigger_t *trg1, *trg2;
	uintptr_t addr;
	unsigned int count;
	unsigned int i, j;
	int rw;

	vbprintf("using %s breakpoints\n", options.opt_hw_brk ? "hardware" : "software");

	/*
	 * first entry for: entry, dlopen
	 */
	options.num_code_triggers = 1;
	trg1  = options.code_triggers+1;
	count = 0;

	if (options.code_trigger_start) {

		if (options.opt_code_trigger_repeat && options.code_trigger_stop == 0)
			fatal_error("cannot use --trigger-code-repeat without --trigger-code-stop & --trigger-code-start\n");

		parse_trigger_list(options.code_trigger_start,
				   PFMON_TEXT_SYMBOL, trg1,
				   PFMON_TRIGGER_START, 1, &count);
		/*
		 * we have some triggered start, therefore we do not start right away
		 */
		options.opt_dont_start = 1;
	}
	options.num_code_triggers += count;

	trg1 += count;
	count = 0;

	if (options.code_trigger_stop) {

		if (options.opt_code_trigger_repeat && options.code_trigger_start == 0)
			fatal_error("cannot use --trigger-code-repeat without --trigger-code-stop & --trigger-code-start\n");

		parse_trigger_list(options.code_trigger_stop,
				   PFMON_TEXT_SYMBOL, trg1,
				   PFMON_TRIGGER_STOP, 1, &count);
	}
	trg1 += count;
	options.num_code_triggers += count;

	/* -1 is for entry/dlopen */
	if (!options.nibrs || options.num_code_triggers > (options.nibrs-1))
		fatal_error("not enough code debug registers to fit all code triggers, max=%u\n", options.nibrs);

	trg1  = options.data_triggers;
	count = 0;

	if (options.data_trigger_start) {

		if (options.opt_data_trigger_repeat && options.data_trigger_stop == 0)
			fatal_error("cannot use --trigger-data-repeat without --trigger-data-stop & --trigger-data-start\n");

		parse_trigger_list(options.data_trigger_start,
				   PFMON_DATA_SYMBOL, trg1,
				   PFMON_TRIGGER_START, 1, &count);
		/*
		 * we have some triggered start, therefore we do not start right away
		 */
		options.opt_dont_start = 1;
	}
	options.num_data_triggers += count;

	trg1 += count;
	count = 0;

	if (options.data_trigger_stop) {

		if (options.opt_data_trigger_repeat && options.data_trigger_start == 0)
			fatal_error("cannot use --trigger-data-repeat without --trigger-data-stop & --trigger-data-start\n");

		parse_trigger_list(options.data_trigger_stop,
				   PFMON_DATA_SYMBOL, trg1,
				   PFMON_TRIGGER_STOP, 1, &count);
	}
	options.num_data_triggers += count;
	trg1 += count;

	if (options.num_data_triggers > options.ndbrs)
		fatal_error("not enough data debug registers to fit all code triggers, max=%u\n", options.ndbrs);

	/*
	 * checks on code triggers
	 */
	for (i=0; i < options.num_code_triggers; i++) {

		trg1     = options.code_triggers+i;
		addr     = trg1->brk_address;

		if (addr == 0)
			continue;

		if (pfmon_validate_code_trigger_address(addr))
			fatal_error("");

		/*
		 * scan list of triggers to find matching stop breakpoint,
		 * if so consider stop as dynamic stop, link two breakpoints
		 *
		 * XXX: fix code when number of breakpoints > 1
		 */
		if (trg1->brk_type == PFMON_TRIGGER_START) {

			/* 1 is due to reserved slot at index 0 */
			for (j=0; j < options.num_code_triggers; j++) {
				trg2 = options.code_triggers+j;
				if (j == i || trg2->brk_type != PFMON_TRIGGER_STOP)
					continue;
				if (trg2->brk_address == addr) {
					if (trg1->brk_stop_idx == -1) {
						trg1->brk_stop_idx = j;
						trg2->brk_address = 0; /* to be filled dynamically */
					} else 
						fatal_error("cannot  have twice the same code trigger %p %d %d\n", addr, trg1->brk_type, trg2->brk_type);
				}
			}
		}
	}

	/* propagate global attributes */
	for (i=0; i < options.num_code_triggers; i++) {
		options.code_triggers[i].trg_attr_repeat  = options.opt_code_trigger_repeat;
		options.code_triggers[i].trg_attr_inherit = options.opt_code_trigger_follow;
	}

	/* default RW */
	rw = 0x3;
	if (options.opt_data_trigger_ro)
		rw = 0x2;
	if (options.opt_data_trigger_wo)
		rw = 0x1;

	/*
	 * sanity checks on data triggers
	 */
	for (i=0; i < options.num_data_triggers; i++) {
		addr = options.data_triggers[i].brk_address;

		if (pfmon_validate_data_trigger_address(addr)) fatal_error("");

		for (j=0; j < options.num_data_triggers; j++) {
			if (j != i && options.data_triggers[j].brk_address == addr)
				fatal_error("cannot  have twice the same data trigger %p\n", addr);
		}
	}

	for (i=0; i < options.num_data_triggers; i++) {
		options.data_triggers[i].trg_attr_repeat  = options.opt_data_trigger_repeat;
		options.data_triggers[i].trg_attr_inherit = options.opt_data_trigger_follow;
		options.data_triggers[i].trg_attr_rw      = rw;

		vbprintf("%-5s data %s trigger @%p\n", 
			options.data_triggers[i].brk_type != PFMON_TRIGGER_STOP ? "start" : "stop",
			rw == 0x3 ? "read-write" : (rw == 0x1 ? "write-only" : "read-write"),
			(void *)options.data_triggers[i].brk_address);
	}
}

static void
__pfmon_show_event_info(unsigned int idx)
{
	pfmlib_regmask_t cnt, impl_cnt;
	char *desc;
	unsigned int n, i, c;
	int code;
	char name[PFMON_MAX_EVTNAME_LEN];

	pfm_get_event_name(idx, name, PFMON_MAX_EVTNAME_LEN);
	pfm_get_event_code(idx, &code);
	pfm_get_event_counters(idx, &cnt);
	pfm_get_num_counters(&n);
	pfm_get_impl_counters(&impl_cnt);

	printf("Name     : %s\n"
			"Code     : 0x%x\n"
			"Counters : [ "
			,
			name,
			code);

	for (i=0; n; i++) {
		if (pfm_regmask_isset(&impl_cnt, i))
			n--;
		if (pfm_regmask_isset(&cnt, i))
			printf("%d ", i);
	}
	puts("]");

	pfm_get_num_event_masks(idx, &n);
	pfm_get_event_description(idx, &desc);
 	printf("Desc     : %s\n", desc);
	free(desc);
	for (i = 0; n; n--, i++) {
		pfm_get_event_mask_description(idx, i, &desc);
		pfm_get_event_mask_name(idx, i, name, PFMON_MAX_EVTNAME_LEN);
		pfm_get_event_mask_code(idx, i, &c);
		printf("Umask-%02u : 0x%02x : [%s] : %s\n", i, c, name, desc);
		free(desc);
	}

	if (pfmon_current->pfmon_show_event_info)
		pfmon_current->pfmon_show_event_info(idx);

}

static int
pfmon_show_event_info(char *event)
{
	regex_t preg;
	int code, ret, found = 0;
	unsigned int i, c;
	char *p;
	unsigned long lcode;
	char name[PFMON_MAX_EVTNAME_LEN];

	if (isdigit(*event)) {

		/* using strotul() allows base auto-detection */
		lcode = strtoul(event, NULL, 0);
		if (lcode >= INT_MAX)
			fatal_error("invalid code %s\n", lcode);
		code = (int) lcode;

		ret = pfm_find_event_bycode(code, &c);
		if (ret != PFMLIB_SUCCESS)
			fatal_error("no event with code 0x%x\n", code);
		__pfmon_show_event_info(c);
		return 0;
	}
	p = strchr(event, ':');
	if (p)
		*p = '\0';

	if (regcomp(&preg, event, REG_ICASE|REG_NOSUB))
		fatal_error("error in regular expression for event \"%s\"\n", event);

	pfm_get_num_events(&c);
	for(i=0; i < c; i++) {
		pfm_get_event_name(i, name, PFMON_MAX_EVTNAME_LEN);
		if (regexec(&preg, name, 0, NULL, 0) == 0) {
			__pfmon_show_event_info(i);
			found = 1;
		}
	}
	if (!found)
		fatal_error("event \"%s\" not found\n", event);

	return 0;
}

static void
pfmon_show_info(void)
{
	unsigned int version, num_cnt;
	pfmon_support_t **supp;

	pfm_get_num_counters(&num_cnt);
	pfmon_print_simple_cpuinfo(stdout, "detected host CPUs: ");
	printf("detected PMU model: %s\n", pfmon_current->name ? pfmon_current->name : "None");
	printf("max counters/set: %u\n", num_cnt);
	printf("supported PMU models: ");
	for(supp = pfmon_cpus; *supp; supp++) {
		printf("[%s] ", (*supp)->name);
	}
	putchar('\n');
	pfmon_list_smpl_modules();
	pfm_get_version(&version);

	printf("pfmlib version: %u.%u\n", PFMLIB_MAJ_VERSION(version), PFMLIB_MIN_VERSION(version));
	if (options.pfm_version == 0)
		printf("kernel perfmon version: not available\n");
	else
		printf("kernel perfmon version: %u.%u\n", PFM_VERSION_MAJOR(options.pfm_version), PFM_VERSION_MINOR(options.pfm_version));

	printf("kernel clock resolution: %"PRIu64"ns (%.0fHz)\n",
		options.clock_res,
		1000000000.0 / options.clock_res);
}

static void
segv_handler(int n, struct siginfo *info, struct sigcontext *sc)
{
	pfmon_segv_handler_info(info, sc);
	pfmon_backtrace();
	fatal_error("pfmon got a fatal SIGSEGV signal\n");
}

static void
setup_common_signals(void)
{
	struct sigaction act;

	memset(&act,0,sizeof(act));
	act.sa_handler = (sig_t)segv_handler;
	sigaction (SIGSEGV, &act, 0);
}

static void
pfmon_initialize(char **argv)
{
	uint64_t long_val;
	pfmlib_event_t e;
	struct timespec ts;
	char *str;
	size_t len;
	unsigned int version;
	int ret;

	pfmon_get_version();

	/*
	 * check if kernel supports event sets
	 */
	if (options.pfm_version >= PERFMON_VERSION_22)
		options.opt_is22 = 1;

	pfmon_collect_affinity();

	/*
	 * must be done before pfm_initialize() on some arch (e.g., MIPS)
	 */
	pfmon_arch_initialize();

	setup_common_signals();

	if (pfm_initialize() != PFMLIB_SUCCESS) 
		fatal_error("cannot initialize library. Most likely host PMU is not supported.\n");

	pfm_get_version(&version);
	if (PFM_VERSION_MAJOR(version) < 3 || PFM_VERSION_MINOR(version) < 2)
		fatal_error("linked with libpfm v%u.%u, needs at least v3.2\n",
			PFM_VERSION_MAJOR(version),PFM_VERSION_MINOR(version));

	ret = pfm_get_pmu_type(&options.pmu_type);
	if (ret != PFMLIB_SUCCESS) {
		fatal_error("cannot determine PMU type\n");
	}

	ret = pfm_get_num_counters(&options.max_counters);
	if (ret != PFMLIB_SUCCESS) {
		fatal_error("cannot determine max counters\n");
	}

	if (check_forced_generic(argv[0])) {

		if (options.opt_support_gen == 0) 
			fatal_error("pfmon cannot be forced to generic mode\n");

		if (pfm_force_pmu(options.libpfm_generic) != PFMLIB_SUCCESS)
			fatal_error("failed to force  generic mode (support may not be available).\n");
	}

	pfmon_detect();

	options.session_timeout = PFMON_NO_TIMEOUT;
	options.warmup_time = PFMON_NO_TIMEOUT;
	options.interval = PFMON_NO_TIMEOUT;
	options.init_time = PFMON_NO_TIMEOUT;
	

	/*
	 * collect some system parameters
	 */
	long_val = sysconf(_SC_NPROCESSORS_ONLN);
	if (long_val == -1) 
		fatal_error("cannot figure out the number of online processors\n");

	options.online_cpus = long_val;

	long_val = sysconf(_SC_NPROCESSORS_CONF);
	if (long_val == -1) 
		fatal_error("cannot figure out the number of configured processors\n");

	options.config_cpus = long_val;

	clock_getres(CLOCK_MONOTONIC, &ts);
	options.clock_res  = ts.tv_sec * 1000000000 + ts.tv_nsec;
	options.page_size  = getpagesize();
	options.cpu_mhz    = pfmon_find_cpu_speed();

	pfm_get_max_event_name_len(&len);
	options.ev_name1 = malloc(len+len+1+1);
	if (!options.ev_name1)
		fatal_error("cannot allocate temporary event name buffers\n");

	options.ev_name2 = options.ev_name1+len+1;

	/*
	 * invoke model-specific initialization, if any
	 * (register model-specific options)
	 */
	if (pfmon_current->pfmon_initialize) 
		pfmon_current->pfmon_initialize();

	/*
	 * XXX: dropped opcode match config file for now
	 * load_config_file();
	 */

	/*
	 * must happen before pfmon_smpl_initialize()
	 */
	options.generic_pmu_type = pfmon_current->generic_pmu_type;

	/*
	 * initialize sampling subsystem (default module)
	 */
	pfmon_smpl_initialize();

	pfm_get_cycle_event(&e);
	str = malloc(len+1);
	if (!str)
		fatal_error("cannot create default set\n");
	pfm_get_full_event_name(&e, str, len+1);	
	/*
	 * create a default event set
	 */
	create_event_set(str);
}

static void
setup_plm(pfmon_event_set_t *set)
{
	char *arg;
	unsigned int cnt=0;
	int dfl_plm;
	int val;

	/*
	 * if not specified, force to defaut priv level
	 */
	dfl_plm = options.dfl_plm;
	if (dfl_plm == 0) {
		options.dfl_plm = dfl_plm = PFM_PLM3;
		vbprintf("measuring at %s privilege level ONLY\n", priv_level_str(dfl_plm));
	}

	for (set = options.sets; set; set = set->next) {

		/* set default privilege level: used when not explicitly specified for an event */
		set->inp.pfp_dfl_plm = dfl_plm;
		/*
		 * set default priv level for all events
		 */
		for(cnt=0; cnt < set->event_count; cnt++) {
			set->inp.pfp_events[cnt].plm = dfl_plm;
		}

		if (set->priv_lvl_str == NULL) continue;

		/*
		 * adjust using per-event settings
		 */
		for (cnt=0, arg = set->priv_lvl_str ; *arg; ) {
			if (cnt == set->event_count) goto too_many;
			val = 0;
			while (*arg && *arg != ',') {
				switch (*arg) {
					case 'k':
					case '0': val |= PFM_PLM0; break;
					case '1': val |= PFM_PLM1; break;
					case '2': val |= PFM_PLM2; break;
					case '3': 
					case 'u': val |= PFM_PLM3; break;
					default: goto error;
				}
				arg++;
			}
			if (*arg) arg++;

			if (val) {
				set->inp.pfp_events[cnt].plm = val;
			}
			cnt++;
		}
	}
	return;
error:
	fatal_error("unknown per-event privilege level %c ([ku0123])\n", *arg);
	/* no return */
too_many:
	fatal_error("too many per-event privilege levels specified, max=%d\n", set->inp.pfp_event_count);
	/* no return */
}

static int
pfmon_check_extra_options(int c, char *optarg)
{
	if (pfmon_current->pfmon_parse_options
	    && pfmon_current->pfmon_parse_options(c, optarg) == 0) {
		return 0;
	}

	if (options.smpl_mod && options.smpl_mod->parse_options) {
		return options.smpl_mod->parse_options(c, optarg);
	}
	return -1;
}

static void
populate_cpumask(char *cpu_list)
{
	char *p;
	int start_cpu, end_cpu = 0;
	int i, j, count = 0;

	if (cpu_list == NULL)  {
		/*
		 * The limit is mostly driven by the affinity support in NPTL and glibc __CPU_SETSIZE.
		 * the kernel interface does not expose any limitation.
	         */
		if (options.online_cpus >= PFMON_MAX_CPUS)
			fatal_error("pfmon can only handle to %u CPUs\n", PFMON_MAX_CPUS);

		for(i=0, j=0; i < options.online_cpus; i++) {
			if (pfmon_bitmask_isset(options.phys_cpu_mask, i)) {
				if (options.opt_vcpu) {
					pfmon_bitmask_set(options.virt_cpu_mask, j);
				} else {
					pfmon_bitmask_set(options.virt_cpu_mask, i);

				}
				j++;
			}
		}
		options.selected_cpus = j;
		goto end;
	} 

	if (!isdigit(*cpu_list))
		fatal_error("CPU range must start with a number\n");

	while(isdigit(*cpu_list)) { 
		p = NULL;
		start_cpu = strtoul(cpu_list, &p, 0); /* auto-detect base */

		if (start_cpu == ULONG_MAX || (*p != '\0' && *p != ',' && *p != '-')) goto invalid;

		if (*p == '-') {
			cpu_list = ++p;
			p = NULL;

			end_cpu = strtoul(cpu_list, &p, 0); /* auto-detect base */
			
			if (end_cpu == ULONG_MAX || (*p != '\0' && *p != ',')) goto invalid;
			if (end_cpu < start_cpu) goto invalid_range; 
		} else {
			end_cpu = start_cpu;
		}

		if (start_cpu >= options.online_cpus || end_cpu >= options.online_cpus) goto too_big;

		for (; start_cpu <= end_cpu; start_cpu++) {
			int phys_cpu;

			phys_cpu = pfmon_cpu_virt_to_phys(start_cpu);
			if (phys_cpu == -1)
				goto no_access;

			if(!pfmon_bitmask_isset(options.phys_cpu_mask, phys_cpu))
					goto no_access;

			pfmon_bitmask_set(options.virt_cpu_mask, start_cpu);

			count++;
		}

		if (*p) ++p;

		cpu_list = p;
	}

	options.selected_cpus = count;
end:
	if (options.opt_verbose) {
		vbprintf("selected CPUs (%lu CPU in set, %lu CPUs online): ",
			options.selected_cpus,
			options.online_cpus);

		count = options.selected_cpus;
		for(i=0; count;i++) {
			if (pfmon_bitmask_isset(options.virt_cpu_mask, i) == 0) continue;
			vbprintf("CPU%lu ", i);
			count--;
		}
		vbprintf("\n");
	}
	return;
invalid:
	fatal_error("invalid cpu list argument: %s\n", cpu_list);
	/* no return */
invalid_range:
	fatal_error("cpu range %lu - %lu is invalid\n", start_cpu, end_cpu);
	/* no return */
too_big:
	fatal_error("CPU range goes beyond number of available processors\n", PFMON_MAX_CPUS);
	/* no return */
no_access:
	fatal_error("CPU%d is not accessible from your CPU set\n", start_cpu);
	/* no return */
}



static void
pfmon_verify_cmdline_options(int argc, char **argv)
{
	int has_code_data_triggers = 0;


	if (optind == argc && options.opt_syst_wide == 0 && options.opt_check_evt_only == 0 && options.opt_attach == 0)
		fatal_error("you need to specify a command to measure\n");

	if (options.opt_attach && optind != argc) 
		fatal_error("you cannot attach to a task AND launch a program to monitor at the same time\n");

	/*
 	 * propagate in case all needs to be activated
 	 */
	if (options.opt_follow_all) {
		options.opt_follow_exec  = 1;
		options.opt_follow_vfork =
		options.opt_follow_fork  =
		options.opt_follow_pthread = 1;
		options.opt_follows = 1;
	} else if (options.opt_follow_fork
		  || options.opt_follow_vfork
		  || options.opt_follow_pthread
		  || options.opt_follow_exec) {
		options.opt_follows = 1;
	}

	if (options.code_trigger_start
	  || options.data_trigger_start
	  || options.code_trigger_stop
	  || options.data_trigger_stop)
		has_code_data_triggers = 1;


	if (options.opt_syst_wide) {

		populate_cpumask(options.cpu_list);

		if (optind != argc && options.session_timeout != PFMON_NO_TIMEOUT)
			fatal_error("you cannot use both a timeout and command in system-wide mode\n");

		if (options.opt_block == 1) 
			fatal_error("cannot use blocking mode in system wide monitoring\n");

		if (options.code_trigger_start)
			fatal_error("cannot use a code trigger start address in system wide mode\n");

		if (options.data_trigger_start)
			fatal_error("cannot use a data trigger start address in system wide mode\n");

		if (options.code_trigger_stop)
			fatal_error("cannot use a code trigger stop address in system wide mode\n");

		if (options.data_trigger_stop)
			fatal_error("cannot use a data trigger stop address in system wide mode\n");

		if (options.opt_follow_exec || options.opt_follow_fork || options.opt_follow_vfork || options.opt_follow_pthread)
			warning("no --follow-* option has any effect in system-wide mode\n");

		if (options.opt_split_exec)
			warning("--exec-split has not effect in system-wide mode\n");

		if (options.opt_aggr && options.interval != PFMON_NO_TIMEOUT)
			fatal_error("--print-interval is not supported with --aggregate-results\n");
	} else {
		/* wait4 use RUSAGE_BOTH */
		if (options.opt_show_rusage && (options.opt_follow_fork || options.opt_follow_vfork || options.opt_follow_pthread))
			fatal_error("show-time cannot be used when following execution across fork/vfork/clone\n");

		if (options.opt_data_trigger_ro && options.opt_data_trigger_wo)
			fatal_error("cannot use --data-trigger-ro and --data-trigger-wo at the same time\n");

		//if (options.opt_split_exec && options.opt_follow_all == 0 && options.opt_follow_exec == 0)
		//	fatal_error("the --exec-split option can only be used in conjunction with --follow-all or --follow-exec\n");

		if (options.trigger_delay)
			fatal_error("cannot use --trigger-start-delay in per-task mode\n");

		if (options.opt_follow_exec && options.opt_split_exec && options.opt_addr2sym) 
			warning("only resolving symbols from first program (binary)\n");
		
		if (options.opt_split_exec && options.opt_follow_exec == 0) {
			warning("--exec-split is ignored, you need to use --follow-exec to activate\n");
			options.opt_split_exec = 0;
		}

		if (options.opt_follow_exec && has_code_data_triggers && (options.opt_code_trigger_follow ||options.opt_data_trigger_follow) )
			fatal_error("cannot use code/data trigger follow with --follow-exec option\n");
		if (options.interval != PFMON_NO_TIMEOUT)
			fatal_error("--print-interval is not supported in per-thread mode\n");
	}

	/*
	 * invoke model specific checker (abort if error found)
	 */
	if (pfmon_current->pfmon_verify_cmdline)
		pfmon_current->pfmon_verify_cmdline(argc, argv);


	if (options.opt_attach) {
		if (options.opt_syst_wide)
			fatal_error("cannot attach to a process in system-wide mode\n");
		if (optind != argc) 
			warning("command is ignored when attaching to a task\n");
		if (options.opt_show_rusage)
			fatal_error("--show-time does not work when attaching to a task\n");
	}

	/*
	 * try to use the command to get the symbols
	 * XXX: require absolute path
	 */
	if (options.symbol_file == NULL) options.symbol_file = argv[optind];

	/* default we print all samples */
	if (options.smpl_cum_thres == 0)
		options.smpl_cum_thres = 100;
}

void
pfmon_verify_event_sets(void)
{
	if (options.nsets > 1 && options.opt_is22 == 0) 
		fatal_error("kernel has no support for event sets, you cannot have more than one set\n");

	/*
	 * does not return in case of error
	 */
	if (pfmon_current->pfmon_verify_event_sets)
		pfmon_current->pfmon_verify_event_sets();
}

static void
pfmon_setup_event_sets(uint64_t switch_timeout)
{
	pfmon_event_set_t *set;
	uint64_t p, pns;

	if (options.nsets > 1) {
		if (!switch_timeout)
			fatal_error("switch timeout required with multiple sets, use --switch-timeout\n");

		/* scale from milliseconds to nanoseconds */
		pns = switch_timeout * 1000000;
		p = options.clock_res * ((pns + options.clock_res-1)/options.clock_res);
		vbprintf("p=%"PRIu64"\n", p);
		if (p != pns) {
			warning("due to clock resolution, timeout forced to %.3fms\n", (double)p/1000000);
		}
		options.switch_timeout = p;
	}

	for(set = options.sets; set; set = set->next) {

		setup_event_set(set);
		setup_plm(set);

		if (set->mod_inp && pfmon_current->pfmon_setup) {
			if (pfmon_current->pfmon_setup(set) == -1) fatal_error("");
		}
	}
}

static void
pfmon_convert_dfl_set(void)
{
	pfmon_event_set_t *nset, *oset;

	nset = options.sets->next;
	oset = options.sets;

	/*
 	 * copy model specific data structures
 	 * to capture any model-sepcific options already set
 	 */
	memcpy(nset + 1, oset + 1, pfmon_current->sz_mod_args
				 + pfmon_current->sz_mod_inp
				 + pfmon_current->sz_mod_outp);

	nset->priv_lvl_str = oset->priv_lvl_str;
	nset->long_smpl_args = oset->long_smpl_args;
	nset->short_smpl_args = oset->short_smpl_args;
	nset->random_smpl_args = oset->random_smpl_args;
	nset->xtra_smpl_pmds_args = oset->xtra_smpl_pmds_args;

	/*
 	 * shorten the list by removing old set
 	 */
	options.sets = nset;

	/*
 	 * override new set id
 	 */
	nset->id = 0;
	/*
 	 * one less set in the list
 	 */
	options.nsets--;

	free(oset->events_str);
	free(oset);
}

int
main(int argc, char **argv)
{
	pfmlib_options_t 	pfmlib_options;
	char 			*endptr = NULL;
	pfmon_smpl_module_t	*smpl_mod = NULL;
	unsigned long 		long_val;
	uint64_t		switch_timeout = 0;
	int 			c, r, ret;
	int			using_def_set = 1;

	memset(&pfmlib_options, 0, sizeof(pfmlib_options));

	pfmon_initialize(argv);

	while ((c=getopt_long(argc, argv,"+0123kuvhe:Il::L::i:Vt:S:p:w:", pfmon_cmd_options, 0)) != -1) {
		switch(c) {
			case   0: continue; /* fast path for options */

			case 'v': options.opt_verbose = 1;
				  break;

			case   1:
			case 'i':
				exit(pfmon_show_event_info(optarg));

			case   2:
			case 'l':
				pfmon_list_all_events(optarg, 0);
				exit(0);
			case '1':
				options.dfl_plm |= PFM_PLM1;
				break;

			case '2':
				options.dfl_plm |= PFM_PLM2;
				break;
			case '3':
 			case   4:
 			case 'u':
				options.dfl_plm |= PFM_PLM3;
				break;

			case '0':
			case   3:
			case 'k':
				options.dfl_plm |= PFM_PLM0;
				break;

			case   5:
			case 'e': 
				create_event_set(optarg);

				if (using_def_set) {
					pfmon_convert_dfl_set();
					using_def_set = 0;
					/*
					 * XXX: would need to free PMU specific
					 * struct
					 */
				}
				break;

			case   6:
			case 'h':
				usage(argv);
				exit(0);

			case 'V':
			case   7:
				printf("pfmon version " PFMON_VERSION " Date: " __DATE__ "\n"
					"Copyright (C) 2001-2007 Hewlett-Packard Company\n");
				exit(0);

			case   8:
				options.outfile = optarg;
				break;

			case 'L':
			case   9:
				pfmon_list_all_events(optarg, 1);
				exit(0);

			case  10:
			case 'I':
				pfmon_show_info();
				exit(0);
			case  11:
				if (options.smpl_entries) 
					fatal_error("smpl-entries already defined\n");

				options.smpl_entries = strtoul(optarg, &endptr, 0);
				if (*endptr != '\0') 
					fatal_error("invalid number of entries: %s\n", optarg);
				break;

			case  12:
				if (options.smpl_outfile) fatal_error("sampling output file specificed twice\n");
				options.smpl_outfile = optarg;
				break;

			case  13:
				if (options.last_set == NULL) fatal_error("first, you need to define an event set with -e\n");
				if (options.last_set->long_smpl_args) fatal_error("long sampling rates specificed twice\n");
				options.last_set->long_smpl_args = optarg;
				options.opt_use_smpl =1;
				break;

			case  14:
				if (options.last_set == NULL) fatal_error("first,you need to define an event set with -e\n");
				if (options.last_set->short_smpl_args) fatal_error("short sampling rates specificed twice\n");
				options.last_set->short_smpl_args = optarg;
				options.opt_use_smpl =1;
				break;

			case 15:
				fatal_error("--cpu-mask obsolete option, use --cpu-list instead\n");
				break;

			case 't':
			case 16 :
				if (options.session_timeout != PFMON_NO_TIMEOUT)
						fatal_error("too many session timeouts\n");
				if (*optarg == '\0')
					fatal_error("--session-timeout needs an argument\n");

			  	long_val = strtoul(optarg,&endptr, 10);
				if (*endptr != '\0') 
					fatal_error("invalid number of seconds for session timeout: %s\n", optarg);

				if (long_val >= UINT_MAX) 
					fatal_error("timeout is too big, must be < %u\n", UINT_MAX);

				options.session_timeout = long_val;
				break;

			case 17 :
				fatal_error("--trigger-address is obsolete, use --trigger-code-start-address instead\n");
				break;

			case 18 :
				if (options.last_set == NULL) fatal_error("first, you need to define an event set with -e\n");
				if (options.last_set->priv_lvl_str) fatal_error("per event privilege levels already defined");
				options.last_set->priv_lvl_str = optarg;
				break;

			case 19 :
				if (options.symbol_file) {
					if (options.opt_sysmap_syms)
						fatal_error("Cannot use --sysmap-file and --symbol-file at the same time\n");
					fatal_error("symbol file already defined\n");
				}
				if (*optarg == '\0') fatal_error("you must provide a filename for --symbol-file\n");

				options.symbol_file = optarg;
				break;

			case 20:
				if (*optarg == '\0') fatal_error("--smpl-module needs an argument\n");
				/*
				 * check if the user already specified a format, but we can override default
				 */
				if (options.smpl_mod && smpl_mod)
					fatal_error("sampling output format already defined\n");

				r = pfmon_find_smpl_module(optarg, &smpl_mod, 0);
				if (r == -1)
					fatal_error("invalid sampling output format %s\n", optarg);

				/* 
				 * initialize module right away to register options, among other things
				 */
				if (smpl_mod->initialize_module && (*smpl_mod->initialize_module)() != 0) {
					fatal_error("failed to intialize sampling module%s\n", smpl_mod->name);
				}
				options.smpl_mod = smpl_mod;
				break;

			case 'S':
			case 21 : 
				  if (*optarg == '\0') fatal_error("--smpl-module-info needs an argument\n");
				  r = pfmon_find_smpl_module(optarg, &smpl_mod, 1);
				  if (r != PFMLIB_SUCCESS)
					fatal_error("invalid sampling output format %s: %s\n", optarg, pfm_strerror(r));
				  pfmon_smpl_module_info(smpl_mod);
				  exit(0);

			case 22 : 
				/* 
				 * Despite /proc/kallsyms, System.map is still useful because it includes data symbols
				 */
				if (options.symbol_file) {
					if (options.opt_sysmap_syms == 0)
						fatal_error("Cannot use --sysmap-file and --symbol-file at the same time\n");
					fatal_error("sysmap file already defined\n");
				}
				if (*optarg == '\0') fatal_error("you must provide a filename for --sysmap-file\n");
				options.opt_sysmap_syms = 1;
				options.symbol_file     = optarg;
				break;

			case 23 :
				if (options.last_set == NULL) fatal_error("first, you need to define an event set with -e\n");
				if (options.last_set->random_smpl_args) fatal_error("randomization parameters specified twice\n");
				options.last_set->random_smpl_args = optarg;
				break;

			case 24 : 
				if (options.trigger_delay) fatal_error("cannot use a code trigger start address with a trigger delay\n");
				if (options.code_trigger_start) fatal_error("code trigger start specificed twice\n");
				if (*optarg == '\0') fatal_error("--trigger-code-start needs an argument\n");
				options.code_trigger_start = optarg;
				break;

			case 25 :
				if (options.code_trigger_start || options.code_trigger_stop) 
					fatal_error("cannot use a trigger delay with a trigger code\n");

				if (options.trigger_delay) fatal_error("trigger start address specificed twice\n");
				if (*optarg == '\0') fatal_error("--trigger-start-delay needs an argument\n");
				long_val = strtoul(optarg,&endptr, 10);
				if (*endptr != '\0') 
					fatal_error("invalid trigger delay : %s\n", optarg);
				if (long_val >= UINT_MAX) 
					fatal_error("trigger delay is too big, must be < %u\n", UINT_MAX);

				options.trigger_delay = (unsigned int)long_val;
				break;

			case 'p':
			case 26 :
				if (options.opt_attach) {
					fatal_error("attach-task or -p specified more than once\n");
				}
				if (*optarg == '\0') fatal_error("you must provide a thread/process id with --attach-task or -p\n");
				options.opt_attach = 1;
				options.attach_tid = atoi(optarg);
				break;

			case 27 :
				if (options.fexec_pattern) fatal_error("cannot have two patterns for --follow-exec\n");
				options.fexec_pattern   = optarg;
				options.opt_follow_exec = 1;
				break;

			case 28 :
				if (options.fexec_pattern) fatal_error("cannot have an exclude pattern and a pattern for --follow-exec\n");
				if (*optarg == '\0') fatal_error("--follow-exec-exlcude needs an argument\n");
				options.fexec_pattern 	     = optarg;
				options.opt_follow_exec      = 1;
				options.opt_follow_exec_excl = 1;
				break;

			case 29 : 
				if (options.trigger_delay) fatal_error("cannot use a code trigger stop address with a trigger delay\n");
				if (options.code_trigger_stop) fatal_error("code trigger stop specificed twice\n");
				if (*optarg == '\0') fatal_error("--trigger-code-stop needs an argument\n");
				options.code_trigger_stop = optarg;
				break;

			case 30 :
				if (options.cpu_list) fatal_error("cannot specify --cpu-list more than once\n");
				if (*optarg == '\0') fatal_error("--cpu-list needs an argument\n");
				options.cpu_list = optarg;
				break;

			case 31: 
				if (options.trigger_delay) fatal_error("cannot use a code trigger start address with a trigger delay\n");
				if (options.data_trigger_start) fatal_error("data trigger start specificed twice\n");
				if (*optarg == '\0') fatal_error("--trigger-data-start needs an argument\n");
				options.data_trigger_start = optarg;
				break;

			case 32 : 
				if (options.trigger_delay) fatal_error("cannot use a code trigger stop address with a trigger delay\n");
				if (options.data_trigger_stop) fatal_error("data trigger stop specificed twice\n");
				if (*optarg == '\0') fatal_error("--trigger-data-stop needs an argument\n");
				options.data_trigger_stop = optarg;
				break;

			case 33 : 
				long_val = strtoull(optarg,&endptr, 10);
				if (*endptr != '\0') 
					fatal_error("invalid number of milliseconds for print interval: %s\n", optarg);
				options.interval = long_val;
				break;
			case 35 :
				if (switch_timeout) fatal_error("too many switch timeouts\n");
			  	switch_timeout = strtoull(optarg,&endptr, 10);
				if (*endptr != '\0') 
					fatal_error("invalid number of milliseconds for switch timeout: %s\n", optarg);

				break;
			case 36 :
				if (options.smpl_show_top) 
					fatal_error("--smpl-show-top already defined\n");
				options.smpl_show_top = strtoul(optarg, &endptr, 0);
				if (*endptr != '\0')
					fatal_error("invalid value for --smpl-show-top : %s\n", optarg);
				break;
			case 37 :
				if (options.last_set == NULL)
					fatal_error("you need to define an event set first\n");

				if (options.last_set->xtra_smpl_pmds_args)
					fatal_error("cannot specify --extra-smpl-pmds -list more than once per set\n");

				if (*optarg == '\0') fatal_error("--extra-smpl-pmds -list needs an argument\n");
				options.last_set->xtra_smpl_pmds_args = optarg;
				break;
			case 38 : 
				if (options.smpl_cum_thres) 
					fatal_error("--smpl-cum-threshold already defined\n");

				options.smpl_cum_thres = strtoul(optarg, &endptr, 0);

				if (options.smpl_cum_thres > 100 || options.smpl_cum_thres < 1)
					fatal_error("--smpl-cum-threshold must be between 1 and 100\n");
				break;
			case 'w':
			case 39:
				if (options.warmup_time != PFMON_NO_TIMEOUT)
						fatal_error("too many warmup periods\n");
				if (*optarg == '\0')
					fatal_error("--warmup needs an argument\n");
			  	long_val = strtoul(optarg, &endptr, 10);
				if (*endptr != '\0') 
					fatal_error("invalid number of seconds for warmup period: %s\n", optarg);
				if (long_val >= UINT_MAX) 
					fatal_error("warmup period is too big, must be < %u\n", UINT_MAX);
			    	options.warmup_time = long_val;
			    	break;
			case 40:
				if (options.init_time != PFMON_NO_TIMEOUT)
						fatal_error("too many init-time periods\n");
				if (*optarg == '\0')
					fatal_error("--init-time needs an argument\n");
			  	long_val = strtoul(optarg, &endptr, 10);
				if (*endptr != '\0') 
					fatal_error("invalid number of seconds for init-time period: %s\n", optarg);
				if (long_val >= UINT_MAX) 
					fatal_error("init-time period is too big, must be < %u\n", UINT_MAX);
			    	options.init_time = long_val;
			    	break;
			default:
				if (pfmon_check_extra_options(c, optarg)) fatal_error("");
		}
	}

	if (PFM_VERSION_MAJOR(options.pfm_version) !=  PFM_VERSION_MAJOR(PFM_VERSION)) {
		if (options.pfm_version == 0)
			fatal_error("host kernel is missing perfmon support or /sys is not available\n");

		fatal_error("perfmon version mismatch, kernel is %u.%u, pfmon needs %u.x\n", 
			    PFM_VERSION_MAJOR(options.pfm_version),
			    PFM_VERSION_MINOR(options.pfm_version),
			    PFM_VERSION_MAJOR(PFM_VERSION));
	}
	pfmon_verify_cmdline_options(argc, argv);
	pfmon_verify_event_sets();

	load_kernel_syms();

	if(options.opt_syst_wide)
		attach_kernel_syms(&options.primary_syms);

	pfmon_setup_event_sets(switch_timeout);
	vbprintf("%u event set(s) defined\n", options.nsets);

	pfmon_setup_sampling_rates();

	/*
	 * propagate debug/verbose options to library
	 */
	if (options.opt_debug)
		pfmlib_options.pfm_debug   = 1;
	if (options.opt_verbose)
		pfmlib_options.pfm_verbose = 1;

	pfm_set_options(&pfmlib_options);

	/*
	 * if attached, setup trigger addresses now
	 * otherwise deferred until we hit the entry
	 * breakpoint
	 */
	if (options.opt_attach)
		setup_trigger_addresses();

	/* used in sampling output header */
	options.argv    = argv;
	options.command = argv+optind;

	/*
	 * if sampling, then check that the sampling module support the
	 * kind of measurement that is requested.
	 *
	 * This is meant to check the command line options of pfmon
	 * as visible via the options data structure.
	 *
	 * At this point we know that if opt_use_smpl is set then we have
	 * a valid sampling module pointed to be smpl_mod.
	 */
	if (options.opt_use_smpl && options.smpl_mod->validate_options) {
		ret = (*options.smpl_mod->validate_options)();
		if (ret) return ret;
	}
	return run_measurements(argv+optind);
}
