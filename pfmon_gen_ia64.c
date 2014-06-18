/*
 * pfmon_generic_ia64.c - generic IA-64 PMU support for pfmon
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

#include <perfmon/pfmlib.h>

typedef struct {
	struct {
		int opt_insecure;	/* allow rum/sum in task mode */
	} pfmon_gen_opt_flags;
} pfmon_gen_options_t;

#define opt_insecure		pfmon_gen_opt_flags.opt_insecure

static pfmon_gen_options_t pfmon_gen_opt;	/* keep track of global program options */
/*
 * This table is used to ease the overflow notification processing
 * It contains a reverse index of the events being monitored.
 * For every hardware counter it gives the corresponding programmed event.
 * This is useful when you get the raw bitvector from the kernel and need
 * to figure out which event it correspond to.
 *
 * This needs to be global because access from the overflow signal
 * handler.
 */

static void
pfmon_gen_verify_event_sets(void)
{
	pfmon_event_set_t *set;

	if (options.opt_syst_wide == 0) {
		for(set = options.sets; set; set = set->next) {
			if (set->set_flags & PFM_ITA_SETFL_EXCL_INTR) {
				fatal_error("excl-intr is not available for per-task measurement\n");
			}
			if (set->set_flags & PFM_ITA_SETFL_INTR_ONLY) {
				fatal_error("intr-only is not available for per-task measurement\n");
			}
		}
	}
}

static void
pfmon_gen_verify_cmdline(int argc, char **argv)
{
	if (pfmon_gen_opt.opt_insecure) {
		if (options.opt_is22 == 0)
			fatal_error("the --insecure option requires at least perfmon v2.2\n");
	}
}

/*
 * Generic IA-64 PMU specific options
 *
 * 000-255   reserved for generic options
 * 400-499   reserved for PMU specific options
 * 500-599   reserved for format specific options
 */
static struct option cmd_gen_options[]={
	{ "excl-intr", 0, 0, 400},
	{ "intr-only", 0, 0, 401},
	{ "insecure", 0, &pfmon_gen_opt.opt_insecure, 0x1},
	{ 0, 0, 0, 0}
};

static void
pfmon_gen_usage(void)
{
	printf( "--insecure\t\t\t\tAllow rum/sum in monitored task\n"
		"\t\t\t\t\t (per-thread mode only).\n"
		"--excl-intr\t\t\t\tExclude interrupt-triggered execution\n"
		"\t\t\t\t\t from system-wide measurement.\n"
		"--intr-only\t\t\t\tInclude only interrupt-triggered\n"
		"\t\t\t\t\t execution from system-wide measurement.\n"
	);
}

static int
pfmon_gen_setup_ctx_flags(pfmon_ctx_t *ctx)
{
	if (pfmon_gen_opt.opt_insecure)
		ctx->ctx_flags |= PFM_ITA_FL_INSECURE;
	return 0;
}
/*
 * 0  means we understood the option
 * -1 unknown option
 */
static int
pfmon_gen_parse_options(int code, char *optarg)
{
	pfmon_event_set_t *set;

	set = options.last_set;

	switch(code) {
		case  400:
			if (set->set_flags & PFM_ITA_SETFL_INTR_ONLY)
				fatal_error("cannot combine --excl-intr with --intr-only\n");
			set->set_flags |= PFM_ITA_SETFL_EXCL_INTR;
			break;
		case 401 :
			if (set->set_flags & PFM_ITA_SETFL_EXCL_INTR)
				fatal_error("cannot combine --excl-intr with --intr-only\n");
			set->set_flags |= PFM_ITA_SETFL_INTR_ONLY;
			break;
		default:
			return -1;
	}
	return 0;
}

static int
pfmon_gen_initialize(void)
{
	int r;

	r = pfmon_register_options(cmd_gen_options, sizeof(cmd_gen_options));
	if (r == -1) return -1;

	/* connect pfmon model specific options */
	options.model_options = &pfmon_gen_opt;

	return 0;
}

pfmon_support_t pfmon_generic_ia64={
	.name             	 = "generic IA-64",
	.pmu_type         	 = PFMLIB_GEN_IA64_PMU,
	.pfmon_verify_event_sets = pfmon_gen_verify_event_sets,
	.pfmon_verify_cmdline	= pfmon_gen_verify_cmdline,
	.pfmon_usage		 = pfmon_gen_usage,	
	.pfmon_parse_options	 = pfmon_gen_parse_options,
	.pfmon_initialize	 = pfmon_gen_initialize,		
	.pfmon_setup_ctx_flags	 = pfmon_gen_setup_ctx_flags,
};
