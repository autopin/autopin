/*
 * pfmon_mips64.c - MIPS64 PMU support for pfmon
 *
 * Copyright (c) 2005-2006 Hewlett-Packard Development Company, L.P.
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
#include "pfmon.h"

#include <ctype.h>
#include <perfmon/pfmlib_gen_mips64.h>

#include "pfmon_mips64.h"

static pfmon_mips64_options_t pfmon_mips64_opt;	/* keep track of global program options */

static void
pfmon_mips64_setup_cnt_mask(pfmon_event_set_t *set)
{
	pfmlib_gen_mips64_input_param_t *param = set->mod_inp;
	pfmon_mips64_args_t *args;
	char *cnt_mask_str;
	char *p;
	unsigned int cnt_mask;
	unsigned int cnt=0;
	unsigned int i;

	args = set->mod_args;

	cnt_mask_str = args->cnt_mask_arg;

	/*
	 * the default value for cnt_mask is 0: this means at least once 
	 * per cycle.
	 */
	if (cnt_mask_str == NULL) {
		for (i=0; i < set->event_count; i++)
			param->pfp_gen_mips64_counters[i].cnt_mask = 0;
		return;
	}

	while (cnt_mask_str) {

		if (cnt == options.max_counters || cnt == set->event_count)
			goto too_many;

		p = strchr(cnt_mask_str,',');

		if ( p ) *p++ = '\0';

		cnt_mask = atoi(cnt_mask_str);

		if (cnt_mask < 0 || cnt_mask >255) goto invalid;

		param->pfp_gen_mips64_counters[cnt++].cnt_mask= cnt_mask;

		cnt_mask_str = p;
	}
	return;
invalid:
	fatal_error("event %d: counter mask must be in [0-256)\n", cnt);
too_many:
	fatal_error("too many counter masks specified\n");
}

static int
pfmon_mips64_prepare_registers(pfmon_event_set_t *set)
{
	return 0;
}

static int
pfmon_mips64_install_pmc_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	return 0;
}

static int
pfmon_mips64_install_pmd_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	return 0;
}

static void
pfmon_mips64_usage(void)
{
	printf( "--counter-mask=msk1,msk2,...\t\tSet event counter mask (0,1,2,3).\n");
}

/*
 * I386-P6-specific options
 *
 * 000-255   reserved for generic options
 * 400-499   reserved for PMU specific options
 * 500-599   reserved for format specific options
 */
static struct option cmd_mips64_options[]={
	{ "counter-mask", 1, 0, 400 },
	{ 0, 0, 0, 0}
};

static int
pfmon_mips64_initialize(void)
{
	int r;

	r = pfmon_register_options(cmd_mips64_options, sizeof(cmd_mips64_options));
	if (r == -1) return -1;

	/* connect pfmon model specific options */
	options.model_options = &pfmon_mips64_opt;

	return 0;
}

/*
 * 0  means we understood the option
 * -1 unknown option
 */
static int
pfmon_mips64_parse_options(int code, char *optarg)
{
	pfmon_mips64_args_t *mips64_args;
	pfmon_event_set_t *set;

	set = options.last_set;

	mips64_args = set->mod_args;

	switch(code) {
		case  400:
			if (mips64_args->cnt_mask_arg) fatal_error("counter masks already defined\n");
				mips64_args->cnt_mask_arg = optarg;
			break;
		default:
			return -1;
	}
	return 0;
}

static int
pfmon_mips64_setup(pfmon_event_set_t *set)
{
	pfmon_mips64_args_t *mips64_args;

	mips64_args = set->mod_args;

	if (mips64_args == NULL) return 0;

	
	/* 
	 * we systematically initialize thresholds to their minimal value
	 * or requested value
	 */
	pfmon_mips64_setup_cnt_mask(set);

	return 0;
}

static int
pfmon_mips64_print_header(FILE *fp)
{
	return 0;
}

static int
pfmon_mips64_setup_ctx_flags(pfmon_ctx_t *ctx)
{
	return 0;
}

static void
pfmon_mips64_verify_cmdline(int argc, char **argv)
{
	if (options.data_trigger_start)
		fatal_error("the --trigger-data-start option is not supported by this processor\n");
	if (options.data_trigger_stop)
		fatal_error("the --trigger-data-stop option is not supported by this processor\n");
	if (options.opt_data_trigger_ro)
		fatal_error("the --trigger-data-ro option is not supported by this processor\n");
}

pfmon_support_t pfmon_mips64_20kc={
	.name				= "MIPS 20KC",
	.pmu_type			= PFMLIB_MIPS_20KC_PMU,
	.pfmon_initialize		= pfmon_mips64_initialize,		
	.pfmon_usage			= pfmon_mips64_usage,	
	.pfmon_parse_options		= pfmon_mips64_parse_options,
	.pfmon_setup			= pfmon_mips64_setup,
	.pfmon_prepare_registers	= pfmon_mips64_prepare_registers,
	.pfmon_install_pmc_registers	= pfmon_mips64_install_pmc_registers,
	.pfmon_install_pmd_registers	= pfmon_mips64_install_pmd_registers,
	.pfmon_print_header		= pfmon_mips64_print_header,
	.pfmon_setup_ctx_flags		= pfmon_mips64_setup_ctx_flags,
	.pfmon_verify_cmdline		= pfmon_mips64_verify_cmdline,
	.sz_mod_args			= sizeof(pfmon_mips64_args_t),
	.sz_mod_inp			= sizeof(pfmlib_gen_mips64_input_param_t)
};
pfmon_support_t pfmon_mips64_25kf={
	.name				= "MIPS 25KF",
	.pmu_type			= PFMLIB_MIPS_25KF_PMU,
	.pfmon_initialize		= pfmon_mips64_initialize,		
	.pfmon_usage			= pfmon_mips64_usage,	
	.pfmon_parse_options		= pfmon_mips64_parse_options,
	.pfmon_setup			= pfmon_mips64_setup,
	.pfmon_prepare_registers	= pfmon_mips64_prepare_registers,
	.pfmon_install_pmc_registers	= pfmon_mips64_install_pmc_registers,
	.pfmon_install_pmd_registers	= pfmon_mips64_install_pmd_registers,
	.pfmon_print_header		= pfmon_mips64_print_header,
	.pfmon_setup_ctx_flags		= pfmon_mips64_setup_ctx_flags,
	.pfmon_verify_cmdline		= pfmon_mips64_verify_cmdline,
	.sz_mod_args			= sizeof(pfmon_mips64_args_t),
	.sz_mod_inp			= sizeof(pfmlib_gen_mips64_input_param_t)
};
pfmon_support_t pfmon_mips64_ice9b={
	.name				= "SiCortex ICE9B",
	.pmu_type			= PFMLIB_MIPS_ICE9B_PMU,
	.pfmon_initialize		= pfmon_mips64_initialize,		
	.pfmon_usage			= pfmon_mips64_usage,	
	.pfmon_parse_options		= pfmon_mips64_parse_options,
	.pfmon_setup			= pfmon_mips64_setup,
	.pfmon_prepare_registers	= pfmon_mips64_prepare_registers,
	.pfmon_install_pmc_registers	= pfmon_mips64_install_pmc_registers,
	.pfmon_install_pmd_registers	= pfmon_mips64_install_pmd_registers,
	.pfmon_print_header		= pfmon_mips64_print_header,
	.pfmon_setup_ctx_flags		= pfmon_mips64_setup_ctx_flags,
	.pfmon_verify_cmdline		= pfmon_mips64_verify_cmdline,
	.sz_mod_args			= sizeof(pfmon_mips64_args_t),
	.sz_mod_inp			= sizeof(pfmlib_gen_mips64_input_param_t)
};
pfmon_support_t pfmon_mips64_ice9a={
	.name				= "SiCortex ICE9A",
	.pmu_type			= PFMLIB_MIPS_ICE9A_PMU,
	.pfmon_initialize		= pfmon_mips64_initialize,		
	.pfmon_usage			= pfmon_mips64_usage,	
	.pfmon_parse_options		= pfmon_mips64_parse_options,
	.pfmon_setup			= pfmon_mips64_setup,
	.pfmon_prepare_registers	= pfmon_mips64_prepare_registers,
	.pfmon_install_pmc_registers	= pfmon_mips64_install_pmc_registers,
	.pfmon_install_pmd_registers	= pfmon_mips64_install_pmd_registers,
	.pfmon_print_header		= pfmon_mips64_print_header,
	.pfmon_setup_ctx_flags		= pfmon_mips64_setup_ctx_flags,
	.pfmon_verify_cmdline		= pfmon_mips64_verify_cmdline,
	.sz_mod_args			= sizeof(pfmon_mips64_args_t),
	.sz_mod_inp			= sizeof(pfmlib_gen_mips64_input_param_t)
};
