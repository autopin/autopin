/*
 * pfmon_pentium4.c - Pentium4/Xeon/EM64T processor family PMU support for pfmon
 *
 * Copyright (c) 2005-2006 Hewlett-Packard Development Company, L.P.
 * Copyright (c) 2006 IBM Corp.
 * Contributed by Kevin Corry <kevcorry@us.ibm.com>
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
//#include <perfmon/pfmlib_i386_p6.h>

#include "pfmon_pentium4.h"

static pfmon_pentium4_options_t pfmon_pentium4_opt;	/* keep track of global program options */

/**
 * pfmon_pentium4_prepare_registers
 **/
static int
pfmon_pentium4_prepare_registers(pfmon_event_set_t *set)
{
	return 0;
}

/**
 * pfmon_pentium4_install_pmc_registers
 **/
static int
pfmon_pentium4_install_pmc_registers(pfmon_sdesc_t *sdesc,
				     pfmon_event_set_t *set)
{
	return 0;
}

/**
 * pfmon_pentium4_install_pmd_registers
 **/
static int
pfmon_pentium4_install_pmd_registers(pfmon_sdesc_t *sdesc,
				     pfmon_event_set_t *set)
{
	return 0;
}

/**
 * pfmon_pentium4_pmc_map
 **/
static int
pfmon_pentium4_pmc_map(unsigned int lib_reg_num, unsigned int *kern_reg_num)
{
	return 0;
}

/**
 * pfmon_pentium4_pmd_map
 **/
static int
pfmon_pentium4_pmd_map(unsigned int lib_reg_num, unsigned int *kern_reg_num)
{
	return 0;
}

/**
 * pfmon_pentium4_print_header
 **/
static int
pfmon_pentium4_print_header(FILE *fp)
{
	return 0;
}

/**
 * cmd_pentium4_options
 *
 * Pentium4-specific command-line options for pfmon.
 *
 * 000-255   reserved for generic options
 * 400-499   reserved for PMU specific options
 * 500-599   reserved for format specific options
 **/
static struct option cmd_pentium4_options[] = {
#if 0
/* No Pentium4-specific command-line options yet. */
	{ "counter-mask", 1, 0, 400 },
	{ "inv-mask", 1, 0, 401 },
	{ "edge-mask", 1, 0, 402 },
#endif
	{ 0, 0, 0, 0}
};

/**
 * pfmon_pentium4_initialize
 *
 * Register the Pentium4 code with the pfmon core.
 **/
static int
pfmon_pentium4_initialize(void)
{
	int r;

	r = pfmon_register_options(cmd_pentium4_options,
				   sizeof(cmd_pentium4_options));
	if (r == -1)
		return -1;

	/* connect pfmon model specific options */
	options.model_options = &pfmon_pentium4_opt;

	return 0;
}

/**
 * pfmon_pentium4_usage
 **/
static void
pfmon_pentium4_usage(void)
{
#if 0
/* No Pentium4-specific command-line options yet. */
	printf(
		"--counter-mask=msk1,msk2,...\t\tset event counter mask (0,1,2,3)\n"
		"--inv-mask=i1,i2,...\t\t\tset event inverse counter mask (y/n,0/1)\n"
		"--edge-mask=e1,e2,...\t\t\tset event edge detect (y/n,0/1)\n"
	);
#endif
}

/**
 * pfmon_pentium4_parse_options
 *
 * 0  means we understood the option
 * -1 unknown option
 **/
static int
pfmon_pentium4_parse_options(int code, char *optarg)
{
	pfmon_pentium4_args_t *pentium4_args;
	pfmon_event_set_t *set;

	set = options.last_set;

	pentium4_args = set->mod_args;

	switch(code) {
#if 0
/* No Pentium4-specific command-line options yet. */
		case  400:
			if (i386_p6_args->cnt_mask_arg) fatal_error("counter masks already defined\n");
			i386_p6_args->cnt_mask_arg = optarg;
			break;
		case  401:
			if (i386_p6_args->inv_mask_arg) fatal_error("inverse mask already defined\n");
			i386_p6_args->inv_mask_arg = optarg;
			break;
		case  402:
			if (i386_p6_args->edge_mask_arg) fatal_error("edge detect mask already defined\n");
			i386_p6_args->edge_mask_arg = optarg;
			break;
#endif
		default:
			return -1;
	}
	return 0;
}

/**
 * pfmon_pentium4_setup
 **/
static int
pfmon_pentium4_setup(pfmon_event_set_t *set)
{
	pfmon_pentium4_args_t *pentium4_args;

	pentium4_args = set->mod_args;

	if (pentium4_args == NULL)
		return 0;
	
	return 0;
}

/**
 * pfmon_pentium4_setup_ctx_flags
 **/
static int
pfmon_pentium4_setup_ctx_flags(pfmon_ctx_t *ctx)
{
	return 0;
}

/**
 * pfmon_pentium4_verify_event_sets
 **/
static void pfmon_pentium4_verify_event_sets(void)
{
	return;
}

/**
 * pfmon_pentium4_verify_cmdline
 *
 * Check all command-line options to make sure they are valid for Pentium4.
 **/
static void
pfmon_pentium4_verify_cmdline(int argc, char **argv)
{
	if (options.dfl_plm & (PFM_PLM1|PFM_PLM2))
		fatal_error("-1 or -2 privilege levels are not "
			    "supported by the Pentium4/Xeon/EM64T PMU.\n");
}

/**
 * pfmon_pentium4_detailed_event_name
 **/
static void
pfmon_pentium4_detailed_event_name(unsigned int evt)
{
}

pfmon_support_t pfmon_pentium4 = {
	.pfmon_prepare_registers	= pfmon_pentium4_prepare_registers,
	.pfmon_install_pmc_registers	= pfmon_pentium4_install_pmc_registers,
	.pfmon_install_pmd_registers	= pfmon_pentium4_install_pmd_registers,
	.pfmon_pmc_map			= pfmon_pentium4_pmc_map,
	.pfmon_pmd_map			= pfmon_pentium4_pmd_map,
	.pfmon_print_header		= pfmon_pentium4_print_header,
	.pfmon_initialize		= pfmon_pentium4_initialize,		
	.pfmon_usage			= pfmon_pentium4_usage,	
	.pfmon_parse_options		= pfmon_pentium4_parse_options,
	.pfmon_setup			= pfmon_pentium4_setup,
	.pfmon_setup_ctx_flags		= pfmon_pentium4_setup_ctx_flags,
	.pfmon_verify_event_sets	= pfmon_pentium4_verify_event_sets,
	.pfmon_verify_cmdline		= pfmon_pentium4_verify_cmdline,
	.pfmon_detailed_event_name	= pfmon_pentium4_detailed_event_name,
	.name				= "Pentium 4",
	.pmu_type			= PFMLIB_PENTIUM4_PMU,
	.generic_pmu_type		= PFMLIB_NO_PMU,
	.sz_mod_args			= sizeof(pfmon_pentium4_args_t),
};
