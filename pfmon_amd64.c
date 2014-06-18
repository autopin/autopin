/*
 * pfmon_amd64.c - AMD X86-64 PMU support for pfmon
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
#include <perfmon/pfmlib_amd64.h>

#include "pfmon_amd64.h"


static pfmon_amd64_options_t pfmon_amd64_opt;	/* keep track of global program options */

static void
pfmon_amd64_setup_cnt_mask(pfmon_event_set_t *set)
{
	pfmlib_amd64_input_param_t *param = set->mod_inp;
	pfmon_amd64_args_t *args;
	char *cnt_mask_str;
	char *p, *endptr = NULL;
	unsigned long l;
	unsigned int cnt = 0, cnt_mask_max = 0;
	unsigned int i;
	int ret;

	args = set->mod_args;

	cnt_mask_str = args->cnt_mask_arg;

	/*
	 * the default value for cnt_mask is 0: this means at least once 
	 * per cycle.
	 */
	if (cnt_mask_str == NULL) {
		for (i=0; i < set->event_count; i++)
			param->pfp_amd64_counters[i].cnt_mask= 0;
		return;
	}

	ret = pfm_get_num_counters(&cnt_mask_max);
	if (ret != PFMLIB_SUCCESS)
		fatal_error("Determining maximum number of counters "
			    "failed with error code %d\n", ret);
	while (cnt_mask_str) {

		if (cnt == options.max_counters || cnt == set->event_count)
			goto too_many;

		p = strchr(cnt_mask_str,',');

		if ( p ) *p = '\0';

		l = strtoul(cnt_mask_str, &endptr, 0);
		if (*endptr || l < 0 || l >= cnt_mask_max)
				goto invalid;

		if ( p ) *p++ = ',';

		param->pfp_amd64_counters[cnt++].cnt_mask = (unsigned int )l;

		cnt_mask_str = p;
	}
	return;
invalid:
	fatal_error("event %d: counter mask must be in [0-%u)\n", cnt, cnt_mask_max);
too_many:
	fatal_error("too many counter masks specified\n");
}

static void
pfmon_amd64_setup_bool(pfmon_event_set_t *set, char *arg_str,
		       unsigned int flag, char *arg_name)
{
	pfmlib_amd64_input_param_t *param = set->mod_inp;
	char *p, c;
	unsigned int cnt=0;
	unsigned int i;

	/*
	 * the default value is 0
	 */
	if (arg_str == NULL) {
		for (i=0; i < set->event_count; i++)
			param->pfp_amd64_counters[i].flags &= ~flag;
		return;
	}

	while (arg_str) {
		if (cnt == options.max_counters || cnt == set->event_count)
			goto too_many;

		p = strchr(arg_str,',');

		if ( p ) *p = '\0';

		if (strlen(arg_str) > 1) goto invalid;

		c = *arg_str;

		if ( p ) *p++ = ',';
		
		if (c == 'y' || c == 'Y' || c == '1')
			param->pfp_amd64_counters[cnt].flags |= flag;
		else if (c != 'n' &&  c != 'N' && c != '0')
			goto invalid;

		cnt++;
		arg_str = p;
	}
	return;
invalid:
	fatal_error("event %d: %s value is any one of y,Y,n,N,0,1\n", cnt, arg_name);
too_many:
	fatal_error("too many %s values specified\n", arg_name);
}

static void
pfmon_amd64_setup_edge(pfmon_event_set_t *set)
{
	pfmon_amd64_args_t *args;

	args = set->mod_args;
	pfmon_amd64_setup_bool(set, args->edge_mask_arg, PFM_AMD64_SEL_EDGE, "edge");
}

static void
pfmon_amd64_setup_inv(pfmon_event_set_t *set)
{
	pfmon_amd64_args_t *args;

	args = set->mod_args;
	pfmon_amd64_setup_bool(set, args->inv_mask_arg, PFM_AMD64_SEL_INV, "inv");
}

static void
pfmon_amd64_setup_guest(pfmon_event_set_t *set)
{
	pfmon_amd64_args_t *args;

	args = set->mod_args;
	pfmon_amd64_setup_bool(set, args->guest_mask_arg, PFM_AMD64_SEL_GUEST, "guest");
}

static void
pfmon_amd64_setup_host(pfmon_event_set_t *set)
{
	pfmon_amd64_args_t *args;

	args = set->mod_args;
	pfmon_amd64_setup_bool(set, args->host_mask_arg, PFM_AMD64_SEL_HOST, "host");
}

static int
pfmon_amd64_prepare_registers(pfmon_event_set_t *set)
{
	return 0;
}

static int
pfmon_amd64_install_pmc_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	return 0;
}

static int
pfmon_amd64_install_pmd_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set)
{
	return 0;
}

static void
pfmon_amd64_usage(void)
{
	printf( "--counter-mask=msk1,msk2,...\t\tSet event counter mask (0,1,2,3).\n"
		"--inv-mask=c1,c2,...\t\t\tSet event inverse counter mask (y/n,0/1)\n"
		"--edge-mask=c1,c2,...\t\t\tSet event edge detect (y/n,0/1)\n"
		"--guest-mask=c1,c2,...\t\t\tSet event guest only (y/n,0/1)\n"
		"--host-mask=c1,c2,...\t\t\tSet event host only (y/n,0/1)\n"
	);
}

/*
 * X86-64-specific options
 *
 * 000-255   reserved for generic options
 * 400-499   reserved for PMU specific options
 * 500-599   reserved for format specific options
 */
static struct option cmd_amd64_options[]={
	{ "counter-mask", 1, 0, 400 },
	{ "inv-mask", 1, 0, 401 },
	{ "edge-mask", 1, 0, 402 },
	{ "guest-mask", 1, 0, 403 },
	{ "host-mask", 1, 0, 404 },
	{ 0, 0, 0, 0}
};

#define NAME_SIZE 32
static char amd64_pmu_name[NAME_SIZE];

pfmon_support_t pfmon_amd64;

static int
pfmon_amd64_initialize(void)
{
	int r;

	r = pfmon_register_options(cmd_amd64_options, sizeof(cmd_amd64_options));
	if (r == -1) return -1;

	/* connect pfmon model specific options */
	options.model_options = &pfmon_amd64_opt;

	/* Rewrite PMU name after CPU detection */
	pfm_get_pmu_name(amd64_pmu_name, NAME_SIZE);
	pfmon_amd64.name = amd64_pmu_name;

	return 0;
}

/*
 * 0  means we understood the option
 * -1 unknown option
 */
static int
pfmon_amd64_parse_options(int code, char *optarg)
{
	pfmon_amd64_args_t *x86_64_args;
	pfmon_event_set_t *set;

	set = options.last_set;

	x86_64_args = set->mod_args;

	switch(code) {
		case  400:
			if (x86_64_args->cnt_mask_arg) fatal_error("counter masks already defined\n");
			x86_64_args->cnt_mask_arg = optarg;
			break;
		case  401:
			if (x86_64_args->inv_mask_arg) fatal_error("inverse mask already defined\n");
			x86_64_args->inv_mask_arg = optarg;
			break;
		case  402:
			if (x86_64_args->edge_mask_arg) fatal_error("edge detect mask already defined\n");
			x86_64_args->edge_mask_arg = optarg;
			break;
		case  403:
			if (x86_64_args->guest_mask_arg) fatal_error("guest only mask already defined\n");
			x86_64_args->guest_mask_arg = optarg;
			break;
		case  404:
			if (x86_64_args->host_mask_arg) fatal_error("host only mask already defined\n");
			x86_64_args->host_mask_arg = optarg;
			break;
		default:
			return -1;
	}
	return 0;
}

static int
pfmon_amd64_setup(pfmon_event_set_t *set)
{
	pfmon_amd64_args_t *x86_64_args;

	x86_64_args = set->mod_args;

	if (x86_64_args == NULL) return 0;

	
	/* 
	 * we systematically initialize thresholds to their minimal value
	 * or requested value
	 */
	pfmon_amd64_setup_cnt_mask(set);
	pfmon_amd64_setup_edge(set);
	pfmon_amd64_setup_inv(set);
	pfmon_amd64_setup_guest(set);
	pfmon_amd64_setup_host(set);

	return 0;
}

static int
pfmon_amd64_print_header(FILE *fp)
{
	return 0;
}

static int
pfmon_amd64_setup_ctx_flags(pfmon_ctx_t *ctx)
{
	return 0;
}

static void
pfmon_amd64_verify_cmdline(int argc, char **argv)
{
	if (options.dfl_plm & (PFM_PLM1|PFM_PLM2))
		fatal_error("-1 or -2 privilege levels are not supported by this PMU model\n");

	if (options.opt_data_trigger_ro)
		fatal_error("the --trigger-data-ro option is not supported by this processor\n");
}

pfmon_support_t pfmon_amd64={
	.name				= "AMD64",
	.pmu_type			= PFMLIB_AMD64_PMU,
	.generic_pmu_type		= PFMLIB_AMD64_PMU,
	.pfmon_initialize		= pfmon_amd64_initialize,		
	.pfmon_usage			= pfmon_amd64_usage,	
	.pfmon_parse_options		= pfmon_amd64_parse_options,
	.pfmon_setup			= pfmon_amd64_setup,
	.pfmon_prepare_registers	= pfmon_amd64_prepare_registers,
	.pfmon_install_pmc_registers	= pfmon_amd64_install_pmc_registers,
	.pfmon_install_pmd_registers	= pfmon_amd64_install_pmd_registers,
	.pfmon_print_header		= pfmon_amd64_print_header,
	.pfmon_setup_ctx_flags		= pfmon_amd64_setup_ctx_flags,
	.pfmon_verify_cmdline		= pfmon_amd64_verify_cmdline,
	.sz_mod_args			= sizeof(pfmon_amd64_args_t),
	.sz_mod_inp			= sizeof(pfmlib_amd64_input_param_t)
};
