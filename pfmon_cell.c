/*
 * Cell Broadband Engine PMU support for pfmon.
 *
 * This file is part of pfmon, a sample tool to measure performance
 * of applications for Linux.
 *
 * Copyright (C) 2008 Sony Computer Entertainment Inc.
 * Copyright 2007,2008 Sony Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of the License.
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
#include "pfmon.h"

/* PM_CONTROL REG macros */
#define CELL_DEFAULT_PM_CONTROL_REG_VALUE     0x80000000
#define CELL_PM_CONTROL_STOP_AT_MAX           0x40000000
#define CELL_PM_CONTROL_COUNT_TRACE           0x10000000
#define CELL_PM_CONTROL_FREEZE                0x00100000
#define CELL_PM_CONTROL_PROBLEM_MODE          0x00080000
#define CELL_PM_CONTROL_EXTERNAL_TRACE_ENABLE 0x00008000
#define CELL_PM_CONTROL_PPE_ADDR_TRACE_ENABLE 0x00006000
#define CELL_PM_CONTROL_PPE_BOOKMARK_ENABLE   0x00001800
#define CELL_PM_CONTROL_SPE_ADDR_TRACE_ENABLE 0x00000600
#define CELL_PM_CONTROL_SPE_BOOKMARK_ENABLE   0x00000180
#define CELL_PM_CONTROL_COUNTER_WIDTH_16      0x01E00000
#define CELL_PM_CONTROL_COUNTER_WIDTH_32      0x00000000
#define CELL_PM_CONTROL_COUNTER_WIDTH_MASK    0x01E00000

#define CELL_OPTION_NAME_COUNTER_BITS "cell-cntr-width"
#define CELL_OPTION_NAME_SPE_LIST     "event-spe-list"
#define CELL_OPTION_CODE_COUNTER_BITS 401
#define CELL_OPTION_CODE_SPE_LIST     402

static pfmon_cell_options_t pfmon_cell_opt;

static int pfmon_cell_prepare_registers(pfmon_event_set_t *set)
{
	DPRINT(("set:%p\n", set));
	return 0;
}

static int pfmon_cell_install_pmc_registers(pfmon_sdesc_t *sdesc,
					    pfmon_event_set_t *set)
{
	DPRINT(("set:%p sdesc:%p\n", set, sdesc));
	return 0;
}

static int pfmon_cell_install_pmd_registers(pfmon_sdesc_t *sdesc,
					    pfmon_event_set_t *set)
{
	DPRINT(("set:%p sdesc:%p\n", set, sdesc));
	return 0;
}

static void pfmon_cell_usage(void)
{
	printf("--%s\t\t\tSpecify the performace counter width.\n"
	       "\t\t\t\t\t(16 or 32)\n"
	       "--%s\t\t\tSpecify the target SPE ID to each SPE\n"
	       "\t\t\t\t\tevent specified by --event option.\n"
	       "\t\t\t\t\tIf multi-event set(list)s are specified\n"
	       "\t\t\t\t\tby --event options,\n"
	       "\t\t\t\t\tmulti --%s options\n"
	       "\t\t\t\t\tshould be specified.\n",
	       CELL_OPTION_NAME_COUNTER_BITS,
	       CELL_OPTION_NAME_SPE_LIST,
	       CELL_OPTION_NAME_SPE_LIST);
}

static struct option cmd_cell_options[] = {
	{CELL_OPTION_NAME_COUNTER_BITS, 1, 0, CELL_OPTION_CODE_COUNTER_BITS},
	{CELL_OPTION_NAME_SPE_LIST, 1, 0, CELL_OPTION_CODE_SPE_LIST},
	{0, 0, 0, 0},
};

static int pfmon_cell_initialize(void)
{
	int r;

	r = pfmon_register_options(cmd_cell_options,
				   sizeof(cmd_cell_options));
	if (r)
		return r;

	/* connect pfmon model specific options */
	options.model_options = &pfmon_cell_opt;
	pfmon_cell_opt.counter_bits = 32;
	pfmon_cell_opt.num_spe_id_lists = 0;
	memset(pfmon_cell_opt.target_spe_info, 0,
	       sizeof(pfmon_cell_opt.target_spe_info));

	return 0;
}

static int pfmon_cell_parse_options(int code, char *optarg)
{
	char *s;
	int num_lists, num_spes;
	int i, hit;
	pfmon_cell_target_spe_info_t *info;

	if (code == CELL_OPTION_CODE_COUNTER_BITS) {
		pfmon_cell_opt.counter_bits = strtol(optarg, NULL, 0);
		if (pfmon_cell_opt.counter_bits != 16 &&
		    pfmon_cell_opt.counter_bits != 32) {
			fatal_error("wrong counter-bits value\n");
			return -1;
		}
		return 0;

	} else if (code == CELL_OPTION_CODE_SPE_LIST) {

		if (pfmon_cell_opt.num_spe_id_lists >= PFMON_CELL_MAX_EVENT_SETS) {
			fatal_error("Too many spe id lists\n");
			return -1;
		}
		num_lists = pfmon_cell_opt.num_spe_id_lists;
		info = &pfmon_cell_opt.target_spe_info[num_lists];
		num_spes = 0;
		s = strtok(optarg, ",");
		while (s) {
			if (num_spes >= PMU_CELL_NUM_COUNTERS) {
				warning("Too many spe ids\n");
				break;
			}

			info->spe[num_spes] = strtol(s, NULL, 0);
			hit = 0;
			for (i = 0; i < info->num_of_used_spes; i++) {
				if (info->spe[num_spes] == info->used_spe[i]) {
					hit = 1;
					break;
				}
			}
			if (!hit) {
				if (info->num_of_used_spes
				    >= PFMON_CELL_MAX_TARGET_SPE_NUM) {
					fatal_error("\nToo many kinds of target SPE"
						    " by --%s\n",
						    CELL_OPTION_NAME_SPE_LIST);
					return -1;
				} else {
					info->used_spe[info->num_of_used_spes] =
						info->spe[num_spes];
					info->num_of_used_spes++;
				}
			}
			num_spes++;
			s = strtok(NULL, ",");
		}
		info->num_of_spes = num_spes;
		pfmon_cell_opt.num_spe_id_lists++;
		return 0;

  	} else {
  		return -1;
  	}
}

static int num_of_spe_events(pfmon_event_set_t *set)
{
	int i;
	int num = 0;

	for (i = 0; i < set->inp.pfp_event_count; i++)
		if (pfm_cell_spe_event(set->inp.pfp_events[i].event))
			num++;
	return num;
}

static int pfmon_cell_set_spe_subunit(pfmon_event_set_t *set)
{
	pfmon_cell_target_spe_info_t *info;
	pfmlib_cell_input_param_t *p;
	int num, i, j;

	info = set->mod_args;
	num = num_of_spe_events(set);

	if (num > 0 && pfmon_cell_opt.num_spe_id_lists == 0) {
		if (options.opt_syst_wide)
			warning("default spe id 0 is used for each spe event\n");
		return 0;
	}

	if (num != info->num_of_spes)
		return -1;

	p = set->mod_inp;
	for (i = 0, j = 0;
	     i < set->inp.pfp_event_count && j < info->num_of_spes; i++) {
		if (pfm_cell_spe_event(set->inp.pfp_events[i].event))
			p->pfp_cell_counters[i].spe_subunit = info->spe[j++];
		else
			p->pfp_cell_counters[i].spe_subunit = 0;
	}

	return 0;
}

static int pfmon_cell_setup(pfmon_event_set_t *set)
{
	pfmlib_cell_input_param_t *p;
	int i;
	int ret;

	DPRINT(("%s set:%p\n", __FUNCTION__, set));

	if (pfmon_cell_opt.num_spe_id_lists > 0
	    && num_of_spe_events(set) == 0) {
		fatal_error("'--%s' needs a SPE event in the event list\n",
			    CELL_OPTION_NAME_SPE_LIST);
		return -1;
	}

	p = set->mod_inp;
	p->control = CELL_DEFAULT_PM_CONTROL_REG_VALUE;
	p->control |= CELL_PM_CONTROL_FREEZE;
	p->interval = 0;
	p->triggers = 0;
	for (i = 0; i < PMU_CELL_NUM_COUNTERS; i++) {
		p->pfp_cell_counters[i].pmX_control_num = 0;
		p->pfp_cell_counters[i].spe_subunit = 0;
		p->pfp_cell_counters[i].polarity = 1;
		p->pfp_cell_counters[i].input_control = 0;
		p->pfp_cell_counters[i].cnt_mask = 0;
		p->pfp_cell_counters[i].flags = 0;
	}

	p->control &= ~CELL_PM_CONTROL_COUNTER_WIDTH_MASK;
	if (pfmon_cell_opt.counter_bits == 16) {
		p->control |= CELL_PM_CONTROL_COUNTER_WIDTH_16;
	}

	set->mod_args = &pfmon_cell_opt.target_spe_info[set->id];
	ret = pfmon_cell_set_spe_subunit(set);
	if (ret) {
		fatal_error("The spe event list is not "
			    "consistent with the spe id list.\n");
		return -1;
	}

	return 0;
}

static int pfmon_cell_print_header(FILE *fp)
{
	DPRINT(("\n"));
	return 0;
}

static int pfmon_cell_setup_ctx_flags(pfmon_ctx_t *ctx)
{
	DPRINT(("\n"));
	return 0;
}

static void pfmon_cell_verify_cmdline(int argc, char **argv)
{
	if (options.data_trigger_start ||
	    options.data_trigger_stop ||
	    options.opt_code_trigger_repeat ||
	    options.opt_code_trigger_follow ||
	    options.opt_data_trigger_repeat ||
	    options.opt_data_trigger_follow ||
	    options.opt_data_trigger_ro || options.opt_data_trigger_wo)
		fatal_error("trigger options are not implemented\n");
}

pfmon_support_t pfmon_cell = {
	.name = "Cell/B.E PMU",
	.pmu_type = PFMLIB_CELL_PMU,
	.pfmon_initialize = pfmon_cell_initialize,
	.pfmon_usage = pfmon_cell_usage,
	.pfmon_parse_options = pfmon_cell_parse_options,
	.pfmon_setup = pfmon_cell_setup,
	.pfmon_prepare_registers = pfmon_cell_prepare_registers,
	.pfmon_install_pmc_registers = pfmon_cell_install_pmc_registers,
	.pfmon_install_pmd_registers = pfmon_cell_install_pmd_registers,
	.pfmon_print_header = pfmon_cell_print_header,
	.pfmon_setup_ctx_flags = pfmon_cell_setup_ctx_flags,
	.pfmon_verify_cmdline = pfmon_cell_verify_cmdline,
	.sz_mod_inp = sizeof(pfmlib_cell_input_param_t)
};
