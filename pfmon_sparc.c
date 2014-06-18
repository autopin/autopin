/*
 * Sparc PMU support for pfmon.
 *
 * This file is part of pfmon, a sample tool to measure performance
 * of applications for Linux.
 *
 * Copyright (C) 2007 David S. Miller (davem@davemloft.net)
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
#include <perfmon/pfmlib_sparc.h>
#include "pfmon.h"

static int pfmon_sparc_prepare_registers(pfmon_event_set_t *set)
{
	return 0;
}

static int pfmon_sparc_install_pmc_registers(pfmon_sdesc_t *sdesc,
					     pfmon_event_set_t *set)
{
	return 0;
}

static int pfmon_sparc_install_pmd_registers(pfmon_sdesc_t *sdesc,
					     pfmon_event_set_t *set)
{
	return 0;
}

static void pfmon_sparc_usage(void)
{
}

static int pfmon_sparc_initialize(void)
{
	return 0;
}

static int pfmon_sparc_parse_options(int code, char *optarg)
{
	return 0;
}

static int pfmon_sparc_setup(pfmon_event_set_t *set)
{
	return 0;
}

static int pfmon_sparc_print_header(FILE *fp)
{
	return 0;
}

static int pfmon_sparc_setup_ctx_flags(pfmon_ctx_t *ctx)
{
	return 0;
}

static void pfmon_sparc_verify_cmdline(int argc, char **argv)
{
	if (options.data_trigger_start)
		fatal_error("the --trigger-data-start option is not supported by this processor\n");
	if (options.data_trigger_stop)
		fatal_error("the --trigger-data-stop option is not supported by this processor\n");
	if (options.opt_data_trigger_ro)
		fatal_error("the --trigger-data-ro option is not supported by this processor\n");
}

pfmon_support_t pfmon_ultra12 = {
	.name = "UltraSparc-I/II/IIi/IIe",
	.pmu_type = PFMLIB_SPARC_ULTRA12_PMU,
	.pfmon_initialize = pfmon_sparc_initialize,
	.pfmon_usage = pfmon_sparc_usage,
	.pfmon_parse_options = pfmon_sparc_parse_options,
	.pfmon_setup = pfmon_sparc_setup,
	.pfmon_prepare_registers = pfmon_sparc_prepare_registers,
	.pfmon_install_pmc_registers = pfmon_sparc_install_pmc_registers,
	.pfmon_install_pmd_registers = pfmon_sparc_install_pmd_registers,
	.pfmon_print_header = pfmon_sparc_print_header,
	.pfmon_setup_ctx_flags = pfmon_sparc_setup_ctx_flags,
	.pfmon_verify_cmdline = pfmon_sparc_verify_cmdline,
};

pfmon_support_t pfmon_ultra3 = {
	.name = "UltraSparc-III",
	.pmu_type = PFMLIB_SPARC_ULTRA3_PMU,
	.pfmon_initialize = pfmon_sparc_initialize,
	.pfmon_usage = pfmon_sparc_usage,
	.pfmon_parse_options = pfmon_sparc_parse_options,
	.pfmon_setup = pfmon_sparc_setup,
	.pfmon_prepare_registers = pfmon_sparc_prepare_registers,
	.pfmon_install_pmc_registers = pfmon_sparc_install_pmc_registers,
	.pfmon_install_pmd_registers = pfmon_sparc_install_pmd_registers,
	.pfmon_print_header = pfmon_sparc_print_header,
	.pfmon_setup_ctx_flags = pfmon_sparc_setup_ctx_flags,
	.pfmon_verify_cmdline = pfmon_sparc_verify_cmdline,
};

pfmon_support_t pfmon_ultra3i = {
	.name = "UltraSparc-IIIi/IIIi+",
	.pmu_type = PFMLIB_SPARC_ULTRA3I_PMU,
	.pfmon_initialize = pfmon_sparc_initialize,
	.pfmon_usage = pfmon_sparc_usage,
	.pfmon_parse_options = pfmon_sparc_parse_options,
	.pfmon_setup = pfmon_sparc_setup,
	.pfmon_prepare_registers = pfmon_sparc_prepare_registers,
	.pfmon_install_pmc_registers = pfmon_sparc_install_pmc_registers,
	.pfmon_install_pmd_registers = pfmon_sparc_install_pmd_registers,
	.pfmon_print_header = pfmon_sparc_print_header,
	.pfmon_setup_ctx_flags = pfmon_sparc_setup_ctx_flags,
	.pfmon_verify_cmdline = pfmon_sparc_verify_cmdline,
};

pfmon_support_t pfmon_ultra3plus = {
	.name = "UltraSparc-III+/IV",
	.pmu_type = PFMLIB_SPARC_ULTRA3PLUS_PMU,
	.pfmon_initialize = pfmon_sparc_initialize,
	.pfmon_usage = pfmon_sparc_usage,
	.pfmon_parse_options = pfmon_sparc_parse_options,
	.pfmon_setup = pfmon_sparc_setup,
	.pfmon_prepare_registers = pfmon_sparc_prepare_registers,
	.pfmon_install_pmc_registers = pfmon_sparc_install_pmc_registers,
	.pfmon_install_pmd_registers = pfmon_sparc_install_pmd_registers,
	.pfmon_print_header = pfmon_sparc_print_header,
	.pfmon_setup_ctx_flags = pfmon_sparc_setup_ctx_flags,
	.pfmon_verify_cmdline = pfmon_sparc_verify_cmdline,
};

pfmon_support_t pfmon_ultra4plus = {
	.name = "UltraSparc-IV+",
	.pmu_type = PFMLIB_SPARC_ULTRA4PLUS_PMU,
	.pfmon_initialize = pfmon_sparc_initialize,
	.pfmon_usage = pfmon_sparc_usage,
	.pfmon_parse_options = pfmon_sparc_parse_options,
	.pfmon_setup = pfmon_sparc_setup,
	.pfmon_prepare_registers = pfmon_sparc_prepare_registers,
	.pfmon_install_pmc_registers = pfmon_sparc_install_pmc_registers,
	.pfmon_install_pmd_registers = pfmon_sparc_install_pmd_registers,
	.pfmon_print_header = pfmon_sparc_print_header,
	.pfmon_setup_ctx_flags = pfmon_sparc_setup_ctx_flags,
	.pfmon_verify_cmdline = pfmon_sparc_verify_cmdline,
};

pfmon_support_t pfmon_niagara1 = {
	.name = "Niagara-1",
	.pmu_type = PFMLIB_SPARC_NIAGARA1_PMU,
	.pfmon_initialize = pfmon_sparc_initialize,
	.pfmon_usage = pfmon_sparc_usage,
	.pfmon_parse_options = pfmon_sparc_parse_options,
	.pfmon_setup = pfmon_sparc_setup,
	.pfmon_prepare_registers = pfmon_sparc_prepare_registers,
	.pfmon_install_pmc_registers = pfmon_sparc_install_pmc_registers,
	.pfmon_install_pmd_registers = pfmon_sparc_install_pmd_registers,
	.pfmon_print_header = pfmon_sparc_print_header,
	.pfmon_setup_ctx_flags = pfmon_sparc_setup_ctx_flags,
	.pfmon_verify_cmdline = pfmon_sparc_verify_cmdline,
};

pfmon_support_t pfmon_niagara2 = {
	.name = "Niagara-2",
	.pmu_type = PFMLIB_SPARC_NIAGARA2_PMU,
	.pfmon_initialize = pfmon_sparc_initialize,
	.pfmon_usage = pfmon_sparc_usage,
	.pfmon_parse_options = pfmon_sparc_parse_options,
	.pfmon_setup = pfmon_sparc_setup,
	.pfmon_prepare_registers = pfmon_sparc_prepare_registers,
	.pfmon_install_pmc_registers = pfmon_sparc_install_pmc_registers,
	.pfmon_install_pmd_registers = pfmon_sparc_install_pmd_registers,
	.pfmon_print_header = pfmon_sparc_print_header,
	.pfmon_setup_ctx_flags = pfmon_sparc_setup_ctx_flags,
	.pfmon_verify_cmdline = pfmon_sparc_verify_cmdline,
};
