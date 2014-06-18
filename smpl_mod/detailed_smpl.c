/*
 * detailed_smpl.c - detailed sampling module for all PMU models
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

#include <perfmon/perfmon_dfl_smpl.h>

static int has_btb; /* set to 1 if IA-64 and has BTB/ETB */

/*
 * register helper functions
 */
typedef int (*print_reg_t)(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set, int rnum, unsigned long val);
extern print_reg_t print_ita_reg,  print_ita2_reg, print_mont_reg;

static print_reg_t print_func;

static int
dfl_print_reg(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set, int rnum, unsigned long val)
{
	return fprintf(sdesc->csmpl.smpl_fp, "\tPMD%-3d:0x%016lx\n", rnum, val);
}

static int
detailed_process_samples(pfmon_sdesc_t *sdesc)
{
	pfm_dfl_smpl_hdr_t *hdr;
	pfm_dfl_smpl_entry_t *ent;
	pfmon_smpl_desc_t *csmpl;
	pfmon_event_set_t *active_set;
	FILE *fp;
	uint64_t count, entry;
	uint64_t *reg;
	uint16_t ovfl_pmd, npmds;
	unsigned int n;
	uint32_t version = sdesc->current_map_version;
	int ret;

	csmpl      = &sdesc->csmpl;
	hdr        = csmpl->smpl_hdr;

	if (hdr == NULL)
		return -1;

	fp         = csmpl->smpl_fp;
	ent        = (pfm_dfl_smpl_entry_t *)(hdr+1);
	entry      = options.opt_aggr ? *csmpl->aggr_count : csmpl->entry_count;
	count      = hdr->hdr_count;
	active_set = sdesc->sets; /* only one set when sampling */
	
	/*
	 * when aggregation is used, for are guaranteed sequential access to
	 * this routine by higher level lock
	 */
	if (options.opt_aggr) {
		*csmpl->aggr_count += count;
	} else {
		csmpl->entry_count += count;
	}
	csmpl->last_count = count;
	csmpl->last_ovfl = hdr->hdr_overflows;

	DPRINT(("hdr_count=%"PRIu64" hdr=%p active_set=%u\n", count, hdr, active_set->id));

	while(count--) {
		ovfl_pmd = ent->ovfl_pmd;
		ret = fprintf(fp, "entry %"PRIu64" PID:%d TID:%d CPU:%d STAMP:0x%"PRIx64" OVFL:%d LAST_VAL:%"PRIu64" SET:%u IIP:",
			entry,
			ent->tgid,
			ent->pid,
			ent->cpu,
			ent->tstamp,
			ovfl_pmd, 
			-ent->last_reset_val,
			ent->set);

		pfmon_print_address(fp,
				    options.primary_syms,
				    PFMON_TEXT_SYMBOL,
				    ent->ip,
				    ent->tgid,
				    version);
		fputc('\n', fp);

		reg = (uint64_t *)(ent+1);
		
		npmds = active_set->rev_smpl_pmds[ovfl_pmd].num_smpl_pmds;
		for (n = 0; n < npmds; n++) {
			ret = print_func(sdesc, active_set,
					 active_set->rev_smpl_pmds[ovfl_pmd].map_pmd_evt[n].pd,
					 reg[active_set->rev_smpl_pmds[ovfl_pmd].map_pmd_evt[n].off]);
		}
		reg += n;
		/* fprintf() error detection */
		if (ret == -1) goto error;

		/*
		 * entries are contiguously stored
		 */
		ent  = (pfm_dfl_smpl_entry_t *)reg;	
		entry++;
	}
	return 0;
error:
	warning("cannot write to sampling file: %s\n", strerror(errno));
	/* not reached */
	return -1;
}

/*
 * Allocate space for the optional BTB/ETB buffer
 */
static int
detailed_initialize_session(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	unsigned int num_pmds;

	if (has_btb == 0) return 0;
	/*
	 * let's be generous and consider all PMDS to be potentially BTB
	 */
	pfm_get_num_pmds(&num_pmds);

	csmpl->data = calloc(num_pmds, sizeof(unsigned long));

	return csmpl->data == NULL ? -1 : 0;
}

static int
detailed_terminate_session(pfmon_sdesc_t *sdesc)
{
	if (sdesc->csmpl.data) free(sdesc->csmpl.data);
	return 0;
}

static int
detailed_initialize_module(void)
{
	switch(options.pmu_type) {
#ifdef CONFIG_PFMON_IA64
		case PFMLIB_ITANIUM_PMU:
			has_btb = 1;
			print_func = print_ita_reg;
			break;
		case PFMLIB_ITANIUM2_PMU:
			has_btb = 1;
			print_func = print_ita2_reg;
			break;
		case PFMLIB_MONTECITO_PMU:
			has_btb = 1;
			print_func = print_mont_reg;
			break;
#endif
		default:
			print_func = dfl_print_reg;
	}
	return 0;
}

pfmon_smpl_module_t detailed_smpl_module;
static void detailed_initialize_mask(void)
{
	pfmon_bitmask_setall(detailed_smpl_module.pmu_mask);
}

pfmon_smpl_module_t detailed_smpl_module = {
	.name		    = "detailed",
	.description	    = "decode register content",
	.process_samples    = detailed_process_samples,
	.initialize_session = detailed_initialize_session,
	.terminate_session  = detailed_terminate_session,
	.initialize_module  = detailed_initialize_module,
	.initialize_mask    = detailed_initialize_mask,
	.fmt_name	    = PFM_DFL_SMPL_NAME
};
