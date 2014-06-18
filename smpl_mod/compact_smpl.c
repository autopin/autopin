/*
 * compact_smpl.c - compact output sampling module for all PMU  models
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


#define SMPL_MOD_NAME			"compact"

/*
 * forward declaration
 */
pfmon_smpl_module_t compact_smpl_module;

static int
compact_process_samples(pfmon_sdesc_t *sdesc)
{
	pfm_dfl_smpl_hdr_t *hdr;
	pfm_dfl_smpl_entry_t *ent;
	pfmon_smpl_desc_t *csmpl;
	pfmon_event_set_t *active_set;
	uint64_t skip, count, entry;
	FILE *fp;
	uint64_t *reg;
	unsigned int n, npmds;
	int ret;

 	csmpl = &sdesc->csmpl;
	hdr   = csmpl->smpl_hdr;
 	fp = csmpl->smpl_fp;

	if (hdr == NULL)
		return -1;

	ent	   = (pfm_dfl_smpl_entry_t *)(hdr+1);
	entry      = options.opt_aggr ? *csmpl->aggr_count : csmpl->entry_count;
	count      = hdr->hdr_count;
	active_set = sdesc->sets; /* only one set when sampling */

	DPRINT(("count=%"PRIu64" entry=%"PRIu64"\n", count, entry));

	/*
 	 * check if we have new entries
 	 * if so skip the old entries and process only the new ones
 	 */
	if((csmpl->last_ovfl == hdr->hdr_overflows && csmpl->last_count <= count)
	  || ((csmpl->last_ovfl+1) == hdr->hdr_overflows && csmpl->last_count < count)) {
		skip = csmpl->last_count;
		vbprintf("skip %"PRIu64" samples out of %"PRIu64" (overflows: %"PRIu64")\n",
			  skip,
			  count,
			  hdr->hdr_overflows);
	} else {
		skip = 0;
	}

	vbprintf("skip=%"PRIu64" count=%"PRIu64" ovfl=%"PRIu64" last_o=%"PRIu64" last_c=%"PRIu64"\n",
		skip,
		count,
		hdr->hdr_overflows,
		csmpl->last_ovfl,
		csmpl->last_count);

	/*
 	 * only account for new entries, i.e., skip leftover entries
 	 */
	if (options.opt_aggr) {
		*csmpl->aggr_count += count - skip;
	} else {
		csmpl->entry_count += count - skip;
	}

	csmpl->last_count = count;
	csmpl->last_ovfl = hdr->hdr_overflows;

	while(count--) {
		if (skip == 0)
			ret = fprintf(fp, "%-8"PRIu64" %8d %8d %2d 0x%llx 0x%016"PRIx64" %3u %5u %16"PRId64" ",
					entry,
					ent->pid,
					ent->tgid,
					ent->cpu,
					(unsigned long long)ent->ip,
					ent->tstamp,
					(unsigned int)ent->ovfl_pmd,
					ent->set,
					ent->last_reset_val);

		reg = (uint64_t *)(ent+1);

		npmds = active_set->rev_smpl_pmds[ent->ovfl_pmd].num_smpl_pmds;
		if (skip == 0) {
			for (n = 0; n < npmds; n++) {
				ret = fprintf(fp, "0x%"PRIx64" ", reg[active_set->rev_smpl_pmds[ent->ovfl_pmd].map_pmd_evt[n].off]);
			}
			ret = fputc('\n', fp);
			if (ret == -1)
				goto error;
			entry++;
		} else
			skip--;

		reg += npmds;

		ent  = (pfm_dfl_smpl_entry_t *)reg;
	}
	return 0;
error:
	warning("cannot write to sampling file: %s\n", strerror(errno));
	return -1;
}


static int
compact_print_header(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	FILE *fp = csmpl->smpl_fp;

	fprintf(fp, "# description of columns:\n"
		    "#\tcolumn  1: entry number\n"
	 	    "#\tcolumn  2: process id\n"
	 	    "#\tcolumn  3: thread id\n"
		    "#\tcolumn  4: cpu number\n"
		    "#\tcolumn  5: instruction pointer\n"
		    "#\tcolumn  6: unique timestamp\n"
		    "#\tcolumn  7: overflowed PMD index\n"
		    "#\tcolumn  8: event set\n"
		    "#\tcolumn  9: initial value of overflowed PMD (sampling period)\n"
		    "#\tfollowed by optional sampled PMD values in command line order\n");
	return 0;
}

pfmon_smpl_module_t compact_smpl_module;
static void compact_initialize_mask(void)
{
	pfmon_bitmask_setall(compact_smpl_module.pmu_mask);
}

static int
compact_terminate_session(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl;
	csmpl = &sdesc->csmpl;

	fprintf(csmpl->smpl_fp, "# total samples          : %"PRIu64"\n", csmpl->entry_count);
	fprintf(csmpl->smpl_fp, "# total buffer overflows : %"PRIu64"\n", csmpl->last_ovfl);

	return 0;
}

pfmon_smpl_module_t compact_smpl_module ={
	.name		    = SMPL_MOD_NAME,
	.description	    = "Column-style raw values",
	.initialize_mask    = compact_initialize_mask,
	.terminate_session  = compact_terminate_session,
	.process_samples    = compact_process_samples,
	.print_header       = compact_print_header,
	.fmt_name	    = PFM_DFL_SMPL_NAME
};
