/*
 * pfmon_smpl_ia64_old.c - collection of support routines for the old
 *                         default sampling module for IA-64 using
 *                         perfmon v2.0.
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
#include <perfmon/perfmon_default_smpl.h>

#define ENTRY_SIZE(npmd, ez)	((ez)+((npmd)*sizeof(uint64_t)))

int
default_smpl_init_ctx_arg(pfmon_ctx_t *ctx, unsigned int max_pmds_sample)
{
	pfm_default_smpl_arg_t *ctx_arg;
	size_t entry_size, pmu_max_entry_size, buf_size, slack;
	unsigned int max_num_pmds = 0;
	int ret;

	pfm_get_num_pmds(&max_num_pmds);
	/*
	 * samples may have different size, max_pmds_samples represent the
	 * largest sample for the measurement.
	 */
	entry_size         = ENTRY_SIZE(max_pmds_sample, sizeof(pfm_default_smpl_entry_t));
	pmu_max_entry_size = ENTRY_SIZE(max_num_pmds, sizeof(pfm_default_smpl_entry_t));
	
	/*
	 * The buffer is full if the space left after recording a sample is
	 * smaller than the maximum sample size possible. The maximum sample size
	 * is defined with an entry_header and all implemented PMDS in the body.
	 *
	 * The slack ensures that slightly less than pmu_max_entry_size is left
	 * after the kernel writes the last entry (doing -1 instead of -entry_size
	 * would also work).
	 *
	 * buffer size is rounded up to kernel page size.
	 *
	 * The kernel is testing for < pmu_max_entry_size and not <=.
	 *
	 * buf_size =  sizeof(pfm_default_smpl_hdr_t) + slack + options.smpl_entries*entry_size;
	 */
	slack = pmu_max_entry_size - entry_size;

	ret = pfmon_compute_smpl_entries(sizeof(pfm_default_smpl_hdr_t), entry_size, slack);	

	buf_size = sizeof(pfm_default_smpl_hdr_t)
		 + slack
		 + options.smpl_entries*entry_size;

	vbprintf("sampling buffer #entries=%lu size=%zu, max_entry_size=%zu\n",
		 options.smpl_entries, buf_size, entry_size);

	/*
	 * ctx_arg is freed in pfmon_create_context().
	 */
	ctx_arg = calloc(1, sizeof(*ctx_arg));
	if (ctx_arg == NULL) {
		warning("cannot allocate format argument\n");
		return -1;
	}
	ctx->ctx_arg      = ctx_arg;
	ctx->ctx_arg_size = sizeof(pfm_default_smpl_arg_t);

	ctx_arg->buf_size = buf_size;
	ctx->ctx_map_size = buf_size;

	return 0;
}

#define CHECK_VERSION(h)	(PFM_VERSION_MAJOR((h)) != PFM_VERSION_MAJOR(PFM_DEFAULT_SMPL_VERSION))

int
default_smpl_check_version(pfmon_sdesc_t *sdesc)
{
	pfm_default_smpl_hdr_t *hdr; 
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;

	hdr = csmpl->smpl_hdr;

	if (CHECK_VERSION(hdr->hdr_version)) {
		warning("format %s expects format v%u.x not v%u.%u\n", 
				options.smpl_mod->name,
				PFM_VERSION_MAJOR(PFM_DEFAULT_SMPL_VERSION),
				PFM_VERSION_MAJOR(hdr->hdr_version),
				PFM_VERSION_MINOR(hdr->hdr_version));
		return -1;
	}
	return 0;
}
	
int
default_smpl_check_new_samples(pfmon_sdesc_t *sdesc)
{
	pfm_default_smpl_hdr_t *hdr; 
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	uint64_t last_ovfl;

	hdr       = csmpl->smpl_hdr;
	last_ovfl = csmpl->last_ovfl;

	if (hdr->hdr_overflows <= last_ovfl && last_ovfl != ~0 && hdr->hdr_count == csmpl->last_count) {
		DPRINT(("skipping identical set of samples %"PRIu64" <= %"PRIu64"\n",
			hdr->hdr_overflows,
			last_ovfl)); 
		return -1;
	}
	csmpl->last_ovfl = hdr->hdr_overflows;

	return 0;
}
