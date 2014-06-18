/*
 * raw_smpl.c - write buffer in binary form into a file for perfmon v2.0
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
#include "pfmon_smpl_ia64_old.h"

#include <perfmon/perfmon_default_smpl.h>

static int
raw_process_samples(pfmon_sdesc_t *sdesc)
{
	pfm_default_smpl_hdr_t *hdr;
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	void *first_pos;
	size_t sz;
	ssize_t ret;

	hdr       = csmpl->smpl_hdr;
	if (hdr == NULL)
		return 0;
	first_pos = (void *)(hdr+1);
	sz        = hdr->hdr_cur_offs - sizeof(*hdr);

	ret = write(fileno(csmpl->smpl_fp), first_pos, sz);
	if (ret < sz) goto error;

	if (options.opt_aggr) {
		*csmpl->aggr_count += hdr->hdr_count;
	} else {
		csmpl->entry_count += hdr->hdr_count;
	}
	return 0;
error:
	warning("cannot write to raw sampling file: %s\n", strerror(errno));
	/* not reached */
	return -1;
}
pfmon_smpl_module_t raw_old_smpl_module;
static void raw_old_initialize_mask(void)
{
	pfmon_bitmask_setall(raw_old_smpl_module.pmu_mask);
}

pfmon_smpl_module_t raw_old_smpl_module ={
	.name		    = "raw",
	.description	    = "dump buffer in binary format",
	.process_samples    = raw_process_samples,
	.init_ctx_arg	    = default_smpl_init_ctx_arg,
	.check_version	    = default_smpl_check_version,
	.check_new_samples  = default_smpl_check_new_samples,
	.initialize_mask    = raw_old_initialize_mask,
	.flags		    = PFMON_SMPL_MOD_FL_LEGACY,
	.uuid		    = PFM_DEFAULT_SMPL_UUID,
};
