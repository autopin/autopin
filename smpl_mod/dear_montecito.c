#include <sys/types.h>
#include "dear_hist_ia64.h"

#include <perfmon/pfmlib_montecito.h>

unsigned long
dear_mont_extract(unsigned long *val, dear_sample_t *smpl)
{
	pfm_mont_pmd_reg_t *pmd;

	pmd = (pfm_mont_pmd_reg_t *)val;

		/* PMD32 */
		smpl->daddr = pmd->pmd32_mont_reg.dear_daddr;

		pmd++;

		/* PMD33 */
		smpl->latency = pmd->pmd33_mont_reg.dear_latency;
		smpl->tlb_lvl = pmd->pmd33_mont_reg.dear_stat;

		pmd++;

		/* PMD36 */
		smpl->iaddr = ((pmd->pmd36_mont_reg.dear_iaddr+pmd->pmd36_mont_reg.dear_bn) << 4) 
				        | (unsigned long)pmd->pmd36_mont_reg.dear_slot;
		return 3;
}

int
dear_mont_info(int event, dear_mode_t *mode)
{
	if (pfm_mont_is_dear(event) == 0) return -1;
	*mode = pfm_mont_is_dear_alat(event) ? DEAR_IS_ALAT
		: (pfm_mont_is_dear_tlb(event) ? DEAR_IS_TLB: DEAR_IS_CACHE);
	return 0;
}
