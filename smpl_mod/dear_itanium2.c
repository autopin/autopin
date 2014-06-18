#include <sys/types.h>

#include "dear_hist_ia64.h"
#include <perfmon/pfmlib_itanium2.h>

unsigned long
dear_ita2_extract(unsigned long *val, dear_sample_t *smpl)
{
	pfm_ita2_pmd_reg_t *pmd;

	pmd = (pfm_ita2_pmd_reg_t *)val;

	/* PMD2 */
	smpl->daddr = pmd->pmd_val;

	pmd++;

	/* PMD3 */
	smpl->latency = pmd->pmd3_ita2_reg.dear_latency;
	smpl->tlb_lvl = pmd->pmd3_ita2_reg.dear_stat;

	pmd++;

	/* PMD17 */
	smpl->iaddr = ((pmd->pmd17_ita2_reg.dear_iaddr+pmd->pmd17_ita2_reg.dear_bn) << 4) 
		| (unsigned long)pmd->pmd17_ita2_reg.dear_slot;

	return 3;
}

int
dear_ita2_info(int event, dear_mode_t *mode)
{
	if (pfm_ita2_is_dear(event) == 0) return -1;
	*mode = pfm_ita2_is_dear_alat(event) ? DEAR_IS_ALAT
		: (pfm_ita2_is_dear_tlb(event) ? DEAR_IS_TLB: DEAR_IS_CACHE);
	return 0;
}
