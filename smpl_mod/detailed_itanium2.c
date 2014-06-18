/*
 * detailed_itanium2.c - Itanium 2 support routine for detailed_ia64_smpl
 *                       module
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

#include "pfmon_itanium2.h"

#define PRINT_ADDRESS(s, type,add) \
	pfmon_print_address((s)->csmpl.smpl_fp,\
			   options.primary_syms, \
			   (type), (add), \
			   (s)->tid, \
			   (s)->current_map_version)


static int
show_ita2_btb_reg(pfmon_sdesc_t *sdesc, unsigned long j, unsigned long val, pfm_ita2_pmd_reg_t pmd16)
{
	pfm_ita2_pmd_reg_t reg;
	FILE *fp = sdesc->csmpl.smpl_fp;
	unsigned long bruflush, b1;
	uintptr_t addr;
	int is_valid;
	int ret;

	reg.pmd_val = val;

	is_valid = reg.pmd8_15_ita2_reg.btb_b == 0 && reg.pmd8_15_ita2_reg.btb_mp == 0 ? 0 :1; 
	b1       = (pmd16.pmd_val >> (4 + 4*(j-8))) & 0x1;
	bruflush = (pmd16.pmd_val >> (5 + 4*(j-8))) & 0x1;

	ret = fprintf(fp, "\tPMD%-3lu: 0x%016lx b=%d mp=%d bru=%lu b1=%lu valid=%c\n",
			j,
			reg.pmd_val,
			 reg.pmd8_15_ita2_reg.btb_b,
			 reg.pmd8_15_ita2_reg.btb_mp,
			 bruflush, b1,
			is_valid ? 'y' : 'n');

	if (!is_valid) return ret;

	if (reg.pmd8_15_ita2_reg.btb_b) {

		addr = (reg.pmd8_15_ita2_reg.btb_addr+b1)<<4;

		addr |= reg.pmd8_15_ita2_reg.btb_slot < 3 ?  reg.pmd8_15_ita2_reg.btb_slot : 0;

		fprintf(fp, "\t       source addr=");

		PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, addr);

		ret = fprintf(fp, "\n\t       taken=%c prediction=%s\n",
			 reg.pmd8_15_ita2_reg.btb_slot < 3 ? 'y' : 'n',
			 reg.pmd8_15_ita2_reg.btb_mp ? "FE failure" : 
			 bruflush ? "BE failure" : "success");
	} else {
		fprintf(fp, "\t       target addr=");
		PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, (reg.pmd8_15_ita2_reg.btb_addr<<4));
		ret = fputc('\n', fp);
	}
	return ret;
}

static int
show_ita2_btb_trace(pfmon_sdesc_t *sdesc, unsigned long val, unsigned long *btb_regs)
{
	pfm_ita2_pmd_reg_t reg;
	unsigned long i, last;
	int ret;

	reg.pmd_val = val;

	i    = reg.pmd16_ita2_reg.btbi_full ? reg.pmd16_ita2_reg.btbi_bbi : 0;
	last = reg.pmd16_ita2_reg.btbi_bbi;

	DPRINT(("btb_trace: i=%lu last=%lu bbi=%d full=%d\n", 
			i,
			last,
			reg.pmd16_ita2_reg.btbi_bbi,
			reg.pmd16_ita2_reg.btbi_full));

	do {
		ret = show_ita2_btb_reg(sdesc, i+8, btb_regs[i], reg);
		i = (i+1) % 8;
	} while (i != last && ret > 0);

	return ret;
}

int
print_ita2_reg(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set, int rnum, unsigned long val)
{
	static const char *tlb_levels[]={"N/A", "L2DTLB", "VHPT", "FAULT", "ALL"};
	static const char *tlb_hdls[]={"N/A", "L2TLB", "VHPT", "SW"};

	pfm_ita2_pmd_reg_t reg;
	pfmlib_ita2_input_param_t *param = set->mod_inp;
	FILE *fp = sdesc->csmpl.smpl_fp;
	unsigned long addr;
	unsigned long *btb_regs = sdesc->csmpl.data;
	int ret = 0;

	reg.pmd_val = val;
	switch(rnum) {
		case 0:
			fprintf(fp, "\tPMD0  : valid=%c, cache line addr=",
				reg.pmd0_ita2_reg.iear_stat ? 'y': 'n');
			/* cache line address */
			PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, (reg.pmd0_ita2_reg.iear_iaddr<<5));

			/* show which level the hit was handled */
			if (param->pfp_ita2_iear.ear_mode == PFMLIB_ITA2_EAR_TLB_MODE)
				ret = fprintf(fp, ", TLB:%s\n", tlb_hdls[reg.pmd0_ita2_reg.iear_stat]);
			else
				ret = fputc('\n', fp);
			break;
		case 1:
			if (param->pfp_ita2_iear.ear_mode  != PFMLIB_ITA2_EAR_TLB_MODE)
				ret = fprintf(fp, "\tPMD1  : latency=%d cycles, latency overflow=%c\n",
						reg.pmd1_ita2_reg.iear_latency, 
						reg.pmd1_ita2_reg.iear_overflow ? 'y' : 'n');
			break;
		case 2:
			fprintf(fp, "\tPMD2  : miss addr=");
			PRINT_ADDRESS(sdesc, PFMON_DATA_SYMBOL, reg.pmd_val);
			ret = fputc('\n', fp);
			break;
		case 3:
			fprintf(fp, "\tPMD3  : valid=%c", reg.pmd3_ita2_reg.dear_stat ? 'y' : 'n');

			if (param->pfp_ita2_dear.ear_mode == PFMLIB_ITA2_EAR_TLB_MODE) {
				ret = fprintf(fp, ", TLB:%s\n", tlb_levels[reg.pmd3_ita2_reg.dear_stat]);
			} else if (param->pfp_ita2_dear.ear_mode == PFMLIB_ITA2_EAR_CACHE_MODE) {
				ret = fprintf(fp, ", latency=%d cycles, latency overflow=%c\n", 
						reg.pmd3_ita2_reg.dear_latency,
						reg.pmd3_ita2_reg.dear_overflow ? 'y' : 'n');
			} else {
				ret = fputc('\n', fp);
			}
			break;

		case 8 ... 15:
			btb_regs[rnum-8] = val;
			break;

		case 16:
			/*
			 * keep track of what the BTB index is saying
			 */
			DPRINT(("\tPMD16 : btb_start=%d, btb_end=%d\n",
				      reg.pmd16_ita2_reg.btbi_full ? reg.pmd16_ita2_reg.btbi_bbi : 0,
				      reg.pmd16_ita2_reg.btbi_bbi == 0 ? 15 : reg.pmd16_ita2_reg.btbi_bbi-1));

			ret = show_ita2_btb_trace(sdesc, val, btb_regs);
			break;
		case 17:
			/*
			 * iaddr is the address of the 2-bundle group (size of dispersal window)
			 * therefore we adjust it with the pdm17.bn field to get which of the 2 bundles
			 * caused the miss.
			 */
			addr = ((reg.pmd17_ita2_reg.dear_iaddr+reg.pmd17_ita2_reg.dear_bn) << 4)
			     | (unsigned long)reg.pmd17_ita2_reg.dear_slot;

			fprintf(fp, "\tPMD17 : valid=%c, instr addr=", 
					reg.pmd17_ita2_reg.dear_vl ? 'y': 'n');

			PRINT_ADDRESS(sdesc,  PFMON_TEXT_SYMBOL, addr);

			ret = fputc('\n', fp);
			break;
		default:
			ret = fprintf(fp, "\tPMD%-3d: 0x%016lx\n", rnum, reg.pmd_val);
	}
	return ret;
}
