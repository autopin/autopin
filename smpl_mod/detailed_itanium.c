/*
 * detailed_itanium.c - Itanium support routine for detailed_ia64_smpl
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

#include "pfmon_itanium.h"

#define PRINT_ADDRESS(s, type,add) \
	pfmon_print_address((s)->csmpl.smpl_fp,\
			   options.primary_syms, \
			   (type), (add), \
			   (s)->tid, \
			   (s)->current_map_version)

static int
show_ita_btb_reg(pfmon_sdesc_t *sdesc, unsigned long j, unsigned long val)
{
	pfm_ita_pmd_reg_t reg;
	FILE *fp = sdesc->csmpl.smpl_fp;
	int is_valid, ret;

	reg.pmd_val = val;
	is_valid = reg.pmd8_15_ita_reg.btb_b == 0 && reg.pmd8_15_ita_reg.btb_mp == 0 ? 0 :1; 

	ret = fprintf(fp, "\tPMD%-3lu: 0x%016lx b=%d mp=%d valid=%c\n",
			j,
			reg.pmd_val,
			 reg.pmd8_15_ita_reg.btb_b,
			 reg.pmd8_15_ita_reg.btb_mp,
			is_valid ? 'y' : 'n');

	if (!is_valid) return ret;

	if (reg.pmd8_15_ita_reg.btb_b) {
		uintptr_t addr;

		addr = 	reg.pmd8_15_ita_reg.btb_addr<<4;
		addr |= reg.pmd8_15_ita_reg.btb_slot < 3 ?  reg.pmd8_15_ita_reg.btb_slot : 0;

		fprintf(fp, "\t       source addr=");

		PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, addr);

		ret = fprintf(fp, "\n\t       taken=%c prediction=%s\n\n",
			 reg.pmd8_15_ita_reg.btb_slot < 3 ? 'y' : 'n',
			 reg.pmd8_15_ita_reg.btb_mp ? "failure" : "success");
	} else {
		fprintf(fp, "\t       target addr=");
		PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, (reg.pmd8_15_ita_reg.btb_addr<<4));
		ret = fputc('\n', fp);
	}
	return ret;
}

static int
show_ita_btb_trace(pfmon_sdesc_t *sdesc, unsigned long val, unsigned long *btb_regs)
{
	pfm_ita_pmd_reg_t reg;
	unsigned long i, last; 
	int ret;

	reg.pmd_val = val;

	i    = reg.pmd16_ita_reg.btbi_full ? reg.pmd16_ita_reg.btbi_bbi : 0;
	last = reg.pmd16_ita_reg.btbi_bbi;

	DPRINT(("btb_trace: i=%lu last=%lu bbi=%d full=%d\n", 
			i,
			last, 
			reg.pmd16_ita_reg.btbi_bbi,
			reg.pmd16_ita_reg.btbi_full));

	do {
		ret = show_ita_btb_reg(sdesc, i+8, btb_regs[i]);
		i = (i+1) % 8;
	} while (i != last);

	return ret;
}

int
print_ita_reg(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set, int rnum, unsigned long val)
{
	static const char *tlb_levels[]={"N/A", "L2DTLB", "VHPT", "SW"};
	static const char *tlb_hdls[]={"VHPT", "SW"};

	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	pfm_ita_pmd_reg_t reg;
	pfmlib_ita_input_param_t *param = set->mod_inp;
	FILE *fp = csmpl->smpl_fp;
	unsigned long *btb_regs = csmpl->data;
	unsigned long addr;
	int ret = 0;

	reg.pmd_val = val;

	switch(rnum) {
		case 0:
			fprintf(fp, "\tPMD0  : valid=%c, cache line=",
				reg.pmd0_ita_reg.iear_v ? 'y': 'n');
			addr = reg.pmd0_ita_reg.iear_icla<<5;
			/* cache line address */
			PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, addr);

			if (param->pfp_ita_iear.ear_mode == PFMLIB_ITA_EAR_TLB_MODE)
				ret = fprintf(fp, ", TLB:%s\n", tlb_hdls[reg.pmd0_ita_reg.iear_tlb]);
			else
				ret = fputc('\n', fp);
			break;
		case 1:
			if (param->pfp_ita_iear.ear_mode != PFMLIB_ITA_EAR_TLB_MODE)
				ret = fprintf(fp, "\tPMD1  : latency=%d cycles\n",
						reg.pmd1_ita_reg.iear_lat);
			break;
		case 2:
			fprintf(fp, "\tPMD2  : miss address=");
			PRINT_ADDRESS(sdesc, PFMON_DATA_SYMBOL, reg.pmd_val);
			ret = fputc('\n', fp);
			break;
		case 3:
			fprintf(fp, "\tPMD3  : ");

			if (param->pfp_ita_dear.ear_mode == PFMLIB_ITA_EAR_TLB_MODE)
				ret = fprintf(fp, ", TLB:%s\n", tlb_levels[reg.pmd3_ita_reg.dear_level]);
			else
				ret = fprintf(fp, ", latency=%d cycles\n", reg.pmd3_ita_reg.dear_latency);
			break;
		case 8 ... 15:
			btb_regs[rnum-8] = val;
			break;
		case 16:
			ret = show_ita_btb_trace(sdesc, val, btb_regs);
			break;
		case 17:

			ret = fprintf(fp, "\tPMD17 : valid=%c, instr address=",
					reg.pmd17_ita_reg.dear_vl ? 'y': 'n');

			addr = ((reg.pmd17_ita_reg.dear_iaddr << 4) | reg.pmd17_ita_reg.dear_slot);
			PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, addr);
			fputc('\n', fp);
			break;
		default:
			ret = fprintf(fp, "\tPMD%-3d: 0x%016lx\n", rnum, reg.pmd_val);
	}
	return ret;
}
