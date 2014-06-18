/*
 * detailed_montecito.c - Dual-Core Itanium 2 support routine for detailed_ia64_smpl
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

#include "pfmon_montecito.h"

#define PRINT_ADDRESS(s, type,add) \
	pfmon_print_address((s)->csmpl.smpl_fp,\
			   options.primary_syms, \
			   (type), (add), \
			   (s)->tid, \
			   (s)->current_map_version)


#define ETB_PMD38	16
#define ETB_PMD39	17

static int
show_mont_etb_reg(pfmon_sdesc_t *sdesc, unsigned long j, unsigned long val, pfm_mont_pmd_reg_t pmd39)
{
	pfm_mont_pmd_reg_t reg;
	FILE *fp = sdesc->csmpl.smpl_fp;
	unsigned long etb_ext, bruflush, b1;
	uintptr_t addr;
	int is_valid;
	int ret;

	reg.pmd_val = val;
	is_valid = reg.pmd48_63_etb_mont_reg.etb_s == 0 && reg.pmd48_63_etb_mont_reg.etb_mp == 0 ? 0 :1; 

	if (j < 8)
		etb_ext = (pmd39.pmd_val>>(8*j)) & 0xf;
	else
		etb_ext = (pmd39.pmd_val>>(4+8*(j-8))) & 0xf;

	b1       = etb_ext & 0x1;
	bruflush = (etb_ext >> 1) & 0x1;

	ret = fprintf(fp, "\tPMD%-3lu: 0x%016lx b=%d mp=%d bru=%lu b1=%lu valid=%c\n",
			j+48,
			reg.pmd_val,
			 reg.pmd48_63_etb_mont_reg.etb_s,
			 reg.pmd48_63_etb_mont_reg.etb_mp,
			 bruflush, b1,
			is_valid ? 'y' : 'n');

	if (!is_valid) return ret;

	if (reg.pmd48_63_etb_mont_reg.etb_s) {

		addr = (reg.pmd48_63_etb_mont_reg.etb_addr+b1)<<4;

		addr |= reg.pmd48_63_etb_mont_reg.etb_slot < 3 ?  reg.pmd48_63_etb_mont_reg.etb_slot : 0;

		fprintf(fp, "\t       source addr=");
		PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, addr);

		ret = fprintf(fp, "\n\t       taken=%c prediction=%s\n",
			 reg.pmd48_63_etb_mont_reg.etb_slot < 3 ? 'y' : 'n',
			 reg.pmd48_63_etb_mont_reg.etb_mp ? "FE failure" : 
			 bruflush ? "BE failure" : "success");
	} else {
		fprintf(fp, "\t       target addr=");
		PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, (reg.pmd48_63_etb_mont_reg.etb_addr<<4));
		ret = fputc('\n', fp);
	}
	return ret;
}

static int
show_mont_etb_buffer(pfmon_sdesc_t *sdesc, unsigned long *etb_regs)
{
	int ret;
	unsigned long i, last;
	pfm_mont_pmd_reg_t pmd38, pmd39;

	pmd38.pmd_val = etb_regs[ETB_PMD38];
	pmd39.pmd_val = etb_regs[ETB_PMD39];

	i    = pmd38.pmd38_mont_reg.etbi_full ? pmd38.pmd38_mont_reg.etbi_ebi : 0;
	last = pmd38.pmd38_mont_reg.etbi_ebi;

	DPRINT(("i=%lu last=%lu bbi=%d full=%d\n", 
		i,
		last,
		pmd38.pmd38_mont_reg.etbi_ebi,
		pmd38.pmd38_mont_reg.etbi_full));

	do {
		ret = show_mont_etb_reg(sdesc, i, etb_regs[i], pmd39);
		i = (i+1) % PMU_MONT_NUM_ETB;
	} while (i != last);

	return ret;
}

static int
show_mont_ipear_buffer(pfmon_sdesc_t *sdesc, unsigned long *etb_regs)
{
	int ret;
	unsigned long i, last;
	pfm_mont_pmd_reg_t pmd38, pmd39;

	pmd38.pmd_val = etb_regs[ETB_PMD38];
	pmd39.pmd_val = etb_regs[ETB_PMD39];

	i    = pmd38.pmd38_mont_reg.etbi_full ? pmd38.pmd38_mont_reg.etbi_ebi : 0;
	last = pmd38.pmd38_mont_reg.etbi_ebi;

	DPRINT(("i=%lu last=%lu bbi=%d full=%d\n", 
		i,
		last,
		pmd38.pmd38_mont_reg.etbi_ebi,
		pmd38.pmd38_mont_reg.etbi_full));

	do {
		ret = show_mont_etb_reg(sdesc, i, etb_regs[i], pmd39);
		i = (i+1) % PMU_MONT_NUM_ETB;
	} while (i != last);

	return ret;
}


int
print_mont_reg(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set, int rnum, unsigned long val)
{
	static const char *tlb_levels[]={"N/A", "L2DTLB", "VHPT", "FAULT", "ALL"};
	static const char *tlb_hdls[]={"N/A", "L2TLB", "VHPT", "SW"};

	pfm_mont_pmd_reg_t reg;
	pfmlib_mont_input_param_t *param = set->mod_inp;
	FILE *fp = sdesc->csmpl.smpl_fp;
	unsigned long *etb_regs = sdesc->csmpl.data;
	unsigned long addr;
	int ret = 0;

	reg.pmd_val = val;

	switch(rnum) {
		case 34:
			fprintf(fp, "\tPMD34 : valid=%c, cache line addr=",
				reg.pmd34_mont_reg.iear_stat ? 'y': 'n');
			/* cache line address */
			PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, (reg.pmd34_mont_reg.iear_iaddr<<5));

			/* show which level the hit was handled */
			if (param->pfp_mont_iear.ear_mode == PFMLIB_MONT_EAR_TLB_MODE)
				ret = fprintf(fp, ", TLB=%s\n", tlb_hdls[reg.pmd34_mont_reg.iear_stat]);
			else
				ret = fputc('\n', fp);
			break;
		case 35:
			if (param->pfp_mont_iear.ear_mode  != PFMLIB_MONT_EAR_TLB_MODE)
				ret = fprintf(fp, "\tPMD35 : latency=%d cycles, latency overflow=%c\n",
						reg.pmd35_mont_reg.iear_latency, 
						reg.pmd35_mont_reg.iear_ov ? 'y' : 'n');
			break;
		case 32:
			fprintf(fp, "\tPMD32 : miss addr=");
			PRINT_ADDRESS(sdesc, PFMON_DATA_SYMBOL, reg.pmd_val);
			ret = fputc('\n', fp);
			break;
		case 33:
			fprintf(fp, "\tPMD33 : valid %c", 
					reg.pmd33_mont_reg.dear_stat ? 'y' : 'n');

			if (param->pfp_mont_dear.ear_mode == PFMLIB_MONT_EAR_TLB_MODE) {
				ret = fprintf(fp, ", TLB %s\n", tlb_levels[reg.pmd33_mont_reg.dear_stat]);
			} else if (param->pfp_mont_dear.ear_mode == PFMLIB_MONT_EAR_CACHE_MODE) {
				ret = fprintf(fp, ", latency=%d cycles, latency overflow=%c\n", 
						reg.pmd33_mont_reg.dear_latency,
						reg.pmd33_mont_reg.dear_ov ? 'y' : 'n');
			} else {
				ret = fputc('\n', fp);
			}
			break;
		case 36:
			/*
			 * iaddr is the address of the 2-bundle group (size of dispersal window)
			 * therefore we adjust it with the pdm36.bn field to get which of the 2 bundles
			 * caused the miss.
			 */
			fprintf(fp, "\tPMD36 : valid %c, instr addr=",
					reg.pmd36_mont_reg.dear_vl ? 'y': 'n');

			addr = ((reg.pmd36_mont_reg.dear_iaddr+reg.pmd36_mont_reg.dear_bn) << 4) | (unsigned long)reg.pmd36_mont_reg.dear_slot;
			PRINT_ADDRESS(sdesc, PFMON_TEXT_SYMBOL, addr);
			ret = fputc('\n', fp);
			break;

		case 38:
			etb_regs[ETB_PMD38] = val;
			break;
		case 39:
			etb_regs[ETB_PMD39] = val;
			break;

		case 48 ... 63:
			etb_regs[rnum-48] = val;
			break;
		default:
			ret = fprintf(fp, "\tPMD%-3d: 0x%016lx\n", rnum, reg.pmd_val);
	}
	/*
	 * on montecito, the ETB index comes before the actual buffer registers,
	 * therefore  assume that if we see the last ETB entry, then the ETB index
	 * were sampled and saved in etb_regs. Worst case, if they are not the index
	 * will be zero.
	 */
	if (rnum == 63) {
		if (param->pfp_mont_ipear.ipear_used)
			ret = show_mont_ipear_buffer(sdesc, etb_regs);
		else
			ret = show_mont_etb_buffer(sdesc, etb_regs);
	}
	return ret;
}

