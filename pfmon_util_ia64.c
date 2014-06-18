/*
 * pfmon_util_ia64.c  - IA-64 specific set of helper functions
 *
 * Copyright (c) 2003-2006 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *
 * This file is part of pfmon, a sample tool to measure performance 
 * of applications on Linux.
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
#ifndef _GNU_SOURCE
#endif
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <link.h>
#include <sys/ptrace.h>
#include <asm/ptrace_offsets.h>

#include "pfmon.h"

/*
 * PSR bits controlling debug breakpoints
 */
#define PSR_DB_BIT	24	/* enable/disble all breakpoints */
#define PSR_ID_BIT	37	/* instruction disable debug fault for one instruction */
#define PSR_DD_BIT	39	/* data disable debug fault for one instruction */

/* 
 * architecture specified minimals
 */
#define DFL_MAX_COUNTERS  4

/*
 * layout of CPUID[3] register
 */
typedef union {
	unsigned long value;
	struct {
	unsigned long number	:  8;
	unsigned long revision	:  8;
	unsigned long model	:  8;
	unsigned long family	:  8;
	unsigned long archrev	:  8;
	unsigned long reserved	: 24;
	} cpuid3;
} cpuid3_t;

typedef struct {
	unsigned long cpuid;
	char *family;
	char *code_name;
} cpu_info_t;


static cpu_info_t cpu_info[]={
	{ 0x7000000 , "Itanium"  , "Merced" },
	{ 0x1f000000, "Itanium 2", "McKinley" },
	{ 0x1f010000, "Itanium 2", "Madison"  },
	{ 0x20000000, "Dual-Core Itanium 2", "Montecito" },
};
#define NUM_CPUIDS	(sizeof(cpu_info)/sizeof(cpu_info_t))

#define CPUID_MATCH_ALL		(~0UL)
#define CPUID_MATCH_FAMILY	(0x00000000ff000000)
#define CPUID_MATCH_REVISION	(0x000000000000ff00)
#define CPUID_MATCH_MODEL	(0x0000000000ff0000)

#ifdef __GNUC__
static inline unsigned long
ia64_get_cpuid (unsigned long regnum)
{
	unsigned long r;

#if defined(PFMON_USING_INTEL_ECC_COMPILER)
	r = __getIndReg(_IA64_REG_INDR_CPUID, (regnum));
#elif defined(__GNUC__)
	asm ("mov %0=cpuid[%r1]" : "=r"(r) : "rO"(regnum));
#else /* !GNUC nor INTEL_ECC */
#error "need to define a set of compiler-specific macros"
#endif
#endif
	return r;
}


static int
ia64_extract_dbr_info(unsigned int *ndbrs, unsigned int *nibrs)
{
	FILE *fp;	
	char *p;
	unsigned int ibr = 0;
	unsigned int dbr = 0;
	int ret = -1;
	char *buffer = NULL;
	size_t len = 0;

	if (ndbrs == NULL || nibrs == NULL) return -1;

	fp = fopen("/proc/pal/cpu0/register_info", "r");
	if (fp == NULL) return -1;

	while(getline(&buffer, &len, fp)) {
		p = strchr(buffer, ':');
		if (p == NULL) goto not_found;

		*p = '\0'; 
		if (!strncmp("Instruction debug register", buffer, 26)) {
			ibr = atoi(p+2);
			continue;
		}

		if (!strncmp("Data debug register", buffer, 19)) {
			dbr = atoi(p+2);
			break;
		}
	}
	*nibrs = ibr;
	*ndbrs = dbr;
	ret = 0;

not_found:
	free(buffer);
	fclose(fp);

	return ret;
}

static cpu_info_t *
ia64_find_cpuid(unsigned long cpuid, unsigned long mask)
{
	unsigned int i;
	cpu_info_t *info;

	for(i=0, info = cpu_info; i < NUM_CPUIDS; i++, info++) {
		if ((info->cpuid & mask) == (cpuid & mask)) return info;
	}
	return NULL;
}

/*
 * levels:
 * 	cache levels: 1, 2, 3
 * 	type        : 0 (unified), 1 (data), 2 (code)
 */
static int
ia64_extract_cache_size(unsigned int level, unsigned int type, unsigned long *size)
{
	FILE *fp;
	char *p, *value = NULL;
	int ret = -1;
	unsigned int lvl = 1, t = -1;
	char *buffer = NULL;
	size_t len = 0;

	if (size == NULL) return -1;

	fp = fopen("/proc/pal/cpu0/cache_info", "r");
	if (fp == NULL) return -1;

	while(getline(&buffer, &len, fp)) {
		p = buffer;

		/* skip  blank lines */
		if (*p == '\n') continue;

		p = strchr(buffer, ':');
		if (p == NULL) goto not_found;

		*p = '\0'; value = p+2;

		if (buffer[0] != '\t') {
			if (buffer[0] == 'D') t = 1; /* data */
			if (buffer[0] == 'I') t = 2; /* instruction */
			/*
			 * unified must begin with D.../
			 */
			if (t == 1 && strchr(buffer, '/')) t = 0; /* unified */
			/*
			 * assume at best 10 levels. Oh well!
			 */
			lvl = buffer[strlen(buffer)-1]-'0';
		}
		/* skip tab */
		p = buffer+1;
		if (lvl == level && t == type && !strncmp("Size", p, 4)) {
			break;
		}	
	}
	if (value) *size = atoi(value);
	ret   = 0;
not_found:
	free(buffer);
	fclose(fp);

	return ret;
}

int
pfmon_get_cache_info(int cpuid, pfmon_cache_info_t *info)
{
	FILE *fp1;	
	char fn[64], *p;
	char *buffer = NULL, *value = NULL;
	size_t len = 0;
	int s, sz, lvl = 0, is_data = 0;

	memset(info, 0, sizeof(*info));

	sprintf(fn, "/proc/pal/cpu%d/cache_info", cpuid);
	fp1 = fopen(fn, "r");
	if (fp1 == NULL) return -1;

	while(getline(&buffer, &len, fp1)) {
		p = buffer;
		/* skip  blank lines */
		if (*p == '\n') continue;

		p = strchr(buffer, ':');
		if (p == NULL) goto end_it;	

		*p = '\0'; value = p+2;

		if (buffer[0] != '\t') {
			lvl = buffer[strlen(buffer)-1] - '0' -1;
			if (strchr(buffer, '/') == NULL) {
				is_data =  buffer[0] == 'D' ? 1 : 0;
			} else {
				is_data = 1; /* unified */
			}
		}
		/* skip tab */
		p = buffer+1;
		if (!strncmp("Size", p, 4)) {
			sz =  atoi(value);
			if (is_data)
				info->d_size[lvl] = sz;
			else
				info->i_size[lvl] = sz;
			continue;
		}	
		if (!strncmp("Store latency", p, 13)) {
			s = atoi(value);
			if (is_data)
				info->d_latency[lvl][1] = s;
			else
				info->i_latency[lvl][1] = s;
			continue;
		}
#if 0
		if (!strncmp("Line size", p, 9)) {
			lsz = atoi(value);
			continue;
		}
#endif
		if (!strncmp("Load latency", p, 12)) {
			s = atoi(value);
			if (is_data)
				info->d_latency[lvl][0] = s;
			else
				info->i_latency[lvl][0] = s;
		}
	}
end_it:
	free(buffer);
	fclose(fp1);
	return 0;
}

static int
ia64_extract_pal_info(program_options_t *options)
{
	int ret;

	ret = ia64_extract_dbr_info(&options->ndbrs, &options->nibrs);

	return ret;
}

static void
ia64_print_palinfo(FILE *fp, int cpuid)
{
	FILE *fp1;	
	char fn[64], *p;
	char *buffer = NULL, *value = NULL;
	size_t len = 0;
	int cache_lvl = 0;
	char cache_name[64];
	int lsz=0, st_lat=0, sz=0;

	sprintf(fn, "/proc/pal/cpu%d/version_info", cpuid);
	fp1 = fopen(fn, "r");
	if (fp1 == NULL) return;

	while (getline(&buffer, &len, fp1)) {

		p = strchr(buffer, ':');
		if (p == NULL) goto end_it;	
		*p = '\0'; value = p+2;

		if (!strncmp("PAL_", buffer, 4)&& (buffer[4] == 'A' || buffer[4] == 'B')) {
			buffer[5] = '\0';
			p = strchr(value, ' ');
			if (p) *p = '\0';
			fprintf(fp, "#\t%s: %s\n", buffer, value);
		}
	}
	free(buffer);

	buffer = NULL; len = 0;

	fclose(fp1);

	sprintf(fn, "/proc/pal/cpu%d/cache_info", cpuid);

	fp1 = fopen(fn, "r");
	if (fp1 == NULL) return;

	while(getline(&buffer, &len, fp1)) {

		p = buffer;
		/* skip  blank lines */
		if (*p == '\n') continue;

		p = strchr(buffer, ':');
		if (p == NULL) goto end_it;	

		*p = '\0'; value = p+2;

		if (buffer[0] != '\t') {
			if (strchr(buffer, '/'))
				sprintf(cache_name, "L%c ",buffer[strlen(buffer)-1]); 
			else {
				sprintf(cache_name, "L%c%c",
						buffer[strlen(buffer)-1],
						buffer[0]);
			}
		}

		if (!strncmp("Cache levels", buffer, 12)) {
			cache_lvl = atoi(value);
			continue;
		}
		if (!strncmp("Unique caches",buffer, 13)) {
			int s = atoi(value);
			fprintf(fp, "#\tCache levels: %d Unique caches: %d\n", cache_lvl, s);
			continue;
		}
		/* skip tab */
		p = buffer+1;
		if (!strncmp("Size", p, 4)) {
			sz = atoi(value);
			continue;
		}	
		if (!strncmp("Store latency", p, 13)) {
			st_lat = atoi(value);
			continue;
		}
		if (!strncmp("Line size", p, 9)) {
			lsz = atoi(value);
			continue;
		}
		if (!strncmp("Load latency", p, 12)) {
			int s = atoi(value);
			fprintf(fp, "#\t%s: %8d bytes, line %3d bytes, load_lat %3d, store_lat %3d\n", 
				    cache_name, sz, lsz, s, st_lat);
		}
	}
end_it:
	free(buffer);
	fclose(fp1);
}

/*
 * Set the desginated bit in the psr. 
 *
 * If mode is:
 *	> 0 : the bit is set
 *	0   : the bit is cleared
 */ 
#define PSR_MODE_CLEAR	0
#define PSR_MODE_SET	1
static int
ia64_set_psr_bit(pid_t pid, int bit, int mode)
{
	unsigned long psr;

	psr = ptrace(PTRACE_PEEKUSER, pid, PT_CR_IPSR, 0);
	if (psr == (unsigned long)-1) return -1;

	/*
	 * set the psr.up bit
	 */
	if (mode) 
		psr |= 1UL << bit;
	else
		psr &= ~(1UL << bit);

	return ptrace(PTRACE_POKEUSER, pid, PT_CR_IPSR, psr) == -1 ? -1 : 0;
}

typedef union {
	struct {
		unsigned long mask:56;
		unsigned long plm:4;
		unsigned long ig:3;
		unsigned long x:1;
	} c;
	struct {
		unsigned long mask:56;
		unsigned long plm:4;
		unsigned long ig:2;
		unsigned long w:1;
		unsigned long r:1;
	} d;
	unsigned long value;
} dbreg_mask_reg_t;

#define IBR_ADDR_OFFSET(x)	((x <<4) + PT_IBR)
#define IBR_CTRL_OFFSET(x)	(IBR_ADDR_OFFSET(x)+8)

#define DBR_ADDR_OFFSET(x)	((x <<4) + PT_DBR)
#define DBR_CTRL_OFFSET(x)	(DBR_ADDR_OFFSET(x)+8)

#define IBR_MAX 4
#define DBR_MAX 4

#define PRIV_LEVEL_USER_MASK	(1<<3) /* user level breakpoints only */

/*
 * this function sets a code breakpoint at bundle address
 * In our context, we only support this features from user level code (of course). It is 
 * not possible to set kernel level breakpoints.
 *
 * The dbreg argument varies from 0 to 3, the configuration registers are not directly
 * visible.
 */
int
pfmon_set_code_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	int dbreg = trg->brk_idx;
	dbreg_mask_reg_t mask;
	long r;

	if (dbreg < 0 || dbreg >= IBR_MAX) return -1;

	r = ptrace(PTRACE_POKEUSER, pid, IBR_ADDR_OFFSET(dbreg), (void *)trg->brk_address);
	if (r == -1) return -1;

	/*
	 * initialize mask
	 */
	mask.value = 0UL;

	mask.c.x    = 1;
	mask.c.plm  = PRIV_LEVEL_USER_MASK;
	/* 
	 * we want exact match here 
	 */
	mask.c.mask = ~0; 

	return ptrace(PTRACE_POKEUSER, pid, IBR_CTRL_OFFSET(dbreg), mask.value) == -1 ? -1 : 0;
}

int
pfmon_clear_code_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	int dbreg = trg->brk_idx;
	dbreg_mask_reg_t mask;

	if (dbreg < 0 || dbreg > IBR_MAX) return -1;

	/*
	 * initialize mask
	 */
	mask.value = 0UL;

	mask.c.x    = 0;
	mask.c.plm  = 0;
	/* 
	 * we want exact match here 
	 */
	mask.c.mask = ~0; 

	return ptrace(PTRACE_POKEUSER, pid, IBR_CTRL_OFFSET(dbreg), mask.value) == -1 ? -1 : 0;
}


/*
 * this function sets a data breakpoint at an address
 * In our context, we only support this features for user level code (of course). It is 
 * not possible to set kernel level breakpoints.
 *
 * The dbreg argument varies from 0 to 4, the configuration registers are not directly
 * visible.
 *
 * the rw field:
 * 	bit 0 = w : 1 means trigger on write access
 * 	bit 1 = r : 1 means trigger on read access
 */
int
pfmon_set_data_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	int dbreg = trg->brk_idx;
	dbreg_mask_reg_t mask;
	long r;

	if (dbreg < 0 || dbreg > DBR_MAX) return -1;

	r = ptrace(PTRACE_POKEUSER, pid, DBR_ADDR_OFFSET(dbreg), (void *)trg->brk_address);
	if (r == -1) return -1;

	/*
	 * initialize mask
	 */
	mask.value = 0UL;

	mask.d.r   = trg->trg_attr_rw & 0x2 ? 1 : 0;
	mask.d.w   = trg->trg_attr_rw & 0x1 ? 1 : 0;
	mask.d.plm = PRIV_LEVEL_USER_MASK;
	/* 
	 * we want exact match here 
	 */
	mask.d.mask = ~0; 

	return ptrace(PTRACE_POKEUSER, pid, DBR_CTRL_OFFSET(dbreg), mask.value) == -1 ? -1 : 0;
}

int
pfmon_clear_data_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	int dbreg = trg->brk_idx;
	dbreg_mask_reg_t mask;

	if (dbreg < 0 || dbreg > DBR_MAX) return -1;

	/*
	 * initialize mask
	 */
	mask.value = 0UL;

	mask.d.r   = 0;
	mask.d.w   = 0;
	mask.d.plm = 0;
	/* 
	 * we want exact match here 
	 */
	mask.d.mask = ~0; 

	return ptrace(PTRACE_POKEUSER, pid, DBR_CTRL_OFFSET(dbreg), mask.value) == -1 ? -1 : 0;
}

int
pfmon_resume_after_code_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	return ia64_set_psr_bit(pid, PSR_ID_BIT, PSR_MODE_SET);
}

int
pfmon_resume_after_data_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	return ia64_set_psr_bit(pid, PSR_DD_BIT, PSR_MODE_SET);
}

void
pfmon_print_simple_cpuinfo(FILE *fp, const char *msg)
{
	cpu_info_t *info;
	unsigned int freq;
	unsigned long l3_size = 0UL;
	cpuid3_t cpuid;

	cpuid.value = ia64_get_cpuid(3);
	freq        = pfmon_find_cpu_speed();

	/*
	 * extract unified L3 cache size
	 */
	ia64_extract_cache_size(3, 0, &l3_size);

	fprintf(fp, "%s %lu-way %uMHz/%.1fMB ", 
		msg ? msg : "", 
		options.online_cpus, 
		freq,
		(1.0*l3_size)/(1024*1024));

	info = ia64_find_cpuid(cpuid.value, CPUID_MATCH_FAMILY|CPUID_MATCH_MODEL);
	if (info) {
		fprintf(fp, "%s (%s, rev %u)\n", info->family, info->code_name, cpuid.cpuid3.revision);
		return;
	}
	info = ia64_find_cpuid(cpuid.value, CPUID_MATCH_FAMILY);
	if (info) {
		fprintf(fp, "%s (rev %u)\n", info->family, cpuid.cpuid3.revision);
		return;
	}
	fprintf(fp, "CPU family %u model %u revision %u\n", cpuid.cpuid3.family, cpuid.cpuid3.model, cpuid.cpuid3.revision);
}

void
pfmon_print_cpuinfo(FILE *fp)
{
	/*
	 * assume all CPUs are identical
	 */
	pfmon_print_simple_cpuinfo(fp, "# host CPUs: ");
	ia64_print_palinfo(fp, 0);
}

void
pfmon_arch_initialize(void)
{
	ia64_extract_pal_info(&options);

  	options.opt_hw_brk = 1;
	options.opt_support_gen = 1;
	options.libpfm_generic  = PFMLIB_GEN_IA64_PMU;
}

int
pfmon_enable_all_breakpoints(pid_t pid)
{
	return ia64_set_psr_bit(pid, PSR_DB_BIT, PSR_MODE_SET);
}

int
pfmon_disable_all_breakpoints(pid_t pid)
{
	return ia64_set_psr_bit(pid, PSR_DB_BIT, PSR_MODE_CLEAR);
}

int
pfmon_validate_code_trigger_address(uintptr_t addr)
{
	unsigned long region;

	if (addr & 0xfUL) {
		warning("code trigger address does not start on bundle boundary : %p\n", (void *)addr);
		return -1;
	}

	region = addr >> 61;
	if (region > 4) {
		warning("code trigger address cannot be inside the kernel : %p\n", (void *)addr);
		return -1;
	}
	return 0;
}
	
int
pfmon_validate_data_trigger_address(uintptr_t addr)
{
	unsigned long region;

	region = addr >> 61;
	if (region > 4) {
		warning("data trigger address cannot be inside the kernel : %p\n", (void *)addr);
		return -1;
	}
	return 0;
}

void
pfmon_segv_handler_info(struct siginfo *info, void *extra)
{
	struct sigcontext *sc = (struct sigcontext *)extra;
	printf("<pfmon fatal error @ [%d:%d] ip=0x%lx addr=%p>\n", getpid(), gettid(), sc->sc_ip, info->si_addr);
}

#define PFMON_ISR_VALID	1UL /* ISR_VALID flag */

#ifndef TRAP_HWBRKPT
#define TRAP_HWBRKPT	4
#endif

int
pfmon_get_breakpoint_addr(pid_t pid, uintptr_t *addr, int *is_data)
{
	struct siginfo si;
	uintptr_t tmp;
	long r;

	r = ptrace(PTRACE_GETSIGINFO, pid, 0, &si);
	if (r == -1) {
		warning("task [%d] ptrace(siginfo)=%s\n", pid, strerror(errno));
		return -1;
	}

	if (si.si_code != TRAP_HWBRKPT) {
		warning("task [%d] unexpected si_code=%d\n", pid, si.si_code);
		return -1;
	}

	*addr = (uintptr_t)si.si_addr;

	/*
	 * fast path, the kernel passes isr on hardware debug traps
	 */
	if (si._sifields._sigfault._si_isr & PFMON_ISR_VALID) {

		*is_data = si._sifields._sigfault._si_isr & (1UL<<32) ? 0 : 1;

		DPRINT(("isr=0x%lx addr=%p data=%d\n", si._sifields._sigfault._si_isr, (void *)*addr, *is_data));
		return 0;
	}

	/*
	 * slow path, we need to compare si_addr with iip
	 * to determine if we hit a data/code breakpoint
	 */
	tmp = (uintptr_t)ptrace(PTRACE_PEEKUSER, pid, PT_CR_IIP, 0);
	if (tmp == (uintptr_t)-1) {
		warning("[%d] cannot peekuse for IIP: %s\n", pid, strerror(errno));
		return -1;
	} 
	*is_data = tmp == *addr ? 0 : 1;
	DPRINT(("isr invalid addr=%p data=%d\n", (void *)*addr, *is_data));

	return 0;
}

int
pfmon_get_return_pointer(pid_t pid, uintptr_t *rp)
{
	uintptr_t tmp;

	tmp  = (uintptr_t)ptrace(PTRACE_PEEKUSER, pid, PT_B0, 0);
	if (tmp == (uintptr_t)-1) {
		warning("[%d] cannot retrieve b0: %s\n", strerror(errno));
		return -1;
	}
	*rp = tmp;
	return 0;
}

struct r_debug32 {
	int32_t  r_version;
	uint32_t r_map_pointer;
	uint32_t r_brk;
	enum {
		RT32_CONSISTENT,
		RT32_ADD,
		RT32_DELETE
	} r_state;
	uint32_t r_ldbase;
}; 

unsigned long
pfmon_get_dlopen_hook(pfmon_sdesc_t *sdesc)
{
	/* XXX: assume sizeof(r_debug) > sizeof(r_debug32) */
#define ROUND_UP_V(s)	((s+sizeof(unsigned long)-1)/sizeof(unsigned long))
	union {
		struct r_debug rd64;
		struct r_debug32 rd32;
		unsigned long  v[ROUND_UP_V(sizeof(struct r_debug))];
	} u;
	unsigned long start, r_brk;
	unsigned long faddr[2];
	size_t sz;
	int ret, i, version;

	vbprintf("[%d] dlopen hook on %.32s\n", sdesc->pid, sdesc->new_cmdline);

	/*
	 * see link.h for description fo _r_debug
	 */
	ret = find_sym_addr("_r_debug", options.primary_syms, PFMON_DATA_SYMBOL, &start, NULL);
	if (ret == -1) {
		vbprintf("[%d] dlopen hook not found, ignoring dlopen/dlclose\n", sdesc->tid);
		return 0;
	}

	if (sdesc->fl_abi32) 
		sz = ROUND_UP_V(sizeof(struct r_debug32));
	else
		sz = ROUND_UP_V(sizeof(struct r_debug));


	/*
	 * XXX: probably does not work with Big Endian systems
	 */
	for(i=0; i < sz; i++) {
		u.v[i] = ptrace(PTRACE_PEEKTEXT, sdesc->tid, start+i*sizeof(unsigned long), 0);
		DPRINT(("v[%d]=0x%lx\n", i, u.v[i]));
	}

	DPRINT(("_r_debug=0x%lx\n", start));

	if (sdesc->fl_abi32)
		r_brk = (unsigned long)u.rd32.r_brk;
	else
		r_brk = u.rd64.r_brk;

	/*
	 * IA-64 uses function descriptor for function pointers
	 * Thus we need to read the function descriptor and extract
	 * the first long to get to the address of the dlopen hook
	 */
	faddr[0] = ptrace(PTRACE_PEEKTEXT, sdesc->tid, r_brk, 0);

	if (sdesc->fl_abi32 == 0) {
		faddr[1] = ptrace(PTRACE_PEEKTEXT, sdesc->tid, r_brk+sizeof(unsigned long), 0);
		version = u.rd32.r_version;
	} else {
		version = u.rd64.r_version;
		faddr[1] = faddr[0] >> 32;
		faddr[0] &= (1UL <<32) -1;
	}
	DPRINT(("abi32=%d version=%d r_brk=%p brk_func=%p\n", sdesc->fl_abi32, version, (void *)r_brk, (void *)faddr[0]));

	return faddr[0];
}
