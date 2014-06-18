/*
 * pfmon_util_x86.c  - X86-64/i386 common set of helper functions
 *
 * Copyright (c) 2007 Hewlett-Packard Development Company, L.P.
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
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <link.h>
#include <sys/ptrace.h>
#include <sys/ucontext.h>
#include <sys/user.h>

#include "pfmon.h"

#define IBRS_BASE	0
#define DBRS_BASE	2

int
pfmon_get_cache_info(int cpuid, pfmon_cache_info_t *info)
{
	return 0;
}

typedef struct {
	unsigned long l0:1;
	unsigned long g0:1;
	unsigned long l1:1;
	unsigned long g1:1;
	unsigned long l2:1;
	unsigned long g2:1;
	unsigned long l3:1;
	unsigned long g3:1;
	unsigned long le:1;
	unsigned long ge:1;
	unsigned long res1:3; /* must be 1 */
	unsigned long gd:1;
	unsigned long res2:2; /* must be 0 */
	unsigned long rw0:2;
	unsigned long len0:2;
	unsigned long rw1:2;
	unsigned long len1:2;
	unsigned long rw2:2;
	unsigned long len2:2;
	unsigned long rw3:2;
	unsigned long len3:2;
	unsigned long res:32;
} dr7_reg_t;

typedef union {
	dr7_reg_t reg;
	unsigned long val;
} dr7_t;

static int
pfmon_x86_set_breakpoint(pid_t pid, int dbreg, unsigned long address, int rw)
{
	dr7_t dr7;
	unsigned long rw_mode = 0;
	unsigned long offset;
	long r;

	offset = offsetof(struct user, u_debugreg[7]);
	dr7.val = ptrace(PTRACE_PEEKUSER, (long)pid, offset, 0);
	if (dr7.val == -1) {
		warning("cannot peek %d\n", errno);
		return -1;
	}
	DPRINT(("dr7=0x%lx\n", dr7.val));

	dr7.reg.res1 = 0; /* reserved bits */
	dr7.reg.le   = 1; /* ignored for AMD64 */
	dr7.reg.ge   = 1; /* ignored for AMD64 */
	/* 
	 * rwXX is zero for instruction execution only
	 * lenXX is zero for instruction execution only
	 */

	/*
	 * XXX: IA-32 cannot do read only, we do do read-write
	 */
	switch(rw) {
		case 0: 
			rw_mode = 0;
			break;
		case  1:
		case  2: /* IA-32 cannot do read-only */
			rw_mode = 1;
			break;
		case  3:
			rw_mode = 3;
			break;
	}
	/*
	 * l0-l3 bits are under the control of
	 *	- clear_breakpoint
	 *	- enable_all_breakpoints
	 *	- disable_all_breakpoints
	 */
	switch(dbreg) {
		case	0:
			dr7.reg.len0 = 0;
			dr7.reg.rw0  = rw_mode;
			break;
		case	1:
			dr7.reg.len1 = 0;
			dr7.reg.rw1  = rw_mode;
			break;
		case	2:
			dr7.reg.len2 = 0;
			dr7.reg.rw2  = rw_mode;
			break;
		case	3:
			dr7.reg.len3 = 0;
			dr7.reg.rw3  = rw_mode;
			break;
		default:
			fatal_error("unexpected debug register %d\n", dbreg);
	}
	DPRINT(("dr7: poke=0x%lx offs=%ld\n", dr7.val, offset));

	r = ptrace(PTRACE_POKEUSER, pid, offset, dr7.val);
	if (r == -1) {
		warning("cannot poke dr7\n");
		return -1;
	}
	dr7.val = ptrace(PTRACE_PEEKUSER, (long)pid, offset, 0);
	DPRINT(("dr7: peek=0x%lx offs=%ld\n", dr7.val, offset));

	DPRINT(("dr%d: poke=0x%lx\n", dbreg, address));

	offset = offsetof(struct user, u_debugreg[dbreg]);
	return ptrace(PTRACE_POKEUSER, pid, offset, address);
}

/*
 * common function to clear a breakpoint
 */
static int
pfmon_x86_clear_breakpoint(pid_t pid, int dbreg)
{
	dr7_t dr7;
	unsigned long offset;

	offset = offsetof(struct user, u_debugreg[7]);

	dr7.val = ptrace(PTRACE_PEEKUSER, pid, offset, 0);
	if (dr7.val == -1) return -1;

	DPRINT(("dr7=0x%lx dbreg=%d\n", dr7.val, dbreg));

	/* clear lX bit */
	switch(dbreg) {
		case	0:
			dr7.reg.l0 = 0;
			break;
		case	1:
			dr7.reg.l1 = 0;
			break;
			break;
		case	2:
			dr7.reg.l2 = 0;
			break;
		case	3:
			dr7.reg.l3 = 0;
			break;
		default:
			fatal_error("unexpected debug register %d\n", dbreg);
	}

	DPRINT(("dr7: poke=0x%lx offs=%ld\n", dr7.val, offset));

	return ptrace(PTRACE_POKEUSER, pid, offset, dr7.val);
}

/*
 * this function sets a code breakpoint at bundle address
 * In our context, we only support this features from user level code (of course). It is 
 * not possible to set kernel level breakpoints.
 */
static int
pfmon_set_code_hw_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	int dbreg = trg->brk_idx;
	if (dbreg < 0 || dbreg >= options.nibrs) return -1;

	dbreg += IBRS_BASE;

	return pfmon_x86_set_breakpoint(pid, dbreg, trg->brk_address, 0);
}

static int
pfmon_set_code_sw_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	unsigned long val, brk = 0xcc;

	/* this call read a long at brk_address */
	val = ptrace(PTRACE_PEEKDATA, (long)pid, trg->brk_address, 0);
	if (val == -1) {
		warning("cannot peektext %s\n", strerror(errno));
		return -1;
	}

	trg->brk_data[0] = val;
	brk = (val&~0xff) | 0xcc;

	DPRINT(("0x%lx=0x%lx (was 0x%lx)\n", trg->brk_address, brk, val));

	val = ptrace(PTRACE_POKEDATA, (long)pid, trg->brk_address, brk);
	if (val == -1) {
		warning("cannot poketext %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int
pfmon_set_code_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	if (options.opt_hw_brk)
		return pfmon_set_code_hw_breakpoint(pid, trg);
	return pfmon_set_code_sw_breakpoint(pid, trg);
}


/*
 * this function removes a code breakpoint
 */
static int
pfmon_clear_code_hw_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	int dbreg = trg->brk_idx;
	if (dbreg < 0 || dbreg >= options.nibrs) return -1;

	dbreg += IBRS_BASE;

	return pfmon_x86_clear_breakpoint(pid, dbreg);
}

static int
pfmon_clear_code_sw_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	unsigned long val;

	/* this call writes a long to brk_address */
	val = ptrace(PTRACE_POKEDATA, (long)pid, trg->brk_address, trg->brk_data[0]);
	if (val == -1) {
		warning("cannot poketext %s\n", strerror(errno));
		return -1;
	}
	DPRINT(("restore 0x%lx=0x%lx\n", trg->brk_address, trg->brk_data[0]));
	return 0;
}

int
pfmon_clear_code_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	if (options.opt_hw_brk)
		return pfmon_clear_code_hw_breakpoint(pid, trg);
	return pfmon_clear_code_sw_breakpoint(pid, trg);
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
	if (dbreg < 0 || dbreg >= options.ndbrs)
		return -1;

	/*
	 * XXX: hack to split DB regs into two sets
	 */
	dbreg += DBRS_BASE;

	return pfmon_x86_set_breakpoint(pid, dbreg, trg->brk_address, trg->trg_attr_rw);
}

int
pfmon_clear_data_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	int dbreg = trg->brk_idx;
	if (dbreg < 0 || dbreg >= options.ndbrs)
		return -1;

	dbreg += DBRS_BASE;

	return pfmon_x86_clear_breakpoint(pid, dbreg);
}

static int
__pfmon_resume_after_hw_breakpoint(pid_t pid)
{
#define X86_EFLAGS_RF 0x00010000
	unsigned long tmp, tmp2;
	unsigned long offs;

	offs = offsetof(struct user, regs.eflags);
	tmp  = (unsigned long)ptrace(PTRACE_PEEKUSER, pid, offs, 0);
	if (tmp == (unsigned long)-1) {
		warning("cannot retrieve eflags: %s\n", strerror(errno));
		return -1;
	}
	DPRINT((">>>>>eflags=0x%lx\n", tmp));

	tmp |= X86_EFLAGS_RF;
	DPRINT((">>>>>eflags=0x%lx\n", tmp));
	ptrace(PTRACE_POKEUSER, pid, offs, tmp);

	tmp2  = (unsigned long)ptrace(PTRACE_PEEKUSER, pid, offs, 0);
	if (tmp2 != tmp)
		fatal_error("your kernel does not have the ptrace EFLAGS.RF fix\n");
	return 0;
}

static int
pfmon_resume_after_code_hw_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	return __pfmon_resume_after_hw_breakpoint(pid);
}

static int
pfmon_resume_after_code_sw_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	long ret = 0;
	pfmon_clear_code_sw_breakpoint(pid, trg);
	/* does not need PTRACE_CONT */
	ret = ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
	if (ret == -1)
		warning("cannot singlestep [%d] : %s\n", pid, strerror(errno));
	return (int)ret;
}

int
pfmon_resume_after_code_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	if (options.opt_hw_brk)
		return pfmon_resume_after_code_hw_breakpoint(pid, trg);
	return pfmon_resume_after_code_sw_breakpoint(pid, trg);
}

int
pfmon_resume_after_data_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
	return 0;
}

void
pfmon_arch_initialize(void)
{
  	options.opt_hw_brk = 1;
	options.opt_support_gen = 1;
	options.libpfm_generic  = PFMLIB_AMD64_PMU;
	/*
	 * XXX: temporary hack. pfmon allows both code and data
	 * triggers to be set at the same time. Yet there is only
	 * one set of DB registers. We should really use an allocator
	 * but for nwo split registers into two sets and hack a
	 * base in the code
	 */
	options.nibrs = 4;
	options.ndbrs = 0;
}

static int
pfmon_enable_all_hw_breakpoints(pid_t pid)
{
	dr7_t dr7;	
	unsigned long offset;
	long r;

	offset = offsetof(struct user, u_debugreg[7]);
	dr7.val=0x355;

	DPRINT(("dr7: poke=0x%lx offs=%ld\n", dr7.val, offset));

	r = ptrace(PTRACE_POKEUSER, pid, offset, (void *)dr7.val);
	if (r == -1) {
		DPRINT(("poke ptrace=%d pid=%d\n", errno, pid));
		return -1;
	}
	return 0;
}

static int
pfmon_enable_all_sw_breakpoints(pid_t pid)
{
	return 0;
}


int
pfmon_enable_all_breakpoints(pid_t pid)
{
	if (options.opt_hw_brk)
		return pfmon_enable_all_hw_breakpoints(pid);
	return pfmon_enable_all_sw_breakpoints(pid);
}

static int
pfmon_disable_all_hw_breakpoints(pid_t pid)
{
	dr7_t dr7;	
	unsigned long offset;
	long r;

	offset = offsetof(struct user, u_debugreg[7]);
	dr7.val=0x300;

	DPRINT(("dr7: offfset=0x%lx poke=0x%lx\n", offset, dr7.val));

	r = ptrace(PTRACE_POKEUSER, pid, offset, (void *)dr7.val);
	if (r == -1) {
		DPRINT(("poke ptrace=%d pid=%d\n", errno, pid));
		return -1;
	}
	return 0;
}

static int
pfmon_disable_all_sw_breakpoints(pid_t pid)
{
	return 0;
}

int
pfmon_disable_all_breakpoints(pid_t pid)
{
	if (options.opt_hw_brk)
		return pfmon_disable_all_hw_breakpoints(pid);
	return pfmon_disable_all_sw_breakpoints(pid);
}

int
pfmon_validate_code_trigger_address(unsigned long addr)
{
	return 0;
}
	
int
pfmon_validate_data_trigger_address(unsigned long addr)
{
	return 0;
}

#ifdef __x86_64__
#define IIP	REG_RIP
#else
#define IIP	REG_EIP
#endif

void
pfmon_segv_handler_info(struct siginfo *si, void *sc)
{
	struct ucontext *uc;
	unsigned long ip;
	uc = (struct ucontext *)sc;
	ip = uc->uc_mcontext.gregs[IIP];
	printf("<pfmon fatal error @ [%d:%d] ip=0x%lx>\n", getpid(), gettid(), ip);
}

static int
pfmon_get_hw_breakpoint_addr(pid_t pid, unsigned long *addr, int *is_data)
{
	dr7_t dr7;
	unsigned long offset, val, which_reg;

	/*
	 * XXX: we use three ptrace(), there ought to be something
	 * faster than this
	 */
	offset = offsetof(struct user, u_debugreg[6]);
	val = ptrace(PTRACE_PEEKUSER, (long)pid, offset, 0);
	if (val == (unsigned long)-1) {
		warning("cannot peek %d\n", errno);
		return -1;
	}
	/* XXX: assume only one bit set */
	which_reg = (val & 0xf);
	if (which_reg == 0) {
		warning("not a breakpoint\n");
		return -1;
	}
	DPRINT(("dr6=0x%lx which_reg=0x%lx\n", val, which_reg));

	val &= ~0xf;
	val = ptrace(PTRACE_POKEUSER, pid, offset, val);
	if (val == (unsigned long)-1) {
		warning("cannot clear dr6 %d\n", errno);
		return -1;
	}
	val = ptrace(PTRACE_PEEKUSER, (long)pid, offset, 0);
	DPRINT(("dr6=0x%lx\n", val));

	offset = offsetof(struct user, u_debugreg[7]);
	dr7.val = ptrace(PTRACE_PEEKUSER, (long)pid, offset, 0);
	if (dr7.val == (unsigned long)-1) {
		warning("cannot peek %d\n", errno);
		return -1;
	}
	DPRINT(("dr7=0x%lx\n", dr7.val));
	/*
	 * XXX: handle only one breakpoint at a time
	 */
	switch(which_reg) {
	case 1:
		*is_data = dr7.reg.rw0 == 0 ? 0 : 1;
		which_reg = 0;
		break;
	case 2:
		*is_data = dr7.reg.rw1 == 0 ? 0 : 1;
		which_reg = 1;
		break;
	case 4:
		*is_data = dr7.reg.rw2 == 0 ? 0 : 1;
		which_reg = 2;
		break;
	case 8:
		*is_data = dr7.reg.rw3 == 0 ? 0 : 1;
		which_reg = 3;
		break;
	default:
		fatal_error("cannot get breakpoint addr which_reg=0x%lx\n", which_reg);
	}

	offset = offsetof(struct user, u_debugreg[which_reg]);
	val = ptrace(PTRACE_PEEKUSER, (long)pid, offset, 0);
	if (val == (unsigned long)-1) {
		warning("cannot peek %d\n", errno);
		return -1;
	}
	DPRINT(("is_data=%d addr=0x%lx\n", *is_data, val));
	*addr = val;
	return 0;
}

static int
pfmon_get_sw_breakpoint_addr(pid_t pid, unsigned long *addr, int *is_data)
{
	struct user_regs_struct regs;
	unsigned long val;
	unsigned long ip;

	val = ptrace(PTRACE_GETREGS, (long)pid, 0, &regs);
	if (val == (unsigned long)-1) {
		warning("cannot getregs %s\n", strerror(errno));
		return -1;
	}
#ifdef __x86_64__
	ip = regs.rip-1;
#else
	ip = regs.eip-1;
#endif
	DPRINT(("ip=0x%lx\n", ip));
	*addr = ip;

	/* correct resume code address */
	val = ptrace(PTRACE_SETREGS, (long)pid, 0, &regs);
	if (val == (unsigned long)-1) {
		warning("cannot setregs %s\n", strerror(errno));
		return -1;
	}
	*is_data = 0;
	return 0;
}

int
pfmon_get_breakpoint_addr(pid_t pid, unsigned long *addr, int *is_data)
{
	if (options.opt_hw_brk)
		return pfmon_get_hw_breakpoint_addr(pid, addr, is_data);
	return pfmon_get_sw_breakpoint_addr(pid, addr, is_data);
}

int
pfmon_get_return_pointer(pid_t pid, unsigned long *rp)
{
	unsigned long stk, bp;
	unsigned long offs;

#ifdef __x86_64__
	offs = offsetof(struct user, regs.rsp);
#else
	offs = offsetof(struct user, regs.esp);
#endif
	stk = (unsigned long)ptrace(PTRACE_PEEKUSER, pid, offs, 0);
	if (stk == (unsigned long)-1) {
		warning("cannot retrieve return: %s\n", strerror(errno));
		return -1;
	}
	bp = (unsigned long)ptrace(PTRACE_PEEKDATA, pid, stk, 0);
	if (bp == (unsigned long)-1) {
		warning("cannot retrieve return: %s\n", strerror(errno));
		return -1;
	}
	DPRINT(("stack=0x%lx, return=0x%lx\n", stk, bp));

	*rp = bp;
	return 0;
}

void
pfmon_print_simple_cpuinfo(FILE *fp, const char *msg)
{
	char *cpu_name, *p, *q, *stepping;
	char *cache_str;
	size_t cache_size;
	int ret;

	ret = find_in_cpuinfo("cache size", &cache_str);
	if (ret == -1)
		cache_str = "0";

	/* size in KB */
	sscanf(cache_str, "%zu", &cache_size);

	free(cache_str);

	ret = find_in_cpuinfo("model name", &cpu_name);
	if (ret == -1)
		cpu_name = "unknown";

	/*
	 * remove extra spaces
	 */
	p = q = cpu_name;
	while (*q) {
		while (*q == ' ' && *(q+1) == ' ') q++;
		*p++ = *q++;
	} 
	*p = '\0';

	ret = find_in_cpuinfo("stepping", &stepping);
	if (ret == -1)
		stepping = "??";

	fprintf(fp, "%s %lu-way %luMHz/%.1fMB -- %s (stepping %s)\n", 
		msg ? msg : "", 
		options.online_cpus, 
		options.cpu_mhz,
		(1.0*(double)cache_size)/1024,
		cpu_name, stepping);

	free(cpu_name);
	free(stepping);
}

void
pfmon_print_cpuinfo(FILE *fp)
{
	/*
	 * assume all CPUs are identical
	 */
	pfmon_print_simple_cpuinfo(fp, "# host CPUs: ");
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
	unsigned long start, brk_func;
	size_t sz;
	int ret, i;

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
	for(i=0; i < sz; i++)
		u.v[i] = ptrace(PTRACE_PEEKTEXT, sdesc->tid, start+i*sizeof(unsigned long), 0);

	DPRINT(("_r_debug=0x%lx\n", start));

	brk_func = sdesc->fl_abi32 ? u.rd32.r_brk : u.rd64.r_brk;

	if (sdesc->fl_abi32)
		DPRINT(("abi32=1 version=%d brk_func=%p\n",
			u.rd32.r_version,
			(void *)brk_func));
	else
		DPRINT(("abi32=0 version=%d brk_func=%p\n",
			u.rd64.r_version,
			(void *)brk_func));

	return brk_func;
}
