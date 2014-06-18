/*
 * Cell Broadband Engine PMU support for pfmon.
 *
 * This file is part of pfmon, a sample tool to measure performance
 * of applications for Linux.
 *
 * Copyright (C) 2007 Sony Computer Entertainment Inc.
 * Copyright 2007 Sony Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of the License.
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
#include <errno.h>
#include <unistd.h>
#include <endian.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>

#include "pfmon.h"

#define BP 0x7d821008 /* tw (RA=RB=R2) */

static int set_breakpoint(pid_t pid, int dbreg, unsigned long address)
{
	int r, val;

	val = ptrace(PTRACE_PEEKTEXT, pid, address, 0);
	if (val == -1) {
		warning("cannot peektext %s\n", strerror(errno));
		return -1;
	}

	r = ptrace(PTRACE_POKETEXT, pid, address, BP);
	if (r == -1) {
		warning("cannot poketext %s\n", strerror(errno));
		return -1;
	}

	return val;
}

static int clear_breakpoint(pid_t pid, int dbreg, unsigned long address, int val)
{
	int r;

	r = ptrace(PTRACE_POKETEXT, pid, address, val);
	if (r == -1) {
		warning("cannot poketext %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int pfmon_set_code_breakpoint(pid_t pid, pfmon_trigger_t *brk)
{
	int dbreg = brk->brk_idx;
	int val;

	if (dbreg < 0 || dbreg >= options.nibrs)
		return -1;

	val = set_breakpoint(pid, dbreg, brk->brk_address);
	if (val == -1)
		return -1;

	brk->brk_data[0] = val;

	return 0;
}

int pfmon_clear_code_breakpoint(pid_t pid, pfmon_trigger_t *brk)
{
	int dbreg = brk->brk_idx;

	if (dbreg < 0 || dbreg >= options.nibrs)
		return -1;

	return clear_breakpoint(pid, dbreg, brk->brk_address,
				brk->brk_data[0]);
}

int pfmon_set_data_breakpoint(pid_t pid, pfmon_trigger_t *brk)
{
	DPRINT(("\n"));
	return -1;
}

int pfmon_clear_data_breakpoint(pid_t pid, pfmon_trigger_t *brk)
{
	DPRINT(("\n"));
	return -1;
}

int pfmon_resume_after_code_breakpoint(pid_t pid, pfmon_trigger_t *brk)
{
	return pfmon_clear_code_breakpoint(pid, brk);
}

int pfmon_resume_after_data_breakpoint(pid_t pid, pfmon_trigger_t *brk)
{
	DPRINT(("\n"));
	return -1;
}

void pfmon_arch_initialize(void)
{
	options.opt_hw_brk = 1;
	options.opt_support_gen = 0;
	options.libpfm_generic = 0;
	options.nibrs = 4;
	options.ndbrs = 0;
}

int pfmon_enable_all_breakpoints(pid_t pid)
{
	return 0;
}

int pfmon_disable_all_breakpoints(pid_t pid)
{
	return 0;
}

int pfmon_validate_code_trigger_address(unsigned long addr)
{
	return 0;
}

int pfmon_validate_data_trigger_address(unsigned long addr)
{
	DPRINT(("\n"));
	return -1;
}

void pfmon_segv_handler_info(struct siginfo *si, void *sc)
{
	DPRINT(("\n"));
}

int pfmon_get_breakpoint_addr(pid_t pid, unsigned long *addr, int
			      *is_data)
{
	*addr = ptrace(PTRACE_PEEKUSER, pid, PT_NIP * sizeof(unsigned long), 0);
	*is_data = 0;
	return 0;
}

int pfmon_get_return_pointer(pid_t pid, unsigned long *rp)
{
	DPRINT(("\n"));
	return -1;
}

void pfmon_print_simple_cpuinfo(FILE *fp, const char *msg)
{
	fprintf(fp, "%sCell Broadband Engine. \n", msg);
}

void pfmon_print_cpuinfo(FILE *fp)
{
	fprintf(fp, "# CPU name: Cell Broadband Engine. \n");
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
#ifdef __LITTLE_ENDIAN
	for(i=0; i < sz; i++)
		u.v[i] = ptrace(PTRACE_PEEKTEXT, sdesc->tid, start+i*sizeof(unsigned long), 0);
#else
#error "must define PEEKTEXT loop for big endian"
#endif

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
