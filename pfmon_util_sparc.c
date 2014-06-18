/*
 * Sparc PMU support for pfmon.
 *
 * This file is part of pfmon, a sample tool to measure performance
 * of applications for Linux.
 *
 * Copyright (C) 2007 David S. Miller (davem@davemloft.net)
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
#include <syscall.h>
#include <sys/ptrace.h>

#include "pfmon.h"

#define BP 0x91d02001 /* break opcode 'ta 0x1' */

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
	return -1;
}

int pfmon_clear_data_breakpoint(pid_t pid, pfmon_trigger_t *brk)
{
	return -1;
}

int pfmon_resume_after_code_breakpoint(pid_t pid, pfmon_trigger_t *brk)
{
	return pfmon_clear_code_breakpoint(pid, brk);
}

int pfmon_resume_after_data_breakpoint(pid_t pid, pfmon_trigger_t *brk)
{
	return -1;
}

void pfmon_arch_initialize(void)
{
  	options.opt_hw_brk = 1;
	options.opt_support_gen = 0;
	options.libpfm_generic = 0;
	options.nibrs = 2;
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
	return -1;
}

void pfmon_segv_handler_info(struct siginfo *si, void *ctx)
{
	struct sigcontext *sc = ctx;
	printf("<pfmon fatal error @ [%d:%d] ip=0x%lx>\n",
	       getpid(), gettid(), (long)sc->si_regs.pc);
}

struct ptrace_regs {
	int	r_psr;
	int	r_pc; 
	int	r_npc;
	int	r_y;  
	int	r_g1; 
	int	r_g2;
	int	r_g3;
	int	r_g4;
	int	r_g5;
	int	r_g6;
	int	r_g7;
	int	r_o0;
	int	r_o1;
	int	r_o2;
	int	r_o3;
	int	r_o4;
	int	r_o5;
	int	r_o6;
	int	r_o7;
};

int pfmon_get_breakpoint_addr(pid_t pid, unsigned long *addr, int *is_data)
{
	struct ptrace_regs regs;
	int r;

	r = ptrace(PTRACE_GETREGS, pid, &regs);
	if (r == -1) {
		warning("cannot getregs %s\n", strerror(errno));
		return -1;
	}

	*addr = regs.r_pc;
	*is_data = 0;

	return 0;
}

int pfmon_get_return_pointer(pid_t pid, unsigned long *rp)
{
	struct ptrace_regs regs;
	int r;

	r = ptrace(PTRACE_GETREGS, pid, &regs);
	if (r == -1) {
		warning("cannot getregs %s\n", strerror(errno));
		return -1;
	}

	*rp = regs.r_o7;

	return 0;
}

static int get_cpu_attr(char *name, unsigned long long *val)
{
	char *buf;
	int r;

	r = pfmon_sysfs_cpu_attr(name, &buf);
	if (r == -1)
		return -1;

	sscanf(buf, "%llu", val);

	free(buf);

	return 0;
}

void pfmon_print_simple_cpuinfo(FILE *fp, const char *msg)
{
	unsigned int freq = pfmon_find_cpu_speed();
	char *cpu_name = NULL;

	find_in_cpuinfo("cpu", &cpu_name);

	fprintf(fp, "%s %lu-way %uMHz %s\n",
		msg ? msg : "",
		options.online_cpus, freq,
		(cpu_name ? cpu_name : "(unknown)"));
}

static void print_cacheinfo(FILE *fp)
{
	unsigned long long cache_size, cache_line_size;

	get_cpu_attr("l1_icache_size", &cache_size);
	get_cpu_attr("l1_icache_line_size", &cache_line_size);

	fprintf(fp, "#\tL1I: %10lld bytes, line %3lld bytes\n",
		cache_size, cache_line_size);

	get_cpu_attr("l1_dcache_size", &cache_size);
	get_cpu_attr("l1_dcache_line_size", &cache_line_size);

	fprintf(fp, "#\tL1D: %10lld bytes, line %3lld bytes\n",
		cache_size, cache_line_size);

	get_cpu_attr("l2_cache_size", &cache_size);
	get_cpu_attr("l2_cache_line_size", &cache_line_size);

	fprintf(fp, "#\tL2 : %10lld bytes, line %3lld bytes\n",
		cache_size, cache_line_size);
}

void pfmon_print_cpuinfo(FILE *fp)
{
	pfmon_print_simple_cpuinfo(fp, "# host CPUs: ");
	print_cacheinfo(fp);
}

unsigned long
pfmon_get_r_brk(struct r_debug *rd)
{
	return (unsigned long)rd->r_brk;
}
