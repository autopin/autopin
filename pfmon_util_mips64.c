/*
 * pfmon_util_mips64.c  - MIPS64 specific set of helper functions
 *
 * Contributed by Philip Mucci <mucci@cs.utk.edu>
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
#include <endian.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/time.h>

#include "pfmon.h"

typedef struct bp_save {
  unsigned long address;
  unsigned long val;
  int is_start;
} breakpoint_t;

#define PFMON_NUM_SWBREAKPOINTS 2

#define BP 0x0005000d  /* break opcode */

/* Hack to substitute functionality that should be in pfmon_task.c */
static __thread breakpoint_t bpoints[PFMON_NUM_SWBREAKPOINTS];

static int is_delay_slot(pid_t pid, unsigned long address)
{
  unsigned int op;
  unsigned long val;

  vbprintf("Checking for branch with delay slot at 0x%lx\n",address-4);
  /* Look to see if we are in a delay slot */
  val = ptrace(PTRACE_PEEKTEXT, pid, address-4, 0);
  if ((val == -1) && (errno)) {
    warning("set cannot peek[%d] %s\n", pid, strerror(errno));
    return 0;
  }

#if __BYTE_ORDER == __LITTLE_ENDIAN
  op = val & 0xffffffff;
#elif __BYTE_ORDER == __BIG_ENDIAN
  op = (val & 0xffffffff00000000) >> 32;
#else
#error "cannot determine endianess"
#endif
  // 332222_22222_21111__11111__10000_000000
  // 109876_54321_09876__54321__09876_543210
  // 000000_xxxxx_xxxxx__xxxxx__xxxxx_00100x // jr/jal
  vbprintf("Found instruction %lx\n",op);
  if ((op & 0xfc000038UL) == 0x00000008UL) {
    vbprintf("found jr/jal prior to breakpoint location\n");
    return 1;
  }
  // 00001x_%target26_______________________ // j/jal
  if ((op & 0xf8000000UL) == 0x08000000UL) {
    vbprintf("found j/jal prior to breakpoint location\n");
    return 1;
  }
  // 000001_xxxxx_x00xx__%broff16___________ // bltz/bgez/bltzl/bgezl
  if ((op & 0xf40c0000UL) == 0x04000000UL) {
    vbprintf("found bltz/bgez/bltzl/bgezl prior to breakpoint location\n");
    return 1;
  }
  // 0001xx_xxxxx_xxxxx__%broff16___________ // beq/bne/blez/bgtz
  if ((op & 0xf0000000UL) == 0x10000000UL) {
    vbprintf("found beq/bne/blez/bgtz prior to breakpoint location\n");
    return 1;
  }
  // 010001_01xxx_xxxxx__%broff16___________ // bc1f/bc1tl/bc1any*
  if ((op & 0xff000000UL) == 0x45000000UL) {
    vbprintf("found bc1f/bc1tl/bc1any prior to breakpoint location\n");
    return 1;
  }
  //0101xx_xxxxx_xxxxx__%broff16___________ // beql/bnel/blezl/bgtzl
  if ((op & 0xf0000000UL) == 0x50000000UL) {
    vbprintf("found beql/bnel/blezl/bgtzl prior to breakpoint location\n");
    return 1;
  }
  return 0;
}

/* Breakpoint instruction */
static uint64_t bpi(void)
{
  uint64_t tmp = 0;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  tmp = BP;
  tmp |= tmp & 0xffffffff00000000ULL;
#elif __BYTE_ORDER == __BIG_ENDIAN
  tmp = ((uint64_t )BP) << 32;
  tmp |= tmp & 0x00000000ffffffffULL;
#else
#error "cannot determine endianess"
#endif
  return tmp;
}

static int
pfmon_mips64_set_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
  unsigned long address;
  long r, val = 0;
  int dbreg = trg->brk_idx;

  address = trg->brk_address;

  if (address == 0) {
    warning("address of 0 to set breakpoint\n", pid, strerror(errno));
    return -1;
  }
  
  val = ptrace(PTRACE_PEEKTEXT, pid, address, 0);
  if ((val == -1) && (errno)) {
    warning("set cannot peek[%d] %s\n", pid, strerror(errno));
    return -1;
  }
  
  DPRINT(("DB%d START%d trgt instruction = 0x%016lx at 0x%lx\n",
	dbreg, trg->trg_attr_start, val, address));
  if (val == bpi()) {
    warning("breakpoint already set at 0x%lx\n", address);
    return -1;
  }
  
  if (is_delay_slot(pid, address)) {
    warning("cannot instrument delay slot instruction\n");
    return -1;
  }

  vbprintf("[%d] setting code breakpoint DB%d, START%d @%p\n", 
	   pid, dbreg, trg->trg_attr_start,
	   address);
  r = ptrace(PTRACE_POKETEXT, pid, address, bpi());
  if (r == -1) {
    warning("set cannot poke[%d] %s\n", pid, strerror(errno));
    return -1;
  }

  r = ptrace(PTRACE_PEEKTEXT, pid, address, 0);
  if ((r == -1) && (errno)) {
    warning("clear cannot peek[%d] %s\n",pid,strerror(errno));
  } else {
    DPRINT(("new instruction = 0x%016lx at 0x%lx\n", r, address)); }

  /* Store hacked data that should be taken care of in pfmon_task.c */

  bpoints[dbreg].address = address;
  bpoints[dbreg].val = val;
  bpoints[dbreg].is_start = trg->trg_attr_start;

  return 0;
}

/*
 * common function to clear a breakpoint
 */
static int
pfmon_mips64_clear_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
  unsigned long offs, tmp, val;
  unsigned long address;
  long r;
  int dbreg = trg->brk_idx;

  address = trg->brk_address;

  /* Get hacked data that should be taken care of in pfmon_task.c */
  
  val = bpoints[dbreg].val;

  vbprintf("[%d] clearing code breakpoint DB%d, START%d, @%p\n", 
	   pid,dbreg,trg->trg_attr_start,
	   address);

  r = ptrace(PTRACE_PEEKTEXT, pid, address, 0);
  if ((r == -1) && (errno)) {
    warning("clear cannot peek %s\n",strerror(errno));
  }
 
  DPRINT(("DB%d START%d curr instruction = 0x%016lx at 0x%lx, writing 0x%016lx\n",
	 dbreg,trg->trg_attr_start,r,address,val));
  
  r = ptrace(PTRACE_POKETEXT, pid, address, val);
  if (r == -1) {
    warning("clear cannot poke %s\n", strerror(errno));
    return -1;
  }

  r = ptrace(PTRACE_PEEKTEXT, pid, address, 0);
  if ((r == -1) && (errno)) {
    warning("clear cannot peek %s\n",strerror(errno));
  } else {
    DPRINT(("new instruction = 0x%016lx at 0x%lx\n", r, address)); }

  offs = EF_CP0_EPC;

  DPRINT(("Setting PC back to 0x%lx\n", address));

  tmp  = (unsigned long)ptrace(PTRACE_POKEUSER, pid, offs, address);
  if (tmp == (unsigned long)-1) {
    warning("cannot poke PC: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/*
 * this function sets a code breakpoint at bundle address
 * In our context, we only support this features from user level code (of course). It is 
 * not possible to set kernel level breakpoints.
 *
 * The dbreg argument varies from 0 to 3, dr7, dr6 are not visible.
 */
int
pfmon_set_code_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
  int dbreg = trg->brk_idx;

  /* MIPS only supports SW breakpoints */
  if (options.opt_hw_brk)
	return -1;

  if (dbreg < 0 || dbreg >= options.nibrs) return -1;

  return pfmon_mips64_set_breakpoint(pid, trg);
}

int
pfmon_clear_code_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
  int dbreg = trg->brk_idx;

  if (dbreg < 0 || dbreg >= options.nibrs) return -1;

  return pfmon_mips64_clear_breakpoint(pid, trg);
}

int
pfmon_set_data_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
  return -1;
}

int
pfmon_clear_data_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
  return -1;
}

/* Only called with when --trigger-code-repeat is used */
int
pfmon_resume_after_code_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
  int dbreg = trg->brk_idx;

  /* This clears the current breakpoint and restores the current instruction. */
  pfmon_mips64_clear_breakpoint(pid, trg);

  /* The following segment could easily be moved to pfmon_task.c */

  /* Use the saved address of the start break point:
     0 -> 1
     1 -> 0
     2 -> 3
     3 -> 2 */
  if ((dbreg % 2) == 0)
    dbreg = dbreg + 1;
  else
    dbreg = dbreg - (dbreg % 2);

  /* Only set the start breakpoint again if we have reached the stop breakpoint. 
     The stop breakpoint setting the start breakpoint again is handled in pfmon_task.c */
  if (trg->trg_attr_start)
    pfmon_mips64_set_breakpoint(pid, trg);

  /* End segment for pfmon_task.c */
  return 0;
}

int
pfmon_resume_after_data_breakpoint(pid_t pid, pfmon_trigger_t *trg)
{
  return -1;
}

void
pfmon_arch_initialize(void)
{
  pfmlib_regmask_t r_pmcs;
  
  /* MIPS using SW breakpoints only */
  options.opt_hw_brk = 0;

  /*
   * a side effect of this call is to create a dummy
   * context which does trigger the kernel module load
   */
  pfmon_detect_unavail_pmcs(&r_pmcs);

  options.opt_support_gen = 0;
  options.libpfm_generic  = 0;

  /*
   * XXX: temporary hack. pfmon allows both code and data
   * triggers to be set at the same time. Yet there is only
   * one set of DB registers. We should really use an allocator
   * but for nwo split registers into two sets and hack a
   * base in the code
   */
  options.nibrs = PFMON_NUM_SWBREAKPOINTS;
  options.ndbrs = 0;
  memset(bpoints,0,PFMON_NUM_SWBREAKPOINTS*sizeof(breakpoint_t));
}

int
pfmon_enable_all_breakpoints(pid_t pid)
{
  DPRINT(("Enabling all breakpoints for pid %d\n",pid));
  return 0;
}

int
pfmon_disable_all_breakpoints(pid_t pid)
{
  int i;
  long val;

  DPRINT(("Disabling all breakpoints for pid %d\n",pid));
  for (i=0;i<PFMON_NUM_SWBREAKPOINTS;i++)
    {
      if (bpoints[i].address == 0)
	continue;
      val = ptrace(PTRACE_PEEKTEXT, pid, bpoints[i].address, 0);
      if ((val == -1) && (errno)) {
	warning("set cannot peek[%d] at 0x%lx: %s\n", pid, bpoints[i].address, strerror(errno));
	return -1;
      }
      if (val == bpi()) {
	val = ptrace(PTRACE_POKETEXT, pid, bpoints[i].address, bpoints[i].val);
	if (val == -1) {
	  warning("clear cannot poke[%d] at 0x%lx: %s\n", pid, bpoints[i].address, strerror(errno));
	  return -1;
	}
      }
    }
	
  return 0;
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

void
pfmon_segv_handler_info(struct siginfo *si, void *sc)
{
  struct ucontext *uc;
  unsigned long ip;
  uc = (struct ucontext *)sc;
  ip = uc->uc_mcontext.pc;
  printf("<pfmon fatal error @ [%d:%d] ip=0x%lx>\n", getpid(), gettid(), ip);
}

int
pfmon_get_breakpoint_addr(pid_t pid, unsigned long *addr, int *is_data)
{
  long tmp;
  void *offs = NULL;
  /* Here we should check if we are mips or mip64 kernel */
  offs = (void *)64;
  /* offs = (void *)EF_CP0_EPC; 32 bit kernel*/
  DPRINT(("Getting PC from PID %d at offset %ld\n",pid,offs));
#if 0
  if (options.opt_debug) {
    unsigned long i;
    for (i=0;i<=EF_SIZE/4;i++)
      {
	DPRINT(("%lu 0x%lx\n",i,ptrace(PTRACE_PEEKUSER, pid, (void *)i, 0)));
	if (errno) break;
      }
  }
#endif
  tmp = ptrace(PTRACE_PEEKUSER, pid, offs, 0);
  if ((tmp == -1) && (errno)){
    warning("cannot PEEKUSER at offset %lu for PC[%d]: %s\n", (unsigned long)offs,pid,strerror(errno));
    return -1;
  }
  DPRINT((">>>>>%lu: PC address=0x%lx\n", offs,tmp));

  *addr = tmp;
  *is_data = 0;
  return 0;
}

int
pfmon_get_return_pointer(pid_t pid, unsigned long *rp)
{
  long tmp;
  unsigned long offs;

  offs = EF_REG31;

  tmp  = (unsigned long)ptrace(PTRACE_PEEKUSER, pid, offs, 0);
  if ((tmp == -1) && (errno)) {
    warning("cannot retrieve stack pointer at offset %ld: %s\n", offs, strerror(errno));
    return -1;
  }

  DPRINT((">>>>>return address=0x%lx\n", tmp));
  *rp = tmp;
  return 0;
}

void
pfmon_print_simple_cpuinfo(FILE *fp, const char *msg)
{
  char *cpu_name, *p, *stepping;
  char *cache_str;
  size_t cache_size;
  int ret;

  ret = find_in_cpuinfo("dcache size\t\t", &cache_str);
  if (ret == -1)
    cache_str = strdup("0");

  /* size in KB */
  sscanf(cache_str, "%zu", &cache_size);

  ret = find_in_cpuinfo("cpu model", &cpu_name);
  if (ret == -1)
    cpu_name = strdup("unknown");

  /*
   * skip leading spaces
   */
  p = cpu_name;
  while (*p == ' ') p++;

  ret = find_in_cpuinfo("stepping", &stepping);
  if (ret == -1)
    stepping = strdup("??");

  fprintf(fp, "%s %lu-way %luMHz/%.2fMB -- %s (stepping %s)\n", 
	  msg ? msg : "", 
	  options.online_cpus, 
	  options.cpu_mhz,
	  (1.0*(double)cache_size)/(double)1024,
	  p, stepping);

  free(cache_str);
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
