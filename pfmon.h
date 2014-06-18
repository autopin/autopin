/*
 * pfmon.h
 *
 * Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
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
#ifndef __PFMON_H__
#define __PFMON_H__
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/resource.h>
#include <getopt.h>
#include <perfmon/perfmon.h>
#include <perfmon/pfmlib.h>

#ifdef __ia64__
#include "pfmon_ia64.h"
#endif

#ifdef __x86_64__
#include "pfmon_amd64.h"
#endif

#ifdef __i386__
#include "pfmon_i386.h"
#include "pfmon_amd64.h"
#endif

#ifdef __mips__
#include "pfmon_mips64.h"
#endif

#ifdef __powerpc__
#include "pfmon_cell.h"
#endif

#ifdef __sparc__
#include "pfmon_sparc.h"
#endif

#ifdef CONFIG_DEBUG_MEM
#include <dmalloc.h>
#endif

typedef pfarg_pmd_t	pfmon_pmd_t;
typedef pfarg_pmc_t	pfmon_pmc_t;
typedef pfarg_setdesc_t	pfmon_setdesc_t;
typedef pfarg_setinfo_t	pfmon_setinfo_t;

#ifndef __ia64__
/*
 * definition for ia-64 perfmon v2.0 sampling format identification
 * we forced definition on non ia-64 to avoid clobbering the code with
 * #ifdef
 */
typedef unsigned char pfm_uuid_t[16];
#endif

/*
 * pfmon context description structure
 */
typedef struct {
	uint32_t	ctx_flags;
	size_t		ctx_arg_size;
	size_t		ctx_map_size;
	void		*ctx_arg;
	pfm_uuid_t	ctx_uuid; /* legacy v2.0 */
	char		*fmt_name;
} pfmon_ctx_t;

#define PFMON_VERSION		"3.4"

/*
 * undef to remove debug code
 */
#define PFMON_DEBUG	1

/*
 * type used for context identifier which is a file descriptor
 * with perfmon-2
 */
typedef int pfmon_ctxid_t;

/*
 * for describing symbol types
 */
typedef enum {
	PFMON_TEXT_SYMBOL,
	PFMON_DATA_SYMBOL
} pfmon_sym_type_t;

/* 
 * max number of cpus (threads) supported
 */
#define PFMON_MAX_CPUS		2048 /* MUST BE power of 2 */
/*
 * max number of PMU models supported
 */
#define PFMON_MAX_PMUS		256	/* MUST BE power of 2 */

#define PFMON_BITMASK_BITS	(sizeof(unsigned long)<<3)

#if PFMON_MAX_CPUS > PFMON_MAX_PMUS
#define PFMON_BITMASK_COUNT	(PFMON_MAX_CPUS/PFMON_BITMASK_BITS)
#else
#define PFMON_BITMASK_COUNT	(PFMON_MAX_PMUS/PFMON_BITMASK_BITS)
#endif

#define PFMON_MAX_FILENAME_LEN	256	/* max for output/input files */
#define PFMON_MAX_CMDLINE_LEN	1024	/* per-task mode max cmdline length /proc/cmdline */
#define PFMON_MAX_EVTNAME_LEN	128	/* maximum length for an event name */

#define PFMON_MAX_PMCS		PFMLIB_MAX_PMCS	/* max number of PMCS (must be power of 2) */
#define PFMON_MAX_PMDS		PFMLIB_MAX_PMDS	/* max number of PMDS (must be power of 2) */

/*
 * limits of for start/stop triggers, number cannot be greater than max number of 
 * hardware breakpoints you can set.
 */
#define PFMON_MAX_TRIGGER_CODE	(4+1)	/* 1=entry/dlopen code trigger */
#define PFMON_MAX_TRIGGER_DATA	4	/* data trigger ranges */

#define PFMON_DFL_INTERVAL	1000	/* default multiplexing interval for all sets */

#define PFMON_DFL_SMPL_ENTRIES	2048	/* default number of entries in sampling buffers */

/*
 * sampling rates type definition
 */
typedef struct {
	uint64_t	value;	/* sampling period */
	uint64_t	mask;	/* bitmask used with randomization */
	uint32_t	seed;	/* seed value for randomization */
	unsigned int	flags;	/* type of value */
} pfmon_smpl_rate_t;

#define PFMON_RATE_NONE_SET	0x0	/* sampling rate non set by user */
#define PFMON_RATE_VAL_SET	0x1	/* sampling rate set by user */
#define PFMON_RATE_MASK_SET	0x2	/* randomization mask set by user */
#define PFMON_RATE_SEED_SET	0x4	/* randomization seed set by user */

typedef struct {
	unsigned int pd_idx;		/* map from PMD index to event index */
	unsigned int num_smpl_pmds;	/* number of bit set in smpl_pmds */
	struct {
		uint16_t  pd;	/* PMD index */
		uint16_t off;	/* offset in sample body */
	} map_pmd_evt[PFM_MAX_PMDS];
} pfmon_rev_smpl_t;

typedef struct _pfmon_event_set_t {
	struct _pfmon_event_set_t	*next;	/* next set */
	pfmlib_input_param_t	inp;		/* common input parameters to libpfm            */
	pfmlib_output_param_t	outp;		/* common output parameters from libpfm         */
	unsigned int		event_count;	/* number of events requested by user */
	unsigned int		pc_count;	/* number of elements in master_pc(>= event_count) */

	pfmon_pmd_t		master_pd[PFMON_MAX_PMDS];
	pfmon_pmd_t		tmp_pd[PFMON_MAX_PMDS];
	pfmon_pmd_t		prev_pd[PFMON_MAX_PMDS];
	pfmon_pmc_t		master_pc[PFMON_MAX_PMDS];

	pfmon_smpl_rate_t 	long_rates[PFMON_MAX_PMDS];	/* long sampling period rates */
	pfmon_smpl_rate_t 	short_rates[PFMON_MAX_PMDS];	/* short sampling period rates */

	uint64_t	common_smpl_pmds[PFM_PMD_BV];	/* PMDs to include in every sample */
	uint64_t	common_reset_pmds[PFM_PMD_BV];	/* PMDs to reset for any counter overflow */
	uint64_t	smpl_pmds[PFMON_MAX_PMCS][PFM_PMD_BV];	/* for each monitor, which PMDs are recorded in sampling buffer */

	pfmon_rev_smpl_t	rev_smpl_pmds[PFMON_MAX_PMDS];  /* smpl_pmds per PMD, indexed by ovfl PMD index */

	char	      		*priv_lvl_str;  	/* per-event privilege level option string */
	char			*long_smpl_args;
	char			*short_smpl_args;
	char			*random_smpl_args;
	char			*xtra_smpl_pmds_args;
	uint32_t		set_flags;		/* flags for set creation */
	char			*events_str;		/* comma separated list of events for the set */
	uint64_t		prev_duration;		/* previous set duration (incremental) */
	uint64_t		duration;		/* active duration in cycles */
	uint64_t		nruns;			/* number of times the set was loaded on the PMU */
	unsigned int		id;			/* logical index */
	void			*mod_args;		/* model specific extensions */
	void			*mod_inp;	/* model specific input parameters to libpfm    */
	void			*mod_outp;	/* model specific output parameters from libpfm */
	uint64_t		last_duration;
	uint64_t 		last_values[PFMON_MAX_PMDS];
} pfmon_event_set_t;

typedef unsigned long pfmon_bitmask_t[PFMON_BITMASK_COUNT];

/*
 * pfmon sampling descriptor. contains information about a
 * particular sampling session
 */
typedef struct {
	void		 *smpl_hdr;	/* virtual address of sampling buffer header */
	FILE		 *smpl_fp;	/* sampling file descriptor */
	uint64_t	 *aggr_count;	/* entry count for aggregated session (protected by aggr_lock) */
	uint64_t	 entry_count;	/* number of entries recorded for this buffer */
	uint64_t	 last_ovfl;	/* last buffer overflow observed XXX: format specific */
	size_t		last_count;	/* last number of entries in ovferflowed buffer */
	size_t		 map_size;	/* remapped buffer size */
	unsigned int	 cpu;		/* on which CPU does this apply to (system wide) */
	int 		 processing;
	void 		 *data;		/* sampling module-specific session data */
} pfmon_smpl_desc_t;

#define PFMON_CHECK_VERSION(h)	(PFM_VERSION_MAJOR((h)) != PFM_VERSION_MAJOR(PFMON_SMPL_VERSION))

/*
 * pfmon monitor definition
 */
typedef struct {
	unsigned int	event;	/* event index (from libpfm) */
	unsigned int	plm;	/* priv level  */
	unsigned int	flags;	/* flags */
} pfmon_monitor_t;

typedef struct {
	unsigned int active:1;		/* true if breakpoint is active */
	unsigned int repeat:1;		/* reuse breakpoint more than once, default oneshot */
	unsigned int inherit:1;		/* true if follow fork/clone/vfork */
	unsigned int is_func:1;		/* is dyanamic stop breakpoint */
	unsigned int rw:2;		/* read/write for debug register (data) */
	unsigned int reserved:26;	/* for future use */
} pfmon_trigger_state_t;

typedef enum {
	PFMON_TRIGGER_ENTRY,	/* entry point */
	PFMON_TRIGGER_START,	/* start trigger */
	PFMON_TRIGGER_STOP,	/* stop trigger */
	PFMON_TRIGGER_DLOPEN
} pfmon_trigger_type_t;

typedef struct pfmon_trigger {
	pfmon_trigger_type_t	brk_type;	/* which type of trigger */
	int			brk_idx;	/* which logical debug register was used */
	unsigned long		brk_address;	/* where to place the breakpoint */
	pfmon_trigger_state_t	brk_attr;	/* attributes */
	int			brk_stop_idx;	/* pfmon_trigger containing stop point (func=1) */
	unsigned long		brk_data[2];	/* SW breakpoint original code */
} pfmon_trigger_t;

/* some handy shortcuts */
#define trg_attr_start		brk_attr.start
#define trg_attr_active		brk_attr.active
#define trg_attr_repeat		brk_attr.repeat
#define trg_attr_inherit	brk_attr.inherit
#define trg_attr_rw		brk_attr.rw
#define trg_attr_func		brk_attr.is_func

/* description of one symbol */
typedef struct {
	char			*name;		/* symbol name */
	unsigned long		value;		/* symbol address */
	unsigned long		size;		/* optional symbol size */
	pfmon_sym_type_t	type;		/* type : CODE or DATA */
} symbol_t;

/* description of one module text and data symbol tables */
typedef struct _module_symbols_t {
	struct _module_symbols_t *next;		/* linked list */
	uint64_t		id;		/* unique identifier */
	symbol_t		*sym_tab[2];	/* text symbol table */
	unsigned long		nsyms[2];	/* number of text symbols */
	unsigned long		refcnt;		/* reference count */
	char			*name;		/* module name */
} module_symbols_t;

/* description of one module mapping in /proc/PID/maps */
typedef struct {
	module_symbols_t	*mod;		/* which module_symbols_t */
	unsigned long		base[2];	/* base addresses (code, data) */
	unsigned long		offs[2];	/* offsets (code, data) */
	unsigned long		max[2];		/* max addr (code, data) */
	unsigned int		version;	/* snapshot version (per task) */
	pid_t			pid;		/* owner */
	char			*path;		/* file path */
} module_map_t;

/*
 * session description structure
 */
typedef struct {
	unsigned int	monitoring:1;	/* measurement started on the task */
	unsigned int	dispatched:1;	/* task is assigned to a worker CPU */
	unsigned int	seen_stopsig:1;	/* detection of task creation for ptrace */
	unsigned int	detaching:1;	/* in the process of detaching the task */
	unsigned int	attached:1;	/* task was monitored via direct/indirect PTRACE_ATTACH */
	unsigned int	singlestep:1;	/* waiting for single step notification */
	unsigned int    has_entry:1;	/* needs entry breakpoint */
	unsigned int	abi32:1;	/* true if using 32-bit ABI */
	unsigned int	reserved:24;
} pfmon_sdesc_flags_t;

typedef struct _pfmon_desc_t {
	struct _pfmon_desc_t	*next;				/* pid hash chain */
	struct _pfmon_desc_t	*fd_next;			/* fd hash chain */
	unsigned short		type;				/* task descriptor type */
	unsigned short		refcnt;				/* #reference to object (max=2) */
	pfmon_sdesc_flags_t	flags;				/* active, inactive */

	pid_t			pid;				/* process identification */
	pid_t			ppid;				/* parent process identification */
	pid_t			tid;				/* thread identification */

	pfmon_ctxid_t		ctxid;				/* perfmon session identifier */
	pfmon_smpl_desc_t	csmpl;				/* sampling descriptor */
	pthread_mutex_t		lock;				/* used to protect refcnt */

	unsigned int		exec_count;			/* number of times the task exec'd */
	unsigned int		nsets;


	pfmon_event_set_t	*sets;				/* copy of event set list */

	struct timeval		tv_start;			/* time of activation */

	unsigned int		cpu;				/* worker assigned to sdesc, if any */
	unsigned int		id;				/* logical id (system-wide + measurements) */

	pfmon_trigger_t		code_triggers[PFMON_MAX_TRIGGER_CODE];
	pfmon_trigger_t		data_triggers[PFMON_MAX_TRIGGER_DATA];
	pfmon_trigger_t		*last_code_trigger;	/* NULL if none, used for SW brk and single step */

	unsigned int		num_code_triggers;
	unsigned int		num_data_triggers;

	char			cmdline[PFMON_MAX_CMDLINE_LEN];		/* process command line */
	char			new_cmdline[PFMON_MAX_CMDLINE_LEN];	/* process command line from exec() */

	FILE			*out_fp;				/* result file pointer */
	int			done_header;				/* true if header printed */

	int			current_map_version;		/* the current version of the /prod/PID/maps snapshot */
} pfmon_sdesc_t;


#define fl_monitoring	flags.monitoring
#define fl_dispatched	flags.dispatched
#define fl_seen_stopsig flags.seen_stopsig
#define fl_detaching	flags.detaching
#define fl_attached	flags.attached
#define fl_has_entry	flags.has_entry
#define fl_abi32	flags.abi32

#define PFMON_SDESC_ATTACH	0	/* task was attached */
#define PFMON_SDESC_FORK	1	/* created via fork() */
#define PFMON_SDESC_VFORK	2	/* created via vfork() */
#define PFMON_SDESC_CLONE	3	/* create via thread clone2() */

#define LOCK_SDESC(h)	pthread_mutex_lock(&(h)->lock)
#define UNLOCK_SDESC(h)	pthread_mutex_unlock(&(h)->lock)

/*
 * intervals for options codes: MUST BE RESPECTED BY ALL MODULES
 * 000-255   reserved for generic options
 * 400-499   reserved for PMU specific options
 * 500-599   reserved for sampling module specific options
 */
#define PFMON_OPT_COMMON_BASE	0
#define PFMON_OPT_PMU_BASE	400
#define PFMON_OPT_SMPL_BASE	500

typedef struct {
	int			(*process_samples)(pfmon_sdesc_t *sdesc);
	int			(*check_new_samples)(pfmon_sdesc_t *sdesc);
	int			(*check_version)(pfmon_sdesc_t *sdesc);
	int			(*print_header)(pfmon_sdesc_t *sdesc);
	int			(*print_footer)(pfmon_sdesc_t *sdesc);
	int			(*init_ctx_arg)(pfmon_ctx_t *ctx, unsigned int max_pmds_sample);
	int			(*parse_options)(int code, char *optarg);
	void			(*show_options)(void);
	void			(*initialize_mask)(void);
	int			(*initialize_module)(void);
	int			(*initialize_session)(pfmon_sdesc_t *sdesc);
	int			(*terminate_session)(pfmon_sdesc_t *sdesc);
	int			(*validate_options)(void);
	int			(*validate_events)(pfmon_event_set_t *set);
	char			*name;		/* name of the format */
	char			*description;	/* one line of text describing the format */
	pfmon_bitmask_t		pmu_mask;	/* supported PMUs (valid after initialize_mask) */
	pfm_uuid_t		uuid;		/* UUID for format (perfmon v2.0 leagcy) */
	char			*fmt_name;	/* name of format */
	int			flags;		/* module flags */
} pfmon_smpl_module_t;

#define PFMON_SMPL_MOD_FL_LEGACY	0x1	/* IA64: module support perfmon v2.x (x<2) only */
#define PFMON_SMPL_MOD_FL_DEF_SYM	0x2	/* defer symbol hash table to terminate session */
#define PFMON_SMPL_MOD_FL_PEBS		0x4	/* use Intel PEBS */

typedef struct {
	struct {
		int opt_syst_wide;
		int opt_no_ovfl_notify;	  /* do not notify sampling buffer overflow (saturation) */
		int opt_reset_non_smpl;	  /* reset non-overflowed, non-sampling counters on overflow */
		int opt_dont_start;	  /* do not explicitely start monitoring */
		int opt_aggr;	  	  /* aggregate results */

		int opt_block;		  /* block child task on counter overflow */
		int opt_append;		  /* append to output file */
		int opt_verbose;	  /* verbose output */
		int opt_debug;		  /* print debug information */
		int opt_with_header;      /* generate header on output results (smpl or not) */
		int opt_use_smpl;	  /* true if sampling is requested */
		int opt_print_cnt_mode;	  /* mode for printing counters */
		int opt_show_rusage;	  /* show process time */
		int opt_sysmap_syms;	  /* use System.map format for symbol file */
		int opt_check_evt_only;   /* stop after checking the event combination is valid */
		int opt_smpl_print_counts;/* print counters values when sampling session ends */
		int opt_attach;		  /* set to 1 if attach pid is specified by user */
		int opt_follow_fork;	  /* follow fork in per-task mode */
		int opt_follow_vfork;	  /* follow vfork in per-task mode */
		int opt_follow_pthread;	  /* follow clone (pthreads) in per-task mode */
		int opt_follow_exec;	  /* follow exec in per-task mode */
		int opt_follow_exec_excl; /* follow exec pattern is excluding */
		int opt_follow_all;	  /* follow all of the above */
		int opt_follows;	  /* set to true if one of the follow* is used */
		int opt_cmd_no_verbose;	  /* redirect command stdout to /dev/null */
		int opt_code_trigger_repeat;  /* repeat start/stop monitoring each time code trigger start/stop is crossed */
		int opt_code_trigger_follow;  /* code trigger start/stop used in all monitored tasks (not just first one) */
		int opt_data_trigger_repeat;  /* repeat start/stop monitoring each time data trigger start/stop is touched */
		int opt_data_trigger_follow;  /* data trigger start/stop used in all monitored tasks (not just first one) */
		int opt_data_trigger_ro;  /* data trigger activated for read access only (default RW) */
		int opt_data_trigger_wo;  /* data trigger activated for write access only (default RW) */
		int opt_block_restart;	  /* for debug only: force a keypress before PFM_RESTART */
		int opt_split_exec;	  /* split result output on execve() */
		int opt_support_gen;	  /* operating in a generic PMU mode is supported */
		int opt_addr2sym;	  /* try converting addresses to symbol */
		int opt_pin_cmd;	  /* in system-wide, pin executed command to cpu-list processors only */
		int opt_print_syms;	  /* print primary sysmbol table */
		int opt_is22;	  	  /* host kernel implements at least perfmon v2.2 */
		int opt_preempt;	  /* allow system-wide session to be preeempted */
		int opt_vcpu;		  /* use logical CPu numbering (relative to affinity cpu_set) */
		int opt_dem_type;	  /* 1=C++-style 2=Java symbol demangling */
		int opt_hw_brk;		  /* use hardware breakpoints */
		int opt_smpl_per_func;	  /* show function-level samples in profiles */
		int opt_smpl_nopid;	  /* ingore pids in system-wide profiles */
	} program_opt_flags;

	char  **argv;			  /* full command line */
	char  **command;		  /* keep track of the command to execute (per-task) */

	char *outfile;			  /* basename for output filename for counters */
	char *smpl_outfile;		  /* basename for sampling output file */
	char *symbol_file;		  /* name of file which holds symbol table */

	char *fexec_pattern;		  /* follow-exec pattern */

	pid_t	attach_tid;		  /* thread/process to attach to */

	pfmon_bitmask_t virt_cpu_mask;	  /* user specified CPUs for system-wide */
	pfmon_bitmask_t phys_cpu_mask;	  /* actual CPUS affinity for pfmon upon start (cpu_set) */

	unsigned int	trigger_delay; 	  /* number of seconds to wait before start a session */
	unsigned int	session_timeout;  /* number of seconds to wait before stopping a session */
	unsigned int	warmup_time;  	  /* number of seconds to wait before starting a session */
	unsigned int	init_time;	  /* number of seconds to wait before starting first session */

	uint64_t	switch_timeout;	  /* requested switch timeout in nanoseconds */

	uint64_t	interval;	  /* number of seconds between two partial counts prints */
	unsigned long   smpl_entries;     /* number of entries in sampling buffer */

	char		*code_trigger_start;	/* code trigger start cmdline */
	char		*code_trigger_stop;	/* code trigger stop cmdline */

	char		*data_trigger_start;	/* data trigger start cmdline */
	char		*data_trigger_stop;	/* data trigger stop cmdline */
	char		*cpu_list;		/* CPU list cmdline */

	pfmon_trigger_t	code_triggers[PFMON_MAX_TRIGGER_CODE];
	pfmon_trigger_t	data_triggers[PFMON_MAX_TRIGGER_DATA];

	unsigned int	num_code_triggers;	/* number of code triggers */
	unsigned int	num_data_triggers;	/* number of data triggers */

	unsigned int	max_sym_modules;	/* how many symbol table we have loaded */

	unsigned long	online_cpus;	/* _SC_NPROCESSORS_ONLN */
	unsigned long	config_cpus;	/* _SC_NPROCESSORS_CONF */
	unsigned long	selected_cpus;	/* number of CPUS  selected by user */
	unsigned int 	nibrs;		/* number of code debug registers */
	unsigned int 	ndbrs;		/* number of data debug registers */
	unsigned int 	max_counters;	/* maximum number of counters */
	unsigned int	page_size;	/* page size used by host kernel */
	uint64_t	clock_res;	/* CLOCK_MONOTONIC resolution */
	int		dfl_plm;	/* default plm */
	unsigned long	cpu_mhz;	/* CPU speed in MHz */
	int		libpfm_generic;	/* generic PMU type */
	int		pmu_type;	/* pfmlib type of host PMU */

	unsigned int	pfm_version;		/* kernel perfmon version */
	unsigned int	pfm_smpl_version;	/* kernel perfmon sampling format version */

	pfmon_event_set_t	*sets;		/* linked list of sets */
	pfmon_event_set_t	*last_set;	/* points to active set in the list */
	unsigned int		nsets;		/* number of sets in the list */
	size_t			max_event_name_len;	/* max len for event name (pretty printing) */
	char			*ev_name1;	/* can hold full event name (cannot share) */
	char			*ev_name2;	/* can hold full event name (cannot share) */
	pfmon_smpl_module_t	*smpl_mod;	/* which sampling module to use */
	size_t			ctx_arg_size;
	void 			*model_options;		/* point to model specific pfmon options */
	module_map_t		*primary_syms;		/* global list of modules symbols */
	int			generic_pmu_type;	/* value for a generic PMU for the architecture */
	int			smpl_cum_thres;		/* cumulative threshold for profiles output */
	int			smpl_show_top;		/* max number of samples to show in profiles */
} program_options_t;

/*
 * reason for terminating pfmon
 */
typedef enum {
	QUIT_NONE,	/* default value */
	QUIT_CHILD,	/* child process terminated */
	QUIT_TIMEOUT,	/* alarm timeout */
	QUIT_ABORT,	/* aborted by user */
	QUIT_ERROR,	/* unrecoverable error */
	QUIT_TERM	/* received a SIGTERM */
} pfmon_quit_reason_t;


static inline void pfmon_bitmask_set(pfmon_bitmask_t m, int i)
{
	m[(i)/PFMON_BITMASK_BITS] |=  (1UL << ((i) % PFMON_BITMASK_BITS));
}

static inline void pfmon_bitmask_clear(pfmon_bitmask_t m, int i)
{
	m[(i)/PFMON_BITMASK_BITS] &= ~(1UL << ((i) % PFMON_BITMASK_BITS));
}

static inline int pfmon_bitmask_isset(pfmon_bitmask_t m, int i)
{
	return (m[(i)/PFMON_BITMASK_BITS] & (1UL << ((i) % PFMON_BITMASK_BITS))) != 0;
}

static inline void pfmon_bitmask_setall(pfmon_bitmask_t m)
{
	memset(m, 0xff, sizeof(pfmon_bitmask_t));
}

#define opt_debug		program_opt_flags.opt_debug
#define opt_verbose		program_opt_flags.opt_verbose
#define opt_append		program_opt_flags.opt_append
#define opt_block		program_opt_flags.opt_block
#define opt_fclone		program_opt_flags.opt_fclone
#define opt_syst_wide		program_opt_flags.opt_syst_wide
#define opt_with_header		program_opt_flags.opt_with_header
#define opt_use_smpl		program_opt_flags.opt_use_smpl
#define opt_aggr		program_opt_flags.opt_aggr
#define opt_print_cnt_mode	program_opt_flags.opt_print_cnt_mode
#define opt_show_rusage		program_opt_flags.opt_show_rusage
#define opt_sysmap_syms		program_opt_flags.opt_sysmap_syms
#define opt_check_evt_only	program_opt_flags.opt_check_evt_only
#define opt_smpl_print_counts   program_opt_flags.opt_smpl_print_counts
#define opt_attach		program_opt_flags.opt_attach
#define opt_reset_non_smpl	program_opt_flags.opt_reset_non_smpl
#define opt_dont_start		program_opt_flags.opt_dont_start
#define opt_follow_fork		program_opt_flags.opt_follow_fork
#define opt_follow_vfork	program_opt_flags.opt_follow_vfork
#define opt_follow_pthread	program_opt_flags.opt_follow_pthread
#define opt_follow_exec		program_opt_flags.opt_follow_exec
#define opt_follow_exec_excl	program_opt_flags.opt_follow_exec_excl
#define opt_follow_all		program_opt_flags.opt_follow_all
#define opt_follows		program_opt_flags.opt_follows
#define opt_cmd_no_verbose	program_opt_flags.opt_cmd_no_verbose
#define opt_code_trigger_repeat	program_opt_flags.opt_code_trigger_repeat
#define opt_code_trigger_follow	program_opt_flags.opt_code_trigger_follow
#define opt_data_trigger_repeat	program_opt_flags.opt_data_trigger_repeat
#define opt_data_trigger_follow	program_opt_flags.opt_data_trigger_follow
#define opt_data_trigger_ro	program_opt_flags.opt_data_trigger_ro
#define opt_data_trigger_wo	program_opt_flags.opt_data_trigger_wo
#define opt_block_restart	program_opt_flags.opt_block_restart
#define opt_split_exec		program_opt_flags.opt_split_exec
#define opt_support_gen		program_opt_flags.opt_support_gen
#define opt_addr2sym		program_opt_flags.opt_addr2sym
#define opt_no_ovfl_notify	program_opt_flags.opt_no_ovfl_notify
#define opt_pin_cmd		program_opt_flags.opt_pin_cmd
#define opt_print_syms		program_opt_flags.opt_print_syms
#define opt_is22		program_opt_flags.opt_is22
#define opt_vcpu		program_opt_flags.opt_vcpu
#define opt_dem_type		program_opt_flags.opt_dem_type
#define opt_hw_brk		program_opt_flags.opt_hw_brk
#define opt_smpl_nopid		program_opt_flags.opt_smpl_nopid
#define opt_smpl_per_func	program_opt_flags.opt_smpl_per_func

typedef struct {
	int	(*pfmon_prepare_registers)(pfmon_event_set_t *set);
	int	(*pfmon_install_pmc_registers)(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set);
	int	(*pfmon_install_pmd_registers)(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set);
	int	(*pfmon_pmc_map)(unsigned int lib_reg_num, unsigned int *kern_reg_num);
	int	(*pfmon_pmd_map)(unsigned int lib_reg_num, unsigned int *kern_reg_num);
	int	(*pfmon_print_header)(FILE *fp);
	int	(*pfmon_initialize)(void);
	void	(*pfmon_usage)(void);
	int	(*pfmon_parse_options)(int code, char *optarg);
	int	(*pfmon_setup)(pfmon_event_set_t *set);
	int	(*pfmon_setup_ctx_flags)(pfmon_ctx_t *ctx);
	void	(*pfmon_verify_event_sets)(void);
	void    (*pfmon_verify_cmdline)(int argc, char **argv);
	void	(*pfmon_detailed_event_name)(unsigned int evt);
	void	(*pfmon_show_event_info)(unsigned int evt);
	char	*name;			/* support module name */
	int	pmu_type;		/* indicate the PMU type, must be one from pfmlib.h */
	int	generic_pmu_type;	/* what is the generic PMU type for the architecture */
	size_t	sz_mod_args, sz_mod_inp, sz_mod_outp; /* size of model specific structures */
} pfmon_support_t;

extern pfmon_support_t *pfmon_current;

extern program_options_t options;

/* from pfmon_util.c */
extern void warning(char *fmt, ...);
extern void dbgprintf(char *fmt, ...);
extern void fatal_error(char *fmt, ...);
extern void gen_reverse_table(pfmon_event_set_t *evt, int *rev_pc);
extern int enable_pmu(pfmon_ctxid_t id);
extern int session_start(pfmon_ctxid_t id);
extern int session_stop(pfmon_ctxid_t id);
extern void session_free(pfmon_ctxid_t id);
extern int create_event_set(char *arg);
extern void setup_event_set(pfmon_event_set_t *set);
extern void add_event_set(pfmon_event_set_t *set);
extern int gen_smpl_rates(char *arg, unsigned int max_count, pfmon_smpl_rate_t *rates, unsigned int *count);
extern int gen_smpl_randomization(char *arg, unsigned int max_count, pfmon_smpl_rate_t *rates, unsigned int *count);
extern int find_current_cpu(pid_t pid, unsigned int *cur_cpu);
extern int register_exit_function(void (*func)(int));
extern void print_standard_header(FILE *fp, pfmon_sdesc_t *sdesc);
extern void vbprintf(char *fmt, ...);
extern void vbprintf_unblock(void);
extern void vbprintf_block(void);
extern void gen_code_range(char *arg, unsigned long *start, unsigned long *end);
extern void gen_data_range(char *arg, unsigned long *start, unsigned long *end);
extern void counter2str(uint64_t value, char *str);
extern void show_task_rusage(const struct timeval *start, const struct timeval *end, const struct rusage *ru);
extern int is_regular_file(char *name);
extern int pfm_uuid2str(pfm_uuid_t uuid, size_t maxlen, char *str);
extern int pfmon_extract_cmdline(pfmon_sdesc_t *sdesc);
extern void pfmon_backtrace(void);
extern unsigned long pfmon_find_cpu_speed(void);
extern int find_pid_attr(pid_t tid, char *attr);
extern int pfmon_pin_self(unsigned int cpu);
extern char * priv_level_str(unsigned int plm);
extern pid_t gettid(void); 
extern int pfmon_print_address(FILE *fp, module_map_t *list, pfmon_sym_type_t type, unsigned long addr, pid_t pid, uint32_t version);
extern int perfmon_debug(int m);
extern int extract_cache_size(unsigned int level, unsigned int type, unsigned long *size);
extern void pfmon_clone_sets(pfmon_event_set_t *list, pfmon_sdesc_t *sdesc);
extern void pfmon_free_sets(pfmon_sdesc_t *sdesc);
extern void pfmon_dump_sets(void);
extern int pfmon_check_kernel_pmu(void);
extern void pfmon_get_version(void);
extern int pfmon_set_affinity(pid_t pid, pfmon_bitmask_t mask); 
extern int pfmon_cpu_virt_to_phys(int vcp);
extern int pfmon_collect_affinity(void);
extern int pfmon_compute_smpl_entries(size_t hdr_sz, size_t entry_sz, size_t slack);
extern int find_in_cpuinfo(char *entry, char **result);
extern int pfmon_detect_unavail_pmcs(pfmlib_regmask_t *r_pmcs);
extern int pfmon_sysfs_cpu_attr(char *name, char **result);
extern void pfmon_print_tid(FILE *fp, pid_t tid);
extern void pfmon_print_quit_reason(pfmon_quit_reason_t q);

/* helper functions provided by arch-specific code */
extern int  pfmon_set_code_breakpoint(pid_t pid, pfmon_trigger_t *brk);
extern int  pfmon_clear_code_breakpoint(pid_t pid, pfmon_trigger_t *brk);
extern int  pfmon_set_data_breakpoint(pid_t pid, pfmon_trigger_t *brk);
extern int  pfmon_clear_data_breakpoint(pid_t pid, pfmon_trigger_t *brk);
extern int  pfmon_resume_after_code_breakpoint(pid_t pid, pfmon_trigger_t *brk);
extern int  pfmon_resume_after_data_breakpoint(pid_t pid, pfmon_trigger_t *brk);
extern void pfmon_arch_initialize(void);
extern int  pfmon_enable_all_breakpoints(pid_t pid);
extern int  pfmon_disable_all_breakpoints(pid_t pid);
extern int  pfmon_validate_code_trigger_address(unsigned long addr);
extern int  pfmon_validate_data_trigger_address(unsigned long addr);
extern void pfmon_segv_handler_info(struct siginfo *info, void *sc);
extern int  pfmon_get_breakpoint_addr(pid_t pid, unsigned long *addr, int *is_data);
extern int  pfmon_get_return_pointer(pid_t pid, unsigned long *rp);
extern int  pfmon_get_cache_info(int cpu, pfmon_cache_info_t *info);
extern int  __pfmon_set_affinity(pid_t pid, size_t size, pfmon_bitmask_t mask); 
extern int  __pfmon_get_affinity(pid_t pid, size_t size, pfmon_bitmask_t mask); 
extern void pfmon_print_simple_cpuinfo(FILE *fp, const char *msg);
extern void pfmon_print_cpuinfo(FILE *fp);
extern unsigned long pfmon_get_dlopen_hook(pfmon_sdesc_t *s);

/* from pfmon.c */
extern int pfmon_register_options(struct option *cmd, size_t sz);
extern int install_registers(pfmon_sdesc_t *sdesc, pfmon_event_set_t *set);
extern int install_event_sets(pfmon_sdesc_t *sdesc);
extern void setup_trigger_addresses(void);

/* from pfmon_results.c */
extern int print_results(pfmon_sdesc_t *sdesc);
extern void close_results(pfmon_sdesc_t *sdesc);
extern int show_results(pfmon_sdesc_t *sdesc, int needs_order);
extern int show_incr_results(pfmon_sdesc_t *sdesc, int needs_order);
extern int open_results(pfmon_sdesc_t *sdesc);
extern int read_results(pfmon_sdesc_t *sdesc);
extern int read_incremental_results(pfmon_sdesc_t *sdesc);

/* pfmon_smpl.c */
extern void pfmon_setup_sampling_rates(void);
extern int pfmon_reset_sampling(pfmon_sdesc_t *sdesc);
extern int pfmon_setup_aggr_sampling_output(pfmon_sdesc_t *sdesc);
extern int pfmon_setup_sampling_output(pfmon_sdesc_t *sdesc, pfmon_sdesc_t *sdesc_aggr);
extern void pfmon_close_sampling_output(pfmon_sdesc_t *sdesc, pid_t tid, unsigned int cpu);
extern void pfmon_close_aggr_sampling_output(pfmon_sdesc_t *sdesc);
extern int pfmon_process_smpl_buf(pfmon_sdesc_t *sdesc, int is_final);
extern int pfmon_find_smpl_module(char *name, pfmon_smpl_module_t **mod, int ignore_cpu);
extern void pfmon_list_smpl_modules(void);
extern void pfmon_smpl_module_info(pfmon_smpl_module_t *mod);
extern void pfmon_smpl_initialize(void);
extern void pfmon_smpl_mod_usage(void);
extern int pfmon_smpl_initialize_session(pfmon_sdesc_t *sdesc);
extern int pfmon_smpl_terminate_session(pfmon_sdesc_t *sdesc);
extern int pfmon_smpl_init_ctx_arg(pfmon_ctx_t *ctx, unsigned int max_pmds_sample);

/* from pfmon_system.c */
extern int measure_system_wide(pfmon_ctx_t *ctx, char **argv);

/* from pfmon_task.c */
extern int measure_task(pfmon_ctx_t *ctx, char **argv);

#define PFMON_DFL_SYM_HASH_SIZE	12	/* log2(): number of collision lists */
#define PFMON_DFL_SYM_ENTRIES	4096	/* number of symbols that can be stored in hash table */

/*
 * from pfmon_symbols.c
 */
extern int load_kernel_syms(void);
extern void attach_kernel_syms(module_map_t **list);
extern void pfmon_gather_module_symbols();	// andrzejn
extern int load_pid_map(pfmon_sdesc_t *sdesc, module_map_t **list);	// andrzejn
//extern int load_pid_syms(pid_t pid, module_map_t **list);	// andrzejn
extern int load_pid_syms(pfmon_sdesc_t *sdesc, pid_t pid, module_map_t **list);	// andrzejn
extern int find_sym_addr(char *sym, module_map_t *list, pfmon_sym_type_t type, unsigned long *start, unsigned long *end);
//extern int find_sym_byaddr(unsigned long addr, module_map_t *list, pfmon_sym_type_t type, char **name, char **module, unsigned long *start, unsigned long *end);
extern int find_sym_by_apv(unsigned long addr, pid_t pid, unsigned int version, module_map_t *list, pfmon_sym_type_t type, char **name, char **module, unsigned long *start, unsigned long *end); // andrzejn
extern int pfmon_is_exact_sym(unsigned long addr, module_map_t *list, pfmon_sym_type_t type);
extern void print_syms(module_map_t *list);
unsigned long pfmon_get_entry_point(char *filename);
extern int pfmon_program_is_abi32(char *filename);


/* from pfmon_conf.c */
extern void load_config_file(void);
extern int find_opcode_matcher(char *name, unsigned long *val);
extern void print_opcode_matchers(void);

/*
 * Some useful inline functions
 */
#ifdef PFMON_DEBUG
#include <unistd.h>
#define DPRINT(a) \
	do { \
		if (options.opt_debug) { fprintf(stderr, "%s.%d: [%d] ", __FUNCTION__, __LINE__, getpid()); dbgprintf a; } \
	} while (0)
#else
#define DPRINT(a)
#endif

#define M_PMD(x)		(1ULL<<(x))

typedef struct _pfmon_hash_key {
	uint64_t	val;	/* use uint64_t because ILP32 on LP64 */
	pid_t		pid;	/* process id */
	pid_t		tid;	/* thread id */
	uint32_t	version;/* module_map_t version */
} pfmon_hash_key_t;

/*
 * payload is contiguous with header
 */
typedef struct _pfmon_hash_entry {
	struct _pfmon_hash_entry 	*next, *prev;		/* active/free list */
	struct _pfmon_hash_entry 	*hash_next, *hash_prev;	/* hash collision chain */

	pfmon_hash_key_t	key;
	unsigned long		bucket;
	uint64_t		access_count;
} pfmon_hash_entry_t;

#define PFMON_HASH_ACCESS_REORDER	0x1	/* put last accessed element at the head of chain */

typedef struct {
	pfmon_hash_entry_t	**table;	/* hash table */
	pfmon_hash_entry_t	*free_list;
	pfmon_hash_entry_t	*active_list;

	uint64_t		mask;		/* mask used for hashing (2^hash_size-1) */
	size_t			entry_size;	/* header + payload */
	uint32_t		shifter;

	uint64_t		accesses;
	uint64_t		misses;
	uint64_t		collisions;

	unsigned long		max_entries;
	unsigned long		used_entries;
	unsigned int		flags;
} pfmon_hash_table_t;

typedef struct {
	size_t		hash_log_size;
	size_t		max_entries;
	size_t		entry_size;
	uint32_t	shifter;
	unsigned int	flags;
} pfmon_hash_param_t;

extern int  pfmon_hash_alloc(pfmon_hash_param_t *param, void **hash_desc);
extern void pfmon_hash_free(void *hash_desc);
extern int  pfmon_hash_add(void *hash_desc, pfmon_hash_key_t key, void **data);
extern int  pfmon_hash_find(void *hash_desc, pfmon_hash_key_t key, void **data);
extern int  pfmon_hash_iterate(void *hash_desc, void (*func)(void *, void *), void *arg);
extern int  pfmon_hash_num_entries(void *hash_desc, unsigned long *num_entries);
extern int  pfmon_hash_flush(void *hash_desc);
extern void pfmon_hash_stats(void *hash_desc, FILE *fp);

/*
 * from pfmon_os.c
 */
extern int pfmon_create_context(pfmon_ctx_t *ctx, void **smpl_addr, int *fd, int *err);
extern int pfmon_write_pmcs(int fd, pfmon_event_set_t *set, pfmon_pmc_t *pc, int count, int *err);
extern int pfmon_write_pmds(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pd, int count, int *err);
extern int pfmon_read_pmds(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pd, int count, int *err);
extern int pfmon_create_evtsets(int fd, pfmon_setdesc_t *setf, int count, int *err);
extern int pfmon_getinfo_evtsets(int fd, pfmon_setinfo_t *setf, int count, int *err);
extern int pfmon_restart(int fd, int *err);
extern int pfmon_start(int fd, int *err);
extern int pfmon_stop(int fd, int *err);
extern int pfmon_load_context(int fd, pid_t tid, int *err);
extern int pfmon_unload_context(int fd, int *err);
extern int prepare_pmc_registers(pfmon_event_set_t *set);
#ifdef __ia64__
extern int pfmon_write_ibrs(int fd, pfmon_pmc_t *pc, int count, int *err);
extern int pfmon_write_dbrs(int fd, pfmon_pmc_t *pc, int count, int *err);
#endif

/*
 * from pfmon_smpl_dfl.c
 */
extern int dfl_smpl_check_new_samples(pfmon_sdesc_t *sdesc);
extern int dfl_smpl_check_version(pfmon_sdesc_t *sdesc);
extern int dfl_smpl_init_ctx_arg(pfmon_ctx_t *ctx, unsigned int max_pmds_sample);
extern int dfl_smpl_is_default(void);
extern void dfl_smpl_compute_smpl_entries(void);

#define PFMON_NO_TIMEOUT	(~0U)	/* timeout not set */

#define PFMON_BPL	64 
#define PFMON_LBPL	6  /* log2(PFMON_BPL) */

static inline void pfmon_bv_set(uint64_t *bv, unsigned int rnum)
{
	bv[rnum>>PFMON_LBPL] |= 1ULL << (rnum&(PFMON_BPL-1));
}

static inline int pfmon_bv_isset(uint64_t *bv, unsigned int rnum)
{
	return bv[rnum>>PFMON_LBPL] & (1ULL <<(rnum&(PFMON_BPL-1))) ? 1 : 0;
}

static inline void pfmon_bv_clear(uint64_t *bv, unsigned int rnum)
{
	bv[rnum>>PFMON_LBPL] &= ~(1ULL << (rnum&(PFMON_BPL-1)));
}

static inline void pfmon_bv_or(uint64_t *d, uint64_t *s)
{
	unsigned int i;
	for(i=0; i < PFM_PMD_BV; i++)
		d[i] |= s[i];
}

static inline void pfmon_bv_copy(uint64_t *d, uint64_t *s)
{
	unsigned int i;
	for(i=0; i < PFM_PMD_BV; i++)
		d[i] = s[i];
}

static inline unsigned int pfmon_bv_weight(uint64_t *d)
{
	unsigned int i, sum = 0;

	for(i=0; i < PFM_PMD_BV; i++)
		sum+= bit_weight(d[i]);
	return sum;
}
#define PERFMON_VERSION_22 (2U<<16|2U)
#define PERFMON_VERSION_24 (2U<<16|4U)

#endif /*__PFMON_H__ */
