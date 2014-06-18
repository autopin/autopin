/*
 * pfmon_task.c : handles per-task measurements
 *
 * Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
 * Parts contributed by Andrzej Nowak (CERN)
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

#include <fcntl.h>
#include <regex.h>
#include <syscall.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sched.h>
#include <string.h>

#include <numa.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/sysinfo.h>


/*
 * This belongs to some LIBC header files for 2.6
 */
#ifndef PTRACE_SETOPTIONS

/* 0x4200-0x4300 are reserved for architecture-independent additions.  */
#define PTRACE_SETOPTIONS	0x4200
#define PTRACE_GETEVENTMSG	0x4201
#define PTRACE_GETSIGINFO	0x4202
#define PTRACE_SETSIGINFO	0x4203

/* options set using PTRACE_SETOPTIONS */
#define PTRACE_O_TRACESYSGOOD	0x00000001
#define PTRACE_O_TRACEFORK	0x00000002
#define PTRACE_O_TRACEVFORK	0x00000004
#define PTRACE_O_TRACECLONE	0x00000008
#define PTRACE_O_TRACEEXEC	0x00000010
#define PTRACE_O_TRACEVFORKDONE	0x00000020
#define PTRACE_O_TRACEEXIT	0x00000040

/* Wait extended result codes for the above trace pt_options.  */
#define PTRACE_EVENT_FORK	1
#define PTRACE_EVENT_VFORK	2
#define PTRACE_EVENT_CLONE	3
#define PTRACE_EVENT_EXEC	4
#define PTRACE_EVENT_VFORK_DONE	5
#define PTRACE_EVENT_EXIT	6
#endif /* PTRACE_OPTIONS */

#define PFMON_SDESC_PID_HASH_SIZE	256
#define PFMON_SDESC_PID_HASH(x)		((x) & (PFMON_SDESC_PID_HASH_SIZE-1))

#define PFMON_SDESC_FD_HASH_SIZE	256
#define PFMON_SDESC_FD_HASH(x)		((x) & (PFMON_SDESC_FD_HASH_SIZE-1))

#ifndef __WNOTHREAD
#define __WNOTHREAD     0x20000000
#endif

/*
 * better is cache line size aligned
 */
typedef struct {
	pthread_t	thread_id;	/* worker's thread id */
	unsigned int	cpu_id;		/* worker's assigned CPU */
	int		to_worker[2];	/* worker's 1-way communication frofromm master */
	int		from_worker[2];	/* worker's 1-way communication back to master */

	pfmon_sdesc_t	*fd_hash[PFMON_SDESC_FD_HASH_SIZE];	/* hash table for sdesc managed by worker */
} task_worker_t;

typedef enum { 
	PFMON_TASK_MSG_QUIT,		/* time to quit */
	PFMON_TASK_MSG_ADD_TASK,	/* new task to handle */
	PFMON_TASK_MSG_REM_TASK,	/* new task to handle */
	PFMON_TASK_MSG_RESET		/* reset perfmon state (used for exec-split) */
} pfmon_worker_msg_type_t;

typedef struct {
	pfmon_worker_msg_type_t	type;
	void			*data;
} task_worker_msg_t;

typedef struct {
	unsigned long num_sdesc;	/* number of sdesc allocated at a particular time */
	unsigned long max_sdesc;	/* max number of allocated sdesc at a particular time */
	unsigned long num_active_sdesc; /* number of sdesc which are actively monitoring */
	unsigned long max_active_sdesc; /* max number of sdesc which are actively monitoring at a particular time */
	unsigned long total_sdesc;	/* total number of sdesc created for the entire session */
} task_info_t;

static pthread_key_t		arg_key;
static pthread_mutex_t		pfmon_hash_pid_lock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t		task_info_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t		task_aggr_lock = PTHREAD_MUTEX_INITIALIZER;
static pfmon_sdesc_t		sdesc_task_aggr;
static regex_t 			follow_exec_preg;
static task_worker_t		*workers;
static pid_t 			master_tid;
static pfmon_sdesc_t 		*sdesc_pid_hash[PFMON_SDESC_PID_HASH_SIZE];
static int volatile 		time_to_quit;
static pfmon_quit_reason_t	quit_reason;
static int 			work_todo;
static task_info_t		task_info;
static sem_t			master_work_sem;

#define MAX_PIN_CONFIGS 	8
#define MAX_CORES 		16
typedef struct
{
  int best_config;
  int current_config;
  int change_count;
  int config_count;
  int pinning[MAX_PIN_CONFIGS][MAX_CORES];
} pin_config_t;
static pin_config_t pin_config;
static __pid_t tid_list[MAX_CORES + 1];
static int has_reported[MAX_CORES + 1];
static int next_tid;
static int alarmed;
static int pinned_threads;
static int measured_threads;
static uint64_t max_rate;

static void pfmon_task_chain_append(pfmon_sdesc_t *sdesc);
static int task_pfm_init(pfmon_sdesc_t *sdesc, int from_exec, pfmon_ctx_t *ctx);

static const char *trigger_strs[]={
	"entry",
	"start",
	"stop",
	"dlopen"
};

#define LOCK_TASK_INFO()	pthread_mutex_lock(&task_info_lock)
#define UNLOCK_TASK_INFO()	pthread_mutex_unlock(&task_info_lock)

/*
 * must be called with aggr_lock held
 */
static inline void
task_aggregate_results(pfmon_sdesc_t *sdesc)
{
	pfmon_event_set_t *set_aggr, *set;
	unsigned int i, count;
	
	for (set_aggr = sdesc_task_aggr.sets,
	     set = sdesc->sets;
	     set_aggr;
	     set_aggr = set_aggr->next,
	     set = set->next) {

		count = set_aggr->event_count;

		for (i=0; i < count; i++) {
			set_aggr->master_pd[i].reg_value += set->master_pd[i].reg_value;
		}
	}
}

static void
task_sigalarm_handler(int n, struct siginfo *info, void *sc)
{
/*
	if (quit_reason == QUIT_NONE)
		quit_reason  = QUIT_TIMEOUT;
	time_to_quit = 1;
*/
	alarmed = 1;
	sem_post(&master_work_sem);
}

static void
task_sigint_handler(int n, struct siginfo *info, void *sc)
{
	if (gettid() != master_tid) return;

	if (quit_reason == QUIT_NONE)
		quit_reason  = QUIT_ABORT;
	time_to_quit = 1;
	sem_post(&master_work_sem);
}

static void
task_sigchild_handler(int n, struct siginfo *info, void *sc)
{
	sem_post(&master_work_sem);
}

/* for debug only */
static void
task_sigterm_handler(int n, struct siginfo *info, void *sc)
{
	if (quit_reason == QUIT_NONE)
		quit_reason  = QUIT_TERM;
	time_to_quit = 1;
	sem_post(&master_work_sem);
}

static void
mask_global_signals(void)
{
	sigset_t my_set;

	sigemptyset(&my_set);
	sigaddset(&my_set, SIGINT);
	sigaddset(&my_set, SIGCHLD);
	sigaddset(&my_set, SIGALRM);
	sigaddset(&my_set, SIGTERM);
	/*
	 * we want to affect the caller's thread only, not the entire process
	 */
        pthread_sigmask(SIG_BLOCK, &my_set, NULL);
}

static void
unmask_global_signals(void)
{
	sigset_t my_set;

	sigemptyset(&my_set);
	sigaddset(&my_set, SIGINT);
	sigaddset(&my_set, SIGCHLD);
	sigaddset(&my_set, SIGALRM);
	sigaddset(&my_set, SIGTERM);

	/*
	 * we want to affect the caller's thread only, not the entire process
	 */
        pthread_sigmask(SIG_UNBLOCK, &my_set, NULL);
}

/*
 * signal handlers are shared by all pfmon threads
 */
static void
setup_global_signals(void)
{
	struct sigaction act;
	sigset_t my_set;

	memset(&act,0,sizeof(act));
	sigemptyset(&my_set);
	sigaddset(&my_set, SIGINT);
	sigaddset(&my_set, SIGTERM);

	act.sa_mask    = my_set;
	act.sa_flags   = SA_SIGINFO;
	act.sa_handler = (__sighandler_t)task_sigalarm_handler;
	sigaction (SIGALRM, &act, 0);

	memset(&act,0,sizeof(act));
	sigemptyset(&my_set);
	sigaddset(&my_set, SIGALRM);
	sigaddset(&my_set, SIGTERM);

	act.sa_mask    = my_set;
	act.sa_handler = (__sighandler_t)task_sigint_handler;
	act.sa_flags   = SA_SIGINFO;
	sigaction (SIGINT, &act, 0);

	memset(&act,0,sizeof(act));
	sigemptyset(&my_set);
	sigaddset(&my_set, SIGALRM);
	sigaddset(&my_set, SIGINT);

	act.sa_mask    = my_set;
	act.sa_handler = (__sighandler_t)task_sigterm_handler;
	act.sa_flags   = SA_SIGINFO;
	sigaction (SIGTERM, &act, 0);

	memset(&act, 0, sizeof(act));
	sigemptyset(&my_set);
	sigaddset(&my_set, SIGINT);
	sigaddset(&my_set, SIGALRM);
	sigaddset(&my_set, SIGTERM);

	act.sa_mask    = my_set;
	act.sa_flags   = SA_SIGINFO;
	act.sa_handler = (__sighandler_t)task_sigchild_handler;
	sigaction (SIGCHLD, &act, 0);
}

static inline int
pfmon_continue(pid_t pid, unsigned long sig)
{
	int r;

	r = ptrace(PTRACE_CONT, pid, NULL, (void *)sig);
	if (r == -1) {
		warning("cannot restart [%d]: %s\n", pid, strerror(errno));
	}
	return r;
}

static inline int
pfmon_detach(pid_t pid)
{
	int r;

	r = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (r == -1) {
		warning("cannot detach [%d]: %s\n", pid, strerror(errno));
	}
	return r;
}

static int
install_code_triggers(pfmon_sdesc_t *sdesc)
{
	unsigned int i, k=0;
	pfmon_trigger_t *trg;
	pid_t pid;
	int ret;

	trg = sdesc->code_triggers;
	pid = sdesc->tid;

	for (i=0; i < sdesc->num_code_triggers; i++, trg++) {

		trg->brk_idx = k++;
		if (trg->brk_address) {
			ret = pfmon_set_code_breakpoint(pid, trg);
			if (ret) {
				warning("cannot install code breakpoints @ %p\n", trg->brk_address);
				return -1;
			}
			vbprintf("[%d] installed %-5s code breakpoint (db%u) at %p\n",
				pid, 
				trigger_strs[trg->brk_type],
				i,
				trg->brk_address);
		}
	}
	return 0;
}

static int
install_data_triggers(pfmon_sdesc_t *sdesc)
{
	pfmon_trigger_t *trg;
	pid_t pid;
	unsigned int i;
	int rw, ret;

	trg = sdesc->data_triggers;
	pid = sdesc->tid;

	for (i=0; i < sdesc->num_data_triggers; i++, trg++) {
		rw = trg->trg_attr_rw;
		trg->brk_idx = i;
		ret = pfmon_set_data_breakpoint(pid, trg);
		if (ret) {
			warning("cannot install data breakpoints\n");
			return -1;
		}
		vbprintf("[%d] installed %-5s data breakpoint at %p\n", 
			pid, 
			trigger_strs[trg->brk_type],
			trg->brk_address);

	}
	return 0;
}

static int
uninstall_code_triggers(pfmon_sdesc_t *sdesc)
{
	unsigned int i;
	pfmon_trigger_t *trg;
	pid_t pid;
	int ret;

	trg = sdesc->code_triggers;
	pid = sdesc->tid;

	for (i=0; i < sdesc->num_code_triggers; i++, trg++) {
		if (trg->brk_address == 0)
			continue;

		ret = pfmon_clear_code_breakpoint(pid, trg);
		if (ret)
			warning("cannot uninstall code breakpoint @ %p\n", trg->brk_address);
		else
			vbprintf("[%d] uninstalled %-5s code breakpoint (db%u) at %p\n",
				pid,
				trigger_strs[trg->brk_type],
				i,
				trg->brk_address);

		trg->brk_address = 0;
		trg->brk_idx = 0;
	}
	return 0;
}

static int
uninstall_data_triggers(pfmon_sdesc_t *sdesc)
{
	pfmon_trigger_t *trg;
	pid_t pid;
	unsigned int i;
	int ret;

	trg = sdesc->data_triggers;
	pid = sdesc->tid;

	for (i=0; i < sdesc->num_data_triggers; i++, trg++) {
		if (trg->brk_address == 0)
			continue;

		ret = pfmon_clear_data_breakpoint(pid, trg);
		if (ret)
			warning("cannot uninstall data breakpoint @ %p\n", trg->brk_address);
		else
			vbprintf("[%d] uninstalled %-5s data breakpoint at %p\n",
				pid,
				trigger_strs[trg->brk_type],
				trg->brk_address);

		trg->brk_address = 0;
		trg->brk_idx = 0;
	}
	return 0;
}

static pfmon_trigger_t *
find_code_trigger(pfmon_sdesc_t *sdesc, unsigned long addr)
{
	unsigned int i, num;

	num = sdesc->num_code_triggers;

	for (i=0; i < num; i++) {
		if (addr == sdesc->code_triggers[i].brk_address) return sdesc->code_triggers+i;
	}
	return NULL;
}

static pfmon_trigger_t *
find_data_trigger(pfmon_sdesc_t *sdesc, unsigned long addr)
{
	unsigned int i, num;

	num = sdesc->num_data_triggers;

	for (i=0; i < num; i++) {
		if (addr == sdesc->data_triggers[i].brk_address) return sdesc->data_triggers+i;
	}
	return NULL;
}

static int 
task_setup_pfm_context(pfmon_sdesc_t *sdesc, pfmon_ctx_t *ctx)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	pfmon_ctxid_t id;
	int ret, error;

	pfmon_clone_sets(options.sets, sdesc);

	memset(csmpl, 0, sizeof(pfmon_smpl_desc_t));

	if (pfmon_create_context(ctx, &csmpl->smpl_hdr, &sdesc->ctxid, &error) == -1 ) {
		if (error == ENOMEM && options.opt_use_smpl)
			warning("Not enough memory to create perfmon context for [%d],\ncheck your locked memory "
				" resource limit with limit or ulimit\n", sdesc->tid);
		else
			warning("can't create perfmon context: %s\n", strerror(error));
		return -1;
	}
	id = sdesc->ctxid;

	/*
	 * set close-on-exec for security reasons
	 */
	ret = fcntl(id, F_SETFD, FD_CLOEXEC);
	if (ret) {
		warning("cannot set CLOEXEC: %s\n", strerror(errno));
		return -1;
	}

	if (open_results(sdesc) == -1) return -1;

	if (options.opt_use_smpl) {
		if (pfmon_setup_sampling_output(sdesc, &sdesc_task_aggr) == -1)
			return -1;
		sdesc->csmpl.map_size = ctx->ctx_map_size;
	}

	if (install_event_sets(sdesc) == -1)
		return -1;

	if (pfmon_load_context(sdesc->ctxid, sdesc->tid, & error) == -1) {
		if (error == EBUSY)
			warning("error concurrent system-wide monitoring session exists\n");
		else
			warning("cannot attach context to %d: %s\n", sdesc->tid, strerror(error));

		return -1;
	}

	return 0;
}

static int 
task_reset_pfm_context(pfmon_sdesc_t *sdesc)
{
	pfmon_event_set_t *set;
	pfmon_pmd_t *pd;
	unsigned int i, count;
	int ret = -1, error;

	vbprintf("[%d] resetting perfmon state hdr=%p\n", sdesc->tid, sdesc->csmpl.smpl_hdr);

	for (set = sdesc->sets; set; set = set->next) {
		pd = set->master_pd;
		count = set->event_count;
		for(i=0; i < count; i++) {
			pd[i].reg_value = set->long_rates[i].value;
		}
	}

	/*
	 * task is stopped but we need to unload because we reprogram
	 * the event sets
	 */
	if (pfmon_unload_context(sdesc->ctxid, &error) == -1)
		return -1;

	install_event_sets(sdesc);

	if (pfmon_load_context(sdesc->ctxid, sdesc->tid, &error) == -1)
		return -1;

	/* monitoring is always stopped on reload */

	if (options.opt_use_smpl) {
		if (pfmon_reset_sampling(sdesc) == -1) goto error;
		if (pfmon_setup_sampling_output(sdesc, &sdesc_task_aggr) == -1) goto error;
		DPRINT(("reset setup sampling buffer for [%d]\n", sdesc->tid));
	}
	ret = 0;
error:
	return ret;
}

static int
task_collect_results(pfmon_sdesc_t *sdesc, int is_final)
{
	/*
	 * no more context attached, there is nothing we can do here
	 */
	if (sdesc->ctxid == -1) return 0;

	/*
	 * read the last known values for the counters
	 */
	if (options.opt_use_smpl == 0 || options.opt_smpl_print_counts) {
		if (read_results(sdesc) == -1) {
			warning("read_results error\n");
			return -1;
		}
	}

	if (options.opt_aggr) {
		pthread_mutex_lock(&task_aggr_lock);

		task_aggregate_results(sdesc);

		if (options.opt_use_smpl) pfmon_process_smpl_buf(sdesc, 1);

		pthread_mutex_unlock(&task_aggr_lock);
	}
	else {
		if (options.opt_use_smpl) pfmon_process_smpl_buf(sdesc, 1);

		show_results(sdesc, 0);

		close_results(sdesc);
	}
	if (options.opt_use_smpl) {
		if (options.opt_aggr == 0)
			pfmon_close_sampling_output(sdesc, sdesc->tid, 0);
		/*
		 * this function is collect on exec-split but we gather partial results,
		 * thus we do not want to unmap the buffer just yet
		 */
		if (is_final)
			munmap(sdesc->csmpl.smpl_hdr, sdesc->csmpl.map_size);
	}
	return 0;
}

/*
 * allocates sdesc with accompanying ctx_arg area
 */
static pfmon_sdesc_t *
pfmon_sdesc_alloc(void)
{
	pfmon_sdesc_t *tmp;

	tmp = calloc(1, sizeof(pfmon_sdesc_t) + options.ctx_arg_size);
	if (tmp == NULL)
		fatal_error("cannot allocate sdesc\n");

	pthread_mutex_init(&tmp->lock, PTHREAD_MUTEX_TIMED_NP);

	return tmp;
}

static void
pfmon_sdesc_free(pfmon_sdesc_t *t)
{
	if(t != NULL) {
		pfmon_free_sets(t);
		free(t);
	}
}

static void
pfmon_sdesc_pid_hash_add(pfmon_sdesc_t **hash, pfmon_sdesc_t *t)
{
	int slot = PFMON_SDESC_PID_HASH(t->tid);

	pthread_mutex_lock(&pfmon_hash_pid_lock);

	t->next    = hash[slot];
	hash[slot] = t;

	pthread_mutex_unlock(&pfmon_hash_pid_lock);

}

static pfmon_sdesc_t *
pfmon_sdesc_pid_hash_find(pfmon_sdesc_t **hash, pid_t pid)
{
	int slot = PFMON_SDESC_PID_HASH(pid);
	pfmon_sdesc_t *q;

	pthread_mutex_lock(&pfmon_hash_pid_lock);

	q = hash[slot];
	while (q) {
		if ((q)->tid == pid) break;
		q = q->next;
	}
	pthread_mutex_unlock(&pfmon_hash_pid_lock);

	return q;
}

static int
pfmon_sdesc_pid_hash_remove(pfmon_sdesc_t **hash, pfmon_sdesc_t *t)
{
	pfmon_sdesc_t *q, *prev = NULL;
	int slot = PFMON_SDESC_PID_HASH(t->tid);

	pthread_mutex_lock(&pfmon_hash_pid_lock);

	q = hash[slot];
	while (q) {
		if (q == t) goto found;
		prev = q;
		q = q->next;
	}
	pthread_mutex_unlock(&pfmon_hash_pid_lock);

	fatal_error("cannot find [%d] in hash queue\n", t->tid);
	return -1;
found:
	if (prev)
		prev->next = t->next;
	else 
		hash[slot] = t->next;

	pthread_mutex_unlock(&pfmon_hash_pid_lock);

	return 0;
}
	
static int
pfmon_setup_ptrace(pid_t pid)
{
	unsigned long ptrace_flags;
	int ret;

	ptrace_flags = 0UL;

	/*
	 * we need this notifcation to stop monitoring on exec when
	 * no "follow" option is specified
	 */
	ptrace_flags |= PTRACE_O_TRACEEXEC;

	if (options.opt_follow_vfork)
		ptrace_flags |= PTRACE_O_TRACEVFORK;
	if (options.opt_follow_fork)
		ptrace_flags |= PTRACE_O_TRACEFORK;
	if (options.opt_follow_pthread)
		ptrace_flags |= PTRACE_O_TRACECLONE;


	vbprintf("follow_exec=%c follow_vfork=%c follow_fork=%c follow_pthread=%c\n",
		options.opt_follow_exec  ? 'y' : 'n',
		options.opt_follow_vfork ? 'y' : 'n',
		options.opt_follow_fork  ? 'y' : 'n',
		options.opt_follow_pthread ? 'y' : 'n');

	if (ptrace_flags == 0UL) return 0;

	/*
	 * update the options
	 */
	ret = ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)ptrace_flags);
	if (ret == -1) warning("cannot set ptrace options on [%d], check PTRACE_SETOPTIONS support: %s\n", pid, strerror(errno));
	return ret;
}

static void
pfmon_sdesc_exit(pfmon_sdesc_t *sdesc)
{
	pid_t tid;

	tid = sdesc->tid;

	LOCK_SDESC(sdesc);

	sdesc->refcnt--;

	if (sdesc->refcnt == 0) {

		pfmon_sdesc_pid_hash_remove(sdesc_pid_hash, sdesc);

		LOCK_TASK_INFO();

		task_info.num_sdesc--;

		if (sdesc->ctxid != -1)
			task_info.num_active_sdesc--;

		vbprintf("[%d] detached\n", tid);

		if (task_info.num_sdesc == 0) {
			work_todo = 0;
			sem_post(&master_work_sem);
			DPRINT(("posted master_work_sem\n"));
		}
		DPRINT(("tid=%d removed active=%lu todo=%d\n", tid, task_info.num_active_sdesc, work_todo));

		UNLOCK_TASK_INFO();

		if (sdesc->ctxid != -1)
			close(sdesc->ctxid);

		// when resolving, freeing the sdesc is delayed until the end of the pfmon run
		if(!options.opt_addr2sym)
			pfmon_sdesc_free(sdesc);

	} else {
		if (sdesc->refcnt < 1) { 
			fatal_error("invalid refcnt=%d for [%d]\n", sdesc->refcnt, tid); 
		}
		DPRINT(("deferring remove tid=%d refcnt=%d\n", tid, sdesc->refcnt));

		UNLOCK_SDESC(sdesc);
	}
}

static const char *sdesc_type_str[]= {
	"attached",
	"fork",
	"vfork",
	"clone"
};

static inline void
pfmon_sdesc_set_pid(pfmon_sdesc_t *sdesc, pid_t new_tid)
{
	sdesc->pid = find_pid_attr(new_tid, "Tgid");
	sdesc->ppid = find_pid_attr(new_tid, "PPid");
	sdesc->tid = new_tid;
}

static int isNUMA()
{
	/* The appropriate function has to be found, right now we
	   do it via libnuma-calls */
	  
	  if (numa_available() == -1)
	  {
	  	fprintf(stderr, "NUMA Library problem"); 
	        return (-1);
	  }
	  
	  if (numa_max_node()<=0) 
	  	return 0;
	  else
	  	return 1;	
}

/* Hardcoded quick hack */
static int doNUMA(pid_t pid)
{
	struct stat filestat;
	FILE *file;
	
	if (stat ("/dev/cpuset", &filestat) == -1)
	{
		perror ("stat /dev/cpuset");
		fprintf (stderr, "No cpuset-Support or no /dev/cpuset available\n");
		fprintf (stderr, "No next touch support\n");
		return -1;
	}
	
	if (stat ("/dev/cpuset/autopin", &filestat) == -1 
		&& mkdir ("/dev/cpuset/autopin", 600) == -1 )
	{
		perror ("mkdir /dev/cpuset/autopin");
		fprintf (stderr, "Can't create /dev/cpuset/autopin\n");
		fprintf (stderr, "Please change permissions.\n");
		fprintf (stderr, "Won't use next touch during this run\n");
		return -1;
	}
	else
		fprintf (stderr, "autopin cpuset already existing, using this one.\n");


	if ((file = fopen ("/dev/cpuset/autopin/migrate_on_fault", "r+")) == NULL)
	{
		perror ("open migrate_on_fault");
		fprintf (stderr, "Your kernel hat cpuset support, but the \n");
		fprintf (stderr, "next touch kernel patch seems to be mising\n");
		return -1;
	}	
	
	fprintf (file, "1");
	fclose (file);

	if ((file = fopen ("/dev/cpuset/autopin/auto_migration", "r+")) == NULL)
	{
		perror ("open auto_migration");
		return -1;
	}
	
	fprintf (file, "1");
	fclose (file);
	
                                                        
	if ((file = fopen ("/dev/cpuset/autopin/cpus", "r+")) == NULL)
	{
		perror ("open cpus");
		return -1;
	}
	
	fprintf (file, "0-%i", get_nprocs()-1);
	fclose (file);
	
	if ((file = fopen ("/dev/cpuset/autopin/mems", "r+")) == NULL)
	{
		perror ("open mems");
		return -1;
	}
	
	fprintf (file, "0-%i", numa_max_node());
	fclose (file);
	
	if ((file = fopen ("/dev/cpuset/autopin/tasks", "r+")) == NULL)
	{
		perror ("open tasks");
		return -1;
	}
	
	fprintf (file, "%i", (int) pid);
	fclose (file);
	
	return 0;
}

static pfmon_sdesc_t *
pfmon_sdesc_new(int type, pfmon_sdesc_t *parent, pid_t new_tid)
{
	pfmon_sdesc_t *sdesc;
	unsigned int n;
	char *coreSteppingStr, *s;
	int myTid, myCore, len, i;
	cpu_set_t cpuMask;
	
	myTid = -1;
	

	
	if (!parent)
	{
		if (type == PTRACE_EVENT_VFORK)
		{
			myTid = 0;
			next_tid = 1;
			tid_list[0] = 1;
			tid_list[myTid + 1] = new_tid;
			pinned_threads = 0;
			measured_threads = 0;
			max_rate = 0;
			pin_config.current_config = 0;
			pin_config.best_config = 0;
			pin_config.change_count = 0;
			memset(has_reported, 0, MAX_CORES + 1);

			pin_config.config_count = 0;
			coreSteppingStr = getenv("SCHEDULE");
			fprintf(stderr, "Schedule Configurations:\n");

			while (coreSteppingStr && strlen(coreSteppingStr))
			{
				s = strchr(coreSteppingStr, ',');
				if (s)
					len = s - coreSteppingStr;
				else
					len = strlen(coreSteppingStr);
				if (len)
				{
					fprintf(stderr, "  %d: ", pin_config.config_count);
					for (i = 0; i < len; i++)
					{
						if ((coreSteppingStr[i] >= '0') && (coreSteppingStr[i] <= '9'))
							pin_config.pinning[pin_config.config_count][i] = coreSteppingStr[i] - '0';
						if ((coreSteppingStr[i] >= 'a') && (coreSteppingStr[i] <= 'f'))
							pin_config.pinning[pin_config.config_count][i] = coreSteppingStr[i] - 'a' + 10;
						if ((coreSteppingStr[i] >= 'A') && (coreSteppingStr[i] <= 'F'))
							pin_config.pinning[pin_config.config_count][i] = coreSteppingStr[i] - 'A' + 10;
						fprintf(stderr, "%d ", pin_config.pinning[pin_config.config_count][i]);
					}
					for (i = len; i < MAX_CORES; i++)
					{
						pin_config.pinning[pin_config.config_count][i] = i;
						fprintf(stderr, "%d ", pin_config.pinning[pin_config.config_count][i]);
					}
					fprintf(stderr, "\n");
					pin_config.config_count++;
					coreSteppingStr += len;
					if (strlen(coreSteppingStr))
						coreSteppingStr++;
				}
			}

			if (!pin_config.config_count)
			{
				fprintf(stderr, "  0: ");
				for (i = 0; i < MAX_CORES; i++)
				{
					pin_config.pinning[pin_config.config_count][i] = i;
					fprintf(stderr, "%d ", pin_config.pinning[pin_config.config_count][i]);
				}
				fprintf(stderr, "\n");
				pin_config.config_count++;
			}
		}
		fprintf(stderr, "  %ld: type=%s  ", (long) new_tid, sdesc_type_str[type]);
	} else
	{
		fprintf(stderr, "  %ld: type=%s  parent->tid=%ld  parent->type=%s  ", (long) new_tid, sdesc_type_str[type], (long) parent->tid, sdesc_type_str[parent->type]);
		if (type == PTRACE_EVENT_CLONE && parent->type == PTRACE_EVENT_VFORK)
		{
			if (next_tid > 1)
			{
				myTid = next_tid - 1;
				tid_list[myTid + 1] = new_tid;
				tid_list[0]++;
			}
			next_tid++;
		}
	}

	if (myTid != -1)
	{
		if (parent && isNUMA())
		{
			printf ("NUMA architecture with more than 1 memory node found\n");
			printf ("Check if there is a Next Touch Kernel available\n");
			printf ("PID: %ld \n", (long) parent->tid);
			doNUMA(parent->tid);
		}                                 


		myCore = pin_config.pinning[pin_config.current_config][myTid];
		pinned_threads++;
		CPU_ZERO(&cpuMask);
		CPU_SET(myCore, &cpuMask);
		if (sched_setaffinity(new_tid, sizeof(cpuMask), &cpuMask))
			fprintf(stderr, "#  Error while pinning thread to Core #%d/%d\n", myCore, (int) options.online_cpus);
		else
			fprintf(stderr, "#  Pinning thread to Core #%d/%d\n", myCore, (int) options.online_cpus);
	} else
	fprintf(stderr, "#  This thread will not be pinned\n");


	sdesc = pfmon_sdesc_alloc();

	pfmon_sdesc_set_pid(sdesc, new_tid);
	sdesc->type = type;

	if (parent)
		strcpy(sdesc->cmdline, parent->cmdline);

	/*
	 * the following rules apply for flags inheritance:
	 * fl_monitoring	: inherited
	 * fl_seen_stopsig	: not inherited
	 * fl_detaching		: not inherited
	 * fl_dispatched	: not inherited
	 * fl_attached		: inherited
	 */
	if (parent) {
		if (parent->fl_attached)
			sdesc->fl_attached = 1;
		if (parent->fl_monitoring)
			sdesc->fl_monitoring = 1;
	}

	if (type == PFMON_SDESC_ATTACH)
		sdesc->fl_attached = 1;

	sdesc->ctxid  = -1; /* not associated with a context */
	sdesc->refcnt = 1;

	/*
	 * parent == NULL indicates first task
	 */
	n = options.num_code_triggers;
	if (n && (options.opt_code_trigger_follow || parent == NULL)) {
		memcpy(sdesc->code_triggers, options.code_triggers, n*sizeof(pfmon_trigger_t));
		sdesc->num_code_triggers = n;
	}

	/*
	 * parent == NULL indicates first task
	 */
	n = options.num_data_triggers;
	if (n && (options.opt_data_trigger_follow || parent == NULL)) {
		memcpy(sdesc->data_triggers, options.data_triggers, n*sizeof(pfmon_trigger_t));
		sdesc->num_data_triggers = n;
	}

	DPRINT(("%s parent=%d pid=%lu tid=%d flags=0x%lx cmd: %.64s\n", 
		sdesc_type_str[type],
		sdesc->ppid,
		sdesc->pid,
		sdesc->tid,
		sdesc->flags,
		sdesc->cmdline));

	LOCK_TASK_INFO();

	task_info.num_sdesc++;

	if (task_info.num_sdesc > task_info.max_sdesc) 
		task_info.max_sdesc = task_info.num_sdesc;

	task_info.total_sdesc++;

	UNLOCK_TASK_INFO();

	pfmon_sdesc_pid_hash_add(sdesc_pid_hash, sdesc);

	if(sdesc->current_map_version == 0) {
		load_pid_map(sdesc, &options.primary_syms);
        } else {
		load_pid_map(sdesc, &options.primary_syms);
	}

	return sdesc;
}

static void
pfmon_sdesc_update(pfmon_sdesc_t *sdesc, int type, pfmon_sdesc_t *parent)
{
	sdesc->new_cmdline[0] = '\0';
	pfmon_extract_cmdline(sdesc);
	strcpy(sdesc->cmdline, sdesc->new_cmdline);

	/*
	 * the following rules apply for flags inheritance:
	 * fl_monitoring	: inherited
	 * fl_seen_stopsig	: not inherited
	 * fl_detaching		: not inherited
	 * fl_dispatched	: not inherited
	 * fl_attached		: inherited
	 */
	if (parent) {
		if (parent->fl_attached)
			sdesc->fl_attached = 1;
		if (parent->fl_monitoring)
			sdesc->fl_monitoring = 1;
	}

	if (type == PFMON_SDESC_ATTACH)
		sdesc->fl_attached = 1;

	/*
	 * update type with actual event type
	 */
	sdesc->type = type;
}

/*
 * return:
 * 	0 : not interested
 * 	1 : interested
 */
static inline int
pfmon_sdesc_interesting(pfmon_sdesc_t *sdesc)
{
	int r = 0;

	if (options.fexec_pattern) {
		/* r = 0 means match */
		r = regexec(&follow_exec_preg, sdesc->new_cmdline, 0, NULL, 0);
		if (options.opt_follow_exec_excl) r = !r;
	}
	return r == 0 ? 1 : 0;
}

static void
pfmon_set_entry_brkpt(pfmon_sdesc_t *sdesc)
{
	unsigned long addr;
	char *p;

	/*
	 * we arm a breakpoint on entry point to capture
	 * symbol table from /proc. We leverage the existing
	 * trigger-code infrastructure by injecting breakpoint.
	 * Monitoring is not started until we reach that breakpoint
	 * which is set on the first user instruction of the program
	 * we are starting.
	 */
	p = strchr(sdesc->new_cmdline, ' ');
	if (p) *p = '\0';
	addr = pfmon_get_entry_point(sdesc->new_cmdline);

	if (addr) {
		vbprintf("entry point @ 0x%lx for %s\n", addr, sdesc->new_cmdline);
		sdesc->code_triggers[0].brk_address = addr;
		sdesc->code_triggers[0].brk_type = PFMON_TRIGGER_ENTRY;
		sdesc->code_triggers[0].trg_attr_repeat = 0;
		sdesc->num_code_triggers = 1;
		/*
 		 * do not issue pfmon_start()  in task_pfm_init()
 		 * and defer to pfmon_handle_entry_trigger9)
 		 */
		sdesc->fl_has_entry = 1;
	}
	if (p) *p = ' ';
}

static void
pfmon_sdesc_exec(pfmon_sdesc_t *sdesc)
{
	char *p;

	pfmon_extract_cmdline(sdesc);

	p = strchr(sdesc->new_cmdline, ' ');
	if (p)
		*p = '\0';
 
	sdesc->fl_abi32 = pfmon_program_is_abi32(sdesc->new_cmdline);
	if (p)
		*p = ' ';

	if (sdesc->fl_abi32)
		vbprintf("[%d] using 32-bit ABI\n", sdesc->pid);
	else
		vbprintf("[%d] using 64-bit ABI\n", sdesc->pid);
 
	/*
	 * no need to catch entry point when attaching
	 */
	if (sdesc->fl_attached == 0)
		pfmon_set_entry_brkpt(sdesc);

	pfmon_task_chain_append(sdesc);

	/*
	 * deactivate symbol hash table after first exec
	 */
	vbprintf("[%d] deactivated the deactivation of symbol resolution because of multiple exec() ;-)\n", sdesc->tid);

        if(sdesc->fl_attached == 0) {
                load_pid_map(sdesc, &options.primary_syms);
        } else {
        	if(sdesc->exec_count == 0)
	                load_pid_syms(sdesc, sdesc->tid, &options.primary_syms);
		else
	                load_pid_map(sdesc, &options.primary_syms);		
        }	
}

static int
task_worker_send_msg(unsigned int cpu, task_worker_msg_t *msg, int wait)
{
	task_worker_msg_t fake;
	int r;

	r = write(workers[cpu].to_worker[1], msg, sizeof(*msg));
	DPRINT(("sending msg.type=%d to wCPU%u\n", msg->type, cpu));

	/*
	 * dummy response, just used for synchronization
	 */
	if (wait) r = read(workers[cpu].from_worker[0], &fake, sizeof(fake));

	return r;
}


static pfmon_sdesc_t *
task_create(char **argv)
{
	pfmon_sdesc_t *sdesc;
	pid_t pid = 0;
	int status, ret;

	if ((pid=vfork()) == -1) {
		warning("cannot vfork process\n");
		return NULL;
	}

	if (pid == 0) {		 
		/*
		 * The use of ptrace() allows us to actually start monitoring after the exec()
		 * is done, i.e., when the new program is ready to go back to user mode for the
		 * "first time". Using this technique we ensure that the overhead of 
		 * exec'ing is not captured in the results. This * can be important for 
		 * short running programs.
		 */
		ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if (ret == -1) {
			warning("cannot ptrace self: %s\n", strerror(errno));
			exit(1);
		}
		if (options.opt_cmd_no_verbose) {
			dup2 (open("/dev/null", O_WRONLY), 1);
			dup2 (open("/dev/null", O_WRONLY), 2);
		}	

		execvp(argv[0], argv);

		warning("cannot exec %s: %s\n", argv[0], strerror(errno));

		exit(1);
		/* NOT REACHED */
	}
	/* 
	 * wait for the child to exec 
	 */
	waitpid(pid, &status, WUNTRACED);

	if (options.opt_verbose) {
		char **p = argv;
		vbprintf("[%d] started task: ", pid);
		while (*p) vbprintf("%s ", *p++);
		vbprintf("\n");
	}

	/*
	 * process is stopped at this point
	 */
	if (WIFEXITED(status)) {
		warning("error cannot monitor task %s(%d): exit status %d\n", argv[0], pid, WEXITSTATUS(status));
		return NULL;
	}

	sdesc = pfmon_sdesc_new(PFMON_SDESC_VFORK, NULL, pid);

	if (sdesc == NULL || pfmon_setup_ptrace(pid)) {
		/* get rid of the task, we cannot proceed */
		status = ptrace(PTRACE_KILL, pid, NULL, NULL);
		if (status != 0) warning("cannot kill task %d: %s\n", pid, strerror(errno));
		if (sdesc)
			pfmon_sdesc_free(sdesc);
		return NULL;
	}
	pfmon_sdesc_exec(sdesc);
	return sdesc;
}

static void pfmon_setup_dlopen(pfmon_sdesc_t *sdesc);

static pfmon_sdesc_t *
task_attach(char **argv)
{
	pfmon_sdesc_t *sdesc;
	pid_t tid = 0;
	int status, ret;

	tid = options.attach_tid;

	sdesc = pfmon_sdesc_new(PFMON_SDESC_ATTACH, NULL, tid);
	if (sdesc == NULL) return NULL;


	status = ptrace(PTRACE_ATTACH, tid, NULL, NULL);
	if (status == -1) {
		warning("cannot attach to %d: %s\n", tid, strerror(errno));
		pfmon_sdesc_free(sdesc);
		return NULL;
	}

	ret = waitpid(tid, &status, WUNTRACED|__WALL);
	if (ret < 0) {
		warning("error attaching to %d : %s\n", tid, strerror(errno));
		ptrace(PTRACE_DETACH, tid, NULL, NULL);
		pfmon_sdesc_free(sdesc);
		return NULL;
	}

	/*
	 * process is stopped at this point
	 */
	if (WIFEXITED(status)) {
		warning("error command already terminated, exit code %d\n", WEXITSTATUS(status));
		pfmon_sdesc_free(sdesc);
		return NULL;
	}

	if (pfmon_setup_ptrace(tid)) {
		/* cannot proceed, just detach */
		status = ptrace(PTRACE_DETACH, tid, NULL, NULL);
		if (status != 0)
			warning("cannot detach task %d: %s\n", tid, strerror(errno));
		pfmon_sdesc_free(sdesc);
		return NULL;
	}
	pfmon_sdesc_set_pid(sdesc, tid);
	pfmon_sdesc_exec(sdesc);

	memcpy(sdesc->code_triggers, options.code_triggers, sizeof(options.code_triggers));
	sdesc->num_code_triggers = options.num_code_triggers;

	/*
	 * install dlopen/dlclose breakpoint in sdesc->code_triggers[0]
	 * also correct sdesc->num_code_triggers
	 */
	pfmon_setup_dlopen(sdesc);

	memcpy(sdesc->data_triggers, options.data_triggers, sizeof(options.data_triggers));
	sdesc->num_data_triggers = options.num_data_triggers;

	vbprintf("[%d] attached to %.16s...\n", tid, sdesc->cmdline);

	return sdesc;
}

static void
task_dispatch_sdesc(pfmon_sdesc_t *sdesc)
{
	task_worker_msg_t msg;
	static unsigned int next_cpu;

	/* sanity check */
	if (sdesc->fl_dispatched) fatal_error("[%d] already dispatched error\n", sdesc->tid);

	msg.type = PFMON_TASK_MSG_ADD_TASK;	
	msg.data = sdesc;

	sdesc->refcnt++;
	sdesc->cpu = next_cpu;
	sdesc->fl_dispatched = 1;

	DPRINT(("[%d] dispatched to worker on CPU%u\n", sdesc->tid, next_cpu));

	task_worker_send_msg(next_cpu, &msg, 0);

	/*
	 * basic round-robin allocation
	 */
	next_cpu = (next_cpu+1) % options.online_cpus;
}

/*
 * return:
 * 	-1 : error
 * 	 0 : ok
 */
static int
task_pfm_init(pfmon_sdesc_t *sdesc, int from_exec, pfmon_ctx_t *ctx)
{
	task_worker_msg_t msg;
	pid_t tid;
	int has_ctxid, was_monitoring;
	int ret, error;
	int activate_brkpoints = 0;

	tid = sdesc->tid;

	/*
	 * we only take the long path if we are coming from exec, otherwise we inherited
	 * from the parent task. 
	 */
	if (from_exec == 0) {
		/*
		 * parent was active, we need to create our context
		 */
		if (sdesc->fl_monitoring) goto init_pfm;
		/*
		 * parent was not active
		 */
		DPRINT(("keep inactive task [%d] monitoring=%d: %s\n", tid, sdesc->fl_monitoring, sdesc->cmdline));
		return 0;
	} 
	/*
	 * we are coming for an exec event
	 */
	DPRINT((" in: [%d] ctxid=%d monitoring=%d refcnt=%d: %s\n", 
		tid, sdesc->ctxid, sdesc->fl_monitoring, sdesc->refcnt,sdesc->cmdline));

	/*
	 * in case we do not follow exec, we have to stop right here
	 * sdesc->ppid=-1 denotes the first process. In case we do not follow exec (pattern), 
	 * we always monitor the first process until it exec's.
	 */
	if (options.opt_follow_exec == 0) {
		//ret = sdesc->ppid != -1 || sdesc->exec_count ? 0 : 1;
		ret = sdesc->exec_count ? 0 : 1;
	} else {
		ret = pfmon_sdesc_interesting(sdesc);
	}
	if (ret == 0) {
		vbprintf("[%d] not monitoring %.55s...\n", sdesc->tid, sdesc->new_cmdline);

		/*
		 * if there was a context attached to the session, then clean up
		 * when split-exec is used. Otherwise, we just stop monitoring
		 * but keep the context around
		 */
		if (sdesc->ctxid != -1) {

			vbprintf("[%d] stopping monitoring at exec\n", tid);

			if (options.opt_split_exec) {
				if (sdesc->fl_monitoring) {
					vbprintf("[%d] collecting results at exec\n", tid);
					task_collect_results(sdesc, 0);
				}

				if (sdesc->fl_dispatched) {
					msg.type = PFMON_TASK_MSG_REM_TASK;
					msg.data = sdesc;

					task_worker_send_msg(sdesc->cpu, &msg, 1);

					sdesc->fl_dispatched = 0;
				}
				close(sdesc->ctxid);
				sdesc->ctxid = -1;
			} else {
				/*
				 * only stop monitoring
				 *
				 * code/data triggers are automatically cleared 
				 * by the kernel on exec()
				 */
				pfmon_stop(sdesc->ctxid, &error);
			}
			/*
			 * monitoring is deactivated
			 */
			sdesc->fl_monitoring = 0;

			LOCK_TASK_INFO();
			task_info.num_active_sdesc--;
			UNLOCK_TASK_INFO();

		}
		/* 
		 * cannot be done before we save results
		 */
		sdesc->exec_count++;
		return 0;
	}
	if (options.opt_split_exec && sdesc->ctxid != -1 && sdesc->fl_monitoring) {
		vbprintf("[%d] collecting results at exec\n", tid);
		task_collect_results(sdesc, 0);
	}

	strcpy(sdesc->cmdline, sdesc->new_cmdline);

	sdesc->exec_count++;

	/*
	 * necessarily in follow-exec mode at this point
	 */

init_pfm:

	vbprintf("[%d] monitoring %.58s...\n", sdesc->tid, sdesc->cmdline);

	was_monitoring = sdesc->fl_monitoring;
	has_ctxid      = sdesc->ctxid != -1;

	/*
	 * we want to monitoring this task
	 */
	sdesc->fl_monitoring = 1;


	/* 
	 * We come either on fork or exec. With the former
	 * we need to create a new context whereas for the latter
	 * it already exists (has_ctxid != 0). 
	 */
	if (has_ctxid == 0) {
		/*
		 * on some architectures (i386,x86-64), debug registers
		 * are systematically inherited by children. We undo did
		 * now to avoid getting spurious breakpoints. Should inheritance
		 * be necessary then use the --trigger-code-follow and
		 * --trigger-data-follow options
		 */
		if (options.num_code_triggers || options.num_data_triggers) {
			ret = pfmon_disable_all_breakpoints(sdesc->tid);	
			if (ret)
				warning("error: could not disable all breakpoints for %d\n", sdesc->tid);
		}
		DPRINT(("setup perfmon ctx for [%d] monitoring=%d refcnt=%d: %s\n", 
			tid, sdesc->fl_monitoring, sdesc->refcnt, sdesc->cmdline));

		ret = task_setup_pfm_context(sdesc, ctx);
		if (ret == -1)
			return -1;

		/*
		 * we may defer actual activation until later
		 *
		 * If it is not attach mode, pfmon_start() is called after
		 * task_handle_entry/start_trigger().
		 */
		if (options.opt_dont_start == 0 && sdesc->fl_has_entry == 0) {
			pfmon_start(sdesc->ctxid, &error);
			vbprintf("[%d] activating monitoring\n", tid);
		} else {
			vbprintf("[%d] monitoring not activated\n", tid);
		}

	} else {
		/*
		 * come here when the context already exists, i.e., exec
		 *
				 */
		/*
		 * in split-exec mode, we need to reset our context
		 * before we proceed further. We also need to reopen
		 * the output file because it was closed in
		 * task_collect_results()
		 */
		if (options.opt_split_exec) {
			task_reset_pfm_context(sdesc);
			if (open_results(sdesc) == -1) return -1;

			/* monitoring is stopped in task_reset_pfm() because of
			 * unload/reload
			 */
			was_monitoring = 0;
		}
		/*
		 * context was not actively monitoring, then we just
		 * need to restart now
		 */
		if (was_monitoring == 0 && options.opt_dont_start == 0) {
			pfmon_start(sdesc->ctxid, &error);
			vbprintf("[%d] restarting monitoring\n", tid);
		}
	}
	/* 
	 * across fork/pthread_create:
	 * 	you need to use --trigger-code-follow or --trigger-data-follow
	 * 	to inherit breakpoints in the new thread/process.
	 *
	 * across exec:
	 * 	breakpoints can never be inherited across exec. However
	 * 	for every newly create binary image, we need to intercept
	 * 	the entry point to snapshot /proc/PID/maps. Thus every
	 * 	new sdesc has one breakpoint, the entry breakpoint. This
	 * 	breakpoint is also used to trigger to dyanmic insertion of
	 * 	the dlopen breakpoint.
	 *
	 * At this point, num_code_trigger = 1, num_data_trigger = 0
	 */
	if (sdesc->num_code_triggers) {
		ret = install_code_triggers(sdesc);
		if (ret) return ret;
		activate_brkpoints = 1;
	}

	if (sdesc->num_data_triggers) {
		ret = install_data_triggers(sdesc);
		if (ret) return ret;
		activate_brkpoints = 1;
	}	

	if (activate_brkpoints)
		pfmon_enable_all_breakpoints(sdesc->tid);

	if (was_monitoring == 0 || has_ctxid == 0) {
		LOCK_TASK_INFO();
		task_info.num_active_sdesc++;
		if (task_info.num_active_sdesc > task_info.max_active_sdesc) 
			task_info.max_active_sdesc = task_info.num_active_sdesc;
		UNLOCK_TASK_INFO();
	}

	DPRINT(("out: [%d] fl_monitoring=%d ctxid=%d was_monitoring=%d has_ctxid=%d\n",
			tid,
			sdesc->fl_monitoring,
			sdesc->ctxid,
			was_monitoring,
			has_ctxid));
	/*
	 * pick a worker thread to manage perfmon notifications, if necessary.
	 */
	if (has_ctxid == 0 && options.opt_use_smpl) task_dispatch_sdesc(sdesc);

	if (options.opt_show_rusage) gettimeofday(&sdesc->tv_start, NULL);

	return 0;
}

static void
task_pfm_exit(pfmon_sdesc_t *sdesc)
{
	/*
	 * a task descriptor not associated with a perfmon context, simply destroy
	 */
	if (sdesc->ctxid != -1)
		task_collect_results(sdesc, 1);

	pfmon_sdesc_exit(sdesc);
}

static void
pfmon_setup_dlopen(pfmon_sdesc_t *sdesc)
{
	unsigned long brk_func;
	int ret = 0;

	brk_func = pfmon_get_dlopen_hook(sdesc);
	if (brk_func == 0) {
		vbprintf("[%d] dlopen hook not found (statically linked?)\n", sdesc->tid);
		return;
	}

	vbprintf("[%d] dlopen hook found @0x%lx\n", sdesc->tid, brk_func);

	/*
	 * append dlopen breakpoint to this list user defined breakpoints
	 */
	ret = sdesc->num_code_triggers;
	sdesc->code_triggers[ret].brk_address = brk_func;
	sdesc->code_triggers[ret].brk_type = PFMON_TRIGGER_DLOPEN;
	sdesc->code_triggers[ret].trg_attr_repeat = 1;
	sdesc->num_code_triggers++;
}

static int
task_handle_dlopen_trigger(pfmon_sdesc_t *sdesc, pfmon_trigger_t *trg)
{
	load_pid_map(sdesc, &options.primary_syms);
	return 0;
}

static int
task_handle_entry_trigger(pfmon_sdesc_t *sdesc, pfmon_trigger_t *trg)
{
	pid_t tid;
	static short int firsttask = 1;

	tid = sdesc->tid;
	/*
	 * we have reached the entry point breakpoint
	 * where there is now enough state to build a symbol table
	 * from /proc/pid/maps
	 *
	 * Once loaded, we can setup the code/data triggers passed
	 * by the user, and they can reference library symbols.
	 */
	if(sdesc->exec_count == 1 && firsttask == 1) {
		load_pid_syms(sdesc, tid, &options.primary_syms);
		firsttask = 0;
	} else {
                 load_pid_map(sdesc, &options.primary_syms);
//               if(sdesc->exec_count == 0)
//                       load_pid_syms(sdesc, sdesc->tid, &options.primary_syms);
//               else
//                       load_pid_map(sdesc, &options.primary_syms);
	}

	/*
	 * Clear dont_start flag before setup_strigger_addresses().
	 * It may be set again in the following setup_trigger_addresses()
	 * if start-trigger option is specified.
	 */
	options.opt_dont_start = 0;

	setup_trigger_addresses();

	/*
	 * side-effect: zero entry 0, i.e., the entry breakpoint
	 */
	memcpy(sdesc->code_triggers, options.code_triggers, sizeof(options.code_triggers));
	sdesc->num_code_triggers = options.num_code_triggers;

	/*
	 * install dlopen/dlclose breakpoint in sdesc->code_triggers[0]
	 * also correct sdesc->num_code_triggers
	 */
	pfmon_setup_dlopen(sdesc);

	memcpy(sdesc->data_triggers, options.data_triggers, sizeof(options.data_triggers));
	sdesc->num_data_triggers = options.num_data_triggers;

	if (options.opt_print_syms)
		print_syms(options.primary_syms);

	if (options.opt_dont_start == 0) {
		int error;
		sdesc->fl_has_entry = 0; /* done with entry breakpoint */
		pfmon_start(sdesc->ctxid, &error);
		vbprintf("[%d] activating monitoring\n", tid);
	}
	return 0;
}

static int
task_handle_start_trigger(pfmon_sdesc_t *sdesc, pfmon_trigger_t *trg)
{
	pfmon_trigger_t *stop_trg;
	unsigned long rp;
	pid_t tid;
	int error, ret;

	tid = sdesc->tid;
	/*
	 * check if start breakpoint triggers a dynamic return
	 * stop breakpoint
	 */
	if (trg->brk_stop_idx != -1) {
		pfmon_get_return_pointer(tid, &rp);

		/*
		 * get address of (to be completed) stop breakpoint
		 */
		stop_trg = sdesc->code_triggers+trg->brk_stop_idx;
		stop_trg->brk_address = rp;
		stop_trg->trg_attr_func = 1; /* is dyanmic stop */

		ret = pfmon_set_code_breakpoint(tid, stop_trg);
		if (ret) {
			warning("cannot set dynamic stop breakpoint\n");
			return 0;
		}
		vbprintf("[%d] installed dynamic stop code breakpoint(db%u) %d at %p\n", 
			tid, 
			trg->brk_stop_idx,
			stop_trg->brk_idx,
			stop_trg->brk_address);
	}
	pfmon_start(sdesc->ctxid, &error);
	vbprintf("[%d] activating monitoring at trigger start\n", tid);
	return 0;
}

static int
task_handle_stop_trigger(pfmon_sdesc_t *sdesc, pfmon_trigger_t *trg)
{
	pid_t tid;
	int error;

	tid = sdesc->tid;

	pfmon_stop(sdesc->ctxid, &error);
	vbprintf("[%d] stopping monitoring at trigger stop\n", tid);
	return 0;
}

static int (*trigger_actions[])(pfmon_sdesc_t *s, pfmon_trigger_t *t)={
	task_handle_entry_trigger,
	task_handle_start_trigger,
	task_handle_stop_trigger,
	task_handle_dlopen_trigger
};

static int
task_handle_trigger(pfmon_sdesc_t *sdesc)
{
	pfmon_trigger_t *trg;
	unsigned long addr;
	int is_repeat, is_data = 0;
	pfmon_trigger_t orig_trg;
	int type;
	pid_t tid;
	
	tid = sdesc->tid;
	
	/*
	 * used for SW breakpoints
	 */
	if (sdesc->last_code_trigger) {
		DPRINT(("reinstall brk after SW singlestep\n"));
		pfmon_set_code_breakpoint(tid, sdesc->last_code_trigger);
		sdesc->last_code_trigger = NULL;
		return  0;
	}

	pfmon_get_breakpoint_addr(tid, &addr, &is_data);

	if (is_data)
		trg = find_data_trigger(sdesc, addr);
	else
		trg = find_code_trigger(sdesc, addr);

	if (trg == NULL) {
		warning("task [%d] interrupted @%p for no reason\n", tid, addr);
		return 1; /* error and issue PTRACE_CONT */
	}

	is_repeat = trg->trg_attr_repeat;
	type      = trg->brk_type;
	orig_trg  = *trg;

	vbprintf("[%d] reached %-5s %s breakpoint @%p\n", 
		tid, 
		trigger_strs[type],
		is_data ? "data" : "code",
		addr);

	/*
	 * trigger may be modified by the call
	 */
	trigger_actions[type](sdesc, trg);

	/*
	 * check type of original breakpoint, some handler may reuse the
	 * slots, e.g., TRIGGER_ENTRY.
	 */
	if (is_repeat == 0) {
		vbprintf("[%d] clearing %s breakpoint(db%d) @%p\n", 
			tid, 
			is_data? "data" : "code", 
			orig_trg.brk_idx,
			orig_trg.brk_address);

		if (is_data)
			pfmon_clear_data_breakpoint(tid, &orig_trg);
		else
			pfmon_clear_code_breakpoint(tid, &orig_trg);
	}

	/*
 	 * install main triggers, must be done after clearing above
 	 * deferred form pfmon_handle_entry_trigger()
 	 */
	if (type == PFMON_TRIGGER_ENTRY) {
		install_code_triggers(sdesc);
		install_data_triggers(sdesc);
		pfmon_enable_all_breakpoints(tid);
	}

	/*
	 * dynamic stop breakpoint are systemtically cleared
	 */
	if (trg->trg_attr_func) {
		trg->brk_address = 0;
		trg->trg_attr_func = 0;
	}

	vbprintf("[%d] resume after %s breakpoint\n", tid, is_data ? "data" : "code");

	if (is_data)
		pfmon_resume_after_data_breakpoint(tid, &orig_trg);
	else {
		if (options.opt_hw_brk == 0)
			sdesc->last_code_trigger = trg;
		pfmon_resume_after_code_breakpoint(tid, &orig_trg);
	}
	return 0; /* needs pfmon_continue() */
}

/*
 * task must be stopped when calling
 */
static int
task_detach(pfmon_sdesc_t *sdesc)
{
	task_worker_msg_t msg;
	int was_dispatched = 0;
	pid_t pid;

	pid = sdesc->tid;


	vbprintf("detaching from [%d]\n", pid);
	if (sdesc->ctxid != -1) {
		
		if (sdesc->fl_dispatched) {
			msg.type = PFMON_TASK_MSG_REM_TASK;
			msg.data = sdesc;

			/* wait for ack */
			task_worker_send_msg(sdesc->cpu, &msg, 1);
			was_dispatched = 1;
		}
		task_collect_results(sdesc, 1);
		if (was_dispatched)
			pfmon_sdesc_exit(sdesc);
	}

	uninstall_code_triggers(sdesc);
	uninstall_data_triggers(sdesc);

	/* ensure everything is shutdown */
	pfmon_disable_all_breakpoints(sdesc->tid);

	vbprintf("detached from [%d]\n", pid);

	pfmon_detach(pid);

	pfmon_sdesc_exit(sdesc);

	return 0;
}

int tgkill(pid_t tgid, pid_t pid, int sig)
{
	return syscall(__NR_tgkill, tgid, pid, sig);
}

static void
task_force_exit(void)
{
	pfmon_sdesc_t *t;
	unsigned int i;
	long sig;
	int ret;

	for(i=0; i < PFMON_SDESC_PID_HASH_SIZE; i++) {
		t = sdesc_pid_hash[i];
		while (t) {
			if (t->fl_attached) {
				sig = SIGSTOP;
				t->fl_detaching = 1;
			} else {
				sig = SIGKILL;
			}

			ret = tgkill(t->pid, t->tid, sig);
			vbprintf("sending signal %d to [%d]\n",
				sig, t->tid, ret);
			t = t->next;
		}
	}
}

typedef struct _pfmon_task_chain {
	struct _pfmon_task_chain *next;
	pfmon_sdesc_t *sdesc;
} pfmon_task_chain_t;

// this points to the last item, the list is built backwards
pfmon_task_chain_t *task_chain = NULL;

static void
pfmon_task_chain_append(pfmon_sdesc_t *sdesc)
{
	pfmon_task_chain_t *task;

	if (sdesc == NULL)
		return;

	task = malloc(sizeof(pfmon_task_chain_t));
	task->sdesc = sdesc;
	task->next = task_chain;
	task_chain = task;
	DPRINT(("Adding sdesc to task chain: %d - %s (previously: %s)\n", sdesc->pid, sdesc->new_cmdline, sdesc->cmdline));
}

static void
pfmon_task_chain_free(void)
{
	pfmon_task_chain_t *task, *next;
	pfmon_task_chain_t *t2, *next2;
	
	for(task=task_chain; task; task = next) {
		next = task->next;
		/*
		 * find references to the same sdesc and null them so
		 * that they're not freed twice. This can happen on
		 * exec (--follow-exec) as we re-use we sdesc but
		 * symbols information is separate
		 */
		if(task->sdesc != NULL)
			for(t2=task; t2; t2=next2) {
				next2 = t2->next;
				if(t2->sdesc == task->sdesc)
					t2->sdesc = NULL;
			}
		pfmon_sdesc_free(task->sdesc);
		free(task);
	}
}

static void
pfmon_task_chain_print(void)
{
	pfmon_task_chain_t *task;

	vbprintf("Task chain registered for processing:\n");
	for(task=task_chain; task; task = task->next) {
		if(task->sdesc)
			vbprintf("        task %d (%s)\n", task->sdesc->pid, task->sdesc->new_cmdline);
		else
			vbprintf("NULL SDESC - this shouldn't happen!\n");
	}
}

static void
pfmon_task_chain_process(void)
{
	pfmon_task_chain_t *task;

	if(options.opt_addr2sym)
		pfmon_gather_module_symbols();

	pfmon_task_chain_print();

	for(task = task_chain; task; task = task->next) {
		if(task->sdesc) {
			if(options.opt_addr2sym) {
				if (options.smpl_mod->terminate_session)
					options.smpl_mod->terminate_session(task->sdesc);
			}
		}
	}

	for(task = task_chain; task; task = task->next)
		if(task->sdesc)
			if(options.opt_addr2sym && task->sdesc->csmpl.smpl_fp)
				fclose(task->sdesc->csmpl.smpl_fp);

	pfmon_task_chain_free();
}

static pid_t
task_handle_ptrace_event(pfmon_sdesc_t *sdesc, int event, char *msg, int cleanup, pfmon_ctx_t *ctx)
{
	unsigned long new_pid; /* must be long due to ptrace */
	pfmon_sdesc_t *new_sdesc;
	int r;

  	/* new pid is really new tid */
  	r = ptrace (PTRACE_GETEVENTMSG, sdesc->tid, NULL, (void *) &new_pid);
	if (r)
		return -1;

	if (cleanup)
		return new_pid;

  	vbprintf ("[%d] %s [%ld]\n", sdesc->tid, msg, new_pid);

	/*
	 * check if pid does not already exist due to the fact that fork event
	 * and child sigstop may come in any order.
	 *
	 * If found, then we need to update sdesc state with parent info,
	 * create the perfmon state and wakeup the task which remained
	 * stop since we got the SIGSTOP notification
	 */
      	new_sdesc = pfmon_sdesc_pid_hash_find (sdesc_pid_hash, new_pid);
	if (!new_sdesc) {
		new_sdesc = pfmon_sdesc_new(event, sdesc, new_pid);
		pfmon_task_chain_append (new_sdesc);
	} else {
		pfmon_sdesc_update(new_sdesc, event, sdesc);
		r = task_pfm_init(new_sdesc, 0 , ctx);
		if (r) {
			time_to_quit = 1;
			quit_reason  = QUIT_ERROR;
		} else {
			vbprintf("[%d] resuming\n", new_sdesc->tid);
			pfmon_continue(new_sdesc->tid, 0);
		}
	}
	return 0;
}

void changePinning()
{
	pfmon_sdesc_t *sdesc;
	pfmon_event_set_t *set;
	int i, j, myCore;
	uint64_t aggr_count, aggr_duration, avg_rate;
	cpu_set_t cpuMask;

	aggr_count = 0;
	aggr_duration = 0;
	
	int err, bestfound = 0;

	for (i = 1; i <= pinned_threads; i++)
	{
		sdesc = pfmon_sdesc_pid_hash_find(sdesc_pid_hash, tid_list[i]);
		for (set = sdesc->sets; set; set = set->next)
		for (j = 0; j < set->event_count; j++)
		{
			fprintf(stderr, "%ld: %d %llu %llu\n", (long) sdesc->tid, j, (long long unsigned int) set->last_duration, (long long unsigned int) set->last_values[j]);
			aggr_count += set->last_values[j];
			aggr_duration += set->last_duration;
		}
	}

	avg_rate = aggr_count / (aggr_duration / 1000000);
	if (avg_rate > max_rate)
	{
	max_rate = avg_rate;
	pin_config.best_config = pin_config.current_config;
	}
	fprintf(stderr, "max=%llu avg=%llu %d %d\n\n", (long long unsigned int) max_rate, (long long unsigned int) avg_rate, pin_config.current_config, pin_config.config_count - 1);

	if (pin_config.change_count < pin_config.config_count)
	{
		if (pin_config.current_config < pin_config.config_count - 1)
			pin_config.current_config++;
		else
		{
			fprintf(stderr, "All configurations have been probed, #%d was best\n", pin_config.best_config);
			pin_config.current_config = pin_config.best_config;
			bestfound = 1;
		}

		fprintf(stderr, "Rescheduling threads to configuration %d\n", pin_config.current_config);
		for (i = 1; i <= pinned_threads; i++)
		{
			sdesc = pfmon_sdesc_pid_hash_find(sdesc_pid_hash, tid_list[i]);
			myCore = pin_config.pinning[pin_config.current_config][i - 1];
			CPU_ZERO(&cpuMask);
			CPU_SET(myCore, &cpuMask);
			if (sched_setaffinity(sdesc->tid, sizeof(cpuMask), &cpuMask))
				fprintf(stderr, "  Error while pinning thread to Core #%d/%d\n", myCore, (int) options.online_cpus);
			else
				fprintf(stderr, "  Pinning thread to Core #%d/%d\n", myCore, (int) options.online_cpus);
		}
		pin_config.change_count++;
	}
	
	if (bestfound)
	{
		for (i=1; i<=(int) tid_list[0]; i++)
		{
			sdesc = pfmon_sdesc_pid_hash_find(sdesc_pid_hash, tid_list[i]);
			if ((err = tgkill(sdesc->pid, sdesc->tid, SIGKILL)))
				fprintf(stderr, "Error signaling %ld %ld: %s\n", (long) sdesc->pid, (long) sdesc->tid, strerror(err));
		}
	
	}
	
}

static int
task_mainloop(pfmon_ctx_t *ctx, char **argv)
{	
	pfmon_sdesc_t *sdesc;
	time_t start_time;
	unsigned long sig;
	struct rusage rusage;
	struct timeval tv;
	long new_pid; /* must be long */
	pid_t tid = -1;
	int status, event, wait_type, has_follow;
	int r, has_workers, needs_time, cleaning_up = 0;
	int i, err, alarm_count;

	has_workers = options.opt_use_smpl    ? 1 : 0;
	needs_time  = options.opt_show_rusage ? 1 : 0;

	sdesc = options.opt_attach == 0 ? task_create(argv) : task_attach(argv);
	if (sdesc == NULL) return -1;

	r = task_pfm_init(sdesc, 1, ctx);
	if (r) return -1; /* return 1, if task is interesting, 0 otherwise, -1 if error */

	time(&start_time);
	vbprintf("measurements started at %s\n", asctime(localtime(&start_time)));

	/* actually start the task */
	pfmon_continue(sdesc->tid, 0);

	if (options.session_timeout != PFMON_NO_TIMEOUT) {
	  alarm(options.init_time);
          alarm_count = 0;
	  fprintf(stderr, "Init-time=%d  Warmup=%d  Timeout=%d\n", options.init_time, options.warmup_time, options.session_timeout);
	}
	has_follow = options.opt_follow_fork || options.opt_follow_vfork || options.opt_follow_pthread;
	/*
 	 * WUNTRACED: PTtrace events
 	 * WNBOHANG : o not block, return -1 instead
 	 * __WALL   : return info about all threads
 	 */
	wait_type = WUNTRACED|WNOHANG|__WALL;

	work_todo = 1;
	alarmed = 0;

	for(;work_todo;) {

		unmask_global_signals();

		sem_wait(&master_work_sem);

		mask_global_signals();
retry:
		while (work_todo && (tid = wait4(-1, &status, wait_type, &rusage)) > 0) {

			if (needs_time) gettimeofday(&tv, NULL);

			sdesc = pfmon_sdesc_pid_hash_find(sdesc_pid_hash, tid);

			DPRINT(("tid=%d errno=%d exited=%d stopped=%d signaled=%d stopsig=%-2d "
					"ppid=%-6d ctxid=%-3d mon=%d att=%d det=%d quit=%d clean=%d cmd: %.16s\n",
					tid, errno, 
					WIFEXITED(status), 
					WIFSTOPPED(status), 
					WIFSIGNALED(status), 
					WSTOPSIG(status), 
					sdesc ? sdesc->ppid : -1,
					sdesc ? sdesc->ctxid: -1,
					sdesc ? sdesc->fl_monitoring: 0,
					sdesc ? sdesc->fl_attached: 0,
					sdesc ? sdesc->fl_detaching: 0,
					time_to_quit, cleaning_up,
					sdesc ? sdesc->cmdline : ""));

			if (sdesc == NULL) { 
				/*
				 * on new task creation 2 events are generated:
				 * - parent gets a PTRACE event
				 * - new task gets a SIGSTOP
				 * There is not guarantee on the order these events are received by pfmon.
				 * Thus we assume that if we get infos about a task we do not know, then it
				 * means, this is for a newly created task. So we create the sdesc but
				 * keep the task blocked until we get the PTRACE event.
				 */
				if (has_follow) {
					vbprintf("[%d] out-of-order creation, stopped\n", tid);
					sdesc = pfmon_sdesc_new(PFMON_SDESC_FORK, NULL, tid);
					pfmon_task_chain_append (sdesc);
					continue;
				} else {
					warning("unknown task [%d]\n", tid); 
					continue; 
				}
			}

			if (WIFEXITED(status) || WIFSIGNALED(status)) {
				struct timeval start;

				start = sdesc->tv_start;

				vbprintf("[%d] task exited\n", tid);
				if (has_workers)
					pfmon_sdesc_exit(sdesc);
				else
					task_pfm_exit(sdesc);

				if (needs_time) show_task_rusage(&start, &tv, &rusage);

				continue;
			}

			/* 
			 * task is stopped
			 */
			sig = WSTOPSIG(status);
			if (sig == SIGTRAP) {
				/*
				 * do not propagate the signal, it was for us
				 */
				sig = 0;

				/*
				 * extract event code from status (should be in some macro)
				 */
				event = status >> 16;
				switch(event) {
					case PTRACE_EVENT_FORK:
						new_pid = task_handle_ptrace_event(sdesc, PFMON_SDESC_FORK, "forked", cleaning_up, ctx);
						if (cleaning_up)
							pfmon_detach(new_pid);
						break;
					case PTRACE_EVENT_CLONE:
						new_pid = task_handle_ptrace_event(sdesc, PFMON_SDESC_CLONE, "cloned", cleaning_up, ctx);
						if (cleaning_up)
							pfmon_detach(new_pid);
						break;
					case PTRACE_EVENT_VFORK:
						new_pid = task_handle_ptrace_event(sdesc, PFMON_SDESC_VFORK, "vforked", cleaning_up, ctx);
						if (cleaning_up)
							pfmon_detach(new_pid);
						break;
					case PTRACE_EVENT_EXEC:
						pfmon_sdesc_exec(sdesc);
						vbprintf("[%d] exec %.64s...\n", sdesc->tid, sdesc->new_cmdline);

						if (cleaning_up)  break;
						r = task_pfm_init(sdesc, 1, ctx);
						if (r) {
							time_to_quit = 1;
							quit_reason  = QUIT_ERROR;
						}
						break;
					case  0:
						if (cleaning_up) break;

						r = task_handle_trigger(sdesc);
						/* we detached the task, no need for PTRACE_CONT */
						if (r == 1) continue;
						/* need a cont */
					default: 
						DPRINT((">>got unknown event %d\n", event));
						/*
						 * when a task is ptraced' and executes execve:
						 * 	- if PTRACE_O_TRACEEXEC is set, then we get PTRACE_EVENT_EXEC event
						 * 	- if PTRACE_O_TRACEEXEC is not set, then we just receive a SIGTRAP
						 */
						if (options.opt_follow_exec == 1) 
							printf("unknown ptrace event %d\n", event);
				}
			} else if (sig == SIGSTOP) {
				i = 1;
				while (i <= tid_list[0] && sdesc->tid != tid_list[i])
					i++;
				if (sdesc->tid == tid_list[i])
				{
					if (has_reported[i] == -1)
					{
						read_results(sdesc);
						has_reported[i] = 1;
						measured_threads++;
						if (measured_threads >= pinned_threads)
						{
							memset(has_reported, 0, MAX_CORES + 1);
							measured_threads = 0;
							if (options.session_timeout != PFMON_NO_TIMEOUT)
							{
								if (pin_config.change_count <= pin_config.config_count && alarm_count % 2)
									changePinning();
								if (pin_config.change_count <= pin_config.config_count && alarm_count % 2)
									alarm(options.warmup_time);
								else
									alarm(options.session_timeout);
								if (pin_config.change_count > pin_config.config_count)
								{
									changePinning();
									alarm(options.session_timeout);
								}
							}
							alarm_count++;
						}
					}
				}

				/* 
				 * cancel signal, it was for us
				 *
				 * XXX: it that always the case?
				 */
				sig = 0;

				/*
				 * we need to wait until a newly created task reaches the stopped
				 * state to ensure that perfmon will see the task actually stopped
				 * and not just cloned. We do get two events: fork/vfork/clone and
				 * the first STOPPED signal when the task reaches its first 
				 * notification point.
				 */
				if (sdesc->fl_detaching) {
					task_detach(sdesc);
					continue;
				}
				if (sdesc->fl_seen_stopsig == 0 && sdesc->fl_monitoring) {
					sdesc->fl_seen_stopsig = 1;
					r = task_pfm_init(sdesc, 0, ctx);
					if (r) {
						time_to_quit = 1;
						quit_reason  = QUIT_ERROR;
					}
				}
			} else {
				DPRINT(("forward signal %lu to [%d]\n", sig, tid));
			}
			pfmon_continue(tid, sig);
		}

		if (alarmed)
		{
			for (i = 1; i <= (int) tid_list[0]; i++)
			{
				sdesc = pfmon_sdesc_pid_hash_find(sdesc_pid_hash, tid_list[i]);
				if ((err = tgkill(sdesc->pid, sdesc->tid, SIGSTOP)))
					fprintf(stderr, "Error signaling %ld %ld: %s\n", (long) sdesc->pid, (long) sdesc->tid, strerror(err));
				has_reported[i] = -1;
			}
			alarmed = 0;
		}

		DPRINT(("tid=%d errno=%d time_to_quit=%d cleaning_up=%d todo=%d active=%lu\n", 
			tid, errno, time_to_quit, cleaning_up, work_todo,task_info.num_active_sdesc));
		/*
		 * we check for interruption only when we are done processing pending ptrace events
		 */
		if (time_to_quit && cleaning_up == 0) {
			pfmon_print_quit_reason(quit_reason);
			task_force_exit();
			cleaning_up  = 1;
			wait_type |= __WNOTHREAD|__WALL;
			goto retry;
		}
	}

	if (options.opt_aggr) {
		if(options.opt_addr2sym)
			pfmon_gather_module_symbols();
		print_results(&sdesc_task_aggr);
		if (options.opt_use_smpl)
			pfmon_close_aggr_sampling_output(&sdesc_task_aggr);
		munmap(sdesc->csmpl.smpl_hdr, sdesc->csmpl.map_size);
	} else {
		pfmon_task_chain_process();
	}

	vbprintf("created tasks        : %lu\n"
		 "maximum tasks        : %lu\n"
		 "maximum active tasks : %lu\n", 
		task_info.total_sdesc, 
		task_info.max_sdesc,
		task_info.max_active_sdesc);

	return 0;
}

static
void pfmon_thread_arg_destroy(void *data)
{
	if (data) free(data);
}

static void
exit_per_task(int i)
{
	if (gettid() == master_tid) exit(i);

	pthread_exit((void *)((unsigned long)i));
}

static void
pfmon_sdesc_fd_hash_add(pfmon_sdesc_t **hash, pfmon_sdesc_t *t)
{
	int slot = PFMON_SDESC_FD_HASH(t->ctxid);
	t->fd_next = hash[slot];
	hash[slot] = t;
}

static pfmon_sdesc_t *
pfmon_sdesc_fd_hash_find(pfmon_sdesc_t **hash, int fd)
{
	pfmon_sdesc_t *q;

	q = hash[PFMON_SDESC_FD_HASH(fd)];
	while (q) {
		if ((q)->ctxid == fd) return q;
		q = q->fd_next;
	}
	/* should not happen */
	return NULL;
}

static int
pfmon_sdesc_fd_hash_remove(pfmon_sdesc_t **hash, pfmon_sdesc_t *t)
{
	pfmon_sdesc_t *q, *prev = NULL;
	int slot = PFMON_SDESC_FD_HASH(t->ctxid);

	q = hash[slot];
	while (q) {
		if (q == t) goto found;
		prev = q;
		q = q->fd_next;
	}
	return -1;
found:
	if (prev)
		prev->fd_next = t->fd_next;
	else 
		hash[slot] = t->fd_next;
	return 0;
}

static void
task_worker_mainloop(void *data)
{
	task_worker_t *mywork = (task_worker_t *)data;
	fd_set master_fds, fds;
	pfmon_sdesc_t **myhash, *sdesc;
#ifdef __ia64__
	pfm_msg_t msg_old;
#endif
	pfarg_msg_t msg;
	size_t sz;
	task_worker_msg_t pfmon_msg;
	pid_t mytid;
	unsigned int mycpu;
	unsigned int myjobs = 0;
	int i, ret;
	int ctrl_fd;
	int max_fd;
	int ndesc, msg_type;

	/*
	 * POSIX threads: 
	 * The signal state of the new thread is initialised as follows:
    	 *    - the signal mask is inherited from the creating thread.
         *    - the set of signals pending for the new thread is empty.
	 *
	 * we want to let the master handle the global signals, therefore
	 * we mask them here.
	 */
	mask_global_signals();

	ctrl_fd = mywork->to_worker[0];
	mycpu   = mywork->cpu_id;
	mytid   = gettid();
	myhash  = mywork->fd_hash;

	/*
	 * some NPTL sanity checks
	 */
	if (mytid == master_tid) 
		fatal_error("pfmon is not compiled/linked with the correct pthread library,"
			"the program is linked with NPTL when it should not. Check Makefile.\n");

	pfmon_pin_self(mycpu);

	FD_ZERO(&master_fds);
	FD_SET(ctrl_fd, &master_fds);

	max_fd = ctrl_fd;

	DPRINT(("worker [%d] on CPU%u ctrl_fd=%d\n", mytid, mycpu, ctrl_fd));
	for(;;) {
		memcpy(&fds, &master_fds, sizeof(fds));

		ndesc = select(max_fd+1, &fds, NULL, NULL, NULL);
		if (ndesc == -1) {
			if (errno == EINTR) continue;
			fatal_error("select returned %d\n", errno);
		}

		DPRINT(("worker on CPU%u max_fd=%d select=%d ctrl_fd=%d\n", mycpu, max_fd, ndesc, ctrl_fd));

		for(i=0; ndesc; i++) {

			if (FD_ISSET(i, &fds) == 0) continue;

			DPRINT(("worker on CPU%u activity on fd=%d\n", mycpu, i));

			ndesc--;

			if (i != ctrl_fd) {
				sdesc = pfmon_sdesc_fd_hash_find(myhash, i);
				if (sdesc == NULL) 
					fatal_error("wCPU%u cannot find context for fd=%d\n", mycpu, i);

#ifdef __ia64__
				if (!options.opt_is22) {
					ret = read(i, &msg_old, sizeof(msg_old));
					sz = sizeof(msg_old);
					msg_type = msg_old.type;
				} else
#endif
 				{
					ret = read(i, &msg, sizeof(msg));
					sz = sizeof(msg);
					msg_type = msg.type;
				}

				if (ret != sz) {
					warning("[%d] error reading on %d: ret=%d msg=%p errno=%s\n", mytid, i, ret, &msg, strerror(errno));
					continue;
				}
				if (msg_type == PFM_MSG_OVFL) {
					pfmon_process_smpl_buf(sdesc, 0);
					continue;
				}

				if (msg_type != PFM_MSG_END) 
					fatal_error("wCPU%u unknown message type %d\n", mycpu, msg_type);

				/*
				 * remove from fd hash table
				 */
				pfmon_sdesc_fd_hash_remove(myhash, sdesc);

				/*
				 * remove from list of descriptors of interest
				 */
				FD_CLR(sdesc->ctxid, &master_fds);

				/* XXX: approximation */
				if (sdesc->ctxid == max_fd) max_fd--;

				myjobs--;

				DPRINT(("wCPU%u end_msg ctxid=%d tid=%d\n",
					mycpu,
					sdesc->ctxid,
					sdesc->tid));

				task_pfm_exit(sdesc);

				continue;
			} 

			ret = read(ctrl_fd, &pfmon_msg, sizeof(pfmon_msg));
			if (ret != sizeof(pfmon_msg)) {
				warning("error reading ctrl_fd(%d) on CPU%u: ret=%d errno=%d\n", ctrl_fd, mycpu, ret, errno);
				continue;
			}

			sdesc = (pfmon_sdesc_t *)pfmon_msg.data;

			switch(pfmon_msg.type) {

				case PFMON_TASK_MSG_ADD_TASK:
					myjobs++;
					DPRINT(("wCPU%u managing [tid=%d:fd=%d] jobs=%u\n", mycpu, sdesc->tid, sdesc->ctxid, myjobs));

					FD_SET(sdesc->ctxid, &master_fds);
					pfmon_sdesc_fd_hash_add(myhash, sdesc);

					if (sdesc->ctxid > max_fd) max_fd = sdesc->ctxid;
					break;

				case PFMON_TASK_MSG_REM_TASK:
					myjobs--;
					vbprintf("wCPU%u removing [%d:%d]\n", mycpu, sdesc->tid, sdesc->ctxid);

					FD_CLR(sdesc->ctxid, &master_fds);
					pfmon_sdesc_fd_hash_remove(myhash, sdesc);

					/* XXX: approximation */
					if (sdesc->ctxid == max_fd) max_fd--;

					/*
					 * ack the removal
					 */
					ret = write(workers[mycpu].from_worker[1], &msg, sizeof(msg));
					if (ret != sizeof(msg))
						warning("cannot ack remove task message\n");
					break;

				case PFMON_TASK_MSG_QUIT:
				default:
					warning("wCPU%u unexpected message %d, size=%d\n", mycpu, pfmon_msg.type, ret);
			}
		}
	}
}

static void
task_create_workers(void)
{
	int i, j, ncpus = 0;
	int nfiles;
	unsigned long fd_hash_size, fd_hash_entries;
	pfmon_sdesc_t *hash_current;
	unsigned long last_bit;
	int ret;

	/*
	 * compute number of accessible CPUs
	 */
	for(i=0, j=0; i < options.online_cpus; i++) {
		if (pfmon_bitmask_isset(options.phys_cpu_mask, i)) ncpus++;
	}

	nfiles = sysconf(_SC_OPEN_MAX);

	fd_hash_entries = nfiles / ncpus;

	last_bit = find_last_bit_set(fd_hash_entries);

	if (fd_hash_entries & ((1UL << last_bit)-1)) last_bit++;

	DPRINT(("ncpus=%lu nfiles=%lu last_bit=%lu (entries=%lu)\n", ncpus, nfiles, last_bit, 1UL<<last_bit));

	fd_hash_entries = 1UL<<last_bit;
	fd_hash_size    = fd_hash_entries * sizeof(pfmon_sdesc_t *);

	workers = (task_worker_t *)malloc(ncpus* (fd_hash_size+sizeof(task_worker_t)));
	if (workers == NULL) fatal_error("cannot allocate worker table\n");

	hash_current = (pfmon_sdesc_t *)(workers+ncpus);

	for (i=0, j=0; i < options.online_cpus; i++) {

		if (pfmon_bitmask_isset(options.phys_cpu_mask, i) == 0) continue;

		workers[j].cpu_id = i;

		if (pipe(workers[j].to_worker) == -1 || pipe(workers[j].from_worker) == -1)
			fatal_error("cannot create control channels for worker for CPU%d\n", i);

		ret = pthread_create(&workers[j].thread_id, NULL, (void *(*)(void *))task_worker_mainloop, workers+j);
		if (ret != 0) 
			fatal_error("cannot create worker thread for CPU%u\n", i);

		hash_current += fd_hash_entries;
		j++;
	}
}

static int
pfmon_task_init(void)
{
	master_tid = gettid();

	sem_init(&master_work_sem, 0, 0);

	if (options.opt_aggr) {
		pfmon_clone_sets(options.sets, &sdesc_task_aggr);
		if (pfmon_setup_aggr_sampling_output(&sdesc_task_aggr) == -1) return -1;
	}

	if (options.opt_use_smpl) task_create_workers();

	/*
	 * create thread argument key
	 */
	pthread_key_create(&arg_key, pfmon_thread_arg_destroy);

	register_exit_function(exit_per_task);

	setup_global_signals();

	/*
	 * compile regex once and for all
	 */
	if (options.fexec_pattern) {
		if (regcomp(&follow_exec_preg, options.fexec_pattern, REG_ICASE|REG_NOSUB)) {
			warning("error in regular expression for event \"%s\"\n", options.fexec_pattern);
			return -1;
		}
	}
	vbprintf("exec-pattern=%s\n", options.fexec_pattern ? options.fexec_pattern : "*");
	return 0;
}

static void
task_cleanup(void)
{
	register_exit_function(NULL);
}

int
measure_task(pfmon_ctx_t *ctx, char **argv)
{
	int ret;
	time_t end_time;

	ret = pfmon_task_init();
	if (ret) return ret;

	ret = task_mainloop(ctx, argv);
	if (ret == 0) {
		time(&end_time);
		vbprintf("measurements completed at %s\n", asctime(localtime(&end_time)));
	}
	task_cleanup();

	return ret;
}
