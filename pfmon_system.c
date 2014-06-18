/*
 * pfmon_system.c : handles per-cpu measurements
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
#include "pfmon.h"

#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/mman.h>

/*
 * argument passed to each worker thread
 * pointer arguments are ALL read-only as they are shared
 * between all threads. To make modification, we need to make a copy first.
 */
typedef enum {
	THREAD_STARTED,
	THREAD_RUN,
	THREAD_DONE,
	THREAD_ERROR
} thread_state_t;

typedef struct {
	unsigned int 	   id;		/* logical thread identification */
	unsigned int 	   cpu;		/* which CPU to pin it on */

	pfmon_ctx_t	   *ctx;	/* generic context description */

	pthread_t	   thread_id;	/* pthread id */
	thread_state_t	   thread_state;
} pfmon_thread_desc_t;

typedef enum {
	SESSION_INIT,
	SESSION_RUN,
	SESSION_STOP,
	SESSION_ABORTED
} session_state_t;

/*
 * create a structure to ensure barrier is padded to cacheline
 * size to avoid problems with other global variables
 */
#define BARRIER_PAD (64-sizeof(pthread_barrier_t))
typedef struct {
	pthread_barrier_t barrier;
	char		  pad[BARRIER_PAD];
} syswide_barrier_t;

static syswide_barrier_t	barrier __attribute__((aligned(64)));
static session_state_t		session_state;
static pfmon_quit_reason_t	quit_reason;

static pthread_mutex_t 		pfmon_sys_aggr_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_key_t   		param_key;

static pfmon_thread_desc_t	thread_desc[PFMON_MAX_CPUS];
static uint64_t			ovfl_cnts[PFMON_MAX_CPUS];
static pfmon_sdesc_t		sdesc_sys_aggr;
static pthread_t		master_thread_id;
static pid_t			master_tid;

static void
syswide_aggregate_results(pfmon_sdesc_t *sdesc)
{
	pfmon_event_set_t *set_aggr, *set;
	unsigned int i, count;
	
	for (set_aggr = sdesc_sys_aggr.sets,
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

static int 
pfmon_sys_setup_context(pfmon_sdesc_t *sdesc, unsigned int cpu, pfmon_ctx_t *ctx)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	pfmon_ctxid_t id;
	int error;

	/*
	 * XXX: cache lines sharing for master list
	 */
	pfmon_clone_sets(options.sets, sdesc);

	memset(csmpl, 0, sizeof(pfmon_smpl_desc_t));

	csmpl->cpu = cpu;
	if (pfmon_create_context(ctx, &csmpl->smpl_hdr, &sdesc->ctxid, &error) == -1) {
		warning("cannot create perfmon context: %s\n", strerror(error));
		return -1;
	}

	id = sdesc->ctxid;

	DPRINT(("CPU%u handles fd=%d\n", cpu, id));

	/*
	 * XXX: need to add FD_CLOEXEC. however there seems to be a bug either in libc
	 * or in the kernel whereby if FD_CLOEXEC is set, then if we fork/exec an external
	 * command, we lose the SIGIO notification signal. So for now, we leak the file
	 * the contexts file descriptors to the command being run.
	 *
	 * Moving the FD_CLOEXEC in the child process before the actual execvp() fixes the problem.
	 * However, the context file descriptors are not easily acessible from there.
	 */

	if (open_results(sdesc) == -1) return -1;

	if (options.opt_use_smpl) {
		if (pfmon_setup_sampling_output(sdesc, &sdesc_sys_aggr) == -1) return -1;
		DPRINT(("-->sampling buffer at %p aggr_count=%p data=%p\n", csmpl->smpl_hdr, csmpl->aggr_count, csmpl->data));
		sdesc->csmpl.map_size = ctx->ctx_map_size;
	}

	install_event_sets(sdesc);

	if (pfmon_load_context(sdesc->ctxid, cpu, &error) == -1) {
		if (error == EBUSY)
			warning("CPU%u error conflicting monitoring session\n", cpu);
		else
			warning("CPU%u cannot load context: %s\n", cpu, strerror(error));
		return -1;
	}

	return 0;
}

static void
setup_worker_signals(void)
{
        sigset_t my_set;

	/*
	 * workers have all the signals handled by the master blocked
	 * such that they are never called for them.
	 */
        sigemptyset(&my_set);
        sigaddset(&my_set, SIGINT);
        sigaddset(&my_set, SIGCHLD);
        sigaddset(&my_set, SIGALRM);
        pthread_sigmask(SIG_BLOCK, &my_set, NULL);
	
	/*
	 * POSIX: blocked signal mask is inherited from 
	 * parent thread. The master thread has SIGUSR1 blocked
	 * therefore we must reenable it.
	 */
	sigemptyset(&my_set);
        sigaddset(&my_set, SIGUSR1);
        pthread_sigmask(SIG_UNBLOCK, &my_set, NULL);

}

static int
do_measure_one_cpu(void *data)
{
	pfmon_thread_desc_t *arg = (pfmon_thread_desc_t *)data;
	pfmon_sdesc_t sdesc_var; /* local pfmon task descriptor */
	pfmon_sdesc_t *sdesc = &sdesc_var; 
	pfmon_ctxid_t ctxid = -1;
	pid_t mytid = gettid();
	unsigned int mycpu;
	int aggr, needs_order;
	int r, error;

	/*
	 * POSIX threads: 
	 * The signal state of the new thread is initialised as follows:
    	 *    - the signal mask is inherited from the creating thread.
         *    - the set of signals pending for the new thread is empty.
	 *
	 * we want to let the master handle the global signals, therefore
	 * we mask them here.
	 */
	setup_worker_signals();

	mycpu       = arg->cpu;
	aggr        = options.opt_aggr;

	/*
	 * some NPTL sanity checks
	 */
	if (mytid == master_tid) {
		warning("pfmon is not compiled/linked with the correct pthread library,"
			"the program is linked with NPTL when it should not."
			"Check Makefile."
			"[pid=%d:tid=%d]\n", getpid(), mytid);
		goto error;
	}

	/*
	 * we initialize our "simplified" sdesc
	 */
	memset(sdesc, 0, sizeof(*sdesc));
	/*
	 * just to make sure we have these fields initialized
	 */
	sdesc->type =  PFMON_SDESC_ATTACH;
	sdesc->tid  = mytid;
	sdesc->pid  = getpid();
	sdesc->cpu  = mycpu;
	sdesc->id   = arg->id; /* logical id */

	DPRINT(("CPU%u: pid=%d tid=%d\n", mycpu, sdesc->pid, sdesc->tid));

	pthread_setspecific(param_key, arg);

	if (options.online_cpus > 1) {

		r = pfmon_pin_self(mycpu);
		if (r == -1) {
			warning("[%d] cannot set affinity to CPU%u: %s\n", mytid, mycpu, strerror(errno));
			goto error;
		}
	}

	r = pfmon_sys_setup_context(sdesc, arg->cpu, arg->ctx);
	if (r)
		goto error;

	ctxid       = sdesc->ctxid;
	needs_order = aggr || sdesc->out_fp == stdout;

	DPRINT(("sdesc->id=%u needs_order=%d\n", sdesc->id, needs_order));

	/*
	 * indicate we have reach the starting point
	 */
	arg->thread_state = THREAD_RUN;

	if (session_state == SESSION_ABORTED)
		goto error;

	/*
	 * wait for the start signal
	 */
	pthread_barrier_wait(&barrier.barrier);

	DPRINT(("CPU%u after barrier state=%d\n", mycpu, session_state));

	if (session_state == SESSION_ABORTED) goto error;

	if (options.opt_dont_start == 0) {
		if (pfmon_start(ctxid, &error) == -1)
			goto error;
		vbprintf("CPU%u started monitoring\n", mycpu);
	} else {
		vbprintf("CPU%u pfmon does not start session\n", mycpu);
	}

	/*
	 * interval is not possible when sampling
	 */
	if (options.interval != PFMON_NO_TIMEOUT) {
		struct timespec tm;

		tm.tv_sec = options.interval / 1000;
		tm.tv_nsec = (options.interval % 1000) * 1000000;

		for(;session_state == SESSION_RUN; ) {

			nanosleep(&tm, NULL);

			/*
			 * we only check on stop to avoid printing too many messages
			 */
			if (pfmon_stop(ctxid, &error) == -1)
				warning("CPU%u could not stop monitoring, CPU may be offline, check results\n", mycpu);

			read_incremental_results(sdesc);
			show_incr_results(sdesc, needs_order);

			pfmon_start(ctxid, &error);
		}
		pthread_testcancel();
	} else {
		if (options.opt_use_smpl) {
			for(;session_state == SESSION_RUN;) {
				pfarg_msg_t msg;

				r = read(sdesc->ctxid, &msg, sizeof(msg));
				if (r ==-1) {
					/*
					 * we have been interrupted by signal (likely),
					 * go check session_state
					 */
					continue;
				}

				ovfl_cnts[mycpu]++;

				pthread_testcancel();

				if (aggr) pthread_mutex_lock(&pfmon_sys_aggr_lock);

				r = pfmon_process_smpl_buf(sdesc, 0);
				if (r)
					vbprintf("CPU%-4u error processing buffer\n", mycpu);

				if (aggr) pthread_mutex_unlock(&pfmon_sys_aggr_lock);

				pthread_testcancel();
			}
		} else {
			sigset_t myset;
			int sig;

        		sigemptyset(&myset);
        		sigaddset(&myset, SIGUSR1);
			for(;session_state == SESSION_RUN;) {
				sigwait(&myset, &sig);
			}
		}
	}

	if (pfmon_stop(ctxid, &error) == -1)
		warning("CPU%u could not stop monitoring, CPU may be offline, check results\n", mycpu);

	vbprintf("CPU%-4u stopped monitoring\n", mycpu);
	/*
	 * read the final counts
	 */
	if (options.opt_use_smpl == 0 || options.opt_smpl_print_counts) {
		if (read_results(sdesc) == -1) {
			warning("CPU%u read_results error\n", mycpu);
			goto error;
		}
	}
	DPRINT(("CPU%u has read PMDS\n", mycpu));

	/* 
	 * dump results 
	 */
	if (options.opt_aggr) {
		pthread_mutex_lock(&pfmon_sys_aggr_lock);

		syswide_aggregate_results(sdesc);

		if (options.opt_use_smpl)
			pfmon_process_smpl_buf(sdesc, 1);

		pthread_mutex_unlock(&pfmon_sys_aggr_lock);

	} else {
		if (options.opt_use_smpl)
			pfmon_process_smpl_buf(sdesc, 1);
			
		/*
		 * no final totals in interval printing mode
		 */
		if (options.interval == PFMON_NO_TIMEOUT)
			show_results(sdesc, needs_order);

		close_results(sdesc);
	}

	if (options.opt_use_smpl) {
		if (options.opt_aggr == 0)
			pfmon_close_sampling_output(sdesc, -1, mycpu);
		munmap(sdesc->csmpl.smpl_hdr, sdesc->csmpl.map_size);
	}
	close(sdesc->ctxid);

	arg->thread_state = THREAD_DONE;

	DPRINT(("CPU%u is done\n", mycpu));

	pthread_exit((void *)(0));
	/* NO RETURN */
error:
	if (sdesc->ctxid > -1)
		close(sdesc->ctxid);

	arg->thread_state = THREAD_ERROR;

	vbprintf("CPU%-4u session aborted\n", mycpu);

	if (options.opt_use_smpl) {
		if (options.opt_aggr == 0)
			pfmon_close_sampling_output(sdesc, -1, mycpu);
		munmap(sdesc->csmpl.smpl_hdr, sdesc->csmpl.map_size);
	}

	pthread_exit((void *)(~0UL));
	/* NO RETURN */
}

/*
 * only called by the master thread
 */
static void
syswide_sigalarm_handler(int n, siginfo_t *info, void *sc)
{
	if (pthread_equal(pthread_self(), master_thread_id) == 0) {
		warning("SIGALRM not handled by master thread master\n");
		return;
	}
	if (quit_reason == QUIT_NONE)
		quit_reason = QUIT_TIMEOUT;
}

static void
syswide_sigterm_handler(int n, siginfo_t *info, void *sc)
{
	if (pthread_equal(pthread_self(), master_thread_id) == 0) {
		warning("SIGTERM not handled by master thread master\n");
		return;
	}
	if (quit_reason == QUIT_NONE)
		quit_reason = QUIT_TERM;
}

/*
 * only called by the master thread
 */
static void
syswide_sigint_handler(int n, siginfo_t *info, void *sc)
{
	DPRINT(("sigint handler by %d master=%d\n", gettid(), master_tid));

	if (pthread_equal(pthread_self(), master_thread_id) == 0) {
		warning("SIGINT not handled by master thread master\n");
		return;
	}
	if (quit_reason == QUIT_NONE)
		quit_reason = QUIT_ABORT;
}

/*
 * only called by the master thread
 */
static void
syswide_sigchild_handler(int n, siginfo_t *info, void *sc)
{
	if (pthread_equal(pthread_self(), master_thread_id) == 0) {
		warning("SIGCHLD not handled by master thread master\n");
		return;
	}
	/*
	 * We are only interested in SIGCHLD indicating that the process is
	 * dead
	 */
	if (info->si_code != CLD_EXITED && info->si_code != CLD_KILLED) return;

	/*
	 * if we have a session timeout+child, then we are not using sleep
	 * therefore it is safe to clear the alarm.
	 */
	if (options.session_timeout != PFMON_NO_TIMEOUT || options.trigger_delay)
		alarm(0);

	if (quit_reason == QUIT_NONE)
		quit_reason = QUIT_CHILD;
}

/*
 * must be executed by worker on each CPU and never by master thread
 * do not know which worker thread will execute the handler but this is
 * fine because all we care about is that the thread is interrupted 
 * from any blocking system calls it might have been into so that it
 * can go back to mainloop and check session_state
 */
static void
syswide_sigusr1_handler(int n, siginfo_t *info, void *sc)
{
	/* nothing to do */
}

static void
setup_global_signals(void)
{
	struct sigaction act;
	sigset_t my_set;

	/*
	 * SIGALRM, SIGINT, SIGCHILD are all asynchronous signals
	 * sent to the process (not a specific thread). POSIX states
	 * that one and only one thread will execute the handler. This
	 * could be any thread that does not have the signal blocked.
	 *
	 * For us, SIGALARM, SIGINT, and SIGCHILD, SIGTERM are only handled
	 * by the master thread. Therefore all the per-CPU worker threads
	 * MUST have those signals blocked.
	 *
	 * Conversly, SIGUSR1 must be delivered to the worker threads.
	 * We cannot control which of the worker thread will get the
	 * signal. 
	 */

	/*
	 * install SIGALRM handler
	 */
	memset(&act,0,sizeof(act));

	sigemptyset(&my_set);
	sigaddset(&my_set, SIGCHLD);
	sigaddset(&my_set, SIGINT);
	sigaddset(&my_set, SIGTERM);

	act.sa_mask    = my_set;
	act.sa_flags   = SA_SIGINFO;
	act.sa_handler = (sig_t)syswide_sigalarm_handler;

	sigaction (SIGALRM, &act, 0);
	
	/* 
	 * install SIGCHLD handler
	 */
	memset(&act,0,sizeof(act));

	sigemptyset(&my_set);
	sigaddset(&my_set, SIGALRM);
	sigaddset(&my_set, SIGINT);
	sigaddset(&my_set, SIGTERM);

	act.sa_mask    = my_set;
	act.sa_flags   = SA_SIGINFO;
	act.sa_handler = (__sighandler_t)syswide_sigchild_handler;

	sigaction (SIGCHLD, &act, 0);

	/*
	 * install SIGINT handler
	 */
	memset(&act,0,sizeof(act));

	sigemptyset(&my_set);
	sigaddset(&my_set, SIGCHLD);
	sigaddset(&my_set, SIGALRM);
	sigaddset(&my_set, SIGTERM);

	act.sa_mask    = my_set;
	act.sa_flags   = SA_SIGINFO;
	act.sa_handler = (__sighandler_t)syswide_sigint_handler;

	sigaction (SIGINT, &act, 0);

	/*
	 * install SIGTERM handler
	 */
	memset(&act,0,sizeof(act));

	sigemptyset(&my_set);
	sigaddset(&my_set, SIGCHLD);
	sigaddset(&my_set, SIGALRM);
	sigaddset(&my_set, SIGINT);

	act.sa_mask    = my_set;
	act.sa_flags   = SA_SIGINFO;
	act.sa_handler = (__sighandler_t)syswide_sigterm_handler;

	sigaction (SIGTERM, &act, 0);


	/*
	 * install global SIGUSR1 handler (termination signal)
	 * used by worker thread only,
	 * no need to have other signals 
	 * masked during handler execution because
	 * they are completely masked for the thread.
	 */
	memset(&act,0,sizeof(act));
	act.sa_handler = (__sighandler_t)syswide_sigusr1_handler;
	sigaction (SIGUSR1, &act, 0);

	/*
	 * master thread does not handle SIGUSR1
	 * (inherited in sub threads)
	 */
        sigemptyset(&my_set);
        sigaddset(&my_set, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &my_set, NULL);
}

static void
exit_system_wide(int i)
{
	pfmon_thread_desc_t *arg = (pfmon_thread_desc_t *)pthread_getspecific(param_key);

	DPRINT(("thread on CPU%-3u aborting\n", arg->cpu));

	arg->thread_state = THREAD_ERROR;
	pthread_exit((void *)((unsigned long)i));
}



static int
delay_start(void)
{
	unsigned int left_over;

	vbprintf("delaying start for %u seconds\n", options.trigger_delay);

	/*
	 * if aborted by some signal (SIGINT or SIGCHILD), then left_over
	 * is not 0
	 */
	left_over = sleep(options.trigger_delay);

	DPRINT(("delay_start: left_over=%u\n", left_over));

	return left_over ? -1 : 0;
}

static int
delimit_session(char **argv)
{
	struct timeval time_start, time_end;
	time_t the_time;
	struct rusage ru;
	unsigned left_over;
	pid_t pid;
	int status;
	int ret = 0;

	/*
	 * take care of the easy case first: no command to start
	 */
	if (argv == NULL || *argv == NULL) {

		if (options.trigger_delay && delay_start() == -1)
			return -1;

		/*
		 * this will start the session in each "worker" thread
		 */
		pthread_barrier_wait(&barrier.barrier);

		time(&the_time);
		vbprintf("measurements started on %s\n", asctime(localtime(&the_time)));

		the_time = 0;

		if (options.session_timeout != PFMON_NO_TIMEOUT) {
			printf("<session to end in %u seconds>\n", options.session_timeout);

			left_over = sleep(options.session_timeout);
			if (left_over)
				pfmon_print_quit_reason(quit_reason);
			else
				time(&the_time);
		} else {
			printf("<press ENTER to stop session>\n");

			ret = getchar();
			if (ret == EOF) 
				pfmon_print_quit_reason(quit_reason);
			else
				time(&the_time);
		}
		if (the_time) vbprintf("measurements completed at %s\n", asctime(localtime(&the_time)));

		return 0;
	}
	gettimeofday(&time_start, NULL);

	/*
	 * we fork+exec the command to run during our system wide monitoring
	 * session. When the command ends, we stop the session and print
	 * the results.
	 */
	if ((pid=fork()) == -1) {
		warning("Cannot fork new process\n");
		return -1;
	}

	if (pid == 0) {		 
		pid = getpid();

		if (options.opt_verbose) {
			char **p = argv;
			vbprintf("starting process [%d]: ", pid);
			while (*p) vbprintf("%s ", *p++);
			vbprintf("\n");
		}
		if (options.opt_pin_cmd) {
			vbprintf("applied cpu-list for %s\n", *argv);
			if (pfmon_set_affinity(pid,  options.virt_cpu_mask)) {
				warning("could not pin %s to cpu-list\n");
			}
		}
		/*
		 * The use of ptrace() allows us to actually start monitoring after the exec()
		 * is done, i.e., when the new program is ready to go back to user mode for the
		 * "first time". With this technique, we can actually activate the workers
		 * only when the process is ready to execute. Hence, we can capture even
		 * the short lived workloads without measuring the overhead caused by fork/exec.
		 * We will capture the overhead of the PTRACE_DETACH, though.
		 */
		if (options.trigger_delay == 0) {
			if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
				warning("cannot ptrace me: %s\n", strerror(errno));
				exit(1);
			}
		}
		if (options.opt_cmd_no_verbose) {
			dup2 (open("/dev/null", O_WRONLY), 1);
			dup2 (open("/dev/null", O_WRONLY), 2);
		}	

		execvp(argv[0], argv);

		warning("child: cannot exec %s: %s\n", argv[0], strerror(errno));
		exit(-1);
	} 

	if (options.trigger_delay) {
		if (delay_start() == -1) {
			warning("process %d terminated before session was activated, nothing measured\n", pid);
			return -1;
		}
	} else {
		vbprintf("waiting for [%d] to exec\n", pid);
		/* 
	 	 * wait for the child to exec 
	 	 */
		waitpid(pid, &status, WUNTRACED);
	}

	/*
	 * this will start the session in each "worker" thread
	 *
	 */
	pthread_barrier_wait(&barrier.barrier);

	/*
	 * let the task run free now
	 */
	if (options.trigger_delay == 0)	ptrace(PTRACE_DETACH, pid, NULL, NULL);

	ret = wait4(pid, &status, 0, &ru);

	gettimeofday(&time_end, NULL);

	if (ret == -1) {
		if (errno == EINTR) { 
			pfmon_print_quit_reason(quit_reason);
			ret = 0;  /* will cause the session to print results so far */
		} else {
			vbprintf("unexpected wait() error for [%d]: %s\n", pid, strerror(errno));
		}
	} else {
		if (WEXITSTATUS(status) != 0) {
			warning("process %d exited with non zero value (%d): results may be incorrect\n", 
				pid, WEXITSTATUS(status));
		}
		if (options.opt_show_rusage) show_task_rusage(&time_start, &time_end, &ru);
	}
	return ret;
}

int
measure_system_wide(pfmon_ctx_t *ctx, char **argv)
{
	void *retval;
	unsigned long i, j, num_cpus;
	int ret;

	master_tid       = gettid();
	master_thread_id = pthread_self();

printf("sizeof=%zu %zu\n", sizeof(syswide_barrier_t), sizeof(barrier.pad));

	setup_global_signals();

	if (options.opt_aggr) {
		/*
		 * used by syswide_aggregate_results()
		 */
		pfmon_clone_sets(options.sets, &sdesc_sys_aggr);

		if (pfmon_setup_aggr_sampling_output(&sdesc_sys_aggr) == -1) 
			return -1;
	}

	session_state = SESSION_INIT;

	num_cpus = options.selected_cpus;

	vbprintf("system wide session on %lu processor(s)\n", num_cpus);

	pthread_barrier_init(&barrier.barrier, NULL, num_cpus+1);

	pthread_key_create(&param_key, NULL);

	register_exit_function(exit_system_wide);

	for(i=0, j=0; num_cpus; i++) {
		
		if (pfmon_bitmask_isset(options.virt_cpu_mask, i) == 0) continue;

		thread_desc[j].id    = j;
		thread_desc[j].cpu   = i;

		thread_desc[j].thread_state = THREAD_STARTED;
		thread_desc[j].ctx   = ctx;

		ret = pthread_create(&thread_desc[j].thread_id, 
				     NULL, 
				     (void *(*)(void *))do_measure_one_cpu, 
				     thread_desc+j);

		if (ret != 0) goto abort;

		DPRINT(("created thread[%u], %d\n", j, thread_desc[j].thread_id));

		num_cpus--;
		j++;
	}

	/* reload number of cpus */
	num_cpus = options.selected_cpus;

	for (j=0; j < num_cpus;) {
		DPRINT(("nthread_ok=%d ncpus=%d\n", j, num_cpus));
		/*
		 * poll thread state for errors
		 */
		for(i=0, j=0; i < num_cpus; i++) {
			if (thread_desc[i].thread_state == THREAD_ERROR)
				goto abort;
			if (thread_desc[i].thread_state == THREAD_RUN)
				j++;
		}
	}
	session_state = SESSION_RUN;

	if (delimit_session(argv) == -1) goto abort;

	/*
	 * set end of session and unblock all threads
	 */
	session_state = SESSION_STOP;

	/*
	 * get worker thread out of their mainloop
	 */
	for (i=0; i < num_cpus; i++) {
		if (thread_desc[i].thread_state != THREAD_ERROR)
			pthread_kill(thread_desc[i].thread_id, SIGUSR1);
	}

	DPRINT(("main thread after session stop\n"));

	for(i=0; i< num_cpus; i++) {
		ret = pthread_join(thread_desc[i].thread_id, &retval);
		if (ret !=0) warning("cannot join thread %u\n", i);
		DPRINT(("CPU%-4u session exited with value %ld\n", thread_desc[i].cpu, (unsigned long)retval));
	}

	if (options.opt_aggr) {
		print_results(&sdesc_sys_aggr); /* mask taken from options.virt_cpu_mask */
		if (options.opt_use_smpl)
			pfmon_close_aggr_sampling_output(&sdesc_sys_aggr);
	}

	pthread_key_delete(param_key);

	register_exit_function(NULL);

	if (options.opt_verbose && options.opt_use_smpl) {
		num_cpus = options.selected_cpus;
		for(i=0; num_cpus; i++) { 
			if (pfmon_bitmask_isset(options.virt_cpu_mask, i)) {
				vbprintf("CPU%-4u %"PRIu64" sampling buffer overflows\n", i, ovfl_cnts[i]);
				num_cpus--;
			}
		}
	}

	return 0;
abort:
	session_state = SESSION_ABORTED;

	if (session_state == SESSION_RUN) 
		for (i=0; i < num_cpus; i++)
			if (thread_desc[i].thread_id) {
				DPRINT(("killing thread %d\n", i));
				pthread_kill(thread_desc[i].thread_id, SIGUSR1);
			}

	num_cpus = options.selected_cpus;
	vbprintf("aborting %lu sessions\n", num_cpus);

	for(i=0; i < num_cpus; i++) {
		DPRINT(("cancelling on CPU%lu\n", i));
		pthread_cancel(thread_desc[i].thread_id);
	}

	for(i=0; i < num_cpus; i++) {
		ret = pthread_join(thread_desc[i].thread_id, &retval);
		if (ret != 0) warning("cannot join thread %i\n", i);
		DPRINT(("CPU%-3d thread exited with value %ld\n", thread_desc[i].cpu, (unsigned long)retval));
	}

	pthread_key_delete(param_key);

	register_exit_function(NULL);

	return -1;
}
