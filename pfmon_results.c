/*
 * pfmon_results.c 
 *
 * Copyright (c) 2003-2006 Hewlett-Packard Development Company, L.P.
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
#include <math.h>
#include <sys/utsname.h>

static pthread_mutex_t results_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  results_cond = PTHREAD_COND_INITIALIZER;
static unsigned int who_must_print;

static void
print_sdesc_header(FILE *fp, pfmon_sdesc_t *sdesc)
{
	fprintf(fp, "# command line     : %s\n#\n"
		    "# process id(tgid) : %d\n"
		    "# thread  id(pid)  : %d\n"
		    "# parent process id: %d\n"
		    "# exec count       : %u\n#\n",
		    sdesc->cmdline,
		    sdesc->pid,
		    sdesc->tid,
		    sdesc->ppid,
		    sdesc->exec_count);
}

void
print_standard_header(FILE *fp, pfmon_sdesc_t *sdesc)
{
	char **argv = options.argv;
	pfmon_event_set_t *set;
	struct utsname uts;
	uint64_t m1, m2, pgsz;
	time_t t;
	unsigned int i;
	char *name;
	size_t l;

	l = 1 + options.max_event_name_len;
	name = malloc(l);
	if (!name)
		fatal_error("cannot allocate string buffer\n");

	uname(&uts);
	time(&t);

	fprintf(fp, "#\n# date: %s", asctime(localtime(&t)));
	fprintf(fp, "#\n# hostname: %s\n", uts.nodename);
	fprintf(fp, "#\n# kernel version: %s %s %s\n", 
			uts.sysname, 
			uts.release, 
			uts.version);

	fprintf(fp, "#\n# pfmon version: "PFMON_VERSION"\n");
	fprintf(fp, "# kernel perfmon version: %u.%u\n#\n", 
			PFM_VERSION_MAJOR(options.pfm_version),
			PFM_VERSION_MINOR(options.pfm_version));

	fprintf(fp, "#\n# page size: %u bytes\n#\n", options.page_size);
	fprintf(fp, "# CLK_TCK: %"PRIu64" ticks/second\n#\n", (uint64_t)llround(1000000000.0 / options.clock_res));
	fprintf(fp, "# CPU configured: %lu\n# CPU online    : %lu\n#\n", 
			options.config_cpus,
			options.online_cpus);

	pgsz = options.page_size;

	m1 = sysconf(_SC_PHYS_PAGES)*pgsz;
	m2 = sysconf(_SC_AVPHYS_PAGES)*pgsz;

	fprintf(fp, "# physical memory          : %"PRIu64" bytes (%.1f MB)\n"
		    "# physical memory available: %"PRIu64" bytes (%.1f MB)\n#\n", 
		    m1, (1.0*m1) / (1024*1024),
		    m2, (1.0*m2) / (1024*1024));

	pfmon_print_cpuinfo(fp);

	for(set = sdesc->sets; set ; set = set->next) {

		fprintf(fp, "#\n#\n# information for set%u:\n", set->id);
		/*
		 * when sampling, we may need to generate the header before the
		 * session is over (flushing the samples). Thus we cannot know in advance
		 * the final number of runs
		 */
		if (options.opt_use_smpl == 0) {
			fprintf(fp, "#\tnumber of runs : %"PRIu64"\n", set->nruns);
			fprintf(fp, "#\tactive duration: %"PRIu64" ns\n", set->duration);
		}
		for(i=0; i < set->event_count; i++) {
			pfm_get_full_event_name(&set->inp.pfp_events[i], name, l);
			fprintf(fp, "#\tPMD%u: %s = %s\n",
					set->outp.pfp_pmds[i].reg_num,
					name,
					priv_level_str(set->inp.pfp_events[i].plm));
		}
	}
	fprintf(fp, "#\n");
	if (options.nsets > 1)
		fprintf(fp, "# sets requested switch timeout: %.3fmsecs\n", (double)options.switch_timeout/1000000);
	/*
	 * invoke CPU model specific routine to print any additional information
	 */
	if (pfmon_current->pfmon_print_header) {
		pfmon_current->pfmon_print_header(fp);
	}

	fprintf(fp, "#\n# pfmon command line:");
	while (*argv) fprintf(fp, " %s", *argv++);

	fprintf(fp, "\n#\n");

	if (options.opt_syst_wide) {
		fprintf(fp, "# monitoring mode  : system wide\n");
	} else {
		fprintf(fp, "# monitoring mode  : per-thread\n");
	}

	if (options.opt_syst_wide) {
		unsigned int i;
		fprintf(fp, "# results captured on physical CPUs: ");
		if (options.opt_aggr == 0 && (options.interval == PFMON_NO_TIMEOUT || fp != stdout)) {
			fprintf(fp, "CPU%d", pfmon_cpu_virt_to_phys(sdesc->cpu));
		} else {
			for(i=0; i < options.online_cpus; i++) {
				if (pfmon_bitmask_isset(options.virt_cpu_mask, i))
					fprintf(fp, "CPU%d ", pfmon_cpu_virt_to_phys(i));
			}
		}
		fputc('\n', fp);
	} else if (options.opt_aggr == 0) {
		if (sdesc) print_sdesc_header(fp, sdesc);
	}

	fprintf(fp, "#\n#\n");
	free(name);
}

int
open_results(pfmon_sdesc_t *sdesc)
{
	FILE *fp = NULL;
	int is_syswide;
	char filename[PFMON_MAX_FILENAME_LEN];

	is_syswide   = options.opt_syst_wide;

	if (options.opt_use_smpl && options.opt_smpl_print_counts == 0) return 0;

	if (options.outfile) {
		if (options.opt_aggr == 0 && is_regular_file(options.outfile)) {
			if (is_syswide) {
				sprintf(filename, "%s.cpu%u", options.outfile, sdesc->cpu);
			} else {
				if (options.opt_follows) {
					if (options.opt_split_exec) {
						sprintf(filename, "%s.%d.%d.%u", 
							options.outfile, 
							sdesc->pid, 
							sdesc->tid, 
							sdesc->exec_count);
					} else {
						sprintf(filename, "%s.%d.%d", 
							options.outfile, 
							sdesc->pid, 
							sdesc->tid);
					}
				} else {
					sprintf(filename, "%s", options.outfile);
				}
			}
		} else {
			strcpy(filename, options.outfile);
		}

		fp = fopen(filename, options.opt_append ? "a" : "w");
		if (fp == NULL) {
			warning("cannot open %s for writing, defaulting to stdout\n", filename);
		}
	}

	if (fp == NULL)	{
		fp = stdout;
		vbprintf("[%d] results are on terminal\n", sdesc->tid);
	} else {
		if (options.opt_aggr) {
			vbprintf("[%d] results are in file \"%s\"\n", sdesc->tid, filename);
		} else if (is_syswide) {
			vbprintf("CPU%-3u results are in file \"%s\"\n", sdesc->cpu, filename);
		} else {
			vbprintf("[%d] results are in file \"%s\"\n", sdesc->tid, filename);
		}
	}	

	sdesc->out_fp = fp;

	return 0;
}

/*
 * Does the pretty printing of results
 *
 * In the case where results are aggregated, the routine expect the results
 * in pd[] and will not generate CPU (or pid) specific filenames
 */
static int
show_generic_results(pfmon_sdesc_t *sdesc)
{
	FILE *fp = NULL;
	char *suffix, *p = NULL;
	char *format_str;
	pfmon_event_set_t *set;
	pid_t pid = 0, tid = 0, ppid = 0;
	int is_syswide;
	unsigned int i, cpu, event_count;
	int need_cr = 0;
	unsigned long max_len, the_len, max;
	char *name;
	char format_base[32];
	char counter_str[32];
	char use_max_len = 0;
	uint64_t count;
	size_t l;

	if (options.opt_use_smpl && options.opt_smpl_print_counts == 0)
		return 0;

	l = 1 + options.max_event_name_len;
	name = malloc(l);
	if (!name)
		fatal_error("cannot allocate string buffer\n");

	is_syswide = options.opt_syst_wide;
	cpu        = sdesc->cpu;
	fp         = sdesc->out_fp;

	suffix = "";
	format_str = "%*s %-*s\n";

	if (options.opt_with_header && !sdesc->done_header) {
		if (options.interval == PFMON_NO_TIMEOUT || sdesc->id == 0 || fp != stdout)
			print_standard_header(fp, sdesc);
		sdesc->done_header = 1;
	}

	if (is_syswide) {
			sprintf(format_base, "CPU%-4u %%*s %%-*s\n", cpu);
			format_str = format_base;
			if (options.selected_cpus > 1)
				use_max_len = 1;
	} else if (options.opt_aggr == 0 && options.opt_follows && options.outfile == NULL) {
		/* isolate command */
		p = strchr(sdesc->cmdline, ' ');
		if (p) *p = '\0';

		/*
		 * XXX: could hard code suffix, tid, pid
		 */
		format_str = "%*s %-*s %s (%d,%d,%d)\n";

		suffix = sdesc->cmdline;
		pid = sdesc->pid; tid = sdesc->tid; ppid = sdesc->ppid;
		use_max_len = 1;
	} 
	max_len = options.max_event_name_len;

	if (use_max_len == 0) {
		/*
		 * find longest count
		 */
		max   = 0;
		count = 0;
		for(set = sdesc->sets; set ; set = set->next) {
			event_count = set->event_count;
			for(i=0; i < event_count; i++) {
				count =  set->master_pd[i].reg_value;
				if (count > max) max = count;
			}
		}
		counter2str(max, counter_str);
		max  = strlen(counter_str);
	} else {
		/*
		 * in follow mode, cannot determine longest count because coming from
		 * different sessions. Use longest possible count.
		 *
		 * comes from UNIT64_MAX + comma separators for thousands (20+6)
		 */
		max = 26;
	}

	for(set = sdesc->sets; set ; set = set->next) {
		event_count = set->event_count;

		for (i=0; i < event_count; i++) {
			pfm_get_full_event_name(&set->inp.pfp_events[i], name, l);
			counter2str(set->master_pd[i].reg_value, counter_str);
			/*
			 * ensures we do not add spaces when we don't need them
			 */
			the_len = use_max_len ? max_len : strlen(name);

			fprintf(fp, format_str, 
					(int)max, counter_str,
					the_len, name,
					suffix,
					pid, 
					tid, ppid);
		}
	}
	if (need_cr)
		fputc('\n', fp);
	/* restore space character, if needed */
	if (p) *p = ' ';
	free(name);
	return 0;
}

static int
pfmon_ordered_results(pfmon_sdesc_t *sdesc, int (*res_func)(pfmon_sdesc_t *))
{
	int ret;

	pthread_mutex_lock(&results_lock);
	DPRINT(("who_must_print=%u sdesc->id=%u\n", who_must_print, sdesc->id));
	while (who_must_print != sdesc->id) {
		pthread_cond_wait(&results_cond, &results_lock);
	}

	ret = (*res_func)(sdesc);

	who_must_print++;

	/*
	 * only the last sdesc will trigger this
	 */
	if (who_must_print == options.selected_cpus) who_must_print = 0;

	pthread_cond_broadcast(&results_cond);

	pthread_mutex_unlock(&results_lock);

	return ret;
}

/*
 * simplified show_generic_results invoked for system-wide measurements
 * with a print interval
 */
static int
do_show_incr_results(pfmon_sdesc_t *sdesc)
{
	FILE *fp = NULL;
	pfmon_event_set_t *set;
	unsigned int i;
	char counter_str[32];

	fp = sdesc->out_fp;

	if (options.opt_with_header && !sdesc->done_header) {
		if (sdesc->id == 0 || fp != stdout)
			print_standard_header(fp, sdesc);
		sdesc->done_header = 1;
	}
	if (sdesc->id == 0 && fp == stdout)
		fputs("#\n", fp);

	fprintf(fp,"CPU%-4u ", sdesc->cpu);
	for(set = sdesc->sets; set ; set = set->next) {
		for (i=0; i < set->event_count; i++) {
			counter2str(set->master_pd[i].reg_value, counter_str);
			fprintf(fp, "%26s ", counter_str);
		}
	}
	fputc('\n', fp);
	fflush(fp);

	return 0;
}

int
show_incr_results(pfmon_sdesc_t *sdesc, int needs_order)
{
	int ret;

	if (needs_order)
		ret = pfmon_ordered_results(sdesc, do_show_incr_results);
	else
		ret = do_show_incr_results(sdesc); 
	return ret;
}

int
show_results(pfmon_sdesc_t *sdesc, int needs_order)
{
	int ret;

	if (needs_order)
		ret = pfmon_ordered_results(sdesc, show_generic_results);
	else
		ret = show_generic_results(sdesc); 
	return ret;
}

void
close_results(pfmon_sdesc_t *sdesc)
{
	FILE *fp = sdesc->out_fp;

	if (fp && fp != stdout) fclose(fp);
}

int
print_results(pfmon_sdesc_t *sdesc)
{
	int ret;

	ret = open_results(sdesc);
	if (ret) return ret;
	ret = show_generic_results(sdesc);
	if (ret) return ret;
	close_results(sdesc);

	return 0;
}

int
read_incremental_results(pfmon_sdesc_t *sdesc)
{
	pfmon_event_set_t *set;
	pfmon_setinfo_t	setf;
	uint64_t total_duration = 0, d;
	unsigned int j, i;
	int ctxid, error;

	if (sdesc->nsets > 1)
		memset(&setf, 0, sizeof(setf));

	ctxid = sdesc->ctxid;

	for (set = sdesc->sets; set ; set = set->next) {
		if (pfmon_read_pmds(ctxid, set, set->tmp_pd, set->event_count, &error) == -1) {
			warning("pfmon_read_pmds error %s\n", strerror(error));
			return -1;
		}
		/*
		 * calculate delta
		 */
		for(j=0; j < set->event_count; j++) {
			set->master_pd[j].reg_value = set->tmp_pd[j].reg_value - set->prev_pd[j].reg_value;
			set->prev_pd[j].reg_value = set->tmp_pd[j].reg_value;
		}
		/*
		 * calculate run delta
		 */
		if (sdesc->nsets > 1) {
			setf.set_id = set->id;
			if (pfmon_getinfo_evtsets(ctxid, &setf, 1, &error) == -1) {
				warning("pfmon_getinfo_evt_sets error %s\n", strerror(error));
				return -1;
			}
			set->prev_duration = set->duration;
			set->duration = setf.set_act_duration;
			total_duration += setf.set_act_duration - set->prev_duration;
		}
	}
	/*
	 * scale  by duration to avoid rounding errors with runs
	 * use double to avoid 64-bitoverflow
	 */
	if (sdesc->nsets > 1) {
		for (set = sdesc->sets; set ; set = set->next) {
			for(i=0; i < set->event_count; i++) {
				d = set->duration - set->prev_duration;
				if (d)
					set->master_pd[i].reg_value = llround((double)set->master_pd[i].reg_value*total_duration)/(double)d; 
				else
					set->master_pd[i].reg_value = 0;
			}
		}
	}
	return 0;
}

int
read_results(pfmon_sdesc_t *sdesc)
{
	pfmon_event_set_t *set;
	pfmon_setinfo_t	setf;
	uint64_t total_duration = 0;
	unsigned int i;
	int ctxid, error;

	memset(&setf, 0, sizeof(setf));

	ctxid = sdesc->ctxid;

	for (set = sdesc->sets; set ; set = set->next) {
		for (i = 0; i < set->event_count; i++)
			set->last_values[i] = set->master_pd[i].reg_value;

		if (pfmon_read_pmds(ctxid, set, set->master_pd, set->event_count, &error) == -1) {
			warning("pfmon_read_pmds error %s\n", strerror(error));
			return -1;
		}

		if (options.opt_is22) {
			setf.set_id = set->id;
			if (pfmon_getinfo_evtsets(ctxid, &setf, 1, &error) == -1) {
				warning("pfmon_getinfo_evt_sets error %s\n", strerror(error));
				return -1;
			}
			if (setf.set_runs == 0)
				warning("set%u was not activated, set\%u counts set to zero. "
					"Try decreasing the switch timeout.\n",
					setf.set_id, setf.set_id);

			set->last_duration = setf.set_act_duration - set->duration;
			set->nruns  = setf.set_runs;
			set->duration = setf.set_act_duration;
			total_duration += setf.set_act_duration;

			vbprintf("[%d] set%u runs=%"PRIu64" duration=%"PRIu64"\n",
				sdesc->tid,
				set->id,
				setf.set_runs,
				setf.set_act_duration);
		}

		for (i = 0; i < set->event_count; i++)
			set->last_values[i] = set->master_pd[i].reg_value - set->last_values[i];
	}
	/*
	 * scale results based on the number duration to avoid issue with partial runs
	 * we use double to avoid 64-bit overflows
	 */
	if (sdesc->nsets > 1) {
		for (set = sdesc->sets; set ; set = set->next) {
			for(i=0; i < set->event_count; i++) {
				if (set->duration)
					set->master_pd[i].reg_value = llround((double)set->master_pd[i].reg_value*total_duration/(double)set->duration);
				else
					set->master_pd[i].reg_value = 0;
			}
		}
	}
	return 0;
}
