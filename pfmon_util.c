/*
 * pfmon_util.c  - set of helper functions part of the pfmon tool
 *
 * Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
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
#include "pfmon.h"

#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <syscall.h>

/* 
 * architecture specified minimals
 */
#define PFMON_DFL_MAX_COUNTERS  4

/*
 * This points to an alternative exit function.
 * This function can be registered using register_exit_func()
 * 
 * This mechanism is useful when pthread are used. You don't want
 * a pthread to call exit but pthread_exit.
 */
static void (*pfmon_exit_func)(int);

/*
 * levels:
 * 	cache levels: 1, 2, 3
 * 	type        : 0 (unified), 1 (data), 2 (code)
 */
int
extract_cache_size(unsigned int level, unsigned int type, unsigned long *size)
{
	FILE *fp;
	char *p, *value;
	int ret = -1;
	unsigned int lvl = 1, t = -1;
	char buffer[128];

	if (size == NULL) return -1;

	fp = fopen("/proc/pal/cpu0/cache_info", "r");
	if (fp == NULL) return -1;

	for (;;) {	
		p  = fgets(buffer, sizeof(buffer)-1, fp);
		if (p == NULL) goto not_found;

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

	*size = atoi(value);
	ret   = 0;
not_found:
	fclose(fp);

	return ret;
}

void
warning(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

#ifdef PFMON_DEBUG
void
dbgprintf(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
#endif


int
register_exit_function(void (*func)(int))
{
	pfmon_exit_func = func;

	return 0;
}

void
fatal_error(char *fmt, ...) 
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (pfmon_exit_func == NULL) exit(1);

	(*pfmon_exit_func)(1);
	/* NOT REACHED */
}

static pthread_mutex_t vbprintf_lock = PTHREAD_MUTEX_INITIALIZER;

void
vbprintf_block(void)
{
	pthread_mutex_lock(&vbprintf_lock);
}

void
vbprintf_unblock(void)
{
	pthread_mutex_unlock(&vbprintf_lock);
}


void
vbprintf(char *fmt, ...)
{
	va_list ap;

	if (options.opt_verbose == 0) return;

	va_start(ap, fmt);

	pthread_mutex_lock(&vbprintf_lock);

	vprintf(fmt, ap);

	pthread_mutex_unlock(&vbprintf_lock);

	va_end(ap);
}

void
gen_reverse_table(pfmon_event_set_t *set, int *rev_pc)
{
	unsigned int i;

	/* first initialize the array. We cannot use 0 as this 
	 * is the index of the first event
	 */
	for (i=0; i < PFMON_MAX_PMDS; i++) {
		rev_pc[i] = -1;
	}
	for (i=0; i < set->event_count; i++) {
		rev_pc[set->outp.pfp_pmcs[i].reg_num] = i; /* point to corresponding monitor_event */
	}
}

void
setup_event_set(pfmon_event_set_t *set)
{
	char *event_name, *next_event_name;
	size_t l;
	unsigned int i, cnt, idx;
	int ret;

	for (event_name = set->events_str, cnt = 0;
	     event_name;
	     event_name = next_event_name, cnt++) {

		if (cnt == options.max_counters)
			goto too_many;

		next_event_name = strchr(event_name, ',');
		if (next_event_name)
			*next_event_name = '\0';

		l = strlen(event_name);
		ret = pfm_find_full_event(event_name, &set->inp.pfp_events[cnt]);
		if (ret != PFMLIB_SUCCESS)
			goto error;

		if (next_event_name)
			*next_event_name++ = ',';

		if (l > options.max_event_name_len)
			options.max_event_name_len = l;
	}

	/* setup event_count */
	set->inp.pfp_event_count = set->event_count = cnt;
	return;

error:
	if (ret != PFMLIB_ERR_UMASK || pfm_find_event(event_name, &idx) != PFMLIB_SUCCESS)
		fatal_error("event %s : %s\n", event_name, pfm_strerror(ret));

	pfm_get_max_event_name_len(&l);
	next_event_name = malloc(l+1);
	if (!next_event_name)
		fatal_error("event %s : %s\n", event_name, pfm_strerror(ret));

	pfm_get_num_event_masks(idx, &cnt);
	warning("event %s needs at least a unit mask among: ", event_name);
	for (i = 0; i < cnt ; i++) {
		pfm_get_event_mask_name(idx, i, next_event_name, l);
		warning("[%s] ", next_event_name);
	}
	free(next_event_name);
	fatal_error("\n");
too_many:
	fatal_error("too many events specified, max=%d\n", options.max_counters);
}

void
add_event_set(pfmon_event_set_t *set)
{
	set->id   = options.nsets++;
	set->next = NULL;

	if (options.sets == NULL) {
		options.sets = set;
	} else {
		options.last_set->next = set;
	}
	options.last_set   = set;
}

int
create_event_set(char *arg)
{
	pfmon_event_set_t *set;
	void *p;

	set = calloc(1, sizeof(*set)
			+ pfmon_current->sz_mod_args
			+ pfmon_current->sz_mod_inp
			+ pfmon_current->sz_mod_outp);

	if (set == NULL) {
		fatal_error("cannot allocate event set\n");
	}

	set->events_str  = arg;

	p = set + 1;
	if (pfmon_current->sz_mod_args)
		set->mod_args = p;

	p += pfmon_current->sz_mod_args;

	if (pfmon_current->sz_mod_inp)
		set->mod_inp = p;

	p += pfmon_current->sz_mod_inp;

	if (pfmon_current->sz_mod_outp)
		set->mod_outp = p; 

	add_event_set(set);

	return 0;
}

/*
 * input string written
 */
int
gen_smpl_rates(char *arg, unsigned int max_count, pfmon_smpl_rate_t *rates, unsigned int *count)
{
	char *p, *endptr = NULL;
	uint64_t val;
	unsigned int cnt;

	for(cnt = 0; arg; cnt++) {

		if (cnt == max_count) goto too_many;

		p = strchr(arg,',');

		if ( p ) *p = '\0';

		val =strtoull(arg, &endptr, 0);

		if ( p ) *p++ = ',';

		if (*endptr != ',' && *endptr != '\0') goto error;

		rates[cnt].value = -val; /* a period is a neagtive number */
		rates[cnt].flags |= PFMON_RATE_VAL_SET;

		arg = p;
	}
	*count = cnt;
	return 0;
error:
	if (*arg == '\0')
		warning("empty rate specified\n");
	else
		warning("invalid rate %s\n", arg);
	return -1;
too_many:
	warning("too many rates specified, max=%d\n", count);
	return -1;
}

/*
 * input string written
 */
int
gen_smpl_randomization(char *arg, unsigned int max_count, pfmon_smpl_rate_t *rates, unsigned int *count)
{
	char *p, *endptr = NULL;
	uint64_t val;
	uint32_t seed;
	unsigned int cnt, element = 0;
	char c;

	for(cnt = 0; arg; cnt++) {

		if (cnt == max_count) goto too_many;

		element = 0; c = 0;

		p = strpbrk(arg,":,");

		if ( p ) { c = *p; *p = '\0'; }

		val = strtoull(arg, &endptr, 0);

		if ( p ) *p++ = c;

		if (*endptr != c && *endptr != '\0') goto error_seed_mask;

		if (val == 0) goto invalid_mask;

		rates[cnt].mask  = val;
		rates[cnt].flags |= PFMON_RATE_MASK_SET;

		arg = p;

		if (c == ',' || arg == NULL) continue;

		/* extract optional seed */

		p = strchr(arg,',');

		if (p) *p = '\0';

		seed = strtoul(arg, &endptr, 0);
		if (*endptr != '\0') goto error_seed_mask;

		if (seed >= UINT_MAX) goto error_seed_mask;

		if (p) *p++ = ',';

		rates[cnt].seed = seed;
		rates[cnt].flags |= PFMON_RATE_SEED_SET;

		arg = p;
	}
	*count = cnt;
	return 0;
too_many:
	warning("too many rates specified, max=%d\n", count);
	return -1;
error_seed_mask:
	warning("invalid %s at position %u\n", element ? "seed" : "mask", cnt+1);
	return -1;
invalid_mask:
	warning("invalid mask %lu at position %u, to use all bits use -1\n", val, cnt+1);
	return -1;
}

/*
 * XXX: cannot be called from a signal handler (stdio locking)
 */
int
find_current_cpu(pid_t pid, unsigned int *cur_cpu)
{
#define TASK_CPU_POSITION	39 /* position of the task cpu in /proc/pid/stat */
	FILE *fp;
	int count = TASK_CPU_POSITION;
	char *p, *pp = NULL;
	char fn[32];
	char buffer[1024];

	sprintf(fn, "/proc/%d/stat", pid);

	fp = fopen(fn, "r");
	if (fp == NULL) return -1;

	p  = fgets(buffer, sizeof(buffer)-1, fp);
	if (p == NULL) goto error;

	fclose(fp);

	p = buffer;

	/* remove \n */
	p[strlen(p)-1] = '\0';
	p--;

	while (count-- && p) {
		pp = ++p;
		p = strchr(p, ' ');
	}
	if (count>-1) goto error;

	if (p) *p = '\0';

	DPRINT(("count=%d p=%lx pp=%p pp[0]=%d pp[1]=%d cpu=%d\n", count, (unsigned long)p, pp, pp[0], pp[1], 0));

	*cur_cpu = atoi(pp);
	return 0;
error:
	if (fp) fclose(fp);
	DPRINT(("error: count=%d p=%lx pp=%p pp[0]=%d pp[1]=%d cpu=%d\n", count, (unsigned long)p, pp, pp[0], pp[1], 0));
	return -1;
}


/*
 * we abuse libpfm's return values here
 */
static int
convert_data_rr_param(char *param, unsigned long *start, unsigned long *end)
{
	char *endptr;

	if (isdigit(param[0])) {
		endptr = NULL;
		*start  = (unsigned long)strtoul(param, &endptr, 0);

		if (*endptr != '\0') return -1;

		return 0;

	}
	return find_sym_addr(param, options.primary_syms, PFMON_DATA_SYMBOL, start, end);
}

static int
convert_code_rr_param(char *param, unsigned long *start, unsigned long *end)
{
	char *endptr;

	if (isdigit(param[0])) {
		endptr = NULL;
		*start  = (unsigned long)strtoul(param, &endptr, 0);

		if (*endptr != '\0') return -1;

		return 0;

	}
	return find_sym_addr(param, options.primary_syms, PFMON_TEXT_SYMBOL, start, end);
}

static void
gen_range(char *arg, unsigned long *start, unsigned long *end, int (*convert)(char *, unsigned long *, unsigned long *))
{
	char *p;
	void *p_end = NULL;
	int ret;

	p = strchr(arg,'-');
	if (p == arg) goto error;

	if (p == NULL) {
		if (isdigit(*arg)) goto error;
		p_end = end;
	} else {
		*p='\0';
	}

	ret = (*convert)(arg, start, p_end);

	/*
	 * put back the - to get the original string
	 */

	if (ret) goto error_convert;

	if (p == NULL)  return;

	*p = '-';

	arg = p+1;
	if (*arg == '\0') goto error;

	ret = (*convert)(arg, end, NULL);
	if (ret) goto error_convert;

	if (*end <= *start) {
		fatal_error("empty address range [0x%lx-0x%lx]\n", *start, *end);
	}
	return;

error_convert:
	fatal_error("symbol not found: %s\n", arg);
error:
	fatal_error("invalid address range specification. Must be start-end\n");
}


void
gen_data_range(char *arg, unsigned long *start, unsigned long *end)
{
	gen_range(arg, start, end, convert_data_rr_param);
}
	
void
gen_code_range(char *arg, unsigned long *start, unsigned long *end)
{
	if (arg == NULL || start == NULL) return;

	gen_range(arg, start, end, convert_code_rr_param);
}

static void
dec2sep(char *str2, char *str, char sep)
{
	size_t i, l, b, j;
	int c=0;

	/*
	 * number is < 1000
	 */
	l = strlen(str2);
	if (l <= 3) {
		strcpy(str, str2);
		return;
	}
	b = l +  l/3 - ((l%3) == 0 ? 1 : 0); /* l%3=correction to avoid extraneous comma at the end */
	for(i=l, j=0; ; i--, j++) {
		if (j) c++;
		str[b-j] = str2[i];
		if (c == 3 && i > 0) {
			str[b-++j] = sep;
			c = 0;
		}
		/* avoids >= 0 in for() test for unsigned long! */
		if (i==0) break;
	}
}

void
counter2str(uint64_t count, char *str)
{
	char str2[32];

	switch(options.opt_print_cnt_mode) {
		case 1:
			sprintf(str2, "%" PRIu64, count);
			dec2sep(str2, str, ',');
			break;
		case 2:
			sprintf(str2, "%" PRIu64, count);
			dec2sep(str2, str, '.');
			break;
		case 3:
			sprintf(str, "0x%016" PRIx64, count);
			break;
		default:
			sprintf(str, "%" PRIu64, count);
			break;
	}
}

void
show_task_rusage(const struct timeval *start, const struct timeval *end, const struct rusage *ru)
{
	long secs, suseconds, end_usec;

	 secs     =  end->tv_sec - start->tv_sec;
	 end_usec = end->tv_usec;

	if (end_usec < start->tv_usec) {
      		end_usec += 1000000;
      		secs--;
    	}

  	suseconds = end_usec - start->tv_usec;

	printf ("real %ldh%02ldm%02ld.%03lds user %ldh%02ldm%02ld.%03lds sys %ldh%02ldm%02ld.%03lds\n", 
		secs / 3600, 
		(secs % 3600) / 60, 
		secs % 60,
		suseconds / 1000,

		ru->ru_utime.tv_sec / 3600, 
		(ru->ru_utime.tv_sec % 3600) / 60, 
		ru->ru_utime.tv_sec% 60,
		(long)(ru->ru_utime.tv_usec / 1000),

		ru->ru_stime.tv_sec / 3600, 
		(ru->ru_stime.tv_sec % 3600) / 60, 
		ru->ru_stime.tv_sec% 60,
		(long)(ru->ru_stime.tv_usec / 1000)
		);
}

int
is_regular_file(char *name)
{
	struct stat st;

	return stat(name, &st) == -1 || S_ISREG(st.st_mode) ? 1 : 0;
}

int
pfm_uuid2str(pfm_uuid_t uuid, size_t maxlen, char *str)
{
	if (str == NULL || uuid == NULL || maxlen < 48) return -1;

	sprintf(str, "%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
			uuid[0],
			uuid[1],
			uuid[2],
			uuid[3],
			uuid[4],
			uuid[5],
			uuid[6],
			uuid[7],
			uuid[8],
			uuid[9],
			uuid[10],
			uuid[11],
			uuid[12],
			uuid[13],
			uuid[14],
			uuid[15]);
	return 0;
}

/*
 * extract the command name of a process via /proc/pid/
 */
int
pfmon_extract_cmdline(pfmon_sdesc_t *sdesc)
{
	char *cmdline;
	size_t maxlen;
	ssize_t i, m, n;
	int fd;
	char c;
	char fn[PFMON_MAX_FILENAME_LEN];
	char cmdargs[PFMON_MAX_CMDLINE_LEN];

	cmdline = sdesc->new_cmdline;
	maxlen = PFMON_MAX_CMDLINE_LEN;

	/*
	 * extract full cmd pathname
	 */
	sprintf(fn, "/proc/%d/exe", sdesc->pid);
	m = readlink(fn, cmdline, PFMON_MAX_CMDLINE_LEN-1);
	if (m < 0) {
		warning("cannot read symlink %s\n", fn);
		return -1;
	}
	cmdline[m] = ' ';
	maxlen -= m;
	n = m;

	/*
	 * extract cmdline options
	 */
	sprintf(fn, "/proc/%d/cmdline", sdesc->pid);
	fd = open(fn, O_RDONLY);
	if (fd<0) {
		warning("cannot open  %s: %s\n", fn, strerror(errno));
		return -1;
	}

	m = read(fd, cmdargs, sizeof(cmdargs)-1);
	if (m<0) {
		warning("cannot read %s : %s\n", fn, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	cmdargs[m]='\0';

	/*
	 * skip command, we got it from readlink
	 */
	for(i=0; cmdargs[i]; i++);

	for(; maxlen && i<m; i++, maxlen--) {
		c = cmdargs[i];

		if (c == '\0')
			cmdline[n++] = ' ';
		else 
			cmdline[n++] = c;
	}
	if(cmdline[n-1] == ' ')
		cmdline[n-1] = '\0';
	cmdline[n] = '\0';

	return 0;
}

#ifdef CONFIG_PFMON_LIBUNWIND

#include <libunwind.h>

void
pfmon_backtrace(void)
{
  unw_cursor_t cursor;
  unw_word_t ip, off;
  unw_context_t uc;
  char buf[256], name[256];
  int ret;

  unw_getcontext (&uc);
  if (unw_init_local (&cursor, &uc) < 0)
    fatal_error("unw_init_local failed!\n");

  printf("<pfmon fatal error>, pfmon backtrace:\n");
  do
    {
      unw_get_reg (&cursor, UNW_REG_IP, &ip);
      buf[0] = '\0';
      if (unw_get_proc_name (&cursor, name, sizeof (name), &off) == 0)
        {
          if (off)
            snprintf (buf, sizeof (buf), "<%s+0x%lx>", name, off);
          else
            snprintf (buf, sizeof (buf), "<%s>", name);
        }
      printf ("0x%016lx %s\n", (long) ip, buf);

      ret = unw_step (&cursor);
      if (ret < 0)
	{
	  unw_get_reg (&cursor, UNW_REG_IP, &ip);
	  printf ("FAILURE: unw_step() returned %d for ip=%lx\n",
		  ret, (long) ip);
	}
    }
  while (ret > 0);
}
#else
void
pfmon_backtrace(void)
{
	fprintf(stderr, "with libunwind installed, you could get a call stack here!\n");
}
#endif /* CONFIG_PFMON_LIBUNWIND */

int
find_in_proc(FILE *fp1, char *entry, char **result)
{
	char *buffer, *p, *value;
	size_t n, len;

	len = strlen(entry);
	*result = buffer = NULL;

	while(getline(&buffer, &n, fp1) != -1) {

		/* skip  blank lines */
		if (*buffer == '\n')
			continue;

		p = strchr(buffer, ':');
		if (p == NULL)
			goto end_it;	

		/* 
		 * p+2: +1 = space, +2= first character
		 * strlen()-1 gets rid of \n
		 */
		*p = '\0'; 
		value = p+2; 

		value[strlen(value)-1] = '\0';

		if (!strncmp(entry, buffer, len)) {
			*result = strdup(value);
			break;
		}
	}
end_it:
	if (buffer)
		free(buffer);
	return *result == NULL ? -1 : 0;
}

int
find_in_cpuinfo(char *entry, char **result)
{
	FILE *fp1;
	int ret;

	fp1 = fopen("/proc/cpuinfo", "r");
	if (fp1 == NULL)
		return -1;

	ret = find_in_proc(fp1, entry, result);

	fclose(fp1);

	return ret;
}

unsigned long
pfmon_find_cpu_speed(void)
{
	float fl = 0;
	char *mhz;

	if (find_in_cpuinfo("cpu MHz", &mhz) == -1 &&
	    find_in_cpuinfo("BogoMIPS", &mhz) == -1) {
		unsigned long long cycles_per_second;
		char *ctick;

		if (pfmon_sysfs_cpu_attr("clock_tick", &ctick) == -1)
			return 0;

		sscanf(ctick, "%llu", &cycles_per_second);

		free(ctick);
		return cycles_per_second / 1000000;
	}
	sscanf(mhz, "%f", &fl);
	free(mhz);
	return lroundf(fl);
}

int
pfmon_sysfs_cpu_attr(char *name, char **result)
{
	const char *path_base = "/sys/devices/system/cpu/";
	char path_buf[PATH_MAX];
	char val_buf[32];
	DIR *sys_cpu;

	sys_cpu = opendir(path_base);
	if (sys_cpu) {
		struct dirent *cpu;

		while ((cpu = readdir(sys_cpu)) != NULL) {
			int fd;

			if (strncmp("cpu", cpu->d_name, 3))
				continue;
			strcpy(path_buf, path_base);
			strcat(path_buf, cpu->d_name);
			strcat(path_buf, "/");
			strcat(path_buf, name);

			fd = open(path_buf, O_RDONLY);
			if (fd < 0)
				continue;

			if (read(fd, val_buf, 32) < 0)
				continue;
			close(fd);

			*result = strdup(val_buf);
			return 0;
		}
	}
	return -1;
}

/*
 * find thread groud id (tgid) using the thread id (tid)
 */
pid_t find_pid_attr(pid_t tid, char *attr)
{
	FILE *fp1;
	char path[32];
	char *result = NULL;
	int ret;

	snprintf(path, sizeof(path), "/proc/%d/status", tid);

	fp1 = fopen(path, "r");
	if (fp1 == NULL)
		return -1;

	ret = find_in_proc(fp1, attr, &result);

	fclose(fp1);

	if (ret == 0) {
		ret = atoi(result);
	}
	if (result)
		free(result);

	return ret;
}

/*
 * There are several ways to implement this depending on:
 * 	- NPTL vs. LinuxThreads (pthread_setaffinity_np())
 * 	- the version of libc.
 *
 * Instead of having to auto-detect or have a config.mk option
 * I decided to go straight to the kernel system call. This works
 * independently of the thread package or library.
 *
 * I do not use the cpu_set_t defined in /usr/include/bits/sched.h
 * because it is not always present in all versions of libc. Moreover
 * it does have a 1024 processor limit which could be too low for
 * some big machines. The kernel interface does not have this kind
 * of limit. Here we simply limit it to whatever is used for PFMON_MAX_CPUS.
 */

int
pfmon_set_affinity(pid_t pid, pfmon_bitmask_t mask)
{
	pfmon_bitmask_t phys_mask;
	int phys_cpu;
	int i;

	memset(phys_mask, 0, sizeof(phys_mask));

	for (i=0; i < options.online_cpus; i++) {
		if (pfmon_bitmask_isset(mask, i)) {
			phys_cpu = pfmon_cpu_virt_to_phys(i);
			if (phys_cpu == -1) {
				warning("logical CPU%d does not exist in current CPU set\n", i);
				return -1;
			}	
			vbprintf("vCPU%d -> pCPU%d\n", i, phys_cpu);
			pfmon_bitmask_set(phys_mask, phys_cpu);
		}
	}
	/*
	 * actual kernel affinity call, only taskes physical processor number at this point
	 */
	return __pfmon_set_affinity(pid, sizeof(pfmon_bitmask_t), phys_mask);
}

int
pfmon_pin_self(unsigned int cpu)
{	
	pfmon_bitmask_t mask; /* size of the mask limited by PFMON_MAX_CPUS */

	memset(mask, 0, sizeof(pfmon_bitmask_t));

	pfmon_bitmask_set(mask, cpu);

	return pfmon_set_affinity(gettid(), mask);
}

char *
priv_level_str(unsigned int plm)
{
	static char *priv_levels[]={
		"nothing",
		"kernel",
		"1",
		"kernel+1",
		"2",
		"kernel+2",
		"1+2",
		"kernel+1+2",
		"user",
		"kernel+user",
		"1+user",
		"kernel+1+user",
		"2+user",
		"kernel+2+user",
		"kernel+1+2+user"
	};

	if (plm > 0xf) return "invalid";

	return priv_levels[plm];
}

// if version == 0, the address will NOT BE RESOLVED
int
pfmon_print_address(FILE *fp, module_map_t *list, pfmon_sym_type_t type, unsigned long addr, pid_t pid, unsigned int version)
{
	char *sym, *module;
	unsigned long start_addr, offs;
	int ret = -1;

	// in system wide the version will be zero (TBD: fix this in the future)
        if(version != 0 || options.opt_syst_wide)
//	printf("v: %d\n", version);
//        if(version != 0)
                ret = find_sym_by_apv(addr, pid, version,  list, type, &sym, &module, &start_addr, NULL);

	if (ret == -1) {
		fprintf(fp, "%p", (void *)addr);
		return 0;
	}

	offs = addr - start_addr;
	if (offs == 0)
		ret =  fprintf(fp, "%s<%s>", sym, module);
	else
		ret =  fprintf(fp, "%s+%p<%s>", sym, (void *)offs, module);
	
	return ret;
}

void
pfmon_clone_sets(pfmon_event_set_t *list, pfmon_sdesc_t *sdesc)
{
	pfmon_event_set_t *set, *head = NULL, *last = NULL;
	unsigned int cnt = 0;

	for(; list; list = list->next) {
		set = malloc(sizeof(pfmon_event_set_t));
		if (set == NULL)
			fatal_error("cannot clone event set list\n");

		memcpy(set, list, sizeof(*set));

		if (head == NULL) 
			head = set;
		else 
			last->next = set;
		last = set;
		cnt++;
	}
	sdesc->sets  = head;
	sdesc->nsets = cnt;
}

void
pfmon_free_sets(pfmon_sdesc_t *sdesc)
{
	pfmon_event_set_t *set, *tmp;
	for (set = sdesc->sets ; set; set = tmp) {
		tmp = set->next;
		free(set);
	}
	sdesc->sets = NULL;
}

/*
 * on IA-64 with perfmon-2.0, we used to get the information from /proc/perfmon
 */
int
pfmon_get_version_legacy(void)
{
	FILE *fp;
	char *buf = NULL;
	char *p, *s;
	size_t len = 0;
	int ret = -1;

	fp = fopen("/proc/perfmon", "r");
	if (fp == NULL)
		return -1;

	ret = getline(&buf, &len, fp);
	if (ret < 0)
		goto invalid_file;

	if (strncmp(buf, "perfmon version", 15))
		goto invalid_format;

	p = strchr(buf+15, ':');
	if (p == NULL) goto invalid_format;
	s = p+1;
	p = strchr(s, '.');
	if (p == NULL) goto invalid_format;
	*p = '\0';
	options.pfm_version = atoi(s) << 16;
	s  = p+1;
	options.pfm_version |= atoi(s);

	ret = 0;
invalid_format:
	free(buf);
invalid_file:
	fclose(fp);
	return ret;
}

void
pfmon_get_version(void)
{
	FILE *fp;
	char *buf = NULL;
	size_t len = 0;
	char *p;
	int ret;

	if (pfmon_get_version_legacy() == 0)
		return;

	fp = fopen("/sys/kernel/perfmon/version", "r");
	if (fp == NULL)
		return;

	ret = getline(&buf, &len, fp);
	if (ret < 0)
		fatal_error("cannot extract perfmon version\n");

	p = strchr(buf, '.');
	if (p == NULL)
		goto invalid_format;
	*p = '\0';
	options.pfm_version = atoi(buf) << 16;
	p++;
	options.pfm_version |= atoi(p);

	free(buf);
	fclose(fp);
	return;
invalid_format:
	fatal_error("cannot parse perfmon version number\n");
}

int
pfmon_cpu_virt_to_phys(int virt_cpu)
{
	int i, ncpus;

	if (options.opt_vcpu == 0) {
		return virt_cpu;
	}

	for(i=0, ncpus=0; i < PFMON_MAX_CPUS; i++) {
		if (pfmon_bitmask_isset(options.phys_cpu_mask, i)) {
			if (virt_cpu < ++ncpus) {
				return i;
			}
		}
	}
	return -1;
}

int
pfmon_collect_affinity(void)
{
	int ret;

	ret = __pfmon_get_affinity(getpid(), sizeof(pfmon_bitmask_t), options.phys_cpu_mask);
	if (ret == -1) {
		warning("cannot get affinity: %s\n", strerror(errno));
	}
	return ret;
}

static size_t pfmon_get_perfmon_smpl_mem(void)
{
	int fd;
	size_t max, used;
	char number[32];
	ssize_t ret;

	if (options.opt_is22 == 0)
		return (size_t)-1;

	/*
	 * extract amount of memory currently used
	 */
	fd = open("/sys/kernel/perfmon/smpl_buffer_mem_cur", O_RDONLY);
	if (fd == -1)
		return (size_t)-1;

	memset(number, 0, sizeof(number));

	ret = read(fd, number, sizeof(number));
	close(fd);

	used = strtoul(number, NULL, 0);

	/*
	 * extract max amount of memory possible
	 */
	fd = open("/sys/kernel/perfmon/smpl_buffer_mem_max", O_RDONLY);
	if (fd == -1)
		return (size_t)-1;

	memset(number, 0, sizeof(number));
	ret = read(fd, number, sizeof(number));

	close(fd);

	max = strtoul(number, NULL, 0);
	if (max == -1)
		max = sysconf(_SC_PHYS_PAGES)*getpagesize();

	return max - used;
}

int
pfmon_compute_smpl_entries(size_t hdr_sz, size_t entry_sz, size_t slack)
{
	int ret;
	struct rlimit rlim_memlock;
	unsigned long max_entries = 0, orig_smpl_entries = 0;
	size_t pfm_avail, memlock_avail, mem_avail, pgsz;

	/*
	 * hack to work around a bug in older v2.0 kernel
	 * implementations for IA-64
	 */
	if (options.opt_is22 == 0) {
		if (options.smpl_entries == 0)
			options.smpl_entries = 2048UL;
		return 0;
	}

	pgsz = getpagesize();
	pfm_avail = pfmon_get_perfmon_smpl_mem();

	ret = getrlimit(RLIMIT_MEMLOCK, &rlim_memlock);
	if (ret == -1) {
		warning("cannot retrieve maximum memory useable by buffer\n");
		return -1;
	}

	vbprintf("max=%zu cur=%lu\n", rlim_memlock.rlim_max, rlim_memlock.rlim_cur);
	if (rlim_memlock.rlim_cur != RLIM_INFINITY)
		memlock_avail = rlim_memlock.rlim_cur;
	else
		memlock_avail = sysconf(_SC_PHYS_PAGES)*pgsz;

	/* compute maximum memory available */
	mem_avail = memlock_avail < pfm_avail ? memlock_avail : pfm_avail;

	if (options.opt_syst_wide)
		mem_avail /= options.selected_cpus;

	/* round down to multiple of page size */
	mem_avail /= pgsz;
	mem_avail *= pgsz;

	if (mem_avail < (hdr_sz + slack))
		goto no_solution;

	mem_avail -= hdr_sz + slack;

	//max_entries = (mem_avail - hdr_sz - slack) / entry_sz;
	max_entries = mem_avail / entry_sz;
no_solution:
	orig_smpl_entries = options.smpl_entries;

	if (options.smpl_entries == 0) {
		options.smpl_entries = max_entries < PFMON_DFL_SMPL_ENTRIES ? max_entries : PFMON_DFL_SMPL_ENTRIES;
	} else if (options.smpl_entries > max_entries) {
		options.smpl_entries = max_entries;
	}

		
	vbprintf("locked_mem_avail=%zu pfm_mem_avail=%zu mem_avail=%zu ncpus=%lu max_entries=%lu smpl_entries=%lu orig_smpl_entries=%lu pgsz=%zu hdrsz=%zu entrysz=%zu slack=%zu\n",
		memlock_avail,
		pfm_avail,
		mem_avail,
		options.selected_cpus,
		max_entries,
		options.smpl_entries,
		orig_smpl_entries,
		pgsz,
		hdr_sz,
		entry_sz,
		slack);

	if ((options.smpl_entries < orig_smpl_entries && orig_smpl_entries) || !max_entries)
		warning("Sampling buffer entries limited to %lu (from %u) due to lack of memory resource.\n"
		 	"Check the locked memory limit with ulimit or limit.\n"
		 	"Check /etc/limits.conf for memorylocked hard and soft limits.\n"
			"Check the perfmon global buffer limit in /sys/kernel/perfmon/smpl_buffer_mem_max.\n",
			options.smpl_entries, orig_smpl_entries);
	
	return options.smpl_entries ? 0 : -1;
}

int
pfmon_detect_unavail_pmcs(pfmlib_regmask_t *r_pmcs)
{
	pfarg_ctx_t ctx;
	pfmon_setinfo_t	setf;
	int ret, i, j, fd, error;

	memset(r_pmcs, 0, sizeof(*r_pmcs));

	if (options.opt_is22 == 0)
		return 0;

	memset(&ctx, 0, sizeof(ctx));
	memset(&setf, 0, sizeof(setf));

	/*
	 * must use kernel interface directly
	 */
	fd = pfm_create_context(&ctx, NULL, NULL, 0);
	if (fd == -1)
		return 0;

	ret = pfmon_getinfo_evtsets(fd, &setf, 1, &error);
	if (ret == 0) {
		for(i=0; i < PFM_PMC_BV; i++) {
			for(j=0; j < 64; j++) {
				if ((setf.set_avail_pmcs[i] & (1ULL << j)) == 0)
					pfm_regmask_set(r_pmcs, (i<<6)+j);
			}
		}
	}
	vbprintf("unavailable_pmcs=0x%lx\n", r_pmcs->bits[0]);
	close(fd);
	return 0;
}


/*
 * NPTL:
 * 	getpid() identical for all thread
 * 	gettid() unique for each thread
 * LinuxThreads:
 * 	getpid() unique for each thread
 *	gettid() undefined by library, could be getpid()
 *
 * To avoid issues between NPTL and LinuxThreads, we hardcode gettid() 
 * to always return the value managed by the kernel.
 *
 * Kernel (independent of thread package):
 * 	sys_gettid(): kernel task->pid
 * 	sys_getpid(): kernel task->tgid
 * 	first task in group is such that task->tgid == task->pid
 */
pid_t
gettid(void)
{
	return (pid_t)syscall(__NR_gettid);
}

/*
 * we define our own syscall entries because depending on the version
 * of glibc the affinity calls are supported with a different API.
 * In other words, there is a glibc interface that then maps onto
 * the kernel interface which has been stable for quite some time now.
 */
int
__pfmon_set_affinity(pid_t pid, size_t size, pfmon_bitmask_t mask)
{
	return (int)syscall(__NR_sched_setaffinity, pid, size, mask);
}

int
__pfmon_get_affinity(pid_t pid, size_t size, pfmon_bitmask_t mask)
{
	return (int)syscall(__NR_sched_getaffinity, pid, size, mask);
}

void
pfmon_print_tid(FILE *fp, pid_t tid)
{
	char tmp1[PFMON_MAX_FILENAME_LEN];
	char tmp2[PFMON_MAX_FILENAME_LEN];
	int l;

	if (tid == 0) {
		fprintf(fp, " (idle,0)");
		return;
	}

	sprintf(tmp1, "/proc/%d/exe", tid);
	l = readlink(tmp1, tmp2, sizeof(tmp2));
	if (l > 0) {
		tmp2[l] = '\0';
		fprintf(fp, " (%s,%d)", tmp2, tid);
	} else {
		sprintf(tmp1, "/proc/%d/stat", tid);
		FILE *tfp = fopen(tmp1,"r");
		if (tfp == NULL)
			fprintf(fp, " (%d)", tid);
		else {
			int ti;
			if (fscanf(tfp, " %d (%s) ", &ti, tmp2) == 2) {
				strtok(tmp2,")");
				fprintf(fp, " (%s,%d)", tmp2, tid);
			} else
				fprintf(fp, " (%d)", tid);
			fclose(tfp);
		}
	}
}

void
pfmon_print_quit_reason(pfmon_quit_reason_t q)
{
	switch(q) {
		case QUIT_NONE:
			return;
		case QUIT_CHILD:
			printf("session terminated by child process termination\n"); 
			break;
		case QUIT_TIMEOUT:
			printf("session terminated by timeout expiration\n"); 
			break;
		case QUIT_ABORT:
			printf("session terminated by interruption from user\n"); 
			break;
		case QUIT_TERM:
			printf("session terminated by SIGTERM\n"); 
			break;
		case QUIT_ERROR:
			printf("session terminated by unrecoverable error\n"); 
			break;
		default:
			printf("session terminated for unknown reason\n"); 
			break;
	}
}
