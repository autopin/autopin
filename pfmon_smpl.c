/*
 * pfmon_smpl.c - sampling support for pfmon
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

#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>

#include "pfmon_smpl.h"

static pfmon_smpl_module_t *smpl_modules[]={
	&inst_hist_smpl_module,		/* works for any PMU model */
	&detailed_smpl_module,		/* works for any PMU model */
	&compact_smpl_module,		/* works for any PMU model */
	&raw_smpl_module,		/* works for any PMU model */
#if defined(CONFIG_PFMON_I386) || defined(CONFIG_PFMON_X86_64)
	&pebs_smpl_module,
#endif

#ifdef CONFIG_PFMON_IA64
	&dear_hist_ia64_smpl_module,

	&inst_hist_old_smpl_module,	/* for perfmon v2.0 */
	&detailed_old_smpl_module,	/* for perfmon v2.0 (must be first for old modules) */
	&dear_hist_ia64_old_smpl_module,/* for perfmon v2.0 */
	&compact_old_smpl_module,	/* for perfmon v2.0 */
	&raw_old_smpl_module,		/* for perfmon v2.0 */
#endif
	NULL
};

void
pfmon_smpl_initialize(void)
{
	pfmon_smpl_module_t *mod, **p;

	for(p= smpl_modules; *p; p++)
		(*p)->initialize_mask();

	/*
	 * pick a default sampling output format
	 */
	if (pfmon_find_smpl_module(NULL, &mod, 0) != 0)
		return;

	if (mod->initialize_module && (*mod->initialize_module)() != 0) {
		fatal_error("failed to intialize sampling module%s\n", mod->name);
	}
	options.smpl_mod = mod;
}

/*
 * sdesc is NULL when aggregation is used
 */
static void
print_smpl_header(pfmon_sdesc_t *sdesc)
{
	FILE *fp = sdesc->csmpl.smpl_fp;
	pfmon_event_set_t *set;
	unsigned int i, j;
	char name[PFMON_MAX_EVTNAME_LEN];

	print_standard_header(fp, sdesc);

	for(set = sdesc->sets; set; set = set->next) {

		fprintf(fp, "# sampling information for set%u:\n", set->id);

		for(i=0; i < set->event_count; i++) {

			if ((set->short_rates[i].flags & PFMON_RATE_VAL_SET) == 0) continue;

			pfm_get_event_name(set->inp.pfp_events[i].event, name, PFMON_MAX_EVTNAME_LEN);

			fprintf(fp, "# recorded PMDs when %s overflows: ", name);

			for(j=0; j < PFM_MAX_PMDS; j++)
				if (pfmon_bv_isset(set->smpl_pmds[i], j)) fprintf(fp, "PMD%u ", j);

			fputc('\n', fp);
		}
		fprintf(fp, "#\n# short sampling rates (base/mask/seed):\n");
		for(i=0; i < set->event_count; i++) {
			pfm_get_event_name(set->inp.pfp_events[i].event, name, PFMON_MAX_EVTNAME_LEN);

			if (set->short_rates[i].flags & PFMON_RATE_VAL_SET) {
				fprintf(fp, "#\t%s %"PRIu64,
						name,
						-set->short_rates[i].value);

				if (set->short_rates[i].flags & PFMON_RATE_MASK_SET) {
					fprintf(fp, "/0x%"PRIx64"/%u",
							set->short_rates[i].mask,
							set->short_rates[i].seed);
				}
				fputc('\n', fp);
			} else {
				fprintf(fp, "#\t%s none\n", name); 
			}
		}
		fprintf(fp, "#\n# long sampling rates (base/mask/seed):\n");
		for(i=0; i < set->event_count; i++) {
			pfm_get_event_name(set->inp.pfp_events[i].event, name, PFMON_MAX_EVTNAME_LEN);

			if (set->long_rates[i].flags & PFMON_RATE_VAL_SET) {
				fprintf(fp, "#\t%s %"PRIu64,
						name,
						-set->long_rates[i].value);

				if (set->long_rates[i].flags & PFMON_RATE_MASK_SET) {
					fprintf(fp, "/0x%"PRIx64"/%u", 
							set->long_rates[i].mask,
							set->long_rates[i].seed);
				}
				fputc('\n', fp);
			} else {
				fprintf(fp, "#\t%s none\n", name); 
			}
		}
		fprintf(fp, "#\n#\n");
	}

	/* 
	 * invoke additional header printing routine if defined
	 */
	if (options.smpl_mod->print_header)
		(*options.smpl_mod->print_header)(sdesc);

	fprintf(fp, "#\n#\n");
}
static pthread_mutex_t smpl_results_lock = PTHREAD_MUTEX_INITIALIZER;

static int
__pfmon_process_smpl_buffer(pfmon_sdesc_t *sdesc, int is_final)
{
	pfmon_smpl_module_t *mod = options.smpl_mod;
	int ret = 0;
	int need_lock;

	need_lock = sdesc->csmpl.smpl_fp == stdout ? 1 : 0;
	/*
	 * if necessary, verify we are not parsing the same samples again
	 */
	if (mod->check_new_samples) {
		ret = (*mod->check_new_samples)(sdesc);
		DPRINT(("check_new_samples=%d\n", ret));
		if (ret) return ret;
	}
	/*
	 * in case we output directly to the screen we synchronize
	 * to avoid concurrent printf()
	 */
	if (need_lock) {
		pthread_mutex_lock(&smpl_results_lock);
	}

	ret = (*options.smpl_mod->process_samples)(sdesc);

	if (need_lock) {
		pthread_mutex_unlock(&smpl_results_lock);
	}
	return ret;
}

/*
 * setup aggregated sampling output data structure (shared state)
 */
int
pfmon_setup_aggr_sampling_output(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
        FILE *fp = stdout;
	char *filename;
	int ret;

	filename = options.smpl_outfile;

	if (options.opt_use_smpl == 0 || options.opt_aggr == 0) return 0;

        if (options.smpl_outfile) {
                fp = fopen(filename, "w");
                if (fp == NULL) {
                        warning("cannot create sampling output file %s: %s\n", filename, strerror(errno));
                        return -1;
                }
                if (options.opt_syst_wide)
			vbprintf("CPU%-3u sampling results will be in file \"%s\"\n", csmpl->cpu, filename);
		else
			vbprintf("sampling results will be in file \"%s\"\n", filename);
        }

        csmpl->smpl_fp    = fp;
	csmpl->last_ovfl  = ~0;
	csmpl->last_count = ~0;

	/* 
	 * sampling module session initialization
	 */
	if (options.smpl_mod->initialize_session) {
		ret = (*options.smpl_mod->initialize_session)(sdesc); 
		if (ret == -1) { 
			if (fp != stdout) fclose(fp); 
			return -1;
		}
	}

	if (options.opt_with_header) print_smpl_header(sdesc);

        return 0;
}

/*
 * setup session private data structure (private state in aggregated mode)
 */
int
pfmon_setup_sampling_output(pfmon_sdesc_t *sdesc, pfmon_sdesc_t *sdesc_aggr)
{
        FILE *fp = stdout;
	int ret;
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
        char filename[PFMON_MAX_FILENAME_LEN];

	if (options.opt_use_smpl == 0) return 0;

	/*
	 * check version
	 */
	if (options.smpl_mod->check_version)
		if ((*options.smpl_mod->check_version)(sdesc) == -1) return -1;

	csmpl->last_ovfl  = ~0;
	csmpl->last_count = ~0;
	csmpl->entry_count = 0;

	/*
	 * We must initialize sym_hash, last_ovfl, last_count 
	 * which are private to each session. 
	 * the rest (fp, entry_count, initialize_session) is shared 
	 * from the aggregated structure.
	 */
	if (options.opt_aggr) {
		csmpl->smpl_fp    = sdesc_aggr->csmpl.smpl_fp;
		csmpl->aggr_count = &sdesc_aggr->csmpl.entry_count;
		csmpl->data       = sdesc_aggr->csmpl.data;
		return 0;
	} 

        if (options.smpl_outfile) {
                if (is_regular_file(options.smpl_outfile)) {
                    	if (options.opt_syst_wide) {
				sprintf(filename, "%s.cpu%u", options.smpl_outfile, csmpl->cpu);
			} else {
				if (options.opt_follows) {
					if (options.opt_split_exec) {
						sprintf(filename, "%s.%d.%d.%u", 
							options.smpl_outfile, 
							sdesc->pid, 
							sdesc->tid, 
							sdesc->exec_count);
					} else {
						sprintf(filename, "%s.%d.%d", 
							options.smpl_outfile, 
							sdesc->pid, 
							sdesc->tid);
					}
				} else {
					sprintf(filename, "%s", options.smpl_outfile);
				}
			}
                } else {
                        strcpy(filename, options.smpl_outfile);
                }

                fp = fopen(filename, "w");
                if (fp == NULL) {
                        warning("cannot create private sampling output file %s: %s\n", filename, strerror(errno));
                        return -1;
                }
                if (options.opt_syst_wide) 
			vbprintf("CPU%-3u results will be in file \"%s\"\n", csmpl->cpu, filename);
		else
			vbprintf("[%d] sampling results will be in file \"%s\"\n", sdesc->tid, filename);
        }
	csmpl->smpl_fp = fp;

	/* 
	 * sampling module session initialization
	 */
	if (options.smpl_mod->initialize_session) {
		ret = (*options.smpl_mod->initialize_session)(sdesc); 
		if (ret == -1) { 
			if (fp != stdout) fclose(fp); 
			return -1;
		}
	}

	if (options.opt_with_header)
		print_smpl_header(sdesc);

        return 0;
}

void
pfmon_close_aggr_sampling_output(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	if (options.smpl_mod->terminate_session)
		options.smpl_mod->terminate_session(sdesc);

	if (csmpl->smpl_fp && csmpl->smpl_fp != stdout) {
		vbprintf("%"PRIu64" samples collected\n", csmpl->entry_count);
		fclose(csmpl->smpl_fp);
	}
}

void
pfmon_close_sampling_output(pfmon_sdesc_t *sdesc, pid_t tid, unsigned int cpu)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	uint64_t count;
	int need_lock;


	if (options.opt_aggr) return;

	need_lock = sdesc->csmpl.smpl_fp == stdout ? 1 : 0;

	if (need_lock) {
		pthread_mutex_lock(&smpl_results_lock);
	}

	if(!options.opt_addr2sym || options.opt_syst_wide)
		if (options.smpl_mod->terminate_session)
			options.smpl_mod->terminate_session(sdesc);
	
	if (need_lock) {
		pthread_mutex_unlock(&smpl_results_lock);
	}

	if (options.opt_aggr == 0 && csmpl->smpl_fp && csmpl->smpl_fp != stdout) {
		count  = csmpl->entry_count;
		if (options.opt_syst_wide) {
			vbprintf("CPU%u %"PRIu64" samples collected\n", cpu, count);
		} else {
			vbprintf("[%d] %"PRIu64" samples collected (%"PRIu64 " buffer overflows)\n", 
				tid, 
				count, 
				csmpl->last_ovfl == -1 ? 0 : csmpl->last_ovfl);
		}
		if(!options.opt_addr2sym)
			fclose(csmpl->smpl_fp);
	}
}

static int
pfmon_check_smpl_module_legacy(pfm_uuid_t uuid)
{
	FILE *fp;
	char *p;
	size_t len;
	char uuid_str[64];
	char buffer[256];

	pfm_uuid2str(uuid, sizeof(uuid_str), uuid_str);

	len = strlen(uuid_str);

	fp = fopen("/proc/perfmon", "r");
	if (fp == NULL) {
		warning("unable to open /proc/perfmon\n");
		return -1; /* will fail later on if module not present */
	}
	for (;;) {
		p  = fgets(buffer, sizeof(buffer)-1, fp);

		if (p == NULL) break;

		if (strncmp("format", buffer, 6)) continue;
		p = strchr(buffer, ':');
		if (p == NULL) continue;
		if (!strncmp(p+2, uuid_str, len)) {
			DPRINT(("found uuid_str:%s:\nuuid_p:%s", uuid_str, p+2));
			fclose(fp);
			return 0;
		}

	}
	fclose(fp);
	warning("cannot find requested kernel sampling format : %s\n", uuid_str);
	return -1;
}

static int
pfmon_check_smpl_module(pfmon_smpl_module_t *smpl_mod)
{
#define SYS_KERNEL_PERFMON_FORMATS "/sys/kernel/perfmon/formats"
	DIR *dir;
	struct dirent *de;
	int ret = -1;

	if (options.opt_is22 == 0)
		return pfmon_check_smpl_module_legacy(smpl_mod->uuid);

	dir = opendir(SYS_KERNEL_PERFMON_FORMATS);
	if (dir == NULL) {
		warning("unable to open %s\n", SYS_KERNEL_PERFMON_FORMATS);
		return -1; /* will fail later on if module not present */
	}

	while(ret == -1 && (de = readdir(dir))) {
		/*
		 * skip . and ..
		 */
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		if (!strcmp(de->d_name, smpl_mod->fmt_name)) {
			DPRINT(("found format %s\n", smpl_mod->fmt_name));
			ret = 0;
		}
	}
	closedir(dir);

	if (ret == -1)
		warning("cannot find requested kernel sampling format : %s\n", smpl_mod->fmt_name);

	return ret;
}

static void
pfmon_setup_set_sampling_rates(pfmon_event_set_t *set)
{
	unsigned int cnt = 0;
	int ret;

	if (set->random_smpl_args && set->long_smpl_args == NULL && set->short_smpl_args == NULL)
		fatal_error("no short or long periods provided to apply randomization\n");

	if (set->long_smpl_args) {
		/*
		 * in case not all rates are specified, they will default to zero, i.e. no sampling
		 * on this counter
		 */
		ret = gen_smpl_rates(set->long_smpl_args, set->event_count, set->long_rates, &cnt);
		if (ret == -1) fatal_error("cannot set long sampling rates\n");

		/*
		 * in case the short period rates were not specified, we copy them from the long period rates
		 */
		if (set->short_smpl_args == NULL)
			memcpy(set->short_rates, set->long_rates, cnt*sizeof(pfmon_smpl_rate_t));
	}

	if (set->short_smpl_args) {
		/*
		 * in case not all rates are specified, they will default to zero, i.e. no sampling
		 * on this counter
		 */
		ret = gen_smpl_rates(set->short_smpl_args, set->event_count, set->short_rates, &cnt);
		if (ret == -1) fatal_error("cannot set short sampling rates\n");


		/*
		 * in case the long period rates were not specified, we copy them from the short period rates
		 */
		if (set->long_smpl_args == NULL)
			memcpy(set->long_rates, set->short_rates, cnt*sizeof(pfmon_smpl_rate_t));
	}

	if (options.opt_use_smpl && options.interval != PFMON_NO_TIMEOUT) 
		fatal_error("cannot use --print-interval when sampling\n");

	if (set->random_smpl_args) {
		/*
		 * we place the masks/seeds into the long rates table. It is always defined
		 */
		ret = gen_smpl_randomization(set->random_smpl_args, set->event_count, set->long_rates, &cnt);
		if (ret == -1) fatal_error("cannot setup randomization parameters\n");

		/* propagate mask/seed to short rates */
		for(cnt = 0; cnt < set->event_count; cnt++) {
			set->short_rates[cnt].mask  = set->long_rates[cnt].mask;
			set->short_rates[cnt].seed  = set->long_rates[cnt].seed;
			set->short_rates[cnt].flags = set->long_rates[cnt].flags;
		}
	}
	
	if (options.opt_verbose) {
		unsigned int i;

		vbprintf("long  sampling periods(val/mask/seed): ");
		for(i=0; i < set->event_count; i++) {
			vbprintf("%"PRIu64"/0x%"PRIx64"/%u", 
					-set->long_rates[i].value,
					set->long_rates[i].mask,
					set->long_rates[i].seed);
		}
		vbprintf("\nshort sampling periods(val/mask/seed): ");
		for(i=0; i < set->event_count; i++) {
			vbprintf("%"PRIu64"/0x%"PRIx64"/%u", 
					-set->short_rates[i].value,
					set->short_rates[i].mask,
					set->short_rates[i].seed);
		}
		vbprintf("\n");
	}
}

void 
pfmon_setup_sampling_rates(void)
{
	pfmon_event_set_t *set;

	for (set = options.sets; set; set = set->next) {
		pfmon_setup_set_sampling_rates(set);
	}

	/*
	 * this is a limitation of the tool, not the perfmon2 interface
	 */
	if (options.nsets > 1 && options.opt_use_smpl) 
		fatal_error("combining event multiplexing with sampling, not supported by pfmon\n");

	/* 
	 * nothing else to do, we are not sampling
	 */
	if (options.opt_use_smpl == 0) return;

	/*
	 * some extra sanity checks now that we know we are sampling
	 */
	if (options.opt_addr2sym && options.opt_syst_wide)
		warning("only kernel symbols are resolved in system-wide mode\n");

	/*
	 * some sanity checks
	 */
	if (options.smpl_mod == NULL) 
		fatal_error("error, no sampling module selected\n");

	if (pfmon_check_smpl_module(options.smpl_mod))
		fatal_error("cannot proceed");

	if (options.smpl_mod->process_samples == NULL)
		fatal_error("sampling module %s without sampling process entry point\n", options.smpl_mod->name);

	vbprintf("using %s sampling module\n", options.smpl_mod->name);
}

/*
 * look for a matching sampling format.
 * The name and CPU model must match.
 *
 * if ignore_cpu is true, then we don't check if the host CPU matches
 */
int
pfmon_find_smpl_module(char *name, pfmon_smpl_module_t **mod, int ignore_cpu)
{
	pfmon_smpl_module_t **p;
	int is22, m;

	is22 = options.opt_is22;
	m = options.pmu_type;

	for(p = smpl_modules; *p ; p++) {
		if (name == NULL || !strcmp(name, (*p)->name)) {
			if (   (is22      && ((*p)->flags & PFMON_SMPL_MOD_FL_LEGACY))
			    || (is22 == 0 && ((*p)->flags & PFMON_SMPL_MOD_FL_LEGACY) == 0)) continue;

			if (   ignore_cpu == 0
			    && pfmon_bitmask_isset((*p)->pmu_mask, m) == 0) {
				continue;
			}
			*mod = *p;
			return 0;
		}
	}
	return -1;
}

void
pfmon_list_smpl_modules(void)
{
	pfmon_smpl_module_t **p = smpl_modules;
	int type, is22;

	pfm_get_pmu_type(&type);

	is22 = options.opt_is22;

	printf("supported sampling modules: ");
	if (options.smpl_mod == NULL)
		printf("none available");
	while (*p) {	

		if (   (is22      && ((*p)->flags & PFMON_SMPL_MOD_FL_LEGACY))
		    || (is22 == 0 && ((*p)->flags & PFMON_SMPL_MOD_FL_LEGACY) == 0)
		    || (pfmon_bitmask_isset((*p)->pmu_mask, type) == 0)) {
			p++;
			continue;
		}

		printf("[%s] ", (*p)->name);
		p++;
	}
	printf("\n");
}

void
pfmon_smpl_module_info(pfmon_smpl_module_t *fmt)
{
	int i, ret;
	char name[PFMON_MAX_EVTNAME_LEN];

	printf("name        : %s\n"
	       "description : %s\n",
		fmt->name,
		fmt->description);

	printf("PMU models  : ");
	for(i=0; i < PFMON_MAX_PMUS; i++) {
		if (pfmon_bitmask_isset(fmt->pmu_mask, i)) {
			ret = pfm_get_pmu_name_bytype(i, name,PFMON_MAX_EVTNAME_LEN);
			if (ret == PFMLIB_SUCCESS)
				printf("[%s] ", name);
		}
	}
	printf("\n");
	if (fmt->show_options) {
		printf("options     :\n");
		fmt->show_options();
	}
}

int
pfmon_reset_sampling(pfmon_sdesc_t *sdesc)
{
	int ret, error;

	/* for debug purposes */
	if (options.opt_block_restart) {
		printf("<press a key to resume monitoring>\n");
		getchar();
	}
	LOCK_SDESC(sdesc);

	if (sdesc->csmpl.processing) {
		warning("[%d] race conditdion with process_samples in reset_sampling\n", sdesc->tid);
	}

	sdesc->csmpl.entry_count = 0;
	sdesc->csmpl.last_ovfl   = ~0;
	sdesc->csmpl.last_count  = ~0;

	ret = pfmon_restart(sdesc->ctxid, &error);
	UNLOCK_SDESC(sdesc);
 	return ret;
}

int
pfmon_process_smpl_buf(pfmon_sdesc_t *sdesc, int is_final)
{
	int ret, error;

	LOCK_SDESC(sdesc);

	sdesc->csmpl.processing = 1;
	ret = __pfmon_process_smpl_buffer(sdesc, is_final);

	DPRINT(("process_smpl_buf: pid=%d is_final=%d ret=%d\n", getpid(), is_final, ret));

	if (is_final == 0 && ret == 0) {
		if (options.opt_block_restart) {
			printf("<press a key to resume monitoring>\n");
			getchar();
		}
		ret = pfmon_restart(sdesc->ctxid, &error);
	}
	sdesc->csmpl.processing = 0;
	UNLOCK_SDESC(sdesc);
	return ret;
}


void
pfmon_smpl_mod_usage(void)
{
	pfmon_smpl_module_t **mod;
	int type, ret;
	int is22;

	is22 = options.opt_is22;

	ret = pfm_get_pmu_type(&type);
	if (ret != PFMLIB_SUCCESS)
		fatal_error("library not initialized\n");

	for(mod = smpl_modules; *mod; mod++) {
		if (pfmon_bitmask_isset((*mod)->pmu_mask, type) == 0) continue;

		if (   (is22      && ((*mod)->flags & PFMON_SMPL_MOD_FL_LEGACY))
		    || (is22 == 0 && ((*mod)->flags & PFMON_SMPL_MOD_FL_LEGACY) == 0)) continue;

		if ((*mod)->show_options) {
			printf("options for \"%s\" sampling format:\n", (*mod)->name);
			(*(*mod)->show_options)();
		} else {
			printf("options for \"%s\" sampling format:\n\tnone\n", (*mod)->name);
		}
	}
}

int
pfmon_smpl_init_ctx_arg(pfmon_ctx_t *ctx, unsigned int max_pmds_sample)
{
	int ret = 0;

	/*
	 * legacy: copy the module format's UUID
	 */
	if (options.opt_is22)
		ctx->fmt_name = options.smpl_mod->fmt_name;
	else
		memcpy(ctx->ctx_uuid, options.smpl_mod->uuid, sizeof(pfm_uuid_t));

	if (dfl_smpl_is_default())
		return dfl_smpl_init_ctx_arg(ctx, max_pmds_sample);

	if (options.smpl_mod->init_ctx_arg)
		ret = (*options.smpl_mod->init_ctx_arg)(ctx, max_pmds_sample);

	if (ret == 0 && options.smpl_entries == 0)
		warning("number of entries in sampling buffer is zero\n");

	return ret;
}
