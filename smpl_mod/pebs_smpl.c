/*
 * pebs_hist_smpl.c - Intel Core PEBS support IP-based histogram
 *
 * Copyright (c) 2006-2007 Hewlett-Packard Development Company, L.P.
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

#include <perfmon/perfmon_pebs_core_smpl.h>

typedef struct {
	pfmon_hash_key_t key;
	uint64_t	 count;
	unsigned int	 is_base;
} hash_data_t;

typedef struct {
	hash_data_t 	**tab;
	unsigned long 	pos;
	uint64_t	total_count;
	uint64_t	max_count;
} hash_sort_arg_t;

static int
pebs_process_samples(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl;
	pfm_pebs_core_smpl_hdr_t *hdr;
	pfm_pebs_core_smpl_entry_t *ent;
	FILE *fp;
	uint64_t count, entry, skip;
	void *hash_desc, *data;
	hash_data_t *hash_entry;
	pfmon_hash_key_t key;
	uint32_t current_map_version;
	int ret;

	csmpl      = &sdesc->csmpl;
	fp         = csmpl->smpl_fp;
	hash_desc  = csmpl->data;
	entry      = csmpl->entry_count;
	hdr	   = csmpl->smpl_hdr;

	if (hdr == NULL)
		return -1;

	count = (hdr->ds.pebs_index - hdr->ds.pebs_buf_base)/sizeof(*ent);
	ent   = (pfm_pebs_core_smpl_entry_t *)((unsigned long)(hdr+1)+ hdr->start_offs);
	current_map_version = sdesc->current_map_version;

	DPRINT(("count=%"PRIu64" entry=%"PRIu64"\n", count, entry));

	/*
 	 * check if we have new entries
 	 * if so skip the old entries and process only the new ones
 	 */
	if((csmpl->last_ovfl == hdr->overflows && csmpl->last_count <= count)
	  || ((csmpl->last_ovfl+1) == hdr->overflows && csmpl->last_count < count)) {
		skip = csmpl->last_count;
		vbprintf("skip %"PRIu64" samples out of %"PRIu64" (overflows: %"PRIu64")\n",
			  skip,
			  count,
			  hdr->overflows);
	} else {
		skip = 0;
	}
	/*
 	 * only account for new entries, i.e., skip leftover entries
 	 */
	if (options.opt_aggr) {
		*csmpl->aggr_count += count - skip;
	} else {
		csmpl->entry_count += count - skip;
	}

	csmpl->last_count = count;
	csmpl->last_ovfl = hdr->overflows;

	/*
 	 * used for system-wied
 	 */
	key.pid = 0;
	key.tid = 0;

	while(count--) {
		DPRINT(("entry %06"PRIu64" IP:0x%llx\n", entry, ent->ip));

		/*
		 * PEBS does not record pid, therefore we need to ignore it
		 * it cannot be set to 0 because this is used by pfm_find_by_apv()
		 * to identify the kernel. So we use pid=tid=1 instead
		 */
		key.val = ent->ip;

		if (!options.opt_syst_wide) {
			key.pid = sdesc->pid;
			key.tid = sdesc->tid;
		}
		key.version = current_map_version;

		/*
		 * in aggregation mode sample processing is serialized,
		 * therefore we are safe to use a single hash_table here
		 */
		if(skip){
			skip--;
		} else {
			ret = pfmon_hash_find(hash_desc, key, &data);
			if (ret == -1) {
				pfmon_hash_add(hash_desc, key, &data);
				hash_entry = data;
				hash_entry->count = 0;
				hash_entry->key = key;
			} else
				hash_entry = data;
			hash_entry->count++;
			entry++;
		}
		ent++;
	}
	return 0;
}

pfmon_smpl_module_t pebs_smpl_module;
static void pebs_initialize_mask(void)
{
	pfmon_bitmask_set(pebs_smpl_module.pmu_mask, PFMLIB_CORE_PMU);
}


static int
pebs_hist_print_header(pfmon_sdesc_t *sdesc)
{
	FILE *fp = sdesc->csmpl.smpl_fp;

	fprintf(fp, "# description of columns:\n"
		    "#\tcolumn  1: number of samples for this address\n"
	 	    "#\tcolumn  2: relative percentage for this address\n"
		    "#\tcolumn  3: cumulative percentage up to this address\n"
		    "#\tcolumn  4: symbol name or address\n");
	return 0;
}

static int
pebs_hist_validate_events(pfmon_event_set_t *set)
{
	/*
	 * must be sampling with one event only for PEBS
	 */
	if (set->inp.pfp_event_count > 1) {
		warning("the sampling module works with 1 event at a time only\n");
		return -1;
	}
	/*
 	 * PEBS hardware does write samples directly into a memory region with OS
 	 * intervention. PEBS hardware does not randomize the sampling period.
 	 * Thus, at best, we could randomize on buffer overflows. Currently, the
 	 * PEBS kernel sampling format does ntot support this mode. Thus we cannot
 	 * really support randomization.
 	 */
	if (set->master_pd[0].reg_flags & PFM_REGFL_RANDOM) {
		warning("by construction, randomization cannot be used with PEBS\n");
		return -1; 
	}
	/*
	 * PEBS does not record pid in each sample, thus there is no way to reliably
	 * correlate addresses to samples in system-wide mode. Thus we enforce the
	 * --smpl-ignore-pids to make sure users do understand the limitation.
	 */
	if (options.opt_syst_wide && options.opt_smpl_nopid == 0) {
		if (set->inp.pfp_events[0].plm != PFM_PLM0) {
			warning("In system-wide mode, the pid information is ignored. As a consequence,\n"
					"this sampling format only works when capturing kernel level ONLY events.\n"
					"Use --smpl-ignore-pids to override\n");
			return -1;
		}
	}
	return 0;
}

static int
pebs_hist_initialize_session(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	void *hash_desc;
	pfmon_hash_param_t param;

	param.hash_log_size = 12;
	param.max_entries   = ~0;
	param.entry_size    = sizeof(hash_data_t);
	param.shifter	    = 0;
	param.flags	    = PFMON_HASH_ACCESS_REORDER;

	pfmon_hash_alloc(&param, &hash_desc);

	csmpl->data = hash_desc;
	DPRINT(("initialized session for csmpl=%p data=%p\n", csmpl, csmpl->data));
	return 0;
}

static void
pebs_hist_print_data(void *arg, void *data)
{
	hash_data_t *p = (hash_data_t *)data;
	hash_sort_arg_t *sort_arg = (hash_sort_arg_t *)arg;
	hash_data_t **tab = sort_arg->tab;
	unsigned long pos = sort_arg->pos;
	uint64_t count;

	count = p->count;
	tab[pos] = p;

	sort_arg->pos = ++pos;
	sort_arg->total_count += count;

	if (count > sort_arg->max_count) sort_arg->max_count = count;
}

static int
hash_data_sort_cmp(const void *a, const void *b)
{
	hash_data_t **e1 = (hash_data_t **)a;
	hash_data_t **e2 = (hash_data_t **)b;

	return (*e1)->count > (*e2)->count ? 0 : 1;
}

static int
hash_data_sort_byaddr(const void *a, const void *b)
{
	hash_data_t **e1 = (hash_data_t **)a;
	hash_data_t **e2 = (hash_data_t **)b;

	return (*e1)->key.val > (*e2)->key.val ? 1 : 0;
}

static void
pebs_hist_collapse_func(hash_data_t **tab, unsigned long num_entries)
{
	unsigned long i, j;
	unsigned long start, end;
	hash_data_t *p, *psrc = NULL;
	int ret = -1;
	char **nametab;
	char **symtab;

	nametab = calloc(num_entries, sizeof(char *));
	symtab = calloc(num_entries, sizeof(char *));

	for(i=0; i < num_entries; i++) {
		p = tab[i];
		/*
 		 * accumulate counts to first sample for the function
 		 */
		if (ret == 0 && p->key.val >= start && p->key.val < end && (p->key.version == psrc->key.version)) {
			psrc->count += p->count;
			p->count = 0;
			continue;
		}
		/*
 		 * look for a new function to use as a base
 		 * keep track of the address of the symbol name and module name
 		 */
		ret = find_sym_by_apv(p->key.val,
				p->key.tid,
				p->key.version,
				options.primary_syms,
				PFMON_TEXT_SYMBOL,
				&symtab[i], &nametab[i], &start, &end);
		if (ret == -1)
			continue; /* not found */

		/*
 		 * set new function base
 		 */
		p->key.val = start;
		p->is_base = 1;
		psrc = p;
	}
	/*
 	 * accumulate all instances of the same module:symbol to the first instance.
 	 * example:
 	 * 	1000 samples for foo.c:bar() each module version=1
 	 * 	2000 samples for foo.c:bar() each module version=10 
 	 * 	----
 	 * 	3000 samples total for foo.c:bar()
 	 */
	for(i=0; i < num_entries; i++) {
		if(!symtab[i])
			continue;

		for(j=0; j < i; j++) {
			if(symtab[i] == symtab[j] && nametab[i] == nametab[j]) {
				tab[j]->count += tab[i]->count;
					tab[i]->count = 0;
					tab[i]->is_base = 0;
				j = i;
			}
		}
	}
	free(nametab);
	free(symtab);
}

static int
pebs_hist_show_results(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl;
	uint64_t total_count, cum_count, count, top_num;
	FILE *fp;
	void *hash_desc;
	double d_cum, cum_total;
	hash_data_t **tab;
	unsigned long addr, ns = 0;
	unsigned long i, num_entries;
	hash_sort_arg_t arg;
	size_t len;
	int need_resolve;
	char buf[32];

	csmpl = &sdesc->csmpl;
	hash_desc = csmpl->data;
	fp = csmpl->smpl_fp;

	if (hash_desc == NULL)
		return -1;

	pfmon_hash_num_entries(hash_desc, &num_entries);

	tab = (hash_data_t **)malloc(sizeof(hash_data_t *)*num_entries);
	if (tab == NULL) {
		warning("cannot allocate memory to print %lu samples\n", num_entries);
		return -1;
	}
	memset(&cum_count, 0, sizeof(cum_count));
	memset(&arg, 0, sizeof(arg));
	arg.tab = tab;
	arg.pos = 0;
	arg.total_count = 0;
	arg.max_count   = 0;

	pfmon_hash_iterate(csmpl->data, pebs_hist_print_data, &arg);

	total_count = arg.total_count;
	cum_count   = 0;

	sprintf(buf, "%"PRIu64, arg.max_count);
	len = strlen(buf);
	/* adjust for column heading */
	if (len < 6)
		len = 6;

	if (options.opt_smpl_per_func) {
		qsort(tab, num_entries, sizeof(hash_data_t *), hash_data_sort_byaddr);
		pebs_hist_collapse_func(tab, num_entries);
	}
	qsort(tab, num_entries, sizeof(hash_data_t *), hash_data_sort_cmp);

	need_resolve = options.opt_addr2sym;
	top_num = options.smpl_show_top;
	if (!top_num)
		top_num = num_entries;

	if (options.opt_syst_wide)
		fprintf(fp, "# results for CPU%u\n", sdesc->cpu);
	else
		fprintf(fp, "# results for [%d<-[%d]] (%s)\n", sdesc->pid, sdesc->ppid, sdesc->cmdline);

	fprintf(fp, "# total samples          : %"PRIu64"\n", csmpl->entry_count);
	fprintf(fp, "# total buffer overflows : %"PRIu64"\n#\n#", csmpl->last_ovfl);

	if (need_resolve)
		fprintf(fp, "# %*s   %%self    %%cum %*s symbol\n",
			(int)len, "counts",
			(int)(2+(sizeof(unsigned long)<<1)),
			"code addr");
	else
		fprintf(fp, "# %*s   %%self    %%cum %*s\n",
			(int)len, "counts",
			(int)(2+(sizeof(unsigned long)<<1)),
			"code addr");

	len+=2;
	for(i=0; i < num_entries; i++) {

		addr       = tab[i]->key.val;
		count      = tab[i]->count;

		if (options.opt_smpl_per_func && !tab[i]->is_base) 
			continue;

		if (count == 0)
			continue; /* can happen in per-function mode */

		cum_count += count;
		d_cum	   = (double)count*100.0 / (double)total_count;
		cum_total  = (double)cum_count*100.0 / (double)total_count;

		if (cum_total > (double)options.smpl_cum_thres)
			break;

		fprintf(fp, "%*"PRIu64" %6.2f%% %6.2f%% 0x%0*lx ",
			    (int)len, 
			    count, 
			    d_cum,
			    (double)cum_count*100.0 / (double)total_count,
			    (int)(sizeof(unsigned long)<<1),
			    addr);

		if (need_resolve)
			pfmon_print_address(fp,
					    options.primary_syms,
					    PFMON_TEXT_SYMBOL,
					    addr,
					    0,
					    tab[i]->key.version);
		fputc('\n', fp);

		/*
 		 * exit after n samples have been printed
 		 */
		if (++ns == top_num)
			break;
	}

	free(tab);

	return 0;
}

static int
pebs_hist_terminate_session(pfmon_sdesc_t *sdesc)
{
	pebs_hist_show_results(sdesc);

	pfmon_hash_free(sdesc->csmpl.data);
	sdesc->csmpl.data = NULL;
	return 0;
}

static int
pebs_init_ctx_arg(pfmon_ctx_t *ctx, unsigned int max_pmds_sample)
{
#define ENTRY_SIZE(npmd,ez)	((ez)+((npmd)*sizeof(uint64_t)))
	pfm_pebs_core_smpl_arg_t *ctx_arg_core;
	size_t entry_size, pmu_max_entry_size;
	size_t buf_size, ctx_arg_size;
	size_t smpl_entry_size, hdr_size;
	int ret;

	smpl_entry_size = sizeof(pfm_pebs_core_smpl_entry_t);
	hdr_size = sizeof(pfm_pebs_core_smpl_hdr_t);
	ctx_arg_size = sizeof(pfm_pebs_core_smpl_arg_t);

	/*
	 * samples may have different size, max_pmds_samples represent the
	 * largest sample for the measurement.
	 */
	entry_size         = ENTRY_SIZE(0, smpl_entry_size);
	pmu_max_entry_size = ENTRY_SIZE(0, smpl_entry_size);
	
	/*
 	 * PEBS is using fixed size samples. Therefore we can use a 0 slack
 	 * argument. However, PEBS requires 256-byte alignment for the buffer.
 	 * The kernel format is adding 256 to any buffer size to ensure it can
 	 * get to that alignment. Thus we need to simulate this using the slack
 	 * factor but we DO NOT include it in the buf_size request, the kernel
 	 * will do that, otherwise, the 256 bytes are added twice and we can get
 	 * over the RLIMIT_MEMLOCK
	 */
	ret = pfmon_compute_smpl_entries(hdr_size, entry_size, 256);
	if (ret == -1)
		return -1;

	buf_size = hdr_size + options.smpl_entries*entry_size;

	vbprintf("sampling buffer #entries=%lu size=%zu, max_entry_size=%zu\n",
		 options.smpl_entries, buf_size, entry_size);

	/*
	 * ctx_arg is freed in pfmon_create_context().
	 */
	ctx_arg_core = calloc(1, ctx_arg_size);
	if (ctx_arg_core == NULL) {
		warning("cannot allocate format argument\n");
		return -1;
	}
	ctx->ctx_arg = ctx_arg_core;
	ctx->ctx_arg_size = ctx_arg_size;
	ctx->ctx_map_size = buf_size;

	ctx_arg_core->buf_size = buf_size;
	ctx_arg_core->intr_thres = (buf_size/smpl_entry_size)*90/100;
	ctx_arg_core->cnt_reset = options.sets->long_rates[0].value;

	return 0;
}

pfmon_smpl_module_t pebs_smpl_module = {
	.name		    = "pebs",
	.description	    = "Intel Core PEBS sampling",
	.process_samples    = pebs_process_samples,
	.initialize_mask    = pebs_initialize_mask,
	.init_ctx_arg	    = pebs_init_ctx_arg,
	.initialize_session = pebs_hist_initialize_session,
	.terminate_session  = pebs_hist_terminate_session,
	.print_header       = pebs_hist_print_header,
	.validate_events    = pebs_hist_validate_events,
	.flags		    = PFMON_SMPL_MOD_FL_PEBS|PFMON_SMPL_MOD_FL_DEF_SYM,
	.fmt_name	    = PFM_PEBS_CORE_SMPL_NAME
};
