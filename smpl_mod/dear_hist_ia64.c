/*
 * dear_hist_ia64.c - D-EAR histograms for all IA-64 PMU models (with D-EAR)
 *
 * Copyright (c) 2004-2006 Hewlett-Packard Development Company, L.P.
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
#include <perfmon/perfmon_dfl_smpl.h>
#include "dear_hist_ia64.h"


#define DEAR_HDR_VERSION_MAJOR	1
#define DEAR_HDR_VERSION_MINOR	0
#define DEAR_HDR_VERSION	((DEAR_HDR_VERSION_MAJOR<<8) | (DEAR_HDR_VERSION_MINOR))

#define L2C_HIT_COST	5
#define L3C_HIT_COST	10
#define RAM_HIT_COST	150

#define L2T_HIT_COST	5
#define HWT_HIT_COST	30
#define SWT_HIT_COST	200

#define VIEW_INST   1
#define VIEW_DATA   2
#define VIEW_LEVELS 3

#define OUTPUT_NORMAL 1
#define OUTPUT_BINARY 2

#define SORT_BY_COUNT 1
#define SORT_BY_VALUE 2
#define SORT_BY_LEVEL 3

typedef struct {
	int		version;
	int		mode;
	uint64_t	count; 		/* backpatched */
	uint64_t	reserved[6];
} dear_sample_hdr_t;

typedef struct {
	int		output_mode;	/* data, inst, levels */
	int		view_mode;	/* data, inst, levels */
	int		sort_mode;	
	size_t		sample_size;
	dear_mode_t	mode;
	unsigned int	l2_latency;
	unsigned int	l3_latency;
} dear_hist_options_t;

#define DEAR_HIST_MAX_LVL_COUNT	3		/* how many levels in memory hierarchy or tlb handlers */
typedef struct {
		pfmon_hash_key_t key;
		uint64_t	 count;
		uint64_t	 level_counts[DEAR_HIST_MAX_LVL_COUNT];
} hash_data_t;

typedef struct {
	hash_data_t 	**tab;
	unsigned long 	pos;
	uint64_t	total_count;
	uint64_t	avg_sum;
	uint64_t	max_count;
} hash_sort_arg_t;

static dear_hist_options_t dear_hist_options;

static unsigned long (*dear_extract)(unsigned long *pmd, dear_sample_t *smpl);
static int  (*dear_info)(int event, dear_mode_t *mode);

static int
dear_hist_process_samples_binary(pfmon_sdesc_t *sdesc)
{
	pfm_dfl_smpl_hdr_t *hdr;
	pfm_dfl_smpl_entry_t *ent;
	pfmon_smpl_desc_t *csmpl;
	unsigned long *pmd;
	uint64_t entry, count, skip, i;
	FILE *fp;
	dear_sample_t sample;
	void *pos;
	size_t	sample_size;
	int ret, mode;

	csmpl = &sdesc->csmpl;
	hdr   = csmpl->smpl_hdr;
	fp    = csmpl->smpl_fp;

	if (hdr == NULL)
		return -1;

	pos	    = hdr+1;
	entry       = options.opt_aggr ? *csmpl->aggr_count : csmpl->entry_count;
	count       = hdr->hdr_count;
	sample_size = dear_hist_options.sample_size;
	mode        = dear_hist_options.mode;

	DPRINT(("count=%"PRIu64" entry=%"PRIu64"\n", count, entry));

	/*
 	 * check if we have new entries
 	 * if so skip the old entries and process only the new ones
 	 */
	if((csmpl->last_ovfl == hdr->hdr_overflows && csmpl->last_count <= count)
	  || ((csmpl->last_ovfl+1) == hdr->hdr_overflows && csmpl->last_count < count)) {
		skip = csmpl->last_count;
		vbprintf("skip %"PRIu64" samples out of %"PRIu64" (overflows: %"PRIu64")\n",
			  skip,
			  count,
			  hdr->hdr_overflows);
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
	csmpl->last_ovfl = hdr->hdr_overflows;

	for(i=0; i < count; i++, pos+= sample_size) {

		ent = pos;

		DPRINT(("entry %lu PID:%d TID:%d CPU:%d STAMP:0x%lx IIP: %p\n",
			entry,
			ent->tgid,
			ent->pid,
			ent->cpu,
			ent->tstamp, (void *)ent->ip));

		pmd = (unsigned long *)(ent+1);

		pmd += (*dear_extract)(pmd, &sample);

		DPRINT(("daddr=%p iaddr=%p latency=%lu tlb=%lu\n",
			(void *)sample.daddr,
			(void *)sample.iaddr,
			sample.latency,
			sample.tlb_lvl));

		if(skip) {
			skip--;
		} else {
			ret = fwrite(&sample, sizeof(sample), 1, fp);
			if (ret != 1) goto error;
			entry++;
		}
	}
	return 0;
error:
	warning("cannot write to sampling file: %s\n", strerror(errno));
	return -1;
}

static int
dear_hist_process_samples_normal(pfmon_sdesc_t *sdesc)
{
	pfm_dfl_smpl_hdr_t *hdr;
	pfm_dfl_smpl_entry_t *ent;
	pfmon_smpl_desc_t *csmpl;
	unsigned long *pmd;
	dear_sample_t sample;
	uint64_t entry, skip, count, i;
	unsigned long addr;
	unsigned int l2_latency, l3_latency;
	size_t	sample_size;
	void *hash_desc, *data;
	void *pos;
	hash_data_t *hash_entry;
	pfmon_hash_key_t key;
	int ret, mode, lvl = 0;
	int view_mode;
	uint32_t current_map_version;

	csmpl = &sdesc->csmpl;
	hdr   = csmpl->smpl_hdr;

	if (hdr == NULL)
		return -1;

        hash_desc   = csmpl->data;
	pos	    = hdr+1;
	entry       = options.opt_aggr ? *csmpl->aggr_count : csmpl->entry_count;
	count       = hdr->hdr_count;
	sample_size = dear_hist_options.sample_size;
	view_mode   = dear_hist_options.view_mode;
	mode        = dear_hist_options.mode; 
	l2_latency  = dear_hist_options.l2_latency;
	l3_latency  = dear_hist_options.l3_latency;
	current_map_version = sdesc->current_map_version;

	DPRINT(("count=%"PRIu64" entry=%"PRIu64"\n", count, entry));

	/*
 	 * check if we have new entries
 	 * if so skip the old entries and process only the new ones
 	 */
	if((csmpl->last_ovfl == hdr->hdr_overflows) && (csmpl->last_count <= count)) {	
		skip = csmpl->last_count;
		vbprintf("skip %"PRIu64" samples out of %"PRIu64" (overflows: %"PRIu64")\n",
			  skip,
			  count,
			  hdr->hdr_overflows);
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
	csmpl->last_ovfl = hdr->hdr_overflows;

	for(i=0; i < count; i++, pos += sample_size) {

		ent = (pfm_dfl_smpl_entry_t *)pos;

		DPRINT(("entry %lu PID:%d TID:%d CPU:%d STAMP:0x%lx IIP: %p\n",
			entry,
			ent->tgid,
			ent->pid,
			ent->cpu,
			ent->tstamp, (void *)ent->ip));

		pmd = (unsigned long *)(ent+1);

		pmd += (*dear_extract)(pmd, &sample);

		if (view_mode != VIEW_LEVELS) {
			if (mode == DEAR_IS_TLB)
				lvl = sample.tlb_lvl-1;
			else if (sample.latency <= l2_latency) 
				lvl = 0; /* l2 hit */
			else if (sample.latency <= l3_latency)
				lvl = 1; /* l3 hit */
			else
				lvl = 2; /* memory */
		}

		switch(view_mode) {
			case VIEW_INST: 
				addr = sample.iaddr;
				break;
			case VIEW_DATA:
				addr = sample.daddr;
				break;
			case VIEW_LEVELS:
				addr = mode == DEAR_IS_TLB ? sample.tlb_lvl : sample.latency;
				break;
			default:
				addr = 0;
		}
		key.val  = addr;
		key.pid = ent->tgid; /* process id */
		key.tid = ent->pid; /* thread id */
		key.version = current_map_version;

		DPRINT(("daddr=%p iaddr=%p addr=%p latency=%lu tlb=%lu\n",
			(void *)sample.daddr,
			(void *)sample.iaddr,
			(void *)addr,
			sample.latency,
			sample.tlb_lvl));
		/*
		 * in aggregation mode sample processing is serialized,
		 * therefore we are safe to use a single hash_table here
		 */
		if(skip) {
			skip--;
		} else {
			ret = pfmon_hash_find(hash_desc, key, &data);
			if (ret == -1) {
				pfmon_hash_add(hash_desc, key, &data);
				hash_entry = (hash_data_t *)data;
				hash_entry->count = 1;
				hash_entry->key = key;
				if (view_mode != VIEW_LEVELS) {
					hash_entry->level_counts[0] = 0;
					hash_entry->level_counts[1] = 0;
					hash_entry->level_counts[2] = 0;
				}
			} else {
				hash_entry = (hash_data_t *)data;
				hash_entry->count++;
			}

			if (view_mode != VIEW_LEVELS) {
				hash_entry->level_counts[lvl]++;
			}
			entry++;
		}
	}
	return 0;
}

static int
dear_hist_process_samples(pfmon_sdesc_t *sdesc)
{
	if (dear_hist_options.output_mode == OUTPUT_BINARY)
		return dear_hist_process_samples_binary(sdesc);

	return dear_hist_process_samples_normal(sdesc);
}


#define IDX	PFMON_OPT_SMPL_BASE
static struct option dear_hist_cmd_options[]={
	{ "smpl-inst-view", 0, &dear_hist_options.view_mode, VIEW_INST},
	{ "smpl-data-view", 0, &dear_hist_options.view_mode, VIEW_DATA},
	{ "smpl-level-view", 0, &dear_hist_options.view_mode, VIEW_LEVELS},
	{ "smpl-sort-byvalue", 0, &dear_hist_options.sort_mode, SORT_BY_VALUE},
	{ "smpl-sort-bylevel", 0, &dear_hist_options.sort_mode, SORT_BY_LEVEL},
	{ "smpl-save-raw", 0, &dear_hist_options.output_mode, OUTPUT_BINARY},
	{ NULL, 0, 0, 0}
};
#undef IDX

static void
dear_hist_show_options(void)
{
	printf( "\t--smpl-inst-view\t\tShow instruction address based histogram\n"
		"\t\t\t\t\t(default).\n"
		"\t--smpl-data-view\t\tShow data address based histogram.\n"
		"\t--smpl-level-view\t\tShow cache/tlb level based histogram.\n"
		"\t--smpl-sort-byvalue\t\tSort samples by their value.\n"
		"\t--smpl-sort-bylevel\t\tSort samples by cache/tlb hit level.\n"
		"\t--smpl-save-raw\t\t\tSave samples in binary format for\n"
		"\t\t\t\t\toffline processing.\n"
	);
}

/*
 * module initialization
 */
static int
dear_hist_initialize_module(void)
{
	pfmon_cache_info_t info;

	switch(options.pmu_type) {
		case PFMLIB_ITANIUM_PMU:
			dear_extract = dear_ita_extract;
			dear_info    = dear_ita_info;
			break;
		case PFMLIB_ITANIUM2_PMU:
			dear_extract = dear_ita2_extract;
			dear_info    = dear_ita2_info;
			break;
		case PFMLIB_MONTECITO_PMU:
			dear_extract = dear_mont_extract;
			dear_info    = dear_mont_info;
			break;
		default:
			warning("unsupported PMU model for sampling module\n");
			return -1;
	}
	/* set defaults */
	dear_hist_options.view_mode    = VIEW_INST;
	dear_hist_options.sort_mode    = SORT_BY_COUNT;
	dear_hist_options.output_mode  = OUTPUT_NORMAL;

	if (pfmon_get_cache_info(0, &info)) {
		warning("sampling module cannot extract cache info\n");
		return -1;
	}
	dear_hist_options.l2_latency= info.d_latency[1][0];
	dear_hist_options.l3_latency= info.d_latency[2][0];

	vbprintf("l2 load latency: %u l3 load latency: %u\n", 
		dear_hist_options.l2_latency,
		dear_hist_options.l3_latency);

	return pfmon_register_options(dear_hist_cmd_options, sizeof(dear_hist_cmd_options));
}

static int
dear_hist_print_header(pfmon_sdesc_t *sdesc)
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
dear_hist_validate_events(pfmon_event_set_t *set)
{
	/*
	 * must be sampling with one event only (no extra PMDS in payload)
	 */
	if (set->event_count > 1) {
		warning("sampling module works with DATA_EAR_* event only\n");
		return -1;
	}
	/*
	 * verify we have the right event
	 */
	if ((*dear_info)(set->inp.pfp_events[0].event, &dear_hist_options.mode)) {
		warning("sampling module only works with one DATA_EAR_* event at a time\n");
		return -1;
	}


	/*
	 * Assume DEAR_ALAT  uses 2 PMDs
	 *        DEAR_TLB   uses 3 PMDs
	 *        DEAR_CACHE uses 3 PMDs
	 */
	dear_hist_options.sample_size  = dear_hist_options.mode == DEAR_IS_ALAT ? 
						sizeof(pfm_dfl_smpl_entry_t)+ 16
			     		: 	sizeof(pfm_dfl_smpl_entry_t)+ 24;

	if (options.opt_smpl_per_func && dear_hist_options.view_mode != VIEW_INST
	    && dear_hist_options.sort_mode != SORT_BY_COUNT) {
		warning("--smpl-per-function only works for instruction address view and sort by count\n");
		return -1;
	}
	return 0;
}

static int
dear_hist_initialize_session(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	dear_sample_hdr_t dear_hdr;
	void *hash_desc;
	pfmon_hash_param_t param;
	size_t ret;

	if (dear_hist_options.output_mode == OUTPUT_BINARY) {
		dear_hdr.version = DEAR_HDR_VERSION;
		dear_hdr.mode    = dear_hist_options.mode;
		dear_hdr.count   = 0;

		/* write partial header (reserve space) */
		ret = fwrite(&dear_hdr, sizeof(dear_hdr), 1, csmpl->smpl_fp);

		return ret == 1 ? 0 : -1;
	} 

	param.hash_log_size = 12;
	param.max_entries   = ~0;
	param.entry_size    = sizeof(hash_data_t);
	param.shifter	    = dear_hist_options.view_mode == VIEW_INST ? 4 : 0;
	param.flags	    = dear_hist_options.view_mode == VIEW_INST ? 
				PFMON_HASH_ACCESS_REORDER: 0;

	pfmon_hash_alloc(&param, &hash_desc);

	csmpl->data = hash_desc;

	return 0;
}

static void
dear_hist_extract_data(void *arg, void *data)
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
	sort_arg->avg_sum += count * p->key.val;

	if (count > sort_arg->max_count) sort_arg->max_count = count;
}

static int
hash_data_sort_byvalue(const void *a, const void *b)
{
	hash_data_t **e1 = (hash_data_t **)a;
	hash_data_t **e2 = (hash_data_t **)b;

	return (*e1)->key.val > (*e2)->key.val ? 1 : 0;
}

static int
hash_data_sort_bycount(const void *a, const void *b)
{
	hash_data_t **e1 = (hash_data_t **)a;
	hash_data_t **e2 = (hash_data_t **)b;

	return (*e1)->count > (*e2)->count ? 0 : 1;
}

static int
hash_data_sort_bylevel(const void *a, const void *b)
{
	hash_data_t **e1 = (hash_data_t **)a;
	hash_data_t **e2 = (hash_data_t **)b;
	unsigned long cost1, cost2;

	if (dear_hist_options.mode == DEAR_IS_TLB) {
		cost1 = (*e1)->count * ((*e1)->level_counts[0]*L2T_HIT_COST + (*e1)->level_counts[1]*HWT_HIT_COST + (*e1)->level_counts[2]*SWT_HIT_COST);
		cost2 = (*e2)->count * ((*e2)->level_counts[0]*L2T_HIT_COST + (*e2)->level_counts[1]*HWT_HIT_COST + (*e2)->level_counts[2]*SWT_HIT_COST);
	} else {
		cost1 = (*e1)->count * ((*e1)->level_counts[0]*L2C_HIT_COST + (*e1)->level_counts[1]*L3C_HIT_COST + (*e1)->level_counts[2]*RAM_HIT_COST);
		cost2 = (*e2)->count * ((*e2)->level_counts[0]*L2C_HIT_COST + (*e2)->level_counts[1]*L3C_HIT_COST + (*e2)->level_counts[2]*RAM_HIT_COST);
	}

	return cost1 > cost2 ? 0 : 1;
}

static void
dear_hist_collapse_func(hash_data_t **tab, unsigned long num_entries)
{
	unsigned long i;
	uintptr_t start, end;
	hash_data_t *p, *psrc = NULL;
	int ret = -1;

	for(i=0; i < num_entries; i++) {
		p = tab[i];
		//printf("1. i=%lu ret=%d start=%p end=%p value=%p\n", i, ret, (void *)start, (void *)end, (void *)p->value);
		if (ret == 0 && p->key.val >= start && p->key.val < end) {
			psrc->count += p->count;
			psrc->level_counts[0] += p->level_counts[0];
			psrc->level_counts[1] += p->level_counts[1];
			psrc->level_counts[2] += p->level_counts[2];
			p->count = 0;
			//printf("3. i=%lu value=%p -> value=%p count=%lu\n", i, (void *)p->value, (void *)psrc->value, psrc->count);
			continue;
		}
		ret = find_sym_by_apv(p->key.val,
				      p->key.tid,
				      p->key.version,
				      options.primary_syms,
				      PFMON_TEXT_SYMBOL, NULL, NULL,
				      &start, &end);
		//printf("2. i=%lu ret=%d start=%p end=%p value=%p\n", i, ret, (void *)start, (void *)end, (void *)p->key.ip);
		if (ret == -1) continue;
		/* resync base address */
		p->key.val = start;
		psrc = p;
	}
}

static const char *tlb_lvl_str[]={"N/A", "L2DTLB", "VHPT", "SW" };

static int
dear_hist_show_results(pfmon_sdesc_t *sdesc)
{
	uint64_t total_count, cum_count, count, top_num;
	pfmon_smpl_desc_t *smpl = &sdesc->csmpl;
	void *hash_desc = smpl->data;
	FILE *fp = smpl->smpl_fp;
	char *addr_str = "??", *sorted_str = "??";
	double d_cum, cum_total;
	hash_data_t **tab;
	uint64_t value;
	pid_t tid;
	unsigned long i, j, num_entries, max, avg_sum;
	uint32_t version;
	hash_sort_arg_t arg;
	int need_resolve, mode = 0, numeric_mode = 0, view_mode;
	pfmon_sym_type_t sym_mode = PFMON_TEXT_SYMBOL;
	char counter_str[32];
	unsigned long sum_levels[DEAR_HIST_MAX_LVL_COUNT];

	mode      = dear_hist_options.mode;

	pfmon_hash_num_entries(hash_desc, &num_entries);

	tab = (hash_data_t **)malloc(sizeof(hash_data_t *)*num_entries);
	if (tab == NULL) {
		warning("cannot allocate memory to print samples\n");
		return -1;
	}

	arg.tab = tab;
	arg.pos = 0;
	arg.total_count = 0;
	arg.avg_sum = 0;
	arg.max_count   = 0;

	pfmon_hash_iterate(smpl->data, dear_hist_extract_data, &arg);

	total_count = arg.total_count;
	avg_sum     = arg.avg_sum;
	cum_count   = 0;

	memset(sum_levels, 0, sizeof(sum_levels));

	if (options.opt_smpl_per_func) {
		qsort(tab, num_entries, sizeof(hash_data_t *), hash_data_sort_byvalue);
		dear_hist_collapse_func(tab, num_entries);
	}

	switch(dear_hist_options.sort_mode) {
		case SORT_BY_COUNT:
			qsort(tab, num_entries, sizeof(hash_data_t *), hash_data_sort_bycount);
			sorted_str = "count";
			break;
		case SORT_BY_VALUE:
			qsort(tab, num_entries, sizeof(hash_data_t *), hash_data_sort_byvalue);
			sorted_str = "value";
			break;
		case SORT_BY_LEVEL:
			qsort(tab, num_entries, sizeof(hash_data_t *), hash_data_sort_bylevel);
			sorted_str = "level";
			break;
	}
	view_mode    = dear_hist_options.view_mode;
	need_resolve = options.opt_addr2sym;

	top_num = options.smpl_show_top;
	if (top_num && top_num < num_entries)
		num_entries = top_num;

	switch(view_mode) {
		case VIEW_INST:
			sym_mode = PFMON_TEXT_SYMBOL;
			if (options.opt_smpl_per_func)
				addr_str ="function addr";
			else
				addr_str ="instruction addr";
			break;
		case VIEW_DATA:
			sym_mode = PFMON_DATA_SYMBOL;
			addr_str ="data addr";
			break;
		case VIEW_LEVELS:
			numeric_mode = mode == DEAR_IS_TLB ? 1 : 2;
			need_resolve = 0;
			addr_str ="level";
			break;
	}

	fprintf(fp, "# total_samples %lu\n"
		"# %s view\n"
		"# sorted by %s\n"
		"# showing per %s\n"
		"# L2   : %2u cycles load latency\n"
		"# L3   : %2u cycles load latency\n",
		total_count, 
		addr_str,
		sorted_str,
		options.opt_smpl_per_func ? "function histogram" : "distinct value",
		dear_hist_options.l2_latency,
		dear_hist_options.l3_latency);

	switch(mode) {
		case DEAR_IS_CACHE:
			if (view_mode != VIEW_LEVELS)
				fprintf(fp, 
					"# %%L2  : percentage of L1 misses that hit L2\n"
					"# %%L3  : percentage of L1 misses that hit L3\n"
					"# %%RAM : percentage of L1 misses that hit memory\n");
			break;
	}
	fprintf(fp, "# #count   %%self    %%cum ");
	if (mode == DEAR_IS_TLB) {
		if (view_mode != VIEW_LEVELS)
			fprintf(fp, "%7s %7s %7s %18s", "%L2", "%VHPT", "%SW", addr_str);
		else
			fprintf(fp, " level");
	} else {
		if (view_mode != VIEW_LEVELS) 
			fprintf(fp, "%7s %7s %7s %18s", "%L2", "%L3", "%RAM", addr_str);
		else 
			fprintf(fp, "lat(cycles) lat(ns)");
	}
	fputc('\n', fp);
	/*
	 * find longest count
	 */
	counter2str(arg.max_count, counter_str);
	max  = strlen(counter_str);
	/* adjust for column heading */
	if (max < 6) max = 6;

	for(i=0; i < num_entries; i++) {

		value = tab[i]->key.val;
		tid   = tab[i]->key.tid;
		count = tab[i]->count;
		version = tab[i]->key.version;

		/* zero count can happen in per-function mode */
		if (count == 0) continue;

		cum_count += count;
		d_cum	   = (double)count*100.0/(double)total_count;
		cum_total  = (double)cum_count*100.0 / (double)total_count;

		if (cum_total > (double)options.smpl_cum_thres)
			break;

		counter2str(count, counter_str);

		fprintf(fp, "  %*s %6.2f%% %6.2f%% ", 
				(int)max, counter_str,
				d_cum,
				(double)cum_count*100.0 / (double)total_count);


		if (view_mode != VIEW_LEVELS) {
			for (j=0; j < DEAR_HIST_MAX_LVL_COUNT; j++) {
				fprintf(fp, "%6.2f%% ", 
						(double)tab[i]->level_counts[j]*100.0/(double)count);
				sum_levels[j] += tab[i]->level_counts[j];
			}
			fprintf(fp, "0x%"PRIx64" ", value);
			if (need_resolve) {
				pfmon_print_address(fp,
						    options.primary_syms,
						    sym_mode,
						    value,
						    tab[i]->key.pid,
						    version);
			}
		}  else {
				if (mode == DEAR_IS_TLB) 
					fprintf(fp, "%6s ", tlb_lvl_str[value]);
				else
					fprintf(fp, "    %7lu %7.0f", value, (double)value*1.0/(options.cpu_mhz/1000.0));
		}
		if (options.opt_syst_wide)
			pfmon_print_tid(fp, tid);
		fputc('\n', fp);
	}
	free(tab);
#if 0
	if (view_mode != VIEW_LEVELS) {
		unsigned long cost[3];
		double aggr_cost = 0;

		cost[0] = dear_hist_options.l2_latency;
		cost[1] = dear_hist_options.l3_latency;
		cost[2] = 200; /* cycles */

		for (j=0; j < DEAR_HIST_MAX_LVL_COUNT; j++) {
			fprintf(fp, "# level %lu : counts=%lu avg_cycles=%.1fms %6.2f%%\n", 
				j, 
				sum_levels[j], 
				(double)sum_levels[j]*cost[j]/(double)(options.cpu_mhz*1000000),
				(double)sum_levels[j]*100.0/(double)total_count);
			aggr_cost += ((double)(smpl_period*sum_levels[j]*cost[j])/(double)total_count);
		}
		printf("approx cost: %.1fs\n", (double)aggr_cost/(double)(options.cpu_mhz*1000000));
	}
#endif
	return 0;
}

static int
dear_hist_terminate_session(pfmon_sdesc_t *sdesc)
{
	dear_sample_hdr_t dear_hdr;
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	FILE *fp;
	size_t ret;

	fp = csmpl->smpl_fp;

	if (dear_hist_options.output_mode == OUTPUT_BINARY) {
		
		dear_hdr.version = DEAR_HDR_VERSION;
		dear_hdr.mode    = dear_hist_options.mode;
		dear_hdr.count   = options.opt_aggr ? *csmpl->aggr_count : csmpl->entry_count;

		/* rewrite completed header */
		fseek(fp, 0, 0);
		ret = fwrite(&dear_hdr, sizeof(dear_hdr), 1, fp);

		return ret != 1 ? -1 : 0;
	}

	dear_hist_show_results(sdesc);

	pfmon_hash_free(csmpl->data);
	csmpl->data = NULL;

	return 0;
}

pfmon_smpl_module_t dear_hist_ia64_smpl_module;
static void
dear_hist_initialize_mask(void)
{
	pfmon_bitmask_set(dear_hist_ia64_smpl_module.pmu_mask, PFMLIB_ITANIUM_PMU);
	pfmon_bitmask_set(dear_hist_ia64_smpl_module.pmu_mask, PFMLIB_ITANIUM2_PMU);
	pfmon_bitmask_set(dear_hist_ia64_smpl_module.pmu_mask, PFMLIB_MONTECITO_PMU);
}

pfmon_smpl_module_t dear_hist_ia64_smpl_module ={
	.name		    = "dear-hist",
	.description	    = "Data EAR-based cache/tlb misses histograms",
	.process_samples    = dear_hist_process_samples,
	.show_options       = dear_hist_show_options,
	.initialize_mask    = dear_hist_initialize_mask,
	.initialize_module  = dear_hist_initialize_module,
	.initialize_session = dear_hist_initialize_session,
	.terminate_session  = dear_hist_terminate_session,
	.print_header       = dear_hist_print_header,
	.validate_events    = dear_hist_validate_events,
	.fmt_name	    = PFM_DFL_SMPL_NAME
};
