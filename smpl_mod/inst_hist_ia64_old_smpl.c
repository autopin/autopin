/*
 * inst_hist_mult.c - instruction-based histogram multi-event
 * sampling for old perfmon2 (v2.0) interface on IA-64
 *
 * Copyright (c) 2005-2007 Hewlett-Packard Development Company, L.P.
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
#include "pfmon_smpl_ia64_old.h"
#include <perfmon/perfmon_default_smpl.h> /* old compat mode ONLY */

#define	SMPL_MOD_NAME "inst-hist"

typedef struct {
		pfmon_hash_key_t key;
		uint64_t	 count[PFMON_MAX_PMDS];
		unsigned int	 is_base;
} hash_data_t;

typedef struct {
	uint64_t	total_count[PFMON_MAX_PMDS];
	uint64_t	max_count;
	hash_data_t 	**tab;
	unsigned long 	pos;
	unsigned int	event_count;
} hash_sort_arg_t;

static int
inst_hist_process_samples(pfmon_sdesc_t *sdesc)
{
	pfm_default_smpl_hdr_t *hdr;
	pfm_default_smpl_entry_t *ent;
	pfmon_smpl_desc_t *csmpl;
	uint64_t entry, count, skip;
	void *hash_desc, *data, *pos;
	hash_data_t *hash_entry;
	pfmon_hash_key_t key;
	int ret, pd_idx;
	size_t incr;
	uint16_t last_ovfl_pmd;
	uint32_t current_map_version;
	
	csmpl = &sdesc->csmpl;
	hdr   = csmpl->smpl_hdr;

	if (hdr == NULL)
		return -1;

	hash_desc = csmpl->data;
	ent       = (pfm_default_smpl_entry_t *)(hdr+1);
	pos	  = ent;
	entry     = options.opt_aggr ? *csmpl->aggr_count : csmpl->entry_count;
	count     = hdr->hdr_count;
	incr      = 0;
	pd_idx    = 0;

	last_ovfl_pmd = ~0;
	current_map_version = sdesc->current_map_version;

	DPRINT(("count=%"PRIu64" entry=%"PRIu64"\n", count, entry));

	/*
 	 * check if we have new entries
 	 * if so skip the old entries and process only the new ones
 	 */
	if((csmpl->last_ovfl == hdr->hdr_overflows && csmpl->last_count <= count)
	  || ((csmpl->last_ovfl+1) == hdr->hdr_overflows && csmpl->last_count < count)) {
		skip = csmpl->last_count;
		vbprintf("[%d] skip %"PRIu64" samples out of %"PRIu64" (overflows: %"PRIu64")\n",
			  sdesc->tid,
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

	while(count--) {
		DPRINT(("entry %"PRIu64" PID:%d CPU:%d STAMP:0x%"PRIx64" OVF:%u IIP: %llx\n",
			entry,
			ent->pid,
			ent->cpu,
			ent->tstamp,
			ent->ovfl_pmd,
			(unsigned long long)ent->ip));

		key.val = ent->ip;
		key.pid = ent->tgid; /* process id */
		key.tid = ent->pid;
		key.version = current_map_version;

		if (ent->ovfl_pmd != last_ovfl_pmd) {
			pd_idx = sdesc->sets->rev_smpl_pmds[ent->ovfl_pmd].pd_idx;
			last_ovfl_pmd = ent->ovfl_pmd;
			incr =sdesc->sets->rev_smpl_pmds[ent->ovfl_pmd].num_smpl_pmds <<3;
		}

		/*
		 * in aggregation mode sample processing is serialized,
		 * therefore we are safe to use a single hash_table here
		 */
		// andrzejn: skip samples leftover from the previous call
		if(skip) {
			skip--;
		} else {
			ret = pfmon_hash_find(hash_desc, key, &data);
			hash_entry = data;
			if (ret == -1) {
				pfmon_hash_add(hash_desc, key, &data);
				hash_entry = data;
				hash_entry->count[pd_idx] = 0;
				hash_entry->key = key;
			}
			hash_entry->count[pd_idx]++;
			entry++;
		}
		/* skip over body */
		pos += sizeof(*ent) + incr;
		ent = pos;
	}
	return 0;
}

static int
inst_hist_print_header(pfmon_sdesc_t *sdesc)
{
	FILE *fp = sdesc->csmpl.smpl_fp;
	int i;

	fprintf(fp, "# description of columns:\n");

	fprintf(fp, "#\tcolumn  0: number of samples for event 0 (sorting key)\n"
		    "#\tcolumn  1: relative percentage of samples for event 0\n"
		    "#\tcolumn  2: cumulative percentage for event 0\n");

	for(i=1; i < sdesc->sets->event_count; i++) {
		fprintf(fp, "#\tcolumn  %d: number of samples for event %d\n"
			    "#\tcolumn  %d: relative percentage of samples for event %d\n"
			    "#\tcolumn  %d: cumulative percentage for event %d\n",
			    3*i, i,
			    1+3*i, i,
			    2+3*i, i);

	}
	fprintf(fp, "#\tcolumn  %d: code address\n", 3*i);
	fprintf(fp, "#\tcolumn  %d: code address or symbol\n", 1+3*i);
	if (options.opt_syst_wide)
		fprintf(fp, "#\tcolumn  %d: process and thread information\n", 1+1+3*i);
	return 0;
}

static int
inst_hist_initialize_session(pfmon_sdesc_t *sdesc)
{
	pfmon_smpl_desc_t *csmpl = &sdesc->csmpl;
	void *hash_desc;
	pfmon_hash_param_t param;

	param.hash_log_size = 12;
	param.max_entries   = ~0; /* unlimited */
	param.entry_size    = sizeof(hash_data_t);
#ifdef __ia64__
	param.shifter	    = 4;
#else
	param.shifter	    = 0;
#endif
	param.flags	    = PFMON_HASH_ACCESS_REORDER;

	pfmon_hash_alloc(&param, &hash_desc);

	csmpl->data = hash_desc;
	return 0;
}

static void
inst_hist_print_data(void *arg, void *data)
{
	hash_data_t *p = data;
	hash_sort_arg_t *sort_arg = arg;
	hash_data_t **tab = sort_arg->tab;
	unsigned long pos = sort_arg->pos;
	unsigned int i, cnt;

	cnt = sort_arg->event_count;

	tab[pos] = p;

	sort_arg->pos = ++pos;

	for(i=0; i < cnt; i++) {
		sort_arg->total_count[i] += p->count[i];
		if (p->count[i] > sort_arg->max_count)
			sort_arg->max_count = p->count[i];
	}
}

static int
hash_data_sort_byaddr(const void *a, const void *b)
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

	return (*e1)->count[0] > (*e2)->count[0] ? 0 : 1;
}

static void
inst_hist_collapse_func(hash_data_t **tab, unsigned long num_entries, unsigned int event_count)
{
	unsigned long i;
	unsigned long start, end;
	unsigned long j;
	hash_data_t *p, *psrc = NULL;
	int ret = -1;
	char **nametab;
	char **symtab;
	unsigned long k;

	nametab = calloc(num_entries, sizeof(char *));
	symtab = calloc(num_entries, sizeof(char *));

	for(i=0; i < num_entries; i++) {
		p = tab[i];

		if (ret == 0) {
			if (p->key.val >= start && p->key.val < end && p->key.version == psrc->key.version) {
				for(j=0; j < event_count; j++) {
					psrc->count[j] += p->count[j];
					p->count[j] = 0;
				}
				continue;
			} 
		}

		ret = find_sym_by_apv(p->key.val,
				p->key.tid,
				p->key.version,
				options.primary_syms,
				PFMON_TEXT_SYMBOL,
				&symtab[i], &nametab[i], &start, &end);

		if (ret == -1)
			continue;
		/* resync base address */
		p->key.val = start;
		p->is_base = 1; /* is function base address */		
		psrc = p;
	}	

	for(i=0; i < num_entries; i++) {
		if(!symtab[i])
			continue;

		for(j=0; j < i; j++) {
			if(symtab[i] == symtab[j] && nametab[i] == nametab[j]) {
				for(k=0; k<event_count; k++) {
					tab[j]->count[k] += tab[i]->count[k];
					tab[i]->count[k] = 0;
					tab[i]->is_base = 0;
				}
				j = i;
			}
		}
	}
}

static int
inst_hist_show_results(pfmon_sdesc_t *sdesc)
{
	uint64_t top_num, cum_count[PFMON_MAX_PMDS];
	void *hash_desc;
	pfmon_smpl_desc_t *csmpl;
	FILE *fp;
	hash_data_t **tab;
	unsigned long addr, ns=0;
	unsigned long i, num_entries, j;
	double d_cum, cum_total;
	hash_sort_arg_t arg;
	size_t len_count;
	int need_resolve;
	char buf[32];

	csmpl = &sdesc->csmpl;
	fp = csmpl->smpl_fp;
	hash_desc = csmpl->data;

	if (fp == NULL || hash_desc == NULL)
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
	arg.max_count   = 0;
	arg.event_count = sdesc->sets->event_count;

	pfmon_hash_iterate(csmpl->data, inst_hist_print_data, &arg);

	sprintf(buf, "%"PRIu64, arg.max_count);
	len_count = strlen(buf);

	/* adjust for column heading smpl_evXX */
	if (len_count < 10)
		len_count = 10;

	if (options.opt_smpl_per_func) {
		qsort(tab, num_entries, sizeof(hash_data_t *), hash_data_sort_byaddr);
		inst_hist_collapse_func(tab, num_entries, sdesc->sets->event_count);
	}
	qsort(tab, num_entries, sizeof(hash_data_t *), hash_data_sort_bycount);

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

	for(j=0; j < sdesc->sets->event_count; j++)
		fprintf(fp, "%*s%02lu ", (int)len_count+16-2, "event", j);

	fprintf(fp, "\n# ");

	for(j=0; j < sdesc->sets->event_count; j++)
		fprintf(fp, "%*s   %%self    %%cum ", (int)len_count, "counts");

	fprintf(fp, "%*s ",
		(int)(2+(sizeof(unsigned long)<<1)),
		"code addr");

	if (need_resolve)
		fprintf(fp, "symbol");

	fputc('\n', fp);

	for(i=0; i < num_entries; i++) {
		addr = tab[i]->key.val;

		if (options.opt_smpl_per_func && !tab[i]->is_base && tab[i]->count[0] == 0)
			continue;

		fputc(' ', fp); fputc(' ', fp);

		for(j=0; j < arg.event_count; j++) {

			cum_count[j] += tab[i]->count[j];
			if (arg.total_count[j]) {
				cum_total  = (double)cum_count[j]*100.0 / (double)arg.total_count[j];
				d_cum = (double)tab[i]->count[j]*100.0/(double)arg.total_count[j];
			} else {
				cum_total = d_cum = 0; 
			}

			if (cum_total > (double)options.smpl_cum_thres)
				goto out;

			fprintf(fp, "%*"PRIu64" %6.2f%% %6.2f%% ",
				(int)len_count,
				tab[i]->count[j],
				d_cum,
				cum_total);
		}
		fprintf(fp, "0x%0*lx ", (int)(sizeof(unsigned long)<<1), addr);
		if (need_resolve)
			pfmon_print_address(fp,
					    options.primary_syms,
					    PFMON_TEXT_SYMBOL,
					    addr,
					    tab[i]->key.pid,
					    tab[i]->key.version);

		if (options.opt_syst_wide)
			pfmon_print_tid(fp, tab[i]->key.tid);

		fputc('\n', fp);
		/*
 		 * exit after n samples have been printed
 		 */
		if (++ns == top_num)
			break;
	}
out:
	free(tab);

	return 0;
}

static int
inst_hist_terminate_session(pfmon_sdesc_t *sdesc)
{
	inst_hist_show_results(sdesc);

	pfmon_hash_free(sdesc->csmpl.data);
	sdesc->csmpl.data = NULL;
	return 0;
}

pfmon_smpl_module_t inst_hist_old_smpl_module;
static void inst_hist_initialize_mask(void)
{
	pfmon_bitmask_setall(inst_hist_old_smpl_module.pmu_mask);
}

pfmon_smpl_module_t inst_hist_old_smpl_module={
	.name		    = SMPL_MOD_NAME,
	.description	    = "IP-based histogram",
	.process_samples    = inst_hist_process_samples,
	.initialize_mask    = inst_hist_initialize_mask,
	.initialize_session = inst_hist_initialize_session,
	.terminate_session  = inst_hist_terminate_session,
	.print_header       = inst_hist_print_header,
	.init_ctx_arg	    = default_smpl_init_ctx_arg,
	.check_version	    = default_smpl_check_version,
	.check_new_samples  = default_smpl_check_new_samples,
	.flags              = PFMON_SMPL_MOD_FL_LEGACY | PFMON_SMPL_MOD_FL_DEF_SYM,
	.uuid		    = PFM_DEFAULT_SMPL_UUID
};
