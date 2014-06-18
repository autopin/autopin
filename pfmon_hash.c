/*
 * pfmon_hash.c  - hash table management
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
#ifndef COMPILE_DEAR_VIEW
#include "pfmon.h"
#endif

#define HASH_FUNC(h,k)	((k.val >>(h)->shifter) & (h)->mask)

static pfmon_hash_entry_t *
pfmon_find_victim_hash(pfmon_hash_table_t *hash)
{
	pfmon_hash_entry_t *p, *q = NULL;
	unsigned long min = ~0;

	/*
	 * look for a victim across ALL entries
	 */
	for (p = hash->active_list ; p ; p = p->next) {
		if (p->access_count < min) {
			q = p;
			min = p->access_count;
		}
	}
	/*
	 * detach entry from hash list
	 */
	if (q->hash_prev) 
		q->hash_prev->hash_next = q->hash_next;
	else
		hash->table[q->bucket] = q->hash_next;

	if (q->hash_next) 
		q->hash_next->hash_prev = q->hash_prev;

	return q;
}

int
pfmon_hash_find(void *hash_desc, pfmon_hash_key_t key, void **data)
{
	uint64_t collisions = 0;
	pfmon_hash_table_t *hash = (pfmon_hash_table_t *)hash_desc;
	pfmon_hash_entry_t *p, *hash_list;
	uintptr_t bucket;

	if (hash == NULL) {
		fatal_error("invalid hash descriptor\n");
	}

	/*
	 * our hash function, we ignore the bottom 8 bits
	 */
	bucket = HASH_FUNC(hash, key);

	hash_list = hash->table[bucket];
	hash->accesses++;

	for (p = hash_list; p ; p = p->hash_next) {
		if (key.val == p->key.val
			 && key.tid == p->key.tid
			 && key.pid == p->key.pid
			 && key.version == p->key.version)
			goto found;
		collisions++;
	}
	hash->misses++;
	return -1;
found:

	/*
	 * if requested move to the front of the collision chain (take advantage of reuse)
	 */
	if (p->hash_prev && hash->flags & PFMON_HASH_ACCESS_REORDER) {
		if (p->hash_next) p->hash_next->hash_prev = p->hash_prev;
		if (p->hash_prev) p->hash_prev->hash_next = p->hash_next;

		p->hash_prev = NULL;
		p->hash_next = hash_list;

		hash->table[bucket] = p;
	}

	p->access_count++;

	hash->collisions += collisions;

	*data = p+1;

	return 0;
}

int
pfmon_hash_add(void *hash_desc, pfmon_hash_key_t key, void **data)
{
	pfmon_hash_table_t *hash = (pfmon_hash_table_t *)hash_desc;
	pfmon_hash_entry_t *p, *head;
	uintptr_t	   bucket;

	if (hash->free_list) {
		/*
		 * take first element in free list
		 */
		p               = hash->free_list;
		hash->free_list = p->next;
		hash->used_entries++;

	} else if (hash->used_entries == hash->max_entries) {
		p = pfmon_find_victim_hash(hash);
	} else {
		p = (pfmon_hash_entry_t *)calloc(1, hash->entry_size);
		hash->used_entries++;
	}
	/*
	 * relink to active list
	 */
	p->next = hash->active_list;
	p->prev = NULL;
	hash->active_list = p;

	bucket = HASH_FUNC(hash, key);

	p->key       = key;
	p->bucket    = bucket;
	p->hash_prev = NULL;
	head         = hash->table[bucket]; 

	/*
	 * put at the head of the chain
	 */
	p->hash_next        = head;
	hash->table[bucket] = p;
	if (head) head->hash_prev = p;

	p->access_count = 1;

	/* location of payload */
	*data = p+1;

	return 0;
}

int
pfmon_hash_alloc(pfmon_hash_param_t *param, void **hash_desc)
{
	pfmon_hash_table_t *hash;
	uintptr_t i, max;
	size_t sz, hash_log_size;

	if (param == NULL)
		return -1;

	hash_log_size = param->hash_log_size;

	if (hash_log_size > sizeof(uintptr_t)<<3) return -1;

	sz = sizeof(pfmon_hash_table_t) + (1UL<<hash_log_size)*sizeof(pfmon_hash_entry_t *);

	hash = malloc(sz);
	if (hash == NULL) {
		warning("could not allocate %lu bytes for hash table\n", sz);
		return -1;
	}

	hash->free_list    = hash->active_list = NULL;
	hash->table        = (pfmon_hash_entry_t **)(hash+1);

	hash->mask         = (1UL<<hash_log_size) - 1UL;
	hash->shifter	   = param->shifter;
	hash->flags	   = param->flags;
	hash->max_entries  = param->max_entries;
	hash->entry_size   = sizeof(pfmon_hash_entry_t) + param->entry_size;
	hash->accesses     = hash->misses = hash->collisions = 0;
	hash->used_entries = 0;

	DPRINT(("hash_log_size=%lu mask=0x%"PRIx64" entry_size=%lu max_entries=%lu shifter=%lu hash=%p\n", 
		hash_log_size, 
		hash->mask,
		hash->entry_size,
		hash->max_entries,
		hash->shifter,
		hash));

	max = hash->mask+1;

	/*
	 * initialize hash_table
	 */
	for (i=0; i < max; i++) {
		hash->table[i] = NULL;
	}

	/*
	 * return value
	 */
	*hash_desc = hash;

	return 0;
}

void 
pfmon_hash_free(void *hash_desc)
{
	pfmon_hash_table_t *hash = (pfmon_hash_table_t *)hash_desc;
	pfmon_hash_entry_t *entry, *tmp;
	
	if (hash == NULL)
		return;

	entry  = hash->active_list;
	while (entry) {
		tmp = entry->next;
		free(entry);
		entry = tmp;
	}

	entry  = hash->free_list;
	while (entry) {
		tmp = entry->next;
		free(entry);
		entry = tmp;
	}
	free(hash_desc);
}

int 
pfmon_hash_iterate(void *hash_desc, void (*func)(void *, void *), void *arg)
{
	pfmon_hash_table_t *hash = (pfmon_hash_table_t *)hash_desc;
	pfmon_hash_entry_t *entry;
	
	if (hash == NULL) {
		warning("invalid hash in pfmon_hash_iterate\n");
		return -1;
	}
	if (func == NULL) {
		fatal_error("invalid func\n");
		return -1;
	}

	entry  = hash->active_list;
	while (entry) {
		(*func)(arg, entry+1);
		entry = entry->next;
	}
	return 0;
}

int 
pfmon_hash_num_entries(void *hash_desc, unsigned long *num_entries)
{
	pfmon_hash_table_t *hash = (pfmon_hash_table_t *)hash_desc;

	if (hash_desc == NULL || num_entries == NULL) return -1;

	*num_entries = hash->used_entries;
	return 0;
}

int
pfmon_hash_flush(void *hash_desc)
{
	pfmon_hash_table_t *hash = (pfmon_hash_table_t *)hash_desc;
	pfmon_hash_entry_t *entry, *tmp;
	uintptr_t i, max;

	entry  = hash->active_list;
	hash->active_list = NULL;
	while (entry) {
		tmp = entry->next;
		entry->prev = NULL;
		entry->next = hash->free_list;
		hash->free_list = entry;
		entry = tmp;
	}
	max = hash->mask+1;

	/*
	 * initialize hash_table
	 */
	for (i=0; i < max; i++) {
		hash->table[i] = NULL;
	}

	hash->used_entries = 0;
	hash->accesses     = 0;
	hash->collisions   = 0;
	hash->misses       = 0;
	return 0;
}

void
pfmon_hash_stats(void *hash_desc, FILE *fp)
{
	pfmon_hash_table_t *hash = (pfmon_hash_table_t *)hash_desc;

	if (hash->accesses == 0) 
		fprintf(fp, "hash not accessed\n");
	else
		fprintf(fp, "accesses %"PRIu64", misses %"PRIu64", miss ratio %.2f%%, %.2f collisions/access "
		 	"used_entries=%lu max_entries=%lu\n", 
			hash->accesses,
			hash->misses,
			(double)hash->misses*100.0/(double)hash->accesses,
			(double)hash->collisions/(double)hash->accesses, 
			hash->used_entries,
			hash->max_entries);
}
