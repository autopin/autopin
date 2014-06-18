/*
 * pfmon_symbols.c  - management of symbol tables
 *
 * Copyright (c) 2002-2006 Hewlett-Packard Development Company, L.P.
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

#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <libelf.h>

#define PFMON_KALLSYMS		"/proc/kallsyms"

#define for_each_sym_module(m)	
struct sym_hash_table_t;

#define PFMON_MAX_SECTIONS	2

typedef struct _sym_hash_data {
	unsigned long		addr;
	unsigned long		eaddr;
	char			*name;
	char			*module;
} sym_hash_data_t;

//#define PFMON_NM_CMD	"sh -c \"nm -f sysv -v -C --defined -D %s 2>/dev/null; nm -f sysv -v -C --defined %s 2>/dev/null\" | sort | uniq"
//#define PFMON_NM_CMD	"sh -c \"nm -f sysv --demangle -v -C --defined -D %s 2>/dev/null; nm -f sysv --demangle -v -C --defined %s 2>/dev/null\" | sort | uniq"
#define PFMON_NM_CMD    "sh -c \"nm -f sysv -v -C --defined -D %s 2>/dev/null; nm -f sysv -v -C --defined %s 2>/dev/null\" | sort -t'|' -k 2 | uniq"
#define NTOK 8

static module_symbols_t kernel_module_syms;
static module_symbols_t *module_list;

static void show_all_maps();

static void
add_module_syms(module_symbols_t *p)
{
	DPRINT(("module added %s\n", p->name));
	p->next = module_list;
	module_list = p;
}

static int
symcmp(const void *a, const void *b)
{
	symbol_t *ap = (symbol_t *)a;
	symbol_t *bp = (symbol_t *)b;

	return ap->value > bp->value;
}

static inline int is_text(char *s)
{
//	return !strncmp(s, ".text", 5) || !strncmp(s, ".init", 5);
	return !strncmp(s, ".text", 5) || !strncmp(s, ".init", 5) || !strncmp(s, ".fini", 5);
}

static inline int is_data(char *s)
{
	return !strncmp(s, ".bss", 4) || strstr(s, "data") || !strncmp(s, ".dynamic", 8);
}

static int
load_module_syms(const char *filename, module_symbols_t *mod)
{
	FILE *fp;
	int stype;
	size_t max_syms[2];
	char *buf, *line, *saved_line, *p, *q;
	char *nm_toks[NTOK];
	size_t sz, ssz;
	unsigned long addr, i;
        int breakflag;
        int64_t index = 0;

	buf = malloc(2*strlen(filename) + strlen(PFMON_NM_CMD)+1);
	if (!buf)
		return -1;

	sprintf(buf, PFMON_NM_CMD, filename, filename);

	fp = popen(buf, "r");
	free(buf);
	if (!fp)
		return -1;

	max_syms[0] = max_syms[1] = 2048;
	line = NULL, sz = 0; saved_line = NULL;
	while (getline(&line, &sz, fp) != EOF) {
		p = q = line; i = 0;
		nm_toks[6] = NULL;
		while(i < NTOK && (p = strtok_r(q, "|", &saved_line))) {
			if (*p == '\n' || *p == '\0')
				break;
			nm_toks[i++] = p;
			q = NULL;
		}
		if (!nm_toks[6])
			continue;
		/*
		 * XXX: missing ctors/dtros init/fini
		 */

		if (is_text(nm_toks[6])) {
			stype = 0;
		} else if (is_data(nm_toks[6])) {
			stype = 1;
		}
		else
			continue;

		addr = strtoul(nm_toks[1], NULL, 16);
		ssz = strtoul(nm_toks[4], NULL, 16);

		if (mod->nsyms[stype] == 0 || mod->nsyms[stype] == max_syms[stype]) {
			/* exponential growth */
			max_syms[stype] <<=1;
			mod->sym_tab[stype] = realloc(mod->sym_tab[stype], max_syms[stype] * sizeof(symbol_t));
			if (mod->sym_tab[stype] == NULL)
				goto error;
		}

                p = strchr(nm_toks[0], '|');
                if (p)
                        *p = '\0';

                for(i=strlen(nm_toks[0]); nm_toks[0][i-1] == ' '; i--);
                nm_toks[0][i] = '\0';

                breakflag = 0;
                index = (int64_t)mod->nsyms[stype] - 1;
                if((index >= 0) && (mod->sym_tab[stype][index].value == addr)) {
                        DPRINT(("addrs match %s/%p\n", mod->sym_tab[stype][index].name, (void *)mod->sym_tab[stype][index].value));
                        if(strncmp(mod->sym_tab[stype][index].name, "_Z", 2)) {
                                DPRINT(("skipping %s/%p because %s/%p is already inside\n", nm_toks[0], (void *)addr, mod->sym_tab[stype][index].name, (void *)mod->sym_tab[stype][index].value));
                                breakflag = 1;
                        }
                }

		if(breakflag == 1) continue;

		mod->sym_tab[stype][mod->nsyms[stype]].name  = strdup(nm_toks[0]);
		mod->sym_tab[stype][mod->nsyms[stype]].value = addr;
		mod->sym_tab[stype][mod->nsyms[stype]].size  = ssz;
		mod->nsyms[stype]++;
	}

	if (line)
		free(line);

	fclose(fp);

	if (mod->nsyms[0] || mod->nsyms[1]) {
		qsort(mod->sym_tab[0], mod->nsyms[0], sizeof(symbol_t), symcmp);
		for(i=1; i < mod->nsyms[0]; i++) {
			size_t sss;
			sss  = mod->sym_tab[0][i].value - mod->sym_tab[0][i-1].value;
			if (mod->sym_tab[0][i-1].size == 0 || (sss < mod->sym_tab[0][i-1].size))
				mod->sym_tab[0][i-1].size  = sss;
		}

		qsort(mod->sym_tab[1], mod->nsyms[1], sizeof(symbol_t), symcmp);
		for(i=1; i < mod->nsyms[1]; i++) {
			size_t sss;
			sss  = mod->sym_tab[1][i].value - mod->sym_tab[1][i-1].value;
			if (mod->sym_tab[1][i-1].size == 0 || (sss < mod->sym_tab[1][i-1].size))
				mod->sym_tab[1][i-1].size  = sss;
		}
		add_module_syms(mod);
	}
	return 0;
error:
	return -1;
}


static char *
place_str(unsigned long length)
{
	static char *current_free, *current_end;
	char *tmp;
#define STR_CHUNK_SIZE	options.page_size
	if (length >= STR_CHUNK_SIZE)
		fatal_error("sysmap load string is too long\n");

	/*
	 * XXX: that's bad, we do not keep track of previously allocated
	 * chunks, so we cannot free!
	 */
	if (current_free == NULL || (current_end-current_free) < length) {
		current_free = (char *)malloc(STR_CHUNK_SIZE);
		if (current_free == NULL) return NULL;
		current_end = current_free + STR_CHUNK_SIZE;
	}
	tmp = current_free;
	current_free += length;
	return tmp;
}

/*
 * load kernel symbols using /proc/kallsyms.
 * This file does not contains kernel data symbols but includes code/data
 * symbols from modules. Code symbol size is not provided.
 */
static int
load_kallsyms_symbols(module_symbols_t *mod)
{
#define PFMON_KALLSYMS_MAXLEN	256

	FILE *fp;
	unsigned long min_addr[2];
	char *s, *str_addr, *sym_start, *mod_start, *endptr;
	unsigned long line = 1UL;
	unsigned long addr, sym_len, mod_len;
	unsigned long last_value[2];
	unsigned long sym_count[2];
	int need_sorting[2];
	size_t sz;
	char *line_str;
	char addr_str[24]; /* cannot be more than 16+2 (for 0x) */
	int type, ret;

	fp = fopen(PFMON_KALLSYMS, "r");
	if (fp == NULL) {
		DPRINT(("file %s not found\n", PFMON_KALLSYMS));
		return -1;
	}

	/*
	 * allocate a default-sized symbol table 
	 */
	sym_count[0] = sym_count[1] = 8192;
	mod->nsyms[0] = mod->nsyms[1] = 0;
	mod->sym_tab[0] = mod->sym_tab[1] = NULL;
	min_addr[0] = min_addr[1] = 0;
	need_sorting[0] = need_sorting[1] = 0;

	line_str = NULL; sz = 0;
	ret = 0;
	while(getline(&line_str, &sz, fp)>0) {

		s = line_str;

		while(*s != ' ' && *s !='\0')
			s++;

		if (*s == '\0')
			break;

		if (s-line_str > 16+2) {
			ret = -1;
			break;
		}

		strncpy(addr_str, line_str, s-line_str);
		addr_str[s-line_str] = '\0';

		/* point to object type */
		s++;
		type = tolower(*s);

		/* 
		 * keep only text and data symbols
		 *
		 * skip uninteresting symbols
		 */
		if (type == 's' || type == 'd' || type == 'D') 
			type = 1;
		else if (type == 't' || type == 'T' )
			type = 0;
		else
			continue;

		/* look for space separator */
		s++;
		if (*s != ' ') {
			ret = -1;
			break;
		}

		if (mod->nsyms[type] == 0 || mod->nsyms[type] == sym_count[type]) {
			/* exponential growth */
			sym_count[type] <<=1;
			mod->sym_tab[type] = (symbol_t *)realloc(mod->sym_tab[type], sym_count[type]*sizeof(symbol_t));
			if (!mod->sym_tab) {
				ret = -1;
				break;
			}
		}

		/* compute address */
		endptr = NULL;
		addr  = (unsigned long )strtoul(addr_str, &endptr, 16);
		if (*endptr != '\0') {
			ret = -1;
			break;
		}
		/* skip aliased symbols */
		if (mod->nsyms[type] && addr == mod->sym_tab[type][mod->nsyms[type]-1].value) {
			while (*s++ != '\n');
			line++;
			continue;
		}
			
		/*
		 * check that file is sorted correctly
		 */
		if (mod->nsyms[type] == 0) 
			min_addr[type] = addr;


		if (addr < min_addr[type]) 
			need_sorting[type] = 1;

		min_addr[type] = addr;

		/* advance to symbol name */
		sym_start = ++s;

		/* look for end-of-string */
		while(*s != '\n' && *s != '\0' && *s != ' ' && *s != '\t')
			s++;

		if (*s == '\0') {
			ret = -1;
			break;
		}
		sym_len = s - sym_start;


		/* check for module */
		while(*s != '\n' && *s != '\0' && *s != '[')
			s++;

		/* symbol belongs to a kernel module */
		if (*s == '[') {
			mod_start = s++;
			while(*s != '\n' && *s != '\0' && *s != ']')
				s++;
			if (*s != ']') {
				ret = -1;
				break;
			}
			mod_len = s - mod_start + 1;
		} else {
			mod_len   = 0;
			mod_start = NULL;
		}

		line++;

		/*
		 * place string in our memory pool
		 * +1 for '\0'
		 */
		str_addr = place_str(mod_len + sym_len + 1);
		if (str_addr == NULL) {
			ret = -1;
			break;
		}

		strncpy(str_addr, sym_start, sym_len);
		if (mod_len)
			strncpy(str_addr+sym_len, mod_start, mod_len);
		str_addr[sym_len+mod_len] = '\0';

		/*
		 * update size of previous symbol using current (estimate)
		 * unfortunately, /proc/kallsyms does not report the size of the symbols
		 * so we try to approximate uby assuming that symbols are contiguous. If there
		 * is a gap between two symbols, then it is likely that no executable code libves
		 * there, so there should be no risk of getting samples there.
		 */

		mod->sym_tab[type][mod->nsyms[type]].value = addr;
    		mod->sym_tab[type][mod->nsyms[type]].size  = 0;
    		mod->sym_tab[type][mod->nsyms[type]].name  = str_addr;
		if (mod->nsyms[type])
    			mod->sym_tab[type][mod->nsyms[type]-1].size  = mod->sym_tab[type][mod->nsyms[type]].value - last_value[type];

		last_value[type] = mod->sym_tab[type][mod->nsyms[type]].value;
		mod->nsyms[type]++;
	}
	if (line_str)
		free(line_str);

	/*
	 * normally a kallsyms is already sorted
	 * so we should not have to do this
	 */
	if (ret == 0) {
		if (need_sorting[0])
			qsort(mod->sym_tab[0], mod->nsyms[0], sizeof(symbol_t), symcmp);
		if (need_sorting[1])
			qsort(mod->sym_tab[1], mod->nsyms[1], sizeof(symbol_t), symcmp);
	}
	fclose(fp);
	return ret;
}


int
load_kernel_syms(void)
{
	static int kernel_syms_loaded;
	char *from;
	int ret = -1;

	if (kernel_syms_loaded)
		return 0;

	kernel_module_syms.id	= ~0UL;
	kernel_module_syms.name = "kernel";

	/* 
	 * Despite /proc/kallsyms, System.map is still useful because it includes data symbols
	 * We use System.map if specified, otherwise we default to /proc/kallsyms
	 */
	if (options.opt_sysmap_syms) {
		ret  = -1; //load_sysmap_symbols(&kernel_syms);
		from = options.symbol_file;
	} else {
		ret  = load_kallsyms_symbols(&kernel_module_syms);
		from = PFMON_KALLSYMS;
	}
	vbprintf("loaded %lu text symbols %lu data symbols from %s\n",
		kernel_module_syms.nsyms[0],
		kernel_module_syms.nsyms[1],
		from);

	add_module_syms(&kernel_module_syms);

	return 0;
}


// attaches the kernel symbols to the options.primary_syms table in
// system-wide mode to enable kernel-level symbol resolution
void attach_kernel_syms(module_map_t **list) {
	vbprintf("attaching kernel symbols to map array\n");

	module_map_t *tempptr = NULL;
	module_symbols_t *mod = NULL;
	
	tempptr = (module_map_t *)calloc(2, sizeof(module_map_t));
	tempptr[0].mod = mod = &kernel_module_syms;
	tempptr[0].path = "kernel";
	tempptr[0].version = 1;
	tempptr[0].pid = 0;

	tempptr[0].base[0] = mod->sym_tab[0][0].value;
	tempptr[0].base[1] = mod->sym_tab[1][0].value;

	tempptr[0].max[0]  = mod->sym_tab[0][0].value;
	tempptr[0].max[1]  = mod->sym_tab[1][0].value;
//	tempptr[0].max[0]  = -1;
//	tempptr[0].max[1]  = -1;
	
	if (mod->nsyms[0]) {
		tempptr[0].max[0] = mod->sym_tab[0][mod->nsyms[0]-1].value
			    + mod->sym_tab[0][mod->nsyms[0]-1].size;

		if (tempptr[0].mod->sym_tab[0][0].value >= tempptr[0].base[0]) {
			tempptr[0].base[0] = tempptr[0].base[1] = 0;
			DPRINT(("xero base for %s\n", mod->name));
		}
	}
	if (mod->nsyms[1])
		tempptr[0].max[1] = mod->sym_tab[1][mod->nsyms[1]-1].value
			    + mod->sym_tab[1][mod->nsyms[1]-1].size;

	tempptr[0].max[0] += tempptr[0].base[0];
	tempptr[0].max[1] += tempptr[0].base[0]; /* yes, text base */



	tempptr[1].mod = NULL;
	tempptr[1].version = 0;
	tempptr[1].pid = -1;
	
	*list = tempptr;
	show_all_maps();
}

static module_symbols_t *
find_module_syms(uint64_t id)
{
	module_symbols_t *p;

	for(p = module_list; p ; p = p ->next) {
		if (p->id == id)
			return p;
	}
	return NULL;
}

static void
show_all_maps() {
	module_map_t *p;
	
	vbprintf("*** Showing all maps (global)\n");
	for(p = options.primary_syms; p->pid != -1; p++) {
		vbprintf("PID: %d[%d], mod: %p, path: %s\n     TEXT base: %p, offs: %p, max: %p\n",
			p->pid, p->version, p->mod, p->path, (void *)p->base[0], (void *)p->offs[0], (void *)p->max[0]);
	}
			
	vbprintf("*** Done showing all maps (global)\n");
}

// andrzejn
void
pfmon_gather_module_symbols() {
	module_map_t *map = NULL;
	module_symbols_t *mod = NULL;
	struct stat st;
	char *path = NULL;
	uint64_t id = 0;
	
	vbprintf("Gathering module symbols...\n");
	for(map = options.primary_syms; map->pid != -1; map++) {

		// skip modules we have already loaded (find by inode)
		// TBD: I have doubts if this is ok in all cases
		path = strdup(map->path);
		mod = map->mod;
		if(mod == NULL) {
			stat(path, &st);
			id = (uint64_t)st.st_dev << 32 | st.st_ino;
			mod = find_module_syms(id);
		}
		
		vbprintf("(1) mod: %p, map->mod: %p\n", mod, map->mod);

		if(mod == NULL) {
			mod = calloc(1, sizeof(module_symbols_t));
			if (mod == NULL) {
				printf("Module scanner out of memory (1)\n");
				return;
			}
			mod->id = id;
			mod->name = strdup(path);
			if (load_module_syms(path, mod)) {
				// andrzejn: TBD: check if this function returns a non-zero value in
				// other than extreme cases, maybe we don't need to "return" on fail here
				printf("Module scanner out of memory (2)\n");
				return;
			}
			vbprintf("(1.1) mod: %p, map->mod: %p\n", mod, map->mod);
			map->mod = mod;
			vbprintf("(1.2) mod: %p, map->mod: %p\n", mod, map->mod);
		} else {
		        if(map->mod == NULL)
		        	map->mod = mod;
				
		}
		mod->refcnt++;
		vbprintf("(2) mod: %p, map->mod: %p\n", mod, map->mod);
		// estimate symbol bounds
		// andrzejn: TBD: establish whether this should be changed/removed when multiple maps of the
		// same module are involved		
		if (mod->nsyms[0]) {
			map->max[0] = mod->sym_tab[0][mod->nsyms[0]-1].value
				    + mod->sym_tab[0][mod->nsyms[0]-1].size;

			if (map->mod->sym_tab[0][0].value >= map->base[0]) {
				map->base[0] = map->base[1] = 0;
				DPRINT(("xero base for %s\n", mod->name));
			}
		}
		if (mod->nsyms[1])
			map->max[1] = mod->sym_tab[1][mod->nsyms[1]-1].value
				    + mod->sym_tab[1][mod->nsyms[1]-1].size;

		map->max[0] += map->base[0];
		map->max[1] += map->base[0]; /* yes, text base */

		vbprintf("%lu text symbols and %lu data symbols, ELF file %s\n",
			 mod->nsyms[0],
			 mod->nsyms[1],
			 path);

		// clean up.
		if(path)
		         free(path);
	}
}

int
load_pid_map(pfmon_sdesc_t *sdesc, module_map_t **l)
{
	pid_t pid = sdesc->tid;
	module_map_t *p;
	module_symbols_t *mod;
	struct stat st;
	size_t szl;
	FILE *fp;
	uint64_t id;
	unsigned long base_text, base_data, start, offset;
	unsigned long text_offs, data_offs;
	size_t max_count;
	int ret, n, k;
	char perm[8];
	char filename[32];
	char *line, *path, *c;
	int current_map_version = 0;
	char found_text, found_data;

	line = path = NULL;

	vbprintf("[%d] load pid map version %d, flushing samples\n", pid, sdesc->current_map_version+1);

	/*
 	 * flush remaining samples, if any
 	 *
 	 * in per-thread mode, monitored thread is necessary
 	 * stopped because we come here on breakpoints only.
 	 */
	pfmon_process_smpl_buf(sdesc, 0);
	
	/*
 	 * bump map version
 	 */
	sdesc->current_map_version += 1;
	current_map_version = sdesc->current_map_version;

	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	
	if (fp == NULL) 
		return -1;

	szl = 0;
	found_text = found_data = 0;
	base_text = base_data = 0;
	text_offs = data_offs = 0;

	p = NULL;
	k = 0;
	max_count = 4;
	ret = 0;
	while(getline(&line, &szl, fp) >0) {
		n = sscanf (line, "%lx-%*x %s %lx", &start, perm, &offset);

		if (n != 3 || perm[3] != 'p')
			continue;

		path = strchr(line, '/');
		/* remove trailing \n */
		if (path) {
			path[strlen(path)-1] = '\0';
			/*
			 * handle the case where /proc/maps reports the library
			 * path as deleted (from the dcache)
			 */
			c = strchr(path, ';');
			if (c)
				*c = '\0';

			if (perm[2] == 'x' && perm[1] == '-') {
				base_text = start;
				text_offs = offset;
				found_text = 1;
			} else if (perm[0] == 'r' && perm[1] == 'w') {
				base_data = start;
				data_offs = offset;
				found_data = 1;
			} else
				continue;

			if (found_data == 0 || found_text == 0)
				continue;

			if (k == 0 || k == max_count) {
				max_count <<=1;
				p = realloc(p, max_count * sizeof(module_map_t));
				if (!p) {
					ret = -1;
					break;
				}
			}
			stat(path, &st);

			// get the inode number and assign it as an ID
			id = (uint64_t)st.st_dev << 32 | st.st_ino;

			mod = NULL;	// to be filled offline
			DPRINT(("%d 0x%lx 0x%lx 0x%lx 0x%lx %s\n", k, base_text, text_offs, base_data, data_offs, path));

			p[k].base[0]  = base_text;
			p[k].base[1]  = base_data;
			p[k].offs[0]  = text_offs;
			p[k].offs[1]  = data_offs;
			
			p[k].version = current_map_version;
			p[k].pid = pid;
			p[k].path = strdup(path);

			p[k].mod = mod;

			p[k].max[0] = 0;	// to be filled offline
			p[k].max[1] = 0;	// to be filled offline
			found_text = found_data = 0;
			k++;
		}
	}

	if (ret == 0) {
		if (k== 0 || (k+2) >= max_count) {
			max_count+=2;
			p = realloc(p, max_count * sizeof(module_map_t));
			if (!p)
				goto error;
		}

		p[k].mod = NULL;
		p[k].pid = -1;
		p[k].version = 0;

		// instead of substituting the list...
		// ...fast forward to the last element...
		module_map_t *x;
		int i = 0;

		if(*l != NULL) {
			for(x = *l; x->pid != -1; x++) {
				i++; 
			}
			*l = realloc(*l, (i+k+1) * sizeof(module_map_t));
			for(x = *l; x->pid != -1; x++) {
			}
		} else {
			i = 0;
			*l = realloc(*l, (i+k+1) * sizeof(module_map_t));
			x = *l;
		}
		
		memcpy(x, p, (k+1) * sizeof(module_map_t));
	}
error:
	if (line)
		free(line);

	fclose(fp);

	if (ret == -1) {
		warning("abort loading map from %s\n", filename);
		free(p);
	} 
	return ret;
}

int
load_pid_syms(pfmon_sdesc_t *sdesc, pid_t pid, module_map_t **l)
{
	module_map_t *p;
	module_symbols_t *mod;
	struct stat st;
	size_t szl;
	FILE *fp;
	uint64_t id;
	unsigned long base_text, base_data, start, offset;
	unsigned long text_offs, data_offs;
	size_t max_count;
	int ret, n, k;
	char perm[8];
	char filename[32];
	char *line, *path, *c;
	char found_text, found_data;

	line = path = NULL;
	
	sdesc->current_map_version = 1;
	
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if (fp == NULL) 
		return -1;

	szl = 0;
	base_text = base_data = 0;
	found_text = found_data = 0;
	text_offs = data_offs = 0;

	p = NULL;
	max_count = 4;
	k = 0;
	ret = 0;
	while(getline(&line, &szl, fp) >0) {
		n = sscanf (line, "%lx-%*x %s %lx", &start, perm, &offset);

		if (n != 3 || perm[3] != 'p')
			continue;

		path = strchr(line, '/');
		/* remove trailing \n */
		if (path) {
			path[strlen(path)-1] = '\0';
			/*
			 * handle the case where /proc/maps reports the library
			 * path as deleted (from the dcache)
			 */
			c = strchr(path, ';');
			if (c)
				*c = '\0';

			if (perm[2] == 'x' && perm[1] == '-') {
				base_text = start;
				text_offs = offset;
				found_text = 1;
			} else if (perm[0] == 'r' && perm[1] == 'w') {
				base_data = start;
				data_offs = offset;
				found_data = 1;
			} else
				continue;

			if (found_data == 0 || found_text == 0)
				continue;

			if (k == 0 || k == max_count) {
				max_count <<=1;
				p = realloc(p, max_count * sizeof(module_map_t));
				if (!p) {
					ret = -1;
					break;
				}
			}
			stat(path, &st);

			// get the inode number and assign it as an ID
			id = (uint64_t)st.st_dev << 32 | st.st_ino;
			/*
			 * skip modules we have already loaded (find by inode)
			 */
			mod = find_module_syms(id);
			DPRINT(("%d 0x%lx 0x%lx 0x%lx 0x%lx %s\n", k, base_text, text_offs, base_data, data_offs, path));

			// andrzejn
			p[k].pid = pid;

			if(sdesc != NULL)
				p[k].version = sdesc->current_map_version;
			else
				p[k].version = 0;

                        p[k].path = strdup(path);
			
			p[k].base[0]  = base_text;
			p[k].base[1]  = base_data;
			p[k].offs[0]  = text_offs;
			p[k].offs[1]  = data_offs;

			if (!mod) {
				mod = calloc(1, sizeof(module_symbols_t));
				if (mod == NULL) {
					ret = -1;
					break;
				}
				mod->id	= id;
				mod->name = strdup(path);
				if (load_module_syms(path, mod)) {
					ret = -1;
					break;
				}
			}
			mod->refcnt++;
			p[k].mod = mod;

			if (mod->nsyms[0]) {
				p[k].max[0] = mod->sym_tab[0][mod->nsyms[0]-1].value
					    + mod->sym_tab[0][mod->nsyms[0]-1].size;

				if (p[k].mod->sym_tab[0][0].value >= p[k].base[0]) {
					p[k].base[0] = p[k].base[1] = 0;
					DPRINT(("xero base for %s\n", mod->name));
				}
			}
			if (mod->nsyms[1])
				p[k].max[1] = mod->sym_tab[1][mod->nsyms[1]-1].value
					    + mod->sym_tab[1][mod->nsyms[1]-1].size;

			p[k].max[0] += p[k].base[0];
			p[k].max[1] += p[k].base[0]; /* yes, text base */

			found_text = found_data = 0;
			k++;
			vbprintf("[%u] loaded %lu text symbols and %lu data symbols, ELF file %s\n",
				 pid,
				 mod->nsyms[0],
				 mod->nsyms[1],
				 path);
		}
	}
	if (ret == 0) {
		if (k== 0 || (k+2) >= max_count) {
			max_count+=2;
			p = realloc(p, max_count * sizeof(module_map_t));
			if (!p)
				goto error;
		}
		/* add kernel to map */
		p[k].mod = mod = &kernel_module_syms;
		p[k].path = "kernel";
		p[k].version = 1;
		p[k].pid = 0;
		
		p[k].base[0] = mod->sym_tab[0][0].value;
		p[k].base[1] = mod->sym_tab[1][0].value;

		p[k].max[0]  = mod->sym_tab[0][0].value;
		p[k].max[1]  = mod->sym_tab[1][0].value;
		k++;

		/* end marker */		
		p[k].mod = NULL;
		p[k].pid = -1;
		p[k].version = 0;

		*l = p;
	}
error:
	if (line)
		free(line);

	fclose(fp);
	if (ret == -1) {
		warning("abort loading symbols from %s\n", filename);
		free(p);
	} 
	return ret;
}


int
find_sym_addr(char *name, module_map_t *map, pfmon_sym_type_t type, unsigned long *start, unsigned long *end)
{
	module_symbols_t *mod;
	symbol_t *symbol_tab;
	char *p;
	unsigned long i, nsyms, offs = 0;
	int has_mod_name = 0;
	char mod_name[32];

	if (name == NULL || *name == '\0' || start == NULL || map == NULL) 
		return -1;

	/*
	 * check for module name
	 */
	mod_name[0] = '\0';
	p = strchr(name, ':');
	if (p) {
		strncpy(mod_name, name, p - name); 
		mod_name[p-name] = '\0';
		name = p + 1;
		has_mod_name = 1;
	}

	for(; map->mod; map++) {
		if (has_mod_name && strcmp(mod_name, map->mod->name))
			continue;

		mod = map->mod;
		nsyms      = mod->nsyms[type];
		symbol_tab = mod->sym_tab[type];

		for (i = 0; i < nsyms; i++) {
			if (!strcmp(name, symbol_tab[i].name))
				goto found;
		 }
	}
	return -1;
found:
	if (type == PFMON_DATA_SYMBOL && map->base[PFMON_DATA_SYMBOL])
		offs = map->base[PFMON_DATA_SYMBOL] - map->base[PFMON_TEXT_SYMBOL];

	*start = map->base[type] - offs + symbol_tab[i].value;

	if (end) {
		if (symbol_tab[i].size != 0) {
			*end = *start + symbol_tab[i].size; 
			//vbprintf("symbol %s: [0x%lx-0x%lx)=%ld bytes\n", name, *start, *end, symbol_tab[i].size);
		} else {
			vbprintf("using approximation for size of symbol %s\n", name);

			if (i == (nsyms-1)) {
				warning("cannot find another symbol to approximate size of %s\n", name);
				return -1;
			}

		        /*
		 	 * XXX: Very approximative and maybe false at times
		 	 * Use carefully
		 	 */
			*end = symbol_tab[i+1].value;
		}
		vbprintf("symbol %s (%s): [%p-%p)=%ld bytes\n", 
				name, 
				type == PFMON_TEXT_SYMBOL ? "code" : "data",
				(void *)*start, 
				(void *)*end, 
				*end-*start);
	}
	return 0;
}

static int
bsearch_sym_cmp(unsigned long base, unsigned long addr, symbol_t *sym)
{
	unsigned long s, e;

	s = base + sym->value;
	e = s + sym->size;

	/* match */
	if (s <= addr && addr < e)
		return 0;

	/* less than */
	if (addr < s)
		return -1;

	/* greater than */
	return 1;
}

// andrzejn: find by address, pid, version
// andrzejn: TBD: check if it works ok
int
find_sym_by_apv(unsigned long addr, pid_t pid, unsigned int version, module_map_t *map, pfmon_sym_type_t type, char **name, char **module, unsigned long *start, unsigned long *end)
{
	module_symbols_t *mod;
	symbol_t *s = NULL;
	long l, h, m;
	unsigned long base;
	int r;

	DPRINT(("looking for %p for %d[%d]\n", addr, pid, version));

	// andrzejn: TBD: fix the version number in system wide and get rid of the OR
	if ((version != 0 && pid != -1) || options.opt_syst_wide)
		for(; map->mod ; map++) {
			// ensure that kernel space (pid==0, version ignored) is checked
			if (map->pid > 0 && pid > 0)
				if ((map->pid != pid) || (map->version != version))
					continue;
			mod = map->mod;

			/* max is already base adjusted */
			if (addr > map->max[type])
				continue;
			if (mod->nsyms[type] == 0)
				continue;

			base = map->base[type];

			/*
			 * binary search
			 * cannot use bsearch because of base adjustment
			 * s = bsearch(&addr, mod->sym_tab[type], mod->nsyms[type], sizeof(symbol_t), bsearch_sym_cmp);
			 */
			l = 0;
			h = mod->nsyms[type]-1;
			while (l <= h) {
				m = (l + h) / 2;
				s = &mod->sym_tab[type][m];
				r = bsearch_sym_cmp(base, addr, &mod->sym_tab[type][m]);
				if (r > 0)
					l = m + 1;
				else if (r < 0)
					h = m - 1;
				else
					goto found;
			}
		}
	DPRINT(("addr=0x%lx not found (pid=%d, version=%d)\n", addr, pid, version));
	return -1;
found:
	if (name)  *name    = s->name;
	if (start) *start   = base + s->value;
	if (end)   *end     = base + s->value + s->size;
	if (module) *module = mod->name; /* symbol module */
	return 0;
}

int
pfmon_is_exact_sym(unsigned long addr, module_map_t *map, pfmon_sym_type_t type)
{
	module_symbols_t *mod;
	symbol_t *symbol_tab;
	unsigned long i, nsyms;

	/*
	 * map could be NULL
	 */
	if (!map)
		return 0;

	/* table is assumed sorted by address */
	for(; map->mod; map++) {
		mod = map->mod;
		nsyms      = mod->nsyms[type];
		symbol_tab = mod->sym_tab[type];
		for (i = 0; i < nsyms; i++) {
			if (symbol_tab[i].value == addr)
				return 1;
		}
	}
	return 0;
}


/*
 * mostly for debug
 */
void
print_syms(module_map_t *map_syms)
{
	module_map_t *map;
	module_symbols_t *mod;
	symbol_t *symbol_tab;
	unsigned long sz;
	char *mod_name;
	char *c="TD";
	int j;
	unsigned long i, nsyms;

	for(j=0; j < 2; j++) {
		for (map = map_syms; map->mod ; map++) {

			mod      = map->mod;
			mod_name = mod->name;

			nsyms      = mod->nsyms[j];
			symbol_tab = mod->sym_tab[j];
			for (i = 0; i < nsyms; i++) {
				sz = symbol_tab[i].size;
				if (i == (nsyms-1) && sz == 0) {
					if (map[1].mod && map[1].mod->nsyms[j]) {
						unsigned long n;
						n = map[1].base[j]+map[1].mod->sym_tab[j][0].value;
						sz = n - map->base[j]+symbol_tab[i].value;
					} else {
						sz = ~0 - map->base[j]+symbol_tab[i].value;
					}

				}
				printf("%p %c %8lu %s<%s>\n", 
					(void *)(map->base[j]+symbol_tab[i].value), 
					c[j],
					sz,
					symbol_tab[i].name, mod_name);
			}
		}
	}
}

unsigned long pfmon_get_entry_point(char *filename)
{
	Elf *elf;
	Elf64_Ehdr *ehdr64;
	Elf32_Ehdr *ehdr32;
	char *eident;
	unsigned long addr = 0;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		DPRINT(("symbol file for %s not found\n", filename));
		return 0;
	}

  	/* initial call to set internal version value */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		DPRINT(("ELF library out of date"));
		goto end2;
	}

  	/* prepare to read the entire file */
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		DPRINT(("cannot read %s\n", filename));
		goto end2;
	}

	/* error checking */
	if (elf_kind(elf) != ELF_K_ELF) {
		DPRINT(("%s is not an ELF file\n", filename));
		goto end;
	}
  
	eident = elf_getident(elf, NULL);
	switch (eident[EI_CLASS]) {
  		case ELFCLASS64:
			ehdr64 = elf64_getehdr(elf);
			if (ehdr64)
				addr = ehdr64->e_entry;
			break;
		case ELFCLASS32:
			ehdr32 = elf32_getehdr(elf);
			if (ehdr32)
				addr = ehdr32->e_entry;
			break;
		default:
			addr = 0;
	}
end:
	elf_end(elf);
end2:
	close(fd);
	return addr;
}

int
pfmon_program_is_abi32(char *filename)
{
	Elf *elf;
	char *eident;
	int fd, ret;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		DPRINT(("symbol file for %s not found\n", filename));
		return 0;
	}

  	/* initial call to set internal version value */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		DPRINT(("ELF library out of date"));
		goto end2;
	}

  	/* prepare to read the entire file */
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		DPRINT(("cannot read %s\n", filename));
		goto end2;
	}

	/* error checking */
	if (elf_kind(elf) != ELF_K_ELF) {
		DPRINT(("%s is not an ELF file\n", filename));
		goto end;
	}
  
	eident = elf_getident(elf, NULL);
	if (eident[EI_CLASS] == ELFCLASS32)
		ret = 1;
end:
	elf_end(elf);
end2:
	close(fd);
	return ret;
}

