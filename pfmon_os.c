
#include <sys/types.h>
#include <sys/mman.h>

#include "pfmon.h"

#ifdef __ia64__
#define COND_RETURN(_ab, _err)	\
	do { \
		if (options.opt_is22 == 0) { \
			int ret; \
			ret = _ab; \
			*(_err) = errno; \
			return ret; \
		}\
	} while(0)
#else
#define COND_RETURN(a,b) do {} while(0)
#endif

#ifdef __ia64__
static int
pfmon_write_pmds_old(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pmds, int n, int *err)
{
	pfarg_reg_t *old_pmds;
	int i, ret;

	old_pmds = calloc(1, sizeof(*old_pmds)*n);
	if (old_pmds == NULL) {
		*err = errno;
		return -1;
	}

	for(i=0; i < n; i++) {
		/*
		 * reg_long_reset     -> must do
		 * reg_short_reset    -> must do
		 * reg_last_reset_val -> unused
		 * reg_ovfl_switch    -> unused in v2.0
		 * reg_reset_pmds     -> write_pmcs_old
		 * reg_smpl_pmds      -> write_pmcs_old
		 * reg_smpl_eventid   -> unused
		 * reg_random_mask    -> must do
		 * reg_random_seed    -> must do
		 */
		old_pmds[i].reg_num          = pmds[i].reg_num;
		old_pmds[i].reg_value        = pmds[i].reg_value;
		old_pmds[i].reg_long_reset   = pmds[i].reg_long_reset;
		old_pmds[i].reg_short_reset  = pmds[i].reg_short_reset;
		old_pmds[i].reg_random_mask  = pmds[i].reg_random_mask;
		old_pmds[i].reg_random_seed  = pmds[i].reg_random_seed;
	}
	ret = perfmonctl(fd, PFM_WRITE_PMDS, old_pmds, n);
	*err = errno;

	/*
	 * pfmon does not look at per-register error flags so we don't need
	 * to copy reg_flags back.
	 */
	free(old_pmds);

 	return ret;
}

static int
pfmon_write_pmcs_old(int fd, pfmon_event_set_t *set, pfmon_pmc_t *pmcs, int n, int *err)
{
	pfarg_reg_t *old_pmcs;
	int i, ret;

	*err = 0;

	old_pmcs = calloc(1, sizeof(*old_pmcs)*n);
	if (old_pmcs == NULL) {
		*err = errno;
		return -1;
	}

	for(i=0; i < n; i++) {
		/*
		 * reg_flags          -> must do
		 * reg_long_reset     -> write_pmds_old
		 * reg_short_reset    -> write_pmds_old
		 * reg_last_reset_val -> unused
		 * reg_ovfl_switch    -> unused in v2.0
		 * reg_reset_pmds     -> write_pmcs_old
		 * reg_smpl_pmds      -> write_pmcs_old
		 * reg_smpl_eventid   -> unused
		 * reg_random_mask    -> write_pmds_old
		 * reg_random_seed    -> write_pmds_old
		 */
		old_pmcs[i].reg_num   = pmcs[i].reg_num;
		old_pmcs[i].reg_value = pmcs[i].reg_value;
		old_pmcs[i].reg_flags = pmcs[i].reg_flags;

		/*
		 * the reg_smpl_pmds,reg_reset_pmds bitvector have been moved
		 * to the PMD side in the new interface. This is the only way
		 * to put them back where they belong for perfmon v2.0
		 * We only do this for actual counter events.
		 */
		if (i < set->event_count) {
			old_pmcs[i].reg_smpl_pmds[0] = set->master_pd[i].reg_smpl_pmds[0];
			old_pmcs[i].reg_reset_pmds[0] = set->master_pd[i].reg_reset_pmds[0];
		}
	}

	ret = perfmonctl(fd, PFM_WRITE_PMCS, old_pmcs, n);
	*err = errno;

	free(old_pmcs);

 	return ret;
}

static int
pfmon_read_pmds_old(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pmds, int n, int *err)
{
	pfarg_reg_t *old_pmds;
	int i, ret;

	old_pmds = calloc(1, sizeof(*old_pmds)*n);
	if (old_pmds == NULL) {
		*err = errno;
		return -1;
	}

	for(i=0; i < n; i++) {
		old_pmds[i].reg_num  = pmds[i].reg_num;
	}

	ret = perfmonctl(fd, PFM_READ_PMDS, old_pmds, n);
	*err = errno;

	/*
	 * XXX: do the minimum here. pfmon only looks at the reg_value field
	 * XXX: we do this even when the call fails, because it propagates retflags
	 */
	for(i=0; i < n; i++) {
		pmds[i].reg_value = old_pmds[i].reg_value;
	}

	free(old_pmds);

 	return ret;
}

/*
 * for perfmon v2.0
 */
static int
pfmon_create_context_old(pfmon_ctx_t *ctx, void **smpl_hdr, int *fd, int *err)
{
	pfarg_context_t *old_ctx;
	void *addr;
	int ret;

	addr = calloc(1, sizeof(*old_ctx)+ctx->ctx_arg_size);
	if (addr == NULL) {
		*err = errno;
		return -1;
	}
	old_ctx = addr;

	old_ctx->ctx_flags = ctx->ctx_flags;
	memcpy(old_ctx->ctx_smpl_buf_id, ctx->ctx_uuid, sizeof(pfm_uuid_t));

	memcpy(old_ctx+1, ctx->ctx_arg, ctx->ctx_arg_size);

	ret = perfmonctl(0, PFM_CREATE_CONTEXT, old_ctx, 1);
	*err = errno;
	if (ret == -1) {
		goto error;
	}
	*smpl_hdr = old_ctx->ctx_smpl_vaddr;
	*fd = old_ctx->ctx_fd;
	ctx->ctx_map_size = 0;
error:
	free(addr);

	return ret;

}

static int
pfmon_write_ibrs_old(int fd, pfmon_pmc_t *pmcs, int n, int *err)
{
	pfarg_dbreg_t *ibrs;
	int i, ret;

	ibrs = calloc(1, sizeof(*ibrs)*n);
	if (ibrs == NULL) {
		*err = errno;
		return -1;
	}

	for(i=0; i < n; i++) {
		ibrs[i].dbreg_num   = pmcs[i].reg_num - 256;
		ibrs[i].dbreg_value = pmcs[i].reg_value;
	}

	ret = perfmonctl(fd, PFM_WRITE_IBRS, ibrs, n);
	*err = errno;

	free(ibrs);

 	return ret;
}

static int
pfmon_write_dbrs_old(int fd, pfmon_pmc_t *pmcs, int n, int *err)
{
	pfarg_dbreg_t *dbrs;
	int i, ret;

	dbrs = calloc(1, sizeof(*dbrs)*n);
	if (dbrs == NULL) {
		*err = errno;
		return -1;
	}

	for(i=0; i < n; i++) {
		dbrs[i].dbreg_num   = pmcs[i].reg_num - 264;
		dbrs[i].dbreg_value = pmcs[i].reg_value;
	}

	ret = perfmonctl(fd, PFM_WRITE_DBRS, dbrs, n);
	*err = errno;

	free(dbrs);

 	return ret;
}
#endif /* __ia64__ */

int
pfmon_load_context(int fd, pid_t tid, int *err)
{
	pfarg_load_t load_args;
	int ret;

	memset(&load_args, 0, sizeof(load_args));

#ifdef __ia64__
	/* in v2.0 system-wide the load_pid must be the thread id of caller */
	 if (options.opt_is22 == 0 && options.opt_syst_wide)  
		 tid = gettid();
#endif

	load_args.load_pid = tid;
	COND_RETURN(perfmonctl(fd, PFM_LOAD_CONTEXT, &load_args, 1), err);

	ret = pfm_load_context(fd, &load_args);
	*err = errno;
	return ret;
}

int
pfmon_unload_context(int fd, int *err)
{
	int ret;
	COND_RETURN(perfmonctl(fd, PFM_UNLOAD_CONTEXT, NULL, 0), err);

	ret = pfm_unload_context(fd);
	*err = errno;
	return ret;
}

int
pfmon_write_pmds(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pmds, int n, int *err)
{
	int ret;
	COND_RETURN(pfmon_write_pmds_old(fd, set, pmds, n, err), err);

	ret = pfm_write_pmds(fd, pmds, n);
	*err = errno;
	return ret;
}

int
pfmon_write_pmcs(int fd, pfmon_event_set_t *set, pfmon_pmc_t *pmcs, int n, int *err)
{
	int ret;

	COND_RETURN(pfmon_write_pmcs_old(fd, set, pmcs, n, err), err);

	ret = pfm_write_pmcs(fd, pmcs, n);
	*err = errno;
	return ret;
}


int
pfmon_read_pmds(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pmds, int n, int *err)
{
	int ret;

	COND_RETURN(pfmon_read_pmds_old(fd, set, pmds, n, err), err);

	ret = pfm_read_pmds(fd, pmds, n);
	*err = errno;
 	return ret;
}

int
pfmon_create_evtsets(int fd, pfmon_setdesc_t *sets, int n, int *err)
{
	int ret;
	ret = pfm_create_evtsets(fd, sets, n);
	*err = errno;
	return ret;
}

int
pfmon_getinfo_evtsets(int fd, pfmon_setinfo_t *sets, int n, int *err)
{
	int ret;
	ret = pfm_getinfo_evtsets(fd, sets, n);
	*err = errno;
	return ret;
}

int
pfmon_start(int fd, int *err)
{
	int ret;
	COND_RETURN(perfmonctl(fd, PFM_START, NULL, 0), err);

	ret = pfm_start(fd, NULL);
	*err = errno;
	return ret;
}

int
pfmon_stop(int fd, int *err)
{
	int ret;
	COND_RETURN(perfmonctl(fd, PFM_STOP, NULL, 0), err);

	ret = pfm_stop(fd);
	*err = errno;
	return ret;
}

int
pfmon_restart(int fd, int *err)
{
	int ret;

	COND_RETURN(perfmonctl(fd, PFM_RESTART, NULL, 0), err);

	ret = pfm_restart(fd);
	*err = errno;
	return ret;
}

/*
 * for perfmon v2.3 or higher
 */
int
pfmon_create_context(pfmon_ctx_t *ctx, void **smpl_hdr, int *fd, int *err)
{
	pfarg_ctx_t *new_ctx;
	void *addr;
	int ret;

	COND_RETURN(pfmon_create_context_old(ctx, smpl_hdr, fd, err), err);

	addr = calloc(1, sizeof(*new_ctx));
	if (addr == NULL) {
		*err = errno;
		return -1;
	}
	new_ctx = addr;

	new_ctx->ctx_flags = ctx->ctx_flags;

	ret = pfm_create_context(new_ctx, ctx->fmt_name, ctx->ctx_arg, ctx->ctx_arg_size);
	*err = errno;
	if (ret == -1)
		goto error;
	*fd = ret;
	ret = -1;
	if (options.opt_use_smpl && ctx->ctx_map_size) {
		*smpl_hdr = mmap(NULL,
				 ctx->ctx_map_size,
				 PROT_READ, MAP_PRIVATE,
				 *fd,
				 0);
		*err = errno;

		if (*smpl_hdr == MAP_FAILED) {
			DPRINT(("cannot mmap buffer errno=%d\n", errno));
			close(*fd);
			goto error;
		}
		DPRINT(("mmap @%p size=%zu\n",
			*smpl_hdr,
			ctx->ctx_map_size));
	}
	ret = 0;
error:
	free(addr);
	return ret;
}

#ifdef __ia64__
int
pfmon_write_ibrs(int fd, pfmon_pmc_t *pmcs, int n, int *err)
{
	COND_RETURN(pfmon_write_ibrs_old(fd, pmcs, n, err), err);
	return pfmon_write_pmcs(fd, NULL, pmcs, n, err);
}

int
pfmon_write_dbrs(int fd, pfmon_pmc_t *pmcs, int n, int *err)
{
	COND_RETURN(pfmon_write_dbrs_old(fd, pmcs, n, err), err);
	return pfmon_write_pmcs(fd, NULL, pmcs, n, err);
}
#endif
