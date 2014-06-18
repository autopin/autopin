
#include <sys/types.h>
#include <sys/mman.h>

#include "pfmon.h"

int
pfmon_load_context(int fd, pid_t tid)
{
	pfarg_load_t load_args;
	int ret;

	memset(&load_args, 0, sizeof(load_args));

	load_args.load_pid = tid;
 
	if (options.opt_is22)
		ret = pfm_load_context(fd, &load_args);
	else
		ret = perfmonctl(fd, PFM_LOAD_CONTEXT, &load_args, 1);

	if (ret == -1)
		warning("pfm_load_context error %s\n", strerror(errno));

 	return ret;
}

int
pfmon_unload_context(int fd)
{
	int ret;

	if (options.opt_is22)
		ret = pfm_unload_context(fd);
	else
		ret = perfmonctl(fd, PFM_UNLOAD_CONTEXT, NULL, 0);

	if (ret == -1)
		warning("pfm_unload_context error %s\n", strerror(errno));

 	return ret;
}

static int
pfmon_write_pmds_old(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pmds, int n)
{
	pfarg_reg_t *old_pmds;
	int i, ret;

	old_pmds = calloc(1, sizeof(*old_pmds)*n);
	if (old_pmds == NULL) {
		warning("cannot allocate space for DBR registers\n");
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
	if (ret == -1)
		warning("pfm_write_old_pmds error [%d] %s\n", fd, strerror(errno));

	/*
	 * pfmon does not look at per-register error flags so we don't need
	 * to copy reg_flags back.
	 */
	free(old_pmds);

 	return ret;
}

int
pfmon_write_pmds(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pmds, int n)
{
	int ret;

	if (options.opt_is22 == 0)
		return pfmon_write_pmds_old(fd, pmds, n);

	ret = pfm_write_pmds(fd, pmds, n);
	if (ret == -1)
		warning("pfm_write_pmds error [%d] %s\n", fd, strerror(errno));

 	return ret;
}

static int
pfmon_write_pmcs_old(int fd, pfmon_event_set_t *set, pfmon_pmc_t *pmcs, int n)
{
	pfarg_reg_t *old_pmcs;
	int i, ret;

	old_pmcs = calloc(1, sizeof(*old_pmcs)*n);
	if (old_pmcs == NULL) {
		warning("cannot allocate space for DBR registers\n");
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
	if (ret == -1)
		warning("pfm_write_old_pmcs error [%d] %s\n", fd, strerror(errno));

	free(old_pmcs);

 	return ret;
}

int
pfmon_write_pmcs(int fd, pfmon_event_set_t *set, pfmon_pmc_t *pmcs, int n)
{
	int ret;

	if (options.opt_is22 == 0)
		return pfmon_write_pmcs_old(fd, pmcs, n);

	ret = pfm_write_pmcs(fd, pmcs, n);
	if (ret == -1)
		warning("pfm_write_pmcs error [%d] %s\n", fd, strerror(errno));

 	return ret;
}

static int
pfmon_read_pmds_old(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pmds, int n)
{
	pfarg_reg_t *old_pmds;
	int i, ret;

	old_pmds = calloc(1, sizeof(*old_pmds)*n);
	if (old_pmds == NULL) {
		warning("cannot allocate space for DBR registers\n");
		return -1;
	}

	for(i=0; i < n; i++) {
		old_pmds[i].reg_num  = pmds[i].reg_num;
	}

	ret = perfmonctl(fd, PFM_READ_PMDS, old_pmds, n);
	if (ret == -1)
		warning("pfm_write_old_pmds error [%d] %s\n", fd, strerror(errno));

	/*
	 * XXX: do the minimum here. pfmon only looks at the reg_value field
	 */
	for(i=0; i < n; i++) {
		pmds[i].reg_value = old_pmds[i].reg_value;
	}

	free(old_pmds);

 	return ret;
}


int
pfmon_read_pmds(int fd, pfmon_event_set_t *set, pfmon_pmd_t *pmds, int n)
{
	int ret;

	if (options.opt_is22 == 0)
		return pfmon_read_pmds_old(fd, pmds, n);

	ret = pfm_read_pmds(fd, pmds, n);
	if (ret == -1)
		warning("pfm_read_pmds error [%d] %s\n", fd, strerror(errno));

 	return ret;
}

int
pfmon_create_evtsets(int fd, pfmon_setdesc_t *sets, int n)
{
	int ret;

	ret = pfm_create_evtsets(fd, sets, n);
	if (ret == -1)
		warning("pfm_create_evtsets error [%d] %s\n", fd, strerror(errno));

 	return ret;
}

int
pfmon_getinfo_evtsets(int fd, pfmon_setinfo_t *sets, int n)
{
	int ret;

	ret = pfm_getinfo_evtsets(fd, sets, n);
	if (ret == -1)
		warning("pfm_getinfo_evtsets error [%d] %s\n", fd, strerror(errno));

 	return ret;
}

int
pfmon_start(int fd)
{
	int ret;

	if (options.opt_is22)
		ret = pfm_start(fd, NULL);
	else
		ret = perfmonctl(fd, PFM_START, NULL, 0);
	if (ret == -1)
		warning("pfm_start error [%d] %s\n", fd, strerror(errno));

	return ret;
}

int
pfmon_stop(int fd)
{
	int ret;

	if (options.opt_is22)
		ret = pfm_stop(fd);
	else
		ret = perfmonctl(fd, PFM_STOP, NULL, 0);

	if (ret == -1)
		warning("pfm_stop error [%d] %s\n", fd, strerror(errno));

	return ret;
}

int
pfmon_restart(int fd)
{
	int ret;

	if (options.opt_is22)
		ret = pfm_restart(fd);
	else
		ret = perfmonctl(fd, PFM_RESTART, NULL, 0);

	if (ret == -1)
		warning("pfm_restart error [%d] %s\n", fd, strerror(errno));

	return ret;
}

/*
 * for perfmon v2.0
 */
static int
pfmon_create_context_old(pfmon_ctx_t *ctx, void **smpl_hdr, int *fd)
{
	pfarg_context_t *old_ctx;
	void *addr;
	int ret;

	addr = calloc(1, sizeof(*old_ctx)+ctx->ctx_arg_size);
	if (addr == NULL) {
		warning("cannot allocate context structure\n");
		return -1;
	}
	old_ctx = addr;

	old_ctx->ctx_flags = ctx->ctx_flags;
	memcpy(old_ctx->ctx_smpl_buf_id, ctx->ctx_uuid, sizeof(pfm_uuid_t));

	memcpy(old_ctx+1, ctx->ctx_arg, ctx->ctx_arg_size);

	ret = perfmonctl(0, PFM_CREATE_CONTEXT, old_ctx, 1);
	if (ret == -1) {
		warning("pfm_create_context error %s\n", strerror(errno));
		goto error;
	}
	*smpl_hdr = old_ctx->ctx_smpl_vaddr;
	*fd = old_ctx->ctx_fd;

error:
	free(addr);
	/* not needed beyond that point */
	free(ctx->ctx_arg);

	return ret;

}

/*
 * for perfmon v2.2 or higher
 */
int
pfmon_create_context(pfmon_ctx_t *ctx, void **smpl_hdr, int *fd)
{
	pfarg_ctx_t *new_ctx;
	void *addr;
	int ret;

	if (options.opt_is22 == 0) return pfmon_create_context_old(ctx, smpl_hdr, fd);

	addr = calloc(1, sizeof(*new_ctx));
	if (addr == NULL) {
		warning("cannot allocate context structure\n");
		return -1;
	}
	new_ctx = addr;

	new_ctx->ctx_flags = ctx->ctx_flags;
	memcpy(new_ctx->ctx_smpl_buf_id, ctx->ctx_uuid, sizeof(pfm_uuid_t));

	ret = pfm_create_context(new_ctx, ctx->ctx_arg, ctx->ctx_arg_size);
	if (ret == -1) {
		warning("pfm_create_context error %s\n", strerror(errno));
		goto error;
	}
	ret = -1;
	if (options.opt_use_smpl) {
		*smpl_hdr = mmap(NULL,
				 new_ctx->ctx_smpl_buf_size,
				 PROT_READ, MAP_PRIVATE,
				 new_ctx->ctx_fd,
				 0);
		if (*smpl_hdr == MAP_FAILED) {
			DPRINT(("cannot mmap buffer errno=%d\n", errno));
			goto error;
		}
		DPRINT(("--->sampling buffer @%p size=%zu\n",
			*smpl_hdr,
			new_ctx->ctx_smpl_buf_size));
	}
	*fd = new_ctx->ctx_fd;
	ret = 0;
error:
	free(addr);

	/* not needed beyond that point */
	free(ctx->ctx_arg);

	return ret;
}

int
prepare_pmc_registers(pfmon_event_set_t *set)
{
	return 0;
#if 0
	unsigned long tmp_smpl_pmds = 0UL;
	unsigned long m;
	unsigned int i;

	/*
	 * nothing special to do if not sampling
	 */
	if (options.opt_use_smpl == 0) return 0;

	for(i=0; i < set->event_count; i++) {
		/*
		 * The counters for which a sampling period has been
		 * set must have their notify flag set unless requested
		 * otherwise by user in which case the
		 * buffer will saturate: you stop when the buffer becomes
		 * full, i.e., collect the first samples only.
		 *
		 * Counters for which no sampling period is set are
		 * considered part of the set of PMC/PMD to store
		 * in each sample.
		 */
		if (set->long_rates[i].flags & PFMON_RATE_VAL_SET) {

			if (options.opt_no_ovfl_notify == 0) 
				set->master_pc[i].reg_flags |= PFM_REGFL_OVFL_NOTIFY;

			/*
			 * set randomization flag
			 */
			if (set->long_rates[i].flags & (PFMON_RATE_SEED_SET|PFMON_RATE_MASK_SET)) {
				set->master_pc[i].reg_flags |= PFM_REGFL_RANDOM;
			}
		} else {
			/*
			 * accumulate list of all PMC/PMD pairs that we have
			 * to record in each sample.
			 */
			tmp_smpl_pmds |= M_PMD(set->master_pc[i].reg_num) | set->smpl_pmds[i];
		}
	}
	/*
	 * some common PMD may have already been requested by module specific
	 * code (as part of post_options).
	 */
	set->common_smpl_pmds |= tmp_smpl_pmds;

	/*
	 * update smpl_pmds for all sampling periods
	 * we need to wait until we know know all the pmcs involved
	 */
	for(i=0; i < set->event_count; i++) {

		if ((set->long_rates[i].flags & PFMON_RATE_VAL_SET) == 0) continue;

		m  = set->smpl_pmds[i];
		m |=  set->common_smpl_pmds;

		set->master_pc[i].reg_smpl_pmds[0]  = m;

		set->rev_smpl_pmds[set->master_pc[i].reg_num] = m;

		set->smpl_pmds[i] = m;

		m = options.opt_reset_non_smpl ? set->common_smpl_pmds : 0UL;
		set->master_pc[i].reg_reset_pmds[0] |= set->common_reset_pmds | m;
	}
	
	if (options.opt_verbose) {
		DPRINT(("common_smpl_pmds=0x%lx common_reset_pmds=0x%lx\n", 
			set->common_smpl_pmds, set->common_reset_pmds));
		for(i=0; i < set->event_count; i++) {
			vbprintf("[pmc%u set=%u smpl_pmds=0x%lx reset_pmds=0x%lx]\n",
				set->master_pc[i].reg_num,
				set->master_pc[i].reg_set,
				set->master_pc[i].reg_smpl_pmds[0],
				set->master_pc[i].reg_reset_pmds[0]);
		}
	}
	return 0;
#endif
}
	
static int
pfmon_write_ibrs_old(int fd, pfmon_pmc_t *pmcs, int n)
{
	pfarg_dbreg_t *ibrs;
	int i, ret;

	ibrs = calloc(1, sizeof(*ibrs)*n);
	if (ibrs == NULL) {
		warning("cannot allocate space for IBR registers\n");
		return -1;
	}

	for(i=0; i < n; i++) {
		ibrs[i].dbreg_num   = pmcs[i].reg_num - 256;
		ibrs[i].dbreg_value = pmcs[i].reg_value;
	}

	ret = perfmonctl(fd, PFM_WRITE_IBRS, ibrs, n);
	if (ret == -1)
		warning("pfm_write_ibrs error [%d] %s\n", fd, strerror(errno));

	free(ibrs);

 	return ret;
}

int
pfmon_write_ibrs(int fd, pfmon_pmc_t *pmcs, int n)
{
	if (options.opt_is22 == 0) return pfmon_write_ibrs_old(fd, pmcs, n);
		
	return pfmon_write_pmcs(fd, pmcs, n);
}
	
static int
pfmon_write_dbrs_old(int fd, pfmon_pmc_t *pmcs, int n)
{
	pfarg_dbreg_t *dbrs;
	int i, ret;

	dbrs = calloc(1, sizeof(*dbrs)*n);
	if (dbrs == NULL) {
		warning("cannot allocate space for DBR registers\n");
		return -1;
	}

	for(i=0; i < n; i++) {
		dbrs[i].dbreg_num   = pmcs[i].reg_num - 264;
		dbrs[i].dbreg_value = pmcs[i].reg_value;
	}

	ret = perfmonctl(fd, PFM_WRITE_DBRS, dbrs, n);
	if (ret == -1)
		warning("pfm_write_dbrs error [%d] %s\n", fd, strerror(errno));

	free(dbrs);

 	return ret;
}

int
pfmon_write_dbrs(int fd, pfmon_pmc_t *pmcs, int n)
{

	if (options.opt_is22 == 0) return pfmon_write_dbrs_old(fd, pmcs, n);
		
	return pfmon_write_pmcs(fd, pmcs, n);
}

