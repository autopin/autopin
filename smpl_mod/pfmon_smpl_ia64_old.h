/*
 * pfmon_smpl_ia64_old.h - detailed sampling module for the all IA-64 PMU models
 *                         using perfmon v2.0 interface
 *
 * Copyright (c) 2005-2006 Hewlett-Packard Development Company, L.P.
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
#ifndef __PFMON_SMPL_MOD_IA64_OLD_H__
#define __PFMON_SMPL_MOD_IA64_OLD_H__

extern int default_smpl_init_ctx_arg(pfmon_ctx_t *ctx, unsigned int max_pmds_sample);
extern int default_smpl_check_version(pfmon_sdesc_t *sdesc);
extern int default_smpl_check_new_samples(pfmon_sdesc_t *sdesc);

#endif /*__PFMON_SMPL_MOD_IA64_OLD_H__ */
