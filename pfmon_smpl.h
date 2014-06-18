/*
 * pfmon_smpl.h
 *
 * Copyright (c) 2006 Hewlett-Packard Development Company, L.P.
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
#ifndef __PFMON_SMPL_H__
#define __PFMON_SMPL_H__ 1

#include "pfmon.h"
/*
 * IA-64 only: backward compatibility with old sampling format
 * for perfmon v2.0
 */
extern pfmon_smpl_module_t detailed_old_smpl_module;
extern pfmon_smpl_module_t inst_hist_old_smpl_module;
extern pfmon_smpl_module_t dear_hist_ia64_old_smpl_module;
extern pfmon_smpl_module_t compact_old_smpl_module;
extern pfmon_smpl_module_t raw_old_smpl_module;

/*
 * perfmon v2.2 or higher modules
 */
extern pfmon_smpl_module_t dear_hist_ia64_smpl_module;
extern pfmon_smpl_module_t detailed_smpl_module;
extern pfmon_smpl_module_t inst_hist_smpl_module;
extern pfmon_smpl_module_t compact_smpl_module;
extern pfmon_smpl_module_t raw_smpl_module;

/*
 * Intel Core only
 */
extern pfmon_smpl_module_t pebs_smpl_module;

#endif /* __PFMON_SMPL_H__ */
