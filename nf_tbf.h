/*
 * Copyright (C) 2013 Mikhail Vorozhtsov
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef NF_TBF_H
#define NF_TBF_H

#include <linux/types.h>
#ifdef __KERNEL__
#	define NF_TBF_U64_T __u64
#else
#	include <inttypes.h>
#	define NF_TBF_U64_T uint64_t
#endif

#define NF_TBF_MIN_BURST 68
#define NF_TBF_MIN_RATE NF_TBF_MIN_BURST

struct nf_tbf_cfg {
	__u32 limit;
	__u32 burst;
	__u32 rate;
} __attribute__ ((packed));

struct nf_tbf_stats {
	NF_TBF_U64_T first_pkt_ts;
	NF_TBF_U64_T pkts_accepted;
	NF_TBF_U64_T bytes_accepted;
	NF_TBF_U64_T pkts_dropped;
	NF_TBF_U64_T bytes_dropped;
	NF_TBF_U64_T pkts_nomem;
	NF_TBF_U64_T bytes_nomem;
} __attribute__ ((packed));

#endif /* NF_TBF_H */

