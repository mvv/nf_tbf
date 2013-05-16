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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/hrtimer.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/configfs.h>

#include <net/pkt_sched.h>
#include <net/netfilter/nf_queue.h>

#include "nf_tbf.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mikhail Vorozhtsov <mikhail.vorozhtsov@gmail.com>");
MODULE_DESCRIPTION("Token Bucket Filter implemented as a netfilter queue");

struct nf_tbf_entry {
	struct list_head list_node;
	struct nf_queue_entry *entry;
	u32 size;
};

struct nf_tbf_bucket {
	struct rb_node rb_node;

	/* Bucket number */
	u16 id;

	/* Synchronization */
	atomic_t ref_cnt;
	spinlock_t lock;

	/* Configuration */
	u32 max_enqueued_bytes;
	u32 burst;
	s64 burst_tokens;
	struct psched_ratecfg rate;

	/* Statistics */
	struct nf_tbf_stats stats;

	/* State */
	s64 last_pkt_ts;
	s64 tokens_left;
	u32 enqueued_bytes;
	struct nf_tbf_entry *band0;
	struct nf_tbf_entry *band1;
	struct nf_tbf_entry *band2;
	struct hrtimer timer;
	s64 next_timer_ts;
	s64 last_timer_ts;
	s64 try_timer_ts;
	struct config_item cfg_item;
};

#define NF_TBF_BUCKET(item) \
	container_of((item), struct nf_tbf_bucket, cfg_item)

static const u8 prio2band[TC_PRIO_MAX + 1] = {
	1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1
};

static struct rb_root buckets = RB_ROOT;
static DEFINE_RWLOCK(buckets_lock);

static struct nf_tbf_bucket *nf_tbf_bucket_get(u16 bucket_id)
{
	struct nf_tbf_bucket *bucket;
	struct rb_node *n;

	read_lock_bh(&buckets_lock);

	for (n = buckets.rb_node; n;) {
		bucket = rb_entry(n, struct nf_tbf_bucket, rb_node);

		if (bucket_id < bucket->id)
			n = n->rb_left;
		else if (bucket_id > bucket->id)
			n = n->rb_right;
		else {
			if (!atomic_inc_not_zero(&bucket->ref_cnt))
				bucket = NULL;
			read_unlock_bh(&buckets_lock);
			return bucket;
		}
	}

	read_unlock_bh(&buckets_lock);
	return NULL;
}

static void nf_tbf_bucket_put(struct nf_tbf_bucket *bucket)
{
	struct nf_tbf_entry *temp_entry;
	struct nf_tbf_entry *entry;

	if (atomic_dec_return(&bucket->ref_cnt))
		return;

	hrtimer_cancel(&bucket->timer);

	if (bucket->band2)
		list_for_each_entry_safe(entry, temp_entry,
					 &bucket->band2->list_node,
					 list_node) {
			nf_reinject(entry->entry, NF_DROP);
			kfree(entry);
		}
	if (bucket->band1)
		list_for_each_entry_safe(entry, temp_entry,
					 &bucket->band1->list_node,
					 list_node) {
			nf_reinject(entry->entry, NF_DROP);
			kfree(entry);
		}
	if (bucket->band0)
		list_for_each_entry_safe(entry, temp_entry,
					 &bucket->band0->list_node,
					 list_node) {
			nf_reinject(entry->entry, NF_DROP);
			kfree(entry);
		}

	kfree(bucket);
}

static s64 nf_tbf_bucket_burst(struct nf_tbf_bucket *bucket,
			       struct nf_queue_entry *entry, u32 size)
{
	s64 now;
	s64 tokens;

	now = ktime_to_ns(ktime_get());
	tokens = now - bucket->last_pkt_ts;
	if (tokens < bucket->burst_tokens) {
		tokens += bucket->tokens_left;
		if (tokens > bucket->burst_tokens)
			tokens = bucket->burst_tokens;
	} else
		tokens = bucket->burst_tokens;
	tokens -= (s64) psched_l2t_ns(&bucket->rate, size);

	if (tokens >= 0) {
		bucket->last_pkt_ts = now;
		bucket->tokens_left = tokens;
		if (bucket->stats.first_pkt_ts == 0)
			bucket->stats.first_pkt_ts = get_seconds();
		bucket->stats.pkts_accepted += 1;
		bucket->stats.bytes_accepted += size;
		return 0;
	}

	return now - tokens;
}

static int nf_tbf_handle(struct nf_queue_entry *entry, unsigned int qn)
{
	u32 size;
	s64 ns = 0;
	bool try_to_burst;
	bool started_timer;
	bool force_timer_start;
	struct nf_tbf_entry **band;
	struct nf_tbf_entry *bucket_entry;
	struct nf_tbf_bucket *bucket = nf_tbf_bucket_get((u16) qn);

	if (!bucket)
		return -ENOENT;

	size = entry->skb->len;

	if (size == 0) {
		nf_tbf_bucket_put(bucket);
		return -EINVAL;
	}

	spin_lock_bh(&bucket->lock);

	if (bucket->burst == 0) {
		spin_unlock_bh(&bucket->lock);
		nf_tbf_bucket_put(bucket);
		nf_reinject(entry, NF_DROP);
		return 0;
	}

	if (size > bucket->burst) {
		spin_unlock_bh(&bucket->lock);
		nf_tbf_bucket_put(bucket);
		return -EINVAL;
	}

	try_to_burst = false;

	switch (prio2band[entry->skb->priority & TC_PRIO_MAX]) {
	case 0:
		if (!bucket->band0) {
			if (bucket->band1)
				try_to_burst = bucket->band1->size > size;
			else if (bucket->band2)
				try_to_burst = bucket->band2->size > size;
			else
				try_to_burst = true;
		}
		band = &bucket->band0;
		break;
	case 1:
		if (!bucket->band0 && !bucket->band1) {
			if (bucket->band2)
				try_to_burst = bucket->band2->size > size;
			else
				try_to_burst = true;
		}
		band = &bucket->band1;
		break;
	default:
		try_to_burst = bucket->enqueued_bytes == 0;
		band = &bucket->band2;
		break;
	}

	if (try_to_burst) {
		ns = nf_tbf_bucket_burst(bucket, entry, size);

		if (ns == 0) {
			spin_unlock_bh(&bucket->lock);
			nf_tbf_bucket_put(bucket);
			nf_reinject(entry, NF_ACCEPT);
			return 0;
		}
	}

	if (size > bucket->max_enqueued_bytes ||
	    bucket->enqueued_bytes > bucket->max_enqueued_bytes - size) {
		if (bucket->stats.first_pkt_ts == 0)
			bucket->stats.first_pkt_ts = get_seconds();
		bucket->stats.pkts_dropped += 1;
		bucket->stats.bytes_dropped += size;
		spin_unlock_bh(&bucket->lock);
		nf_tbf_bucket_put(bucket);
		nf_reinject(entry, NF_DROP);
		return 0;
	}

	bucket_entry = kzalloc(sizeof(struct nf_tbf_entry), GFP_ATOMIC);

	if (!bucket_entry) {
		if (bucket->stats.first_pkt_ts == 0)
			bucket->stats.first_pkt_ts = get_seconds();
		bucket->stats.pkts_nomem += 1;
		bucket->stats.bytes_nomem += size;
		spin_unlock_bh(&bucket->lock);
		nf_tbf_bucket_put(bucket);
		return -ENOMEM;
	}

	bucket_entry->entry = entry;
	bucket_entry->size = size;

	if (*band)
		list_add_tail(&bucket_entry->list_node, &(*band)->list_node);
	else {
		INIT_LIST_HEAD(&bucket_entry->list_node);
		*band = bucket_entry;
	}

	bucket->enqueued_bytes += size;

	if (!try_to_burst) {
		spin_unlock_bh(&bucket->lock);
		nf_tbf_bucket_put(bucket);
		return 0;
	}

	force_timer_start = false;

	if (bucket->next_timer_ts == bucket->last_timer_ts) {
		if (bucket->try_timer_ts) {
			if (ns < bucket->try_timer_ts)
				bucket->try_timer_ts = ns;
		} else {
			started_timer = !hrtimer_start(&bucket->timer,
						       ns_to_ktime(ns),
						       HRTIMER_MODE_ABS);
			if (started_timer) {
				bucket->next_timer_ts = ns;
				bucket->last_timer_ts = 0;
			} else if (bucket->enqueued_bytes == size) {
				force_timer_start = true;
				bucket->try_timer_ts = ns;
			}
		}
	} else if (bucket->next_timer_ts > ns) {
		if (hrtimer_try_to_cancel(&bucket->timer) >= 0) {
			bucket->next_timer_ts = ns;
			bucket->last_timer_ts = 0;
			hrtimer_start(&bucket->timer, ns_to_ktime(ns),
				      HRTIMER_MODE_ABS);
		}
	}

	while (force_timer_start) {
		spin_unlock_bh(&bucket->lock);
		cpu_relax();
		spin_lock_bh(&bucket->lock);

		if (!bucket->try_timer_ts)
			break;

		ns = bucket->try_timer_ts;
		started_timer = !hrtimer_start(&bucket->timer,
					       ns_to_ktime(ns),
					       HRTIMER_MODE_ABS);

		if (started_timer) {
			bucket->next_timer_ts = ns;
			bucket->last_timer_ts = 0;
			bucket->try_timer_ts = 0;
			break;
		}
	}

	spin_unlock_bh(&bucket->lock);
	nf_tbf_bucket_put(bucket);
	return 0;
}

static enum hrtimer_restart nf_tbf_bucket_watchdog(struct hrtimer *timer) {
	struct nf_tbf_bucket *bucket =
		container_of(timer, struct nf_tbf_bucket, timer);
	struct nf_tbf_entry **band;
	struct nf_tbf_entry *bucket_entry;
	struct nf_tbf_entry *new_band;
	struct nf_queue_entry *entry;
	u32 size;
	s64 ns;
	bool bands_are_empty;
 
	do {
		if (atomic_read(&bucket->ref_cnt) == 0)
			return HRTIMER_NORESTART;

		spin_lock(&bucket->lock);

		bucket->last_timer_ts = bucket->next_timer_ts;

		if (bucket->enqueued_bytes == 0) {
			spin_unlock(&bucket->lock);
			break;
		}

		if (bucket->band0)
			band = &bucket->band0;
		else if (bucket->band1)
			band = &bucket->band1;
		else
			band = &bucket->band2;

		bucket_entry = *band;
		entry = bucket_entry->entry;
		size = bucket_entry->size;
		ns = nf_tbf_bucket_burst(bucket, entry, size);

		if (ns > 0) {
			bucket->next_timer_ts = ns;
			bucket->last_timer_ts = 0;
			hrtimer_set_expires(timer, ns_to_ktime(ns));
		        spin_unlock(&bucket->lock);
			return HRTIMER_RESTART;
		}

		new_band = container_of(bucket_entry->list_node.next,
					struct nf_tbf_entry, list_node);

		if (new_band == bucket_entry)
			new_band = NULL;
		else
			list_del(&bucket_entry->list_node);

		*band = new_band;
		bucket->enqueued_bytes -= size;
		bands_are_empty = bucket->enqueued_bytes == 0;

		spin_unlock(&bucket->lock);

		kfree(bucket_entry);
		nf_reinject(entry, NF_ACCEPT);

		if (bands_are_empty)
			break;
	} while (1);

	return HRTIMER_NORESTART;
}

static ssize_t show_cfg(struct nf_tbf_bucket *bucket, char *buf)
{
	struct nf_tbf_cfg cfg;

	spin_lock_bh(&bucket->lock);
	cfg.limit = bucket->max_enqueued_bytes;
	cfg.burst = bucket->burst;
	cfg.rate  = psched_ratecfg_getrate(&bucket->rate);
	spin_unlock_bh(&bucket->lock);

	memcpy(buf, &cfg, sizeof(cfg));
	return sizeof(cfg);
}

static ssize_t store_cfg(struct nf_tbf_bucket *bucket, const char *buf,
			 size_t size)
{
	struct nf_tbf_cfg cfg;

	if (size != sizeof(cfg))
		return -EINVAL;

	memcpy(&cfg, buf, size);

	if (cfg.rate < NF_TBF_MIN_RATE || cfg.burst < NF_TBF_MIN_BURST ||
	    cfg.limit < cfg.burst)
		return -EINVAL;

	spin_lock_bh(&bucket->lock);
	bucket->max_enqueued_bytes = cfg.limit;
	bucket->burst = cfg.burst;
	psched_ratecfg_precompute(&bucket->rate, cfg.rate);
	bucket->burst_tokens = (s64) psched_l2t_ns(&bucket->rate, cfg.burst);
	bucket->last_pkt_ts = 0;
	bucket->tokens_left = bucket->burst_tokens;
	memset(&bucket->stats, 0, sizeof(struct nf_tbf_stats));
	spin_unlock_bh(&bucket->lock);

	return size;
}

static ssize_t show_stats(struct nf_tbf_bucket *bucket, char *buf)
{
	spin_lock_bh(&bucket->lock);
	memcpy(buf, &bucket->stats, sizeof(struct nf_tbf_stats));
	spin_unlock_bh(&bucket->lock);
	return sizeof(struct nf_tbf_stats);
}

static void nf_tbf_cfg_bucket_release(struct config_item *item)
{
	struct nf_tbf_bucket *bucket = NF_TBF_BUCKET(item);

	write_lock_bh(&buckets_lock);
	rb_erase(&bucket->rb_node, &buckets);
	write_unlock_bh(&buckets_lock);

	nf_tbf_bucket_put(bucket);
}

struct nf_tbf_cfg_bucket_attr {
	struct configfs_attribute attr;
	ssize_t (*show)(struct nf_tbf_bucket *bucket, char *buf);
	ssize_t (*store)(struct nf_tbf_bucket *bucket, const char *buf,
			 size_t size);
};

#define NF_TBF_BUCKET_ATTR(attr) \
	(container_of(attr, struct nf_tbf_cfg_bucket_attr, attr))

static ssize_t nf_tbf_cfg_bucket_show_attr(struct config_item *item,
					   struct configfs_attribute *attr,
					   char *buf)
{
	struct nf_tbf_bucket *bucket = NF_TBF_BUCKET(item);
	return NF_TBF_BUCKET_ATTR(attr)->show(bucket, buf);
}

static ssize_t nf_tbf_cfg_bucket_store_attr(struct config_item *item,
					    struct configfs_attribute *attr,
					    const char *buf, size_t size)
{
	struct nf_tbf_bucket *bucket = NF_TBF_BUCKET(item);
	return NF_TBF_BUCKET_ATTR(attr)->store(bucket, buf, size);
}

#ifndef __CONFIGFS_ATTR
# define __CONFIGFS_ATTR(_name,_mode,_show,_store)                     \
{                                                                      \
	.attr   = {                                                    \
		.ca_name = __stringify(_name),                         \
		.ca_mode = _mode,                                      \
		.ca_owner = THIS_MODULE,                               \
	},                                                             \
	.show   = _show,                                               \
	.store  = _store,                                              \
}
#endif

#define NF_TBF_BUCKET_ATTR_RW(_name)                                   \
static struct nf_tbf_cfg_bucket_attr nf_tbf_cfg_bucket_attr_##_name =  \
        __CONFIGFS_ATTR(_name, S_IRUGO | S_IWUSR,                      \
			show_##_name, store_##_name)
#define NF_TBF_BUCKET_ATTR_RO(_name)                                   \
static struct nf_tbf_cfg_bucket_attr nf_tbf_cfg_bucket_attr_##_name =  \
        __CONFIGFS_ATTR(_name, S_IRUGO, show_##_name, NULL)

NF_TBF_BUCKET_ATTR_RW(cfg);
NF_TBF_BUCKET_ATTR_RO(stats);

static struct configfs_attribute *nf_tbf_cfg_bucket_attrs[] = {
	&nf_tbf_cfg_bucket_attr_cfg.attr,
	&nf_tbf_cfg_bucket_attr_stats.attr,
	NULL
};

static struct configfs_item_operations nf_tbf_cfg_bucket_item_ops = {
	.release         = nf_tbf_cfg_bucket_release,
	.show_attribute  = nf_tbf_cfg_bucket_show_attr,
	.store_attribute = nf_tbf_cfg_bucket_store_attr
};

static struct config_item_type nf_tbf_cfg_bucket_item_type = {
	.ct_item_ops     = &nf_tbf_cfg_bucket_item_ops,
	.ct_attrs        = nf_tbf_cfg_bucket_attrs,
	.ct_owner        = THIS_MODULE
};

static struct config_item *nf_tbf_cfg_bucket_create(
				struct config_group *group,
				const char *name)
{
	char c;
	const char *str;
	u16 d, bucket_id;
	struct rb_node **p;
	struct rb_node *parent;
	struct nf_tbf_bucket *bucket;
	struct nf_tbf_bucket *tmp;

	if (!*name)
		return ERR_PTR(-EINVAL);

	str = name;
	bucket_id = 0;

	do {
		c = *str;

		if (c < '0' || c > '9')
			return ERR_PTR(-EINVAL);

		d = c - '0';

		if (bucket_id > 6553 || (bucket_id == 6553 && d > 5))
			return ERR_PTR(-EINVAL);

		bucket_id = bucket_id * 10 + d;
		str += 1;
	} while (*str);

	bucket = kzalloc(sizeof(struct nf_tbf_bucket), GFP_KERNEL);

	if (!bucket)
		return ERR_PTR(-ENOMEM);

	bucket->id = bucket_id;
	atomic_set(&bucket->ref_cnt, 1);
	spin_lock_init(&bucket->lock);
	config_item_init_type_name(&bucket->cfg_item, name,
				   &nf_tbf_cfg_bucket_item_type);
	hrtimer_init(&bucket->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	bucket->timer.function = nf_tbf_bucket_watchdog;

	write_lock_bh(&buckets_lock);

	p = &buckets.rb_node;
	parent = NULL;

	while (*p) {
		parent = *p;
		tmp = rb_entry(parent, struct nf_tbf_bucket, rb_node);

		if (bucket_id < tmp->id)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&bucket->rb_node, parent, p);
	rb_insert_color(&bucket->rb_node, &buckets);

	write_unlock_bh(&buckets_lock);

	return &bucket->cfg_item;
}

static struct configfs_group_operations nf_tbf_cfg_subsys_group_ops = {
	.make_item = nf_tbf_cfg_bucket_create
};

static struct config_item_type nf_tbf_cfg_subsys_type = {
	.ct_group_ops = &nf_tbf_cfg_subsys_group_ops,
	.ct_owner     = THIS_MODULE
};

static struct configfs_subsystem nf_tbf_cfg_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = KBUILD_MODNAME,
			.ci_type    = &nf_tbf_cfg_subsys_type
		}
	}
};

static struct nf_queue_handler nf_tbf_queue_handler __read_mostly = {
	.outfn = nf_tbf_handle
};

static int __init nf_tbf_init(void)
{
	int ret;

	nf_register_queue_handler(&nf_tbf_queue_handler);

	config_group_init(&nf_tbf_cfg_subsys.su_group);
	mutex_init(&nf_tbf_cfg_subsys.su_mutex);
	ret = configfs_register_subsystem(&nf_tbf_cfg_subsys);

	if (ret != 0) {
		nf_unregister_queue_handler();
		return ret;
	}

	return 0;
}

static void __exit nf_tbf_exit(void)
{
	configfs_unregister_subsystem(&nf_tbf_cfg_subsys);
	nf_unregister_queue_handler();
}

module_init(nf_tbf_init);
module_exit(nf_tbf_exit);

