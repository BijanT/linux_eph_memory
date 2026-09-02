// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF fault ops link implementation.
 *
 * Provides the BPF link type for fault_ops struct_ops maps,
 * including link lifecycle management for BPF-based page fault handling.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/userfaultfd_k.h>

#include "bpf_struct_ops.h"

static DEFINE_MUTEX(fault_update_mutex);

struct bpf_fault_ops_link {
	struct bpf_link link;
	struct bpf_map __rcu *map;
	struct bpf_fault_ctx *ctx;
};

u32 bpf_fault_ops_link_id(struct bpf_fault_ops_link *link)
{
	return link->link.id;
}

struct fault_ops *bpf_fault_ops_map(struct bpf_fault_ops_link *link)
{
	struct bpf_struct_ops_map *st_map;

	st_map = (struct bpf_struct_ops_map *)rcu_dereference(link->map);
	return (struct fault_ops *)st_map->kvalue.data;
}

static void bpf_fault_ops_link_dealloc(struct bpf_link *link)
{
	struct bpf_fault_ops_link *st_link;
	struct bpf_struct_ops_map *st_map;

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	st_map = (struct bpf_struct_ops_map *)
		rcu_dereference_protected(st_link->map, true);
	if (st_map) {
		/*
		 * st_link->map can be NULL if
		 * bpf_fault_ops_link_create() fails to register.
		 */
		st_map->st_ops_desc->st_ops->unreg(&st_map->kvalue.data,
						    &st_link->link);
		bpf_map_put(&st_map->map);
	}

	bpf_fault_release_all(st_link->ctx);
	bpf_fault_ctx_put(st_link->ctx);
	kfree(st_link);
}

static void bpf_fault_ops_link_show_fdinfo(const struct bpf_link *link,
					   struct seq_file *seq)
{
	struct bpf_fault_ops_link *st_link;
	struct bpf_map *map;

	st_link = container_of(link, struct bpf_fault_ops_link, link);

	rcu_read_lock();
	map = rcu_dereference(st_link->map);
	if (map)
		seq_printf(seq, "map_id:\t%d\n", map->id);
	rcu_read_unlock();
}

static int bpf_fault_ops_link_fill_link_info(const struct bpf_link *link,
					     struct bpf_link_info *info)
{
	struct bpf_fault_ops_link *st_link;
	struct bpf_map *map;

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	rcu_read_lock();
	map = rcu_dereference(st_link->map);
	if (map)
		info->fault_ops.map_id = map->id;
	rcu_read_unlock();
	return 0;
}

static int bpf_fault_ops_link_update(struct bpf_link *link,
				     struct bpf_map *new_map,
				     struct bpf_map *expected_old_map)
{
	struct bpf_struct_ops_map *st_map, *old_st_map;
	struct bpf_map *old_map;
	struct bpf_fault_ops_link *st_link;
	int err;

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	st_map = container_of(new_map, struct bpf_struct_ops_map, map);

	if (!bpf_struct_ops_valid_to_reg(new_map))
		return -EINVAL;

	if (!st_map->st_ops_desc->st_ops->update)
		return -EOPNOTSUPP;

	mutex_lock(&fault_update_mutex);

	old_map = rcu_dereference_protected(st_link->map,
					    lockdep_is_held(&fault_update_mutex));
	if (!old_map) {
		err = -ENOLINK;
		goto err_out;
	}
	if (expected_old_map && old_map != expected_old_map) {
		err = -EPERM;
		goto err_out;
	}

	old_st_map = container_of(old_map, struct bpf_struct_ops_map, map);
	/* The new and old struct_ops must be the same type. */
	if (st_map->st_ops_desc != old_st_map->st_ops_desc) {
		err = -EINVAL;
		goto err_out;
	}

	err = st_map->st_ops_desc->st_ops->update(st_map->kvalue.data,
						   old_st_map->kvalue.data,
						   link);
	if (err)
		goto err_out;

	bpf_map_inc(new_map);
	rcu_assign_pointer(st_link->map, new_map);
	bpf_map_put(old_map);

err_out:
	mutex_unlock(&fault_update_mutex);
	return err;
}

static inline struct bpf_fault_wait_queue *find_bpf_fault(struct bpf_fault_ctx *ctx)
{
	wait_queue_entry_t *wq;
	struct bpf_fault_wait_queue *bfwq;

	lockdep_assert_held(&ctx->fault_pending_wqh.lock);

	if (!waitqueue_active(&ctx->fault_pending_wqh))
		return NULL;
	/* walk in reverse to provide FIFO behavior to read faults */
	wq = list_last_entry(&ctx->fault_pending_wqh.head, typeof(*wq), entry);
	bfwq = container_of(wq, struct bpf_fault_wait_queue, wq);
	return bfwq;
}

static ssize_t bpf_fault_ctx_read(struct bpf_fault_ctx *ctx, bool no_wait,
			    struct bpf_fault_msg *msg)
{
	ssize_t ret;
	DECLARE_WAITQUEUE(wait, current);
	struct bpf_fault_wait_queue *bfwq;

	spin_lock_irq(&ctx->pollers_wqh.lock);
	__add_wait_queue(&ctx->pollers_wqh, &wait);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock(&ctx->fault_pending_wqh.lock);
		bfwq = find_bpf_fault(ctx);
		if (bfwq) {
			list_del(&bfwq->wq.entry);
			add_wait_queue(&ctx->fault_wqh, &bfwq->wq);
			*msg = bfwq->msg;
			spin_unlock(&ctx->fault_pending_wqh.lock);
			ret = 0;
			break;
		}

		spin_unlock(&ctx->fault_pending_wqh.lock);
		if (READ_ONCE(ctx->released)) {
			ret = -ENODEV;
			break;
		}
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		if (no_wait) {
			ret = -EAGAIN;
			break;
		}

		/* Nothing for us just yet. Wait until there is. */
		spin_unlock_irq(&ctx->pollers_wqh.lock);
		schedule();
		spin_lock_irq(&ctx->pollers_wqh.lock);
	}

	__remove_wait_queue(&ctx->pollers_wqh, &wait);
	__set_current_state(TASK_RUNNING);
	spin_unlock_irq(&ctx->pollers_wqh.lock);
	return ret;
}

static ssize_t bpf_fault_ops_link_read_iter(struct kiocb *iocb,
					    struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct bpf_link *link = file->private_data;
	struct bpf_fault_ops_link *st_link;
	struct bpf_fault_ctx *ctx;
	struct bpf_fault_msg msg;
	ssize_t _ret, ret = 0;
	bool no_wait;

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	ctx = st_link->ctx;
	if (!ctx)
		return -EINVAL;

	no_wait = file->f_flags & O_NONBLOCK || iocb->ki_flags & IOCB_NOWAIT;
	for (;;) {
		if (iov_iter_count(iter) < sizeof(msg))
			return ret ? ret : -EINVAL;
		_ret = bpf_fault_ctx_read(ctx, no_wait, &msg);
		if (_ret < 0)
			return ret ? ret : _ret;
		_ret = !copy_to_iter_full(&msg, sizeof(msg), iter);
		if (_ret)
			return ret ? ret : -EFAULT;
		ret += sizeof(msg);
		/*
		 * Allow to read more than one fault at time but only
		 * block if waiting for the very first one.
		 */
		no_wait = true;
	}
}

static __poll_t bpf_fault_ops_link_poll(struct file *file,
				  struct poll_table_struct *pts)
{
	struct bpf_link *link = file->private_data;
	struct bpf_fault_ops_link *st_link;
	struct bpf_fault_ctx *ctx;
	__poll_t ret = 0;

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	ctx = st_link->ctx;
	if (!ctx)
		return EPOLLERR;

	poll_wait(file, &ctx->pollers_wqh, pts);

	smp_mb();
	/* Are there any pending faults? */
	if (waitqueue_active(&ctx->fault_pending_wqh))
		ret = EPOLLIN;
	if (READ_ONCE(ctx->released))
		ret |= EPOLLHUP;

	return ret;
}

static const struct bpf_link_ops bpf_fault_ops_link_lops = {
	.dealloc = bpf_fault_ops_link_dealloc,
	.show_fdinfo = bpf_fault_ops_link_show_fdinfo,
	.fill_link_info = bpf_fault_ops_link_fill_link_info,
	.update_map = bpf_fault_ops_link_update,
	.read_iter = bpf_fault_ops_link_read_iter,
	.poll = bpf_fault_ops_link_poll,
};

int bpf_fault_ops_link_create(union bpf_attr *attr)
{
	struct bpf_fault_ops_link *link = NULL;
	struct bpf_link_primer link_primer;
	struct bpf_struct_ops_map *st_map;
	struct bpf_map *map;
	int err;

	if (attr->link_create.fault.flags & ~(BPF_FAULT_FLAG_WP | BPF_FAULT_FLAG_INHERIT))
		return -EINVAL;

	map = bpf_map_get(attr->link_create.map_fd);
	if (IS_ERR(map))
		return PTR_ERR(map);

	st_map = (struct bpf_struct_ops_map *)map;

	if (!bpf_struct_ops_valid_to_reg(map)) {
		err = -EINVAL;
		goto err_out;
	}

	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link) {
		err = -ENOMEM;
		goto err_out;
	}
	bpf_link_init(&link->link, BPF_LINK_TYPE_FAULT_OPS,
		      &bpf_fault_ops_link_lops, NULL,
		      attr->link_create.attach_type);

	err = bpf_link_prime(&link->link, &link_primer);
	if (err)
		goto err_out;

	link->ctx = bpf_fault_ctx_alloc();
	if (!link->ctx) {
		err = -ENOMEM;
		bpf_link_cleanup(&link_primer);
		link = NULL;
		goto err_out;
	}

	/*
	 * Hold the mutex so the subsystem cannot do link->ops->detach()
	 * before the link is fully initialized.
	 */
	mutex_lock(&fault_update_mutex);
	err = st_map->st_ops_desc->st_ops->reg(st_map->kvalue.data,
						&link->link);
	if (err) {
		mutex_unlock(&fault_update_mutex);
		bpf_link_cleanup(&link_primer);
		link = NULL;
		goto err_out;
	}
	mutex_unlock(&fault_update_mutex);

	link->ctx->prog = link;

	err = bpf_fault_register(link->ctx,
				 attr->link_create.fault.start,
				 attr->link_create.fault.len,
				 attr->link_create.fault.flags);
	if (err) {
		/* Undo reg() — dealloc won't call unreg since map isn't set. */
		st_map->st_ops_desc->st_ops->unreg(st_map->kvalue.data,
						    &link->link);
		bpf_link_cleanup(&link_primer);
		link = NULL;
		goto err_out;
	}

	RCU_INIT_POINTER(link->map, map);
	return bpf_link_settle(&link_primer);

err_out:
	bpf_map_put(map);
	kfree(link);
	return err;
}

int bpf_fault_ops_link_writeprotect(union bpf_attr *attr)
{
	struct bpf_fault_ops_link *st_link;
	struct bpf_fault_ctx *ctx;
	struct bpf_link *link;
	bool enable_wp;
	int err;

	if (attr->link_fault_cmd.flags & ~BPF_FAULT_WP_ENABLE)
		return -EINVAL;

	link = bpf_link_get_from_fd(attr->link_fault_cmd.link_fd);
	if (IS_ERR(link))
		return PTR_ERR(link);

	if (link->type != BPF_LINK_TYPE_FAULT_OPS) {
		err = -EINVAL;
		goto out_put_link;
	}

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	ctx = st_link->ctx;
	if (!ctx) {
		err = -EINVAL;
		goto out_put_link;
	}

	if (!(ctx->flags & BPF_FAULT_FLAG_WP)) {
		err = -EINVAL;
		goto out_put_link;
	}

	enable_wp = !!(attr->link_fault_cmd.flags & BPF_FAULT_WP_ENABLE);
	err = bpf_fault_wp_range(ctx->mm,
				 attr->link_fault_cmd.start,
				 attr->link_fault_cmd.len,
				 enable_wp);

out_put_link:
	bpf_link_put(link);
	return err;
}

int bpf_fault_ops_link_add_region(union bpf_attr *attr)
{
	struct bpf_fault_ops_link *st_link;
	struct bpf_fault_ctx *ctx;
	struct bpf_link *link;
	int err;

	link = bpf_link_get_from_fd(attr->link_fault_cmd.link_fd);
	if (IS_ERR(link))
		return PTR_ERR(link);

	if (link->type != BPF_LINK_TYPE_FAULT_OPS) {
		err = -EINVAL;
		goto out_put_link;
	}

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	ctx = st_link->ctx;
	if (!ctx) {
		err = -EINVAL;
		goto out_put_link;
	}

	err = bpf_fault_add_region(ctx,
				   attr->link_fault_cmd.start,
				   attr->link_fault_cmd.len);

out_put_link:
	bpf_link_put(link);
	return err;
}

int bpf_fault_ops_link_remove_region(union bpf_attr *attr)
{
	struct bpf_fault_ops_link *st_link;
	struct bpf_fault_ctx *ctx;
	struct bpf_link *link;
	int err;

	link = bpf_link_get_from_fd(attr->link_fault_cmd.link_fd);
	if (IS_ERR(link))
		return PTR_ERR(link);

	if (link->type != BPF_LINK_TYPE_FAULT_OPS) {
		err = -EINVAL;
		goto out_put_link;
	}

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	ctx = st_link->ctx;
	if (!ctx) {
		err = -EINVAL;
		goto out_put_link;
	}

	err = bpf_fault_unregister(ctx,
				   attr->link_fault_cmd.start,
				   attr->link_fault_cmd.len);

out_put_link:
	bpf_link_put(link);
	return err;
}

/*
 * Claim an inherited bpf_fault context in the current process.
 *
 * After fork with BPF_FAULT_FLAG_INHERIT, the child has an inherited
 * context with no bpf_link lifecycle.  This command creates a proper
 * bpf_link for the child's context using the standard bpf_link_prime/
 * bpf_link_settle path, returning a new fd.
 */
int bpf_fault_ops_link_claim(union bpf_attr *attr)
{
	struct bpf_fault_ops_link *new_link = NULL;
	struct bpf_link_primer primer;
	struct bpf_fault_ctx *ctx;
	struct bpf_struct_ops_map *st_map;
	struct bpf_link *parent_link;
	struct bpf_map *map;
	int err;

	/* Get the parent's bpf_link from the inherited fd */
	parent_link = bpf_link_get_from_fd(attr->link_fault_cmd.link_fd);
	if (IS_ERR(parent_link))
		return PTR_ERR(parent_link);

	if (parent_link->type != BPF_LINK_TYPE_FAULT_OPS) {
		err = -EINVAL;
		goto out_put_parent;
	}

	/* Search current->mm for an inherited ctx matching this parent */
	ctx = bpf_fault_find_inherited_ctx(current->mm, parent_link->id);
	if (!ctx) {
		err = -ENOENT;
		goto out_put_parent;
	}

	/* Atomically claim — only one thread wins the race */
	if (!xchg(&ctx->inherited, 0)) {
		err = -EBUSY;
		goto out_put_parent;
	}

	/* Allocate a proper link for this ctx */
	new_link = kzalloc(sizeof(*new_link), GFP_USER);
	if (!new_link) {
		err = -ENOMEM;
		goto out_unclaim;
	}

	bpf_link_init(&new_link->link, BPF_LINK_TYPE_FAULT_OPS,
		      &bpf_fault_ops_link_lops, NULL, 0);

	err = bpf_link_prime(&new_link->link, &primer);
	if (err)
		goto out_unclaim;

	/* Transfer the map reference from the lightweight link */
	rcu_read_lock();
	map = rcu_dereference(ctx->prog->map);
	if (map)
		bpf_map_inc(map);
	rcu_read_unlock();

	if (!map) {
		bpf_link_cleanup(&primer);
		new_link = NULL;
		err = -ENOENT;
		goto out_unclaim;
	}

	/* Register with struct_ops */
	st_map = container_of(map, struct bpf_struct_ops_map, map);
	mutex_lock(&fault_update_mutex);
	err = st_map->st_ops_desc->st_ops->reg(st_map->kvalue.data,
						&new_link->link);
	mutex_unlock(&fault_update_mutex);
	if (err) {
		bpf_map_put(map);
		bpf_link_cleanup(&primer);
		new_link = NULL;
		goto out_unclaim;
	}

	RCU_INIT_POINTER(new_link->map, map);
	new_link->ctx = ctx;

	/* Free the old lightweight link, replace with proper one */
	bpf_fault_ops_link_free_inherited(ctx->prog);
	ctx->prog = new_link;
	ctx->parent_link_id = 0;

	bpf_link_put(parent_link);
	return bpf_link_settle(&primer);

out_unclaim:
	/* Restore inherited so cleanup paths and retries still work */
	WRITE_ONCE(ctx->inherited, 1);
out_put_parent:
	kfree(new_link);
	bpf_link_put(parent_link);
	return err;
}

/*
 * Allocate a lightweight link for a fork-inherited bpf_fault context.
 * Shares the parent's struct_ops map via bpf_map_inc().  The returned
 * link has no bpf_link lifecycle (no fd, no bpf_link_init) — only the
 * map pointer is populated, which is all bpf_fault_ops_map() needs.
 */
struct bpf_fault_ops_link *bpf_fault_ops_link_alloc_inherited(
		struct bpf_fault_ops_link *parent_link)
{
	struct bpf_fault_ops_link *child_link;
	struct bpf_map *map;

	child_link = kzalloc(sizeof(*child_link), GFP_KERNEL);
	if (!child_link)
		return NULL;

	rcu_read_lock();
	map = rcu_dereference(parent_link->map);
	if (map)
		bpf_map_inc(map);
	rcu_read_unlock();

	if (!map) {
		kfree(child_link);
		return NULL;
	}

	RCU_INIT_POINTER(child_link->map, map);
	return child_link;
}

/*
 * Free an inherited link and its map reference.
 */
void bpf_fault_ops_link_free_inherited(struct bpf_fault_ops_link *link)
{
	struct bpf_map *map;

	if (!link)
		return;

	map = rcu_dereference_protected(link->map, true);
	if (map)
		bpf_map_put(map);
	kfree(link);
}
