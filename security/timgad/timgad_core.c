/*
 * Timgad Linux Security Module
 *
 * Author: Djalal Harouni
 *
 * Copyright (c) 2017 Djalal Harouni
 * Copyright (C) 2017 Endocode AG.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/prctl.h>
#include <linux/rhashtable.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/workqueue.h>

enum {
	TIMGAD_TASK_INITIALIZED = 0,	/* Initialized, not active */
	TIMGAD_TASK_ACTIVE = 1,		/* Linked in hash, active */
	TIMGAD_TASK_INVALID = -1,	/* Scheduled to be removed from hash */
};

struct timgad_task_map {
	unsigned long key_addr;
};

struct timgad_task {
	struct rhash_head t_rhash_head;	/* timgad task hash node */
	unsigned long key;

	atomic_t usage;
	u32 flags;

	struct work_struct clean_work;
};

static struct rhashtable timgad_tasks_table;
static DEFINE_SPINLOCK(timgad_tasks_lock);

static inline int _cmp_timgad_task(struct rhashtable_compare_arg *arg,
				   const void *obj)
{
	const struct timgad_task_map *tmap = arg->key;
	const struct timgad_task *ttask = obj;

	if (ttask->key != tmap->key_addr)
		return 1;

	/* Did we hit an entry that was invalidated ? */
	if (atomic_read(&ttask->usage) == TIMGAD_TASK_INVALID)
		return 1;

	return 0;
}

/* TODO: optimize me */
static const struct rhashtable_params timgad_tasks_hash_params = {
	.nelem_hint = 512,
	.head_offset = offsetof(struct timgad_task, t_rhash_head),
	.key_offset = offsetof(struct timgad_task, key),
	.key_len = sizeof(unsigned long),
	.max_size = 8192,
	.min_size = 256,
	.obj_cmpfn = _cmp_timgad_task,
	.automatic_shrinking = true,
};

int timgad_tasks_init(void)
{
	return rhashtable_init(&timgad_tasks_table, &timgad_tasks_hash_params);
}

void timgad_tasks_clean(void)
{
	rhashtable_destroy(&timgad_tasks_table);
}

unsigned long read_timgad_task_flags(struct timgad_task *timgad_tsk)
{
	return timgad_tsk->flags;
}

static inline int new_timgad_task_flags(unsigned long op,
					unsigned long used_flag,
					unsigned long passed_flag,
					unsigned long *new_flag)
{
	if (passed_flag < used_flag)
		return -EPERM;

	*new_flag = passed_flag;
	return 0;
}

static inline int update_timgad_task_flags(struct timgad_task *timgad_tsk,
					   unsigned long op,
					   unsigned long new_flag)
{
	if (op != PR_TIMGAD_SET_MOD_RESTRICT)
		return -EINVAL;

	timgad_tsk->flags = new_flag;
	return 0;
}

int is_timgad_task_op_set(struct timgad_task *timgad_tsk, unsigned long op,
			  unsigned long *flag)
{
	if (op != PR_TIMGAD_SET_MOD_RESTRICT)
		return -EINVAL;

	*flag = timgad_tsk->flags;
	return 0;
}

int timgad_task_set_op_flag(struct timgad_task *timgad_tsk, unsigned long op,
			    unsigned long flag, unsigned long value)
{
	int ret;
	unsigned long new_flag = 0;
	unsigned long used_flag;

	ret = is_timgad_task_op_set(timgad_tsk, op, &used_flag);
	if (ret < 0)
		return ret;

	ret = new_timgad_task_flags(op, used_flag, flag, &new_flag);
	if (ret < 0)
		return ret;

	/* Nothing to do if the flag did not change */
	if (new_flag == used_flag)
		return 0;

	return update_timgad_task_flags(timgad_tsk, op, new_flag);
}

static struct timgad_task *__lookup_timgad_task(struct task_struct *tsk)
{
	struct timgad_task_map tmap = { .key_addr = (unsigned long)(uintptr_t)tsk };

	return rhashtable_lookup_fast(&timgad_tasks_table, &tmap,
				      timgad_tasks_hash_params);
}

static inline struct timgad_task *__get_timgad_task(struct timgad_task *timgad_tsk)
{
	if (atomic_inc_not_zero(&timgad_tsk->usage))
		return timgad_tsk;

	return NULL;
}

static inline void __put_timgad_task(struct timgad_task *timgad_tsk,
				     bool *collect)
{
	/* First check if we have not been interrupted */
	if (atomic_read(&timgad_tsk->usage) <= TIMGAD_TASK_INITIALIZED ||
	    atomic_dec_and_test(&timgad_tsk->usage)) {
		if (collect)
			*collect = true;
		/*
		 * Invalidate entry as early as possible so we
		 * do not collide
		 */
		atomic_set(&timgad_tsk->usage, TIMGAD_TASK_INVALID);
	}
}

/* We do take a reference count */
struct timgad_task *get_timgad_task(struct task_struct *tsk)
{
	struct timgad_task *ttask;

	rcu_read_lock();
	ttask = __lookup_timgad_task(tsk);
	if (ttask)
		ttask = __get_timgad_task(ttask);
	rcu_read_unlock();

	return ttask;
}

void put_timgad_task(struct timgad_task *timgad_tsk, bool *collect)
{
	if (timgad_tsk)
		__put_timgad_task(timgad_tsk, collect);
}

/*
 * We return all timgad tasks that are not in the TIMGAD_TASK_INVALID state.
 * We do not take reference count on timgad tasks here
 */
struct timgad_task *lookup_timgad_task(struct task_struct *tsk)
{
	struct timgad_task *ttask;

	rcu_read_lock();
	ttask = __lookup_timgad_task(tsk);
	rcu_read_unlock();

	return ttask;
}

static int insert_timgad_task(struct timgad_task *timgad_tsk)
{
	int ret;
	struct timgad_task *ttask = timgad_tsk;

	/* TODO: improve me */
	if (unlikely(atomic_read(&timgad_tasks_table.nelems) >= INT_MAX))
		return -ENOMEM;

	atomic_set(&ttask->usage, TIMGAD_TASK_ACTIVE);
	spin_lock(&timgad_tasks_lock);
	ret = rhashtable_insert_fast(&timgad_tasks_table,
				     &timgad_tsk->t_rhash_head,
				     timgad_tasks_hash_params);
	spin_unlock(&timgad_tasks_lock);
	if (ret != 0 && ret != -EEXIST) {
		atomic_set(&ttask->usage, TIMGAD_TASK_INITIALIZED);
		return ret;
	}

	return 0;
}

void release_timgad_task(struct task_struct *tsk)
{
	struct timgad_task *ttask;
	bool reclaim = false;

	rcu_read_lock();
	/* We do not take a ref count here */
	ttask = __lookup_timgad_task(tsk);
	if (ttask)
		put_timgad_task(ttask, &reclaim);
	rcu_read_unlock();

	if (reclaim)
		schedule_work(&ttask->clean_work);
}

static void reclaim_timgad_task(struct work_struct *work)
{
	struct timgad_task *ttask = container_of(work, struct timgad_task,
						 clean_work);

	WARN_ON(atomic_read(&ttask->usage) != TIMGAD_TASK_INVALID);

	spin_lock(&timgad_tasks_lock);
	rhashtable_remove_fast(&timgad_tasks_table, &ttask->t_rhash_head,
			       timgad_tasks_hash_params);
	spin_unlock(&timgad_tasks_lock);

	kfree(ttask);
}

struct timgad_task *init_timgad_task(struct task_struct *tsk,
				     unsigned long value)
{
	struct timgad_task *ttask;

	ttask = kzalloc(sizeof(*ttask), GFP_KERNEL | __GFP_NOWARN);
	if (ttask == NULL)
		return ERR_PTR(-ENOMEM);

	ttask->key = (unsigned long)(uintptr_t)tsk;
	ttask->flags = value;

	atomic_set(&ttask->usage, TIMGAD_TASK_INITIALIZED);
	INIT_WORK(&ttask->clean_work, reclaim_timgad_task);

	return ttask;
}

/* On success, callers have to do put_timgad_task() */
struct timgad_task *give_me_timgad_task(struct task_struct *tsk,
					unsigned long value)
{
	int ret;
	struct timgad_task *ttask;

	ttask = init_timgad_task(tsk, value);
	if (IS_ERR(ttask))
		return ttask;

	/* Mark it as active */
	ret = insert_timgad_task(ttask);
	if (ret) {
		kfree(ttask);
		return ERR_PTR(ret);
	}

	return ttask;
}
