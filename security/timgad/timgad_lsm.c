/*
 * Timgad Linux Security Module
 *
 * Author: Djalal Harouni
 *
 * Copyright (C) 2017 Djalal Harouni
 * Copyright (C) 2017 Endocode AG.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/errno.h>
#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/prctl.h>
#include <linux/types.h>

#include "timgad_core.h"

static int module_restrict;

static int zero;
static int max_module_restrict_scope = TIMGAD_MODULE_NO_LOAD;

/* TODO:
 *  complete permission check
 *  inline function logic with the per-process if possible
 */
static int timgad_has_global_sysctl_perm(unsigned long op)
{
	int ret = -EINVAL;
	struct mm_struct *mm = NULL;

	if (op != PR_TIMGAD_GET_MOD_RESTRICT)
		return ret;

	switch (module_restrict) {
	case TIMGAD_MODULE_OFF:
		ret = 0;
		break;
	/* TODO: complete this and handle it later per task too */
	case TIMGAD_MODULE_STRICT:
		/*
		 * Are we allowed to sleep here ?
		 * Also improve this check here
		 */
		ret = -EPERM;
		mm = get_task_mm(current);
		if (mm) {
			if (capable(CAP_SYS_MODULE))
				ret = 0;
			mmput(mm);
		}
		break;
	case TIMGAD_MODULE_NO_LOAD:
		ret = -EPERM;
		break;
	}

	return ret;
}

/* TODO: simplify me and move me to timgad_core.c file */
static int module_timgad_task_perm(struct timgad_task *timgad_tsk,
				   char *kmod_name)
{
	int ret;
	unsigned long flag = 0;

	ret = is_timgad_task_op_set(timgad_tsk,
				    PR_TIMGAD_SET_MOD_RESTRICT, &flag);
	if (ret < 0)
		return ret;

	/*
	 * TODO: complete me
	 *    * Allow net modules only with CAP_NET_ADMIN and other cases...
	 *    * Other exotic cases when set to STRICT should be denied...
	 *    * Inline logic
	 */
	switch (flag) {
	case TIMGAD_MODULE_OFF:
		ret = 0;
		break;
	case TIMGAD_MODULE_STRICT:
		if (!capable(CAP_SYS_MODULE))
			ret = -EPERM;
		else
			ret = 0;
		break;
	case TIMGAD_MODULE_NO_LOAD:
		ret = -EPERM;
		break;
	}

	return ret;
}

/* Set the given option in a timgad task */
static int timgad_set_op_value(struct task_struct *tsk,
			       unsigned long op, unsigned long value)
{
	int ret = 0;
	struct timgad_task *ttask;
	unsigned long flag = 0;

	ret = timgad_op_to_flag(op, value, &flag);
	if (ret < 0)
		return ret;

	ttask = get_timgad_task(tsk);
	if (!ttask) {
		ttask = give_me_timgad_task(tsk, value);
		if (IS_ERR(ttask))
			return PTR_ERR(ttask);

		return 0;
	}

	ret = timgad_task_set_op_flag(ttask, op, flag, value);

	put_timgad_task(ttask, NULL);
	return ret;
}

/* Get the given option from a timgad task */
static int timgad_get_op_value(struct task_struct *tsk, unsigned long op)
{
	int ret = -EINVAL;
	struct timgad_task *ttask;
	unsigned long flag = 0;

	ttask = get_timgad_task(tsk);
	if (!ttask)
		return ret;

	ret = is_timgad_task_op_set(ttask, op, &flag);
	put_timgad_task(ttask, NULL);

	return ret < 0 ? ret : flag;
}

/* Copy Timgad context from parent to child */
int timgad_task_copy(struct task_struct *tsk)
{
	int ret = 0;
	struct timgad_task *tparent;
	struct timgad_task *ttask;
	unsigned long value = 0;

	tparent = get_timgad_task(current);

	/* Parent does not have a timgad context, nothing to do */
	if (tparent == NULL)
		return 0;

	value = read_timgad_task_flags(tparent);

	ttask = give_me_timgad_task(tsk, value);
	if (IS_ERR(ttask))
		ret = PTR_ERR(ttask);
	else
		ret = 0;

	put_timgad_task(tparent, NULL);
	return ret;
}

/*
 * Return 0 on success, -error on error.  -EINVAL is returned when Timgad
 * does not handle the given option.
 */
int timgad_task_prctl(int option, unsigned long arg2, unsigned long arg3,
		      unsigned long arg4, unsigned long arg5)
{
	int ret = -EINVAL;
	struct task_struct *myself = current;

	if (option != PR_TIMGAD_OPTS)
		return 0;

	get_task_struct(myself);

	switch (arg2) {
	case PR_TIMGAD_SET_MOD_RESTRICT:
		ret = timgad_set_op_value(myself,
					  PR_TIMGAD_SET_MOD_RESTRICT,
					  arg3);
		break;
	case PR_TIMGAD_GET_MOD_RESTRICT:
		ret = timgad_get_op_value(myself,
					  PR_TIMGAD_SET_MOD_RESTRICT);
		break;
	}

	put_task_struct(myself);
	return ret;
}

/*
 * Free the specific task attached resources
 * task_free() can be called from interrupt context
 */
void timgad_task_free(struct task_struct *tsk)
{
	release_timgad_task(tsk);
}

static int timgad_kernel_module_file(struct file *file)
{
	int ret = 0;
	struct timgad_task *ttask;
	struct task_struct *myself = current;

	/* First check if the task allows that */
	ttask = get_timgad_task(myself);
	if (ttask != NULL) {
		ret = module_timgad_task_perm(ttask, NULL);
		put_timgad_task(ttask, NULL);
	}

	if (ret < 0)
		return ret;

	return timgad_has_global_sysctl_perm(PR_TIMGAD_GET_MOD_RESTRICT);
}

static int timgad_kernel_module_request(char *kmod_name)
{
	int ret = 0;
	struct timgad_task *ttask;
	struct task_struct *myself = current;

	/* First check if the task allows that */
	ttask = get_timgad_task(myself);
	if (ttask != NULL) {
		ret = module_timgad_task_perm(ttask, kmod_name);
		put_timgad_task(ttask, NULL);
	}

	if (ret < 0)
		return ret;

	return timgad_has_global_sysctl_perm(PR_TIMGAD_GET_MOD_RESTRICT);
}

static int timgad_kernel_read_file(struct file *file,
				   enum kernel_read_file_id id)
{
	int ret = 0;

	switch (id) {
	case READING_MODULE:
		ret = timgad_kernel_module_file(file);
		break;
	default:
		break;
	}

	return ret;
}

static struct security_hook_list timgad_hooks[] = {
	LSM_HOOK_INIT(kernel_module_request, timgad_kernel_module_request),
	LSM_HOOK_INIT(kernel_read_file, timgad_kernel_read_file),
	LSM_HOOK_INIT(task_copy, timgad_task_copy),
	LSM_HOOK_INIT(task_prctl, timgad_task_prctl),
	LSM_HOOK_INIT(task_free, timgad_task_free),
};

#ifdef CONFIG_SYSCTL
static int timgad_mod_dointvec_minmax(struct ctl_table *table, int write,
				      void __user *buffer, size_t *lenp,
				      loff_t *ppos)
{
	struct ctl_table table_copy;

	if (write && !capable(CAP_SYS_MODULE))
		return -EPERM;

	table_copy = *table;
	if (*(int *)table_copy.data == *(int *)table_copy.extra2)
		table_copy.extra1 = table_copy.extra2;

	return proc_dointvec_minmax(&table_copy, write, buffer, lenp, ppos);
}

struct ctl_path timgad_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "timgad", },
	{ }
};

static struct ctl_table timgad_sysctl_table[] = {
	{
		.procname       = "module_restrict",
		.data           = &module_restrict,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = timgad_mod_dointvec_minmax,
		.extra1         = &zero,
		.extra2         = &max_module_restrict_scope,
	},
	{ }
};

static void __init timgad_init_sysctl(void)
{
	if (!register_sysctl_paths(timgad_sysctl_path, timgad_sysctl_table))
		panic("Timgad: sysctl registration failed.\n");
}
#else
static inline void timgad_init_sysctl(void) { }
#endif /* CONFIG_SYSCTL */

void __init timgad_add_hooks(void)
{
	pr_info("Timgad: becoming mindful.\n");
	security_add_hooks(timgad_hooks, ARRAY_SIZE(timgad_hooks));
	timgad_init_sysctl();

	if (timgad_tasks_init())
		panic("Timgad: tasks initialization failed.\n");
}
