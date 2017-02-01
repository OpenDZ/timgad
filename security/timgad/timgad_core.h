/*
 * Timgad Linux Security Module
 *
 * Author: Djalal Harouni
 *
 * Copyright (c) 2017 Djalal Harouni
 * Copyright (c) 2017 Endocode AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#define TIMGAD_MODULE_OFF	0x00000000
#define TIMGAD_MODULE_STRICT	0x00000001
#define TIMGAD_MODULE_NO_LOAD	0x00000002

struct timgad_task;

static inline int timgad_op_to_flag(unsigned long op,
				    unsigned long value,
				    unsigned long *flag)
{
	if (op != PR_TIMGAD_SET_MOD_RESTRICT || value > TIMGAD_MODULE_NO_LOAD)
		return -EINVAL;

	*flag = value;
	return 0;
}

unsigned long read_timgad_task_flags(struct timgad_task *timgad_tsk);

int timgad_task_set_op_flag(struct timgad_task *timgad_tsk,
			    unsigned long op, unsigned long flag,
			    unsigned long value);

int is_timgad_task_op_set(struct timgad_task *timgad_tsk, unsigned long op,
			  unsigned long *flag);

struct timgad_task *get_timgad_task(struct task_struct *tsk);
void put_timgad_task(struct timgad_task *timgad_tsk, bool *collect);
struct timgad_task *lookup_timgad_task(struct task_struct *tsk);

void release_timgad_task(struct task_struct *tsk);

struct timgad_task *init_timgad_task(struct task_struct *tsk,
				     unsigned long flag);
struct timgad_task *give_me_timgad_task(struct task_struct *tsk,
					unsigned long value);

int timgad_tasks_init(void);
void timgad_tasks_clean(void);
