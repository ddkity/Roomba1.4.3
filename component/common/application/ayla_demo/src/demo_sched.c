/*
 * Copyright 2016 Ayla Networks, Inc.  All rights reserved.
 */

/*
 * Ayla schedule configuration.
 */
#include <sys/types.h>
#include <ada/libada.h>
#include <ada/sched.h>
#include <ayla/nameval.h>
#include <ayla/assert.h>
#include "conf.h"

static const char *demo_scheds[] = DEMO_SCHED_NAMES;

static u32 demo_sched_saved_run_time;	/* XXX should be in NVRAM */

void demo_sched_init(void)
{
	enum ada_err err;
	unsigned int i;
	int count = ARRAY_LEN(demo_scheds);

	if (!count) {
		return;
	}

	/*
	 * Create schedules.
	 */
	err = ada_sched_init(count);
	ASSERT(!err);

	for (i = 0; i < count; i++) {
		err = ada_sched_set_name(i, demo_scheds[i]);
		ASSERT(!err);
	}
}

void adap_sched_run_time_write(u32 run_time)
{
	demo_sched_saved_run_time = run_time;
}

u32 adap_sched_run_time_read(void)
{
	return demo_sched_saved_run_time;
}
