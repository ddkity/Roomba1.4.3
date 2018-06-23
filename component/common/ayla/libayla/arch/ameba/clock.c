/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <ayla/utypes.h>
#include <ayla/clock.h>

static enum clock_src clock_src;

u32 clock_utc(void)
{
	return clock_get(NULL);
}

void clock_set_hw(u32 val, enum clock_src src)
{
	clock_src = src;
	clock_set_sw(val, 500);
}

enum clock_src clock_source(void)
{
	return clock_src;
}

void clock_init(void)
{
	u32 now = 0;
	enum clock_src src;

	if (clock_gt(now, CLOCK_START)) {
		src = CS_PERSIST;	/* unsure what source was */
	} else {
		now = CLOCK_START;
		src = CS_DEF;
	}
	clock_set(now, src);		/* set s/w clock to h/w clock */
}
