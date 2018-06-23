/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifdef MATRIXSSL
#include <sys/time.h>
#include <time.h>
#endif

#include <string.h>
#include <stdio.h>
#ifndef SCHED_TEST
#define __USE_BSD		/* for timeradd(), timersub() macros */
#endif

#ifdef AMEBA
#define HAVE_UTYPES
#endif

#ifdef AYLA_FreeRTOS
#include <FreeRTOS.h>
#include <task.h>
#endif /* AYLA_FreeRTOS */

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ayla/log.h>
#include <ayla/clock.h>

volatile u32 uptime;		/* seconds since boot */
struct clock_time boot_rel_time; /* time of startup according to RTC */

u32 clock_set_mtime;		/* time when clock last set, ms */

#ifdef AYLA_FreeRTOS
/*
 * Return module monotonic time in milliseconds.
 */
u32 clock_ms(void)
{
	u32 ms;

	if (configTICK_RATE_HZ == 1000) {	/* compile-time evaluated */
		ms = xTaskGetTickCount();
	} else {
		ms = (xTaskGetTickCount() * 1000) / configTICK_RATE_HZ;
	}
	return ms;
}

/*
 * Return module monotonic time in milliseconds.
 */
u64 clock_total_ms(void)
{
	u64 ms;

	if (configTICK_RATE_HZ == 1000) {	/* compile-time evaluated */
		ms = xTaskGetTotalTickCount();
	} else {
		ms = (xTaskGetTotalTickCount() * 1000) / configTICK_RATE_HZ;
	}
	return ms;
}
#else
#ifndef ATHOS /* ADA-QCA4010 */
u32 clock_ms(void)
{
	return 0;
}

u64 clock_total_ms(void)
{
	return 0;
}
#endif /* ATHOS */
#endif /* AYLA_FreeRTOS */

/*
 * Set software notion of time based on UTC = boot_rel_time + clock_total_ms().
 */
void clock_set_sw(u32 new_secs, u32 new_msecs)
{
	struct clock_time *ct = &boot_rel_time;
	u64 msec;

	msec = clock_total_ms();
	clock_set_mtime = (u32)(msec & 0xffffffff);
	ct->ct_sec = new_secs - (msec / 1000);
	msec %= 1000;
	if (msec < new_msecs) {
		ct->ct_usec = (new_msecs - msec) * 1000;
	} else {
		ct->ct_sec--;
		ct->ct_usec = (1000 + new_msecs - msec) * 1000;
	}
}

/*
 * Minor adjustment to time. Drift should be a small amount in milliseconds.
 */
int clock_drift_sw(s32 drift)
{
	s32 now;

	/*
	 * We can ignore whole seconds from the module clock, as we only
	 * care when the msec will wrap into the next second
	 */
	now = boot_rel_time.ct_usec / 1000 + (u32)(clock_total_ms() % 1000);
	if ((now + drift) / 1000 != now / 1000) {
		/*
		 * Don't allow drift adjustments to cross from one full
		 * second to another.
		 */
		return -1;
	}
	drift *= 1000;
	if (drift < 0 && -drift > boot_rel_time.ct_usec) {
		boot_rel_time.ct_usec += 1000000;
		boot_rel_time.ct_sec--;
	}
	boot_rel_time.ct_usec += drift;
	if (boot_rel_time.ct_usec >= 1000000) {
		boot_rel_time.ct_usec -= 1000000;
		boot_rel_time.ct_sec++;
	}
	return 0;
}

/*
 * Get clock using software time since boot.
 */
u32 clock_get(struct clock_time *ct_out)
{
	u64 msec;
	struct clock_time ct;

	msec = clock_total_ms();
	ct.ct_sec = boot_rel_time.ct_sec + msec / 1000;
	ct.ct_usec = boot_rel_time.ct_usec + (msec % 1000) * 1000;
	if (ct.ct_usec >= 1000000) {
		ct.ct_sec++;
		ct.ct_usec -= 1000000;
	}
	if (ct_out) {
		*ct_out = ct;
	}
	return ct.ct_sec;
}

/*
 * Set the clock to a new time.
 * Returns -1 if the src given is a lower priority than the current
 * source. Returns 0 on success
 */
int clock_set(u32 new_time, enum clock_src src)
{
	if (src < clock_source()) {
		return -1;
	}
	clock_set_hw(new_time, src);
	return 0;
}

#ifdef MATRIXSSL /* XXX should be in gettimeofday.c, force them to link here. */

int gettimeofday(struct timeval *tv, void *tz_arg) /* XXX void in header? */
{
	struct timezone *tz = tz_arg;		/* XXX */
	u64 msecs;

	if (tv) {
		msecs = clock_total_ms() + boot_rel_time.ct_usec / 1000;
		tv->tv_sec = boot_rel_time.ct_sec + msecs / 1000;
		tv->tv_usec = (msecs % 1000) * 1000;
	}
	if (tz) {
		if (timezone_info.valid) {
			tz->tz_minuteswest = timezone_info.mins;
		} else {
			tz->tz_minuteswest = 0;
		}
		tz->tz_dsttime = 0;
	}
	return 0;
}

int _gettimeofday(struct timeval *tv, void *tz_arg)
{
	return gettimeofday(tv, tz_arg);
}

int _gettimeofday_r(struct timeval *tv, void *tz_arg)
{
	return gettimeofday(tv, tz_arg);
}
#endif /* MATRIXSSL */
