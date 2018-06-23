/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_TIMER_H__
#define __AYLA_TIMER_H__

/*
 * Simple timer structure modified for device client.
 */
struct timer {
	struct timer *next;
	unsigned long time_ms;		/* monotonic trigger time */
	void (*handler)(struct timer *);
};

#define TIMER_DELAY_MAX	0x7fffffff /* max delay in milliseconds (24 days) */

struct timer_head {
	struct timer *first;
};

static inline int timer_active(const struct timer *timer)
{
	return timer->time_ms != 0;
}

static inline int timer_initialized(const struct timer *timer)
{
	return timer->handler != NULL;
}

void timer_init(struct timer *, void (*handler)(struct timer *));
void timer_cancel(struct timer_head *, struct timer *);
void timer_set(struct timer_head *, struct timer *, unsigned long delay_ms);
void timer_reset(struct timer_head *, struct timer *,
		void (*handler)(struct timer *), unsigned long delay_ms);
unsigned long timer_delay_get_ms(struct timer *);

/*
 * Return current monotonic time in milliseconds since a fixed point.
 */
unsigned long time_now(void);

/*
 * Handle timers and return delay until next timer fires.
 * Return -1 if no timers scheduled.
 */
int timer_advance(struct timer_head *);

/*
 * Return time to next event without running timers.
 * Returns -1 if nothing scheduled.
 */
int timer_delta_get(struct timer_head *);

/*
 * Dequeue the first node on the timer head.
 * Returns NULL for an empty list.
 */
struct timer *timer_first_dequeue(struct timer_head *);

/*
 * Run the timer callback for a timer that has been dequeued.
 */
void timer_run(struct timer *);

#endif /* __AYLA_TIMER_H__ */
