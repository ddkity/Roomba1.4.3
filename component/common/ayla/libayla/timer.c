/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifdef AMEBA
#define HAVE_UTYPES
#endif

#if defined(AYLA_FreeRTOS)
#include <FreeRTOS.h>
#include <task.h>
#elif defined(QCA4010_SDK)
#include <qcom/qcom_time.h>
#define __time_t_defined
#endif
#include <sys/types.h>

#include <ayla/utypes.h>
#include <ayla/timer.h>
#include <ayla/clock.h>

/*
 * Get time since boot in milliseconds.
 * This is assumed low-overhead (no system calls) using shared kernel page.
 */
#if defined(AYLA_FreeRTOS)
unsigned long time_now(void)
{
	return xTaskGetTickCount() / portTICK_RATE_MS;
}
#elif defined(QCA4010_SDK)
unsigned long time_now(void)
{
	return time_ms();
}
#endif

void timer_init(struct timer *timer, void (*handler)(struct timer *))
{
	timer->next = NULL;
	timer->time_ms = 0;
	timer->handler = handler;
}

void timer_cancel(struct timer_head *head, struct timer *timer)
{
	struct timer **prev;
	struct timer *node;

	for (prev = &head->first; (node = *prev) != NULL; prev = &node->next) {
		if (node == timer) {
			*prev = node->next;
			node->time_ms = 0;
			break;
		}
	}
}

void timer_set(struct timer_head *head, struct timer *timer, unsigned long ms)
{
	struct timer **prev;
	struct timer *node;
	unsigned long time;

	if (ms > TIMER_DELAY_MAX) {
		ms = TIMER_DELAY_MAX;
	}
	time = time_now() + ms;
	if (!time) {
		time--;			/* zero means inactive */
	}
	if (timer_active(timer)) {
		timer_cancel(head, timer);
	}
	timer->time_ms = time;

	for (prev = &head->first; (node = *prev) != NULL; prev = &node->next) {
		if (clock_gt(node->time_ms, time)) {
			break;
		}
	}
	*prev = timer;
	timer->next = node;
}

void timer_reset(struct timer_head *head, struct timer *timer,
		void (*handler)(struct timer *), unsigned long ms)
{
	if (timer_active(timer)) {
		timer_cancel(head, timer);
	}
	timer_init(timer, handler);
	timer_set(head, timer, ms);
}


unsigned long timer_delay_get_ms(struct timer *timer)
{
	if (!timer->time_ms) {
		return 0;
	}
	return timer->time_ms - time_now();
}

/*
 * Dequeue the first node on the timer head.
 * Returns NULL for an empty list.
 */
struct timer *timer_first_dequeue(struct timer_head *head)
{
	struct timer *timer;

	timer = head->first;
	if (timer) {
		head->first = timer->next;
		timer->time_ms = 0;
	}
	return timer;
}

/*
 * Run the timer callback.
 */
void timer_run(struct timer *timer)
{
	timer->next = NULL;
	timer->time_ms = 0;
	timer->handler(timer);
}

int timer_advance(struct timer_head *head)
{
	struct timer *node;
	unsigned long ms;

	while ((node = head->first) != NULL) {
		/*
		 * Return if the next timeout is in the future.
		 */
		ms = time_now();
		if (clock_gt(node->time_ms, ms)) {
			return node->time_ms - ms;
		}
		head->first = node->next;
		timer_run(node);
	}
	return -1;
}

int timer_delta_get(struct timer_head *head)
{
	struct timer *timer;
	int delta;

	timer = head->first;
	if (!timer || !timer->time_ms) {
		return -1;
	}

	delta = (int)(timer->time_ms - time_now());
	if (delta < 0) {
		delta = 0;
	}
	return delta;
}
