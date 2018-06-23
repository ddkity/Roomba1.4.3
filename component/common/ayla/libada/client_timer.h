/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CLIENT_TIMER_H_
#define __AYLA_CLIENT_TIMER_H_

struct timer;
void client_timer_set(struct timer *, unsigned long ms);
void client_timer_cancel(struct timer *);
void client_callback_pend(struct net_callback *);

#endif /* __AYLA_CLIENT_TIMER_H_ */
