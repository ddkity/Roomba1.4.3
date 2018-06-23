/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ADW_WIFI_TIMER_H__
#define __AYLA_ADW_WIFI_TIMER_H__

struct timer;
#if !defined(AYLA_BC) && defined(WMSDK)
void adw_wmi_timer_set(struct timer *, unsigned long ms);
void adw_wmi_timer_cancel(struct timer *);
void adw_wmi_callback_pend(struct net_callback *);
#else
#define adw_wmi_timer_set net_timer_set
#define adw_wmi_timer_cancel net_timer_cancel
#define adw_wmi_callback_pend net_callback_pend
#endif

#endif /* __AYLA_ADW_WIFI_TIMER_H__ */
