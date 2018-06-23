/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_POWER_H__
#define __AYLA_POWER_H__

#define POWER_MON_TIMO          100                     /* msecs */
#define POWER_AWAKE_TIME        (1000 * 10)             /* msecs */
#define POWER_STANDBY_POWERED   (1000 * 60 * 5)         /* msecs */
#define POWER_UNCONF_POWERED    (1000 * 60 * 10)        /* msecs */

/*
 * Power profiles.
 *    max_perf  - everything on, minimize network latency.
 *    default   - power savings when idle, 802.11 low power mode.
 *    min       - max CPU power savings, 802.11 low power mode.
 *    standby   - connect only if MCU tells us to, 802.11 only up when
 *                  there is traffic. Link dropped when idle.
 */

void power_init(void);
void power_init_plat_clocks(void);
void power_hw_init(void);
void power_test(unsigned int);
void power_cli(int argc, char **argv);
int power_debug_attached(void);
int power_may_standby(void);

/*
 * Check the state of wakeup line. Returns 0 if wakeup signal is down.
 */
int power_hw_wkup_state(void);

#ifdef STOP_MODE_SUPPORT
void power_stayup(void);
#else
#define power_stayup()
#endif

#endif /* __AYLA_POWER_H__ */
