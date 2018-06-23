/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_NOTIFY_INT_H__
#define __AYLA_NOTIFY_INT_H__

enum notify_event {
	NS_EV_CHECK,	/* check for properties, also note service up */
	NS_EV_DOWN,	/* notification service went down */
	NS_EV_DOWN_RETRY, /* notification service went down, will retry */
	NS_EV_DNS_PASS,	/* notification service dns lookup passed */
	NS_EV_CHANGE,	/* the notification server may have changed - re-ID */
};

#define NP_KEY_LEN	16	/* max AES crypto key length in 8-bit bytes */

extern u32 np_poll_max_perf;
extern u32 np_poll_default;

void np_init(void (*cb_func)(void));
int np_start(u8 *cipher_key, size_t len);
enum notify_event np_event_get(void);
void np_stop(void);
void np_status(void);
void np_set_server(const char *name);
int np_server_host_cmp(const char *name);
void np_retry_server(void);
void np_set_poll_interval(u32 interval);

void notify_timer_set(struct timer *, unsigned long ms);
void notify_timer_cancel(struct timer *);

struct ada_mbuf;
enum ada_err notify_udp_send(struct net_udp *pcb, struct ada_mbuf *am);
enum ada_err notify_udp_open(struct net_udp **pcbp, struct ip_addr *addr,
    u16 port, void *cb_arg);
void notify_udp_close(struct net_udp *pcb);

void np_recv(void *arg, struct net_udp *pcb, struct ada_mbuf *am,
    ip_addr_t *addr, u16_t port);

#endif /* __AYLA_NOTIFY_H_ */
