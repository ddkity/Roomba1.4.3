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
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/timer.h>
#include <net/ada_mbuf.h>
#include <net/net.h>

#include "client_lock.h"
#include "notify_int.h"
#include "client_timer.h"
#include "ada_lock.h"

static struct ada_lock *notify_mutex;
static const char *notify_mutex_func;
static int notify_mutex_line;
u8 notify_locked;			/* for debug only */

void notify_lock_int(const char *func, int line)
{
	int rc;

	ada_lock(notify_mutex);
	ASSERT(!notify_locked);
	notify_locked = 1;
	notify_mutex_func = func;
	notify_mutex_line = line;
}

void notify_unlock_int(const char *func, int line)
{
	int rc;

	ASSERT(notify_locked);
	notify_mutex_func = func;
	notify_mutex_line = line;
	notify_locked = 0;
	ada_unlock(notify_mutex);
}

void notify_lock_init(void)
{
	notify_mutex = ada_lock_create("notify_mutex");
	ASSERT(notify_mutex);
}


void notify_timer_set(struct timer *timer, unsigned long ms)
{
	client_timer_set(timer, ms);
}

void notify_timer_cancel(struct timer *timer)
{
	client_timer_cancel(timer);
}


static void notify_udp_recv(void *arg, struct net_udp *pcb,
		struct ada_mbuf *mbuf,
		ip_addr_t *addr, u16_t port)
{
	np_recv(arg, pcb, mbuf, addr, port);
}

enum ada_err notify_udp_open(struct net_udp **pcbp, struct ip_addr *addr,
    u16 port, void *cb_arg)
{
	struct net_udp *udp;
	enum ada_err err;

	udp = net_udp_new();
	if (udp) {
		err = net_udp_connect(udp, addr, port);
		if (err) {
			return err;
		}
		net_udp_recv(udp, np_recv, cb_arg);
	} else {
		return AE_ALLOC;
	}
	*pcbp = udp;
	return AE_OK;
}

enum ada_err notify_udp_send(struct net_udp *udp, struct ada_mbuf *am)
{
	return net_udp_send(udp, am);
}

void notify_udp_close(struct net_udp *udp)
{
	net_udp_remove(udp);
}
