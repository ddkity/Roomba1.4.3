/*
 * Copyright 2014, 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/base64.h>
#include <ayla/tlv.h>

#include <ayla/log.h>
#include <ayla/clock.h>
#include <ayla/timer.h>

#include <net/net.h>
#include <net/base64.h>
#include <ada/err.h>
#include <ayla/malloc.h>
#include <ada/client.h>
#include <ada/prop.h>
#include <ada/prop_mgr.h>
#include "ada_lock.h"
#include "client_lock.h"
#include "client_timer.h"

/*
 * State bits
 */
#define PROP_MGR_ENABLED	1	/* listen enable */
#define PROP_MGR_FLOW_CTL	2	/* flow controlled */

/*
 * Private structure for list of all property managers.
 */
struct prop_mgr_node {
	const struct prop_mgr *mgr;
	struct prop_mgr_node *next;
	u8 state;
};

static struct prop_mgr_node *prop_mgrs;
static struct prop *prop_mgr_sending;
static struct prop_queue prop_mgr_send_queue =
		STAILQ_HEAD_INITIALIZER(prop_mgr_send_queue);
static struct net_callback prop_mgr_send_callback;
static u8 prop_mgr_dest_mask;
static struct ada_lock *prop_mgr_lock;

static void prop_mgr_send_next(void *);

void prop_mgr_init(void)
{
	net_callback_init(&prop_mgr_send_callback, prop_mgr_send_next, NULL);
	prop_mgr_lock = ada_lock_create("prop_mgr");
	ASSERT(prop_mgr_lock);
}

/*
 * Queue request for the callback.
 */
static void ada_prop_mgr_enqueue(struct prop *prop)
{
	struct prop_queue *qp = &prop_mgr_send_queue;

	ada_lock(prop_mgr_lock);
	STAILQ_INSERT_TAIL(qp, prop, list);
	ada_unlock(prop_mgr_lock);
	client_callback_pend(&prop_mgr_send_callback);
}

static struct prop_mgr_node *prop_mgr_node_lookup(const struct prop_mgr *pm)
{
	struct prop_mgr_node *pg;

	for (pg = prop_mgrs; pg; pg = pg->next) {
		if (pm == pg->mgr) {
			return pg;
		}
	}
	return NULL;
}

/*
 * If all property managers are now ready, enable listen to client.
 */
static void prop_mgr_listen_check(void)
{
	struct prop_mgr_node *pg;

	for (pg = prop_mgrs; pg; pg = pg->next) {
		if (!(pg->state & PROP_MGR_ENABLED)) {
			return;
		}
	}
	client_enable_ads_listen();
}

/*
 * Check the send list for any property updates that can no longer be sent
 * because all destinations specified have lost connectivity.
 */
static void prop_mgr_send_queue_check(u8 mask)
{
	struct prop_queue *qp = &prop_mgr_send_queue;
	struct prop_queue lost_q;
	struct prop *prop;
	struct prop *next;
	const struct prop_mgr *pm;

	/*
	 * Look for props that can no longer be sent to any destination,
	 * take them off the list and put them on the local lost_q list.
	 * Then go through the local lost_q list and do the callbacks after.
	 * dropping the lock.
	 */
	STAILQ_INIT(&lost_q);
	ada_lock(prop_mgr_lock);
	for (prop = STAILQ_FIRST(qp); prop; prop = next) {
		next = STAILQ_NEXT(prop, list);
		if (!(prop->send_dest & mask)) {
			STAILQ_REMOVE(qp, prop, prop, list);
			STAILQ_INSERT_TAIL(&lost_q, prop, list);
		}
	}
	ada_unlock(prop_mgr_lock);
	for (;;) {
		prop = STAILQ_FIRST(&lost_q);
		if (!prop) {
			break;
		}
		STAILQ_REMOVE_HEAD(&lost_q, list);

		/*
		 * report all dests failed
		 */
		pm = prop->mgr;
		if (pm) {
			ASSERT(pm->send_done);
			pm->send_done(PROP_CB_CONN_ERR, prop->send_dest,
			    prop->send_done_arg);
		} else if (prop->prop_mgr_done) {
			prop->prop_mgr_done(prop);
		}
	}
}

void prop_mgr_connect_sts(u8 mask)
{
	struct prop_mgr_node *pg;
	const struct prop_mgr *pm;
	u8 lost_dests;
	u8 added_dests;

	for (pg = prop_mgrs; pg; pg = pg->next) {
		pm = pg->mgr;
		if (pm->connect_status) {
			if (!(mask & NODES_ADS)) {
				pg->state &= ~PROP_MGR_ENABLED;
			}
			pm->connect_status(mask);
		}
	}
	if (mask & NODES_ADS) {
		prop_mgr_listen_check();
	}

	/*
	 * Determine which destinations have been lost and added.
	 */
	lost_dests = prop_mgr_dest_mask & ~mask;
	added_dests = ~prop_mgr_dest_mask & mask;
	prop_mgr_dest_mask = mask;

	/*
	 * If connectivity has improved, send pending properties.
	 */
	if (added_dests) {
		client_lock();
		prop_mgr_send_next(NULL);
		client_unlock();
	}

	/*
	 * If some connectivity has been lost, check queued property updates.
	 */
	if (lost_dests) {
		prop_mgr_send_queue_check(mask);
	}
}

void prop_mgr_event(enum prop_mgr_event event, void *event_specific_arg)
{
	struct prop_mgr_node *pg;
	const struct prop_mgr *pm;

	for (pg = prop_mgrs; pg; pg = pg->next) {
		pm = pg->mgr;

		/*
		 * PME_TIMEOUT events are sent only to the active prop_mgr.
		 * Other events go to all prop_mgrs.
		 */
		if (event == PME_TIMEOUT &&
		    (prop_mgr_sending && pm != prop_mgr_sending->mgr)) {
			continue;
		}
		if (pm->event) {
			pm->event(event, event_specific_arg);
		}
	}
}

void ada_prop_mgr_register(const struct prop_mgr *pm)
{
	struct prop_mgr_node *pg;

	pg = calloc(1, sizeof(*pg));
	ASSERT(pg);
	pg->mgr = pm;
	pg->next = prop_mgrs;
	prop_mgrs = pg;
}

void ada_prop_mgr_ready(const struct prop_mgr *pm)
{
	struct prop_mgr_node *pg;

	pg = prop_mgr_node_lookup(pm);
	if (!pg || (pg->state & PROP_MGR_ENABLED)) {
		return;
	}
	pg->state |= PROP_MGR_ENABLED;
	prop_mgr_listen_check();
}

/*
 * Callback from client state machine to send a property or a request.
 */
static enum ada_err prop_mgr_send_cb(enum prop_cb_status stat, void *arg)
{
	struct prop *prop = prop_mgr_sending;
	const struct prop_mgr *pm;
	enum ada_err err;

	ASSERT(client_locked);
	ASSERT(prop);

	switch (stat) {
	case PROP_CB_BEGIN:
		if (!prop->val) {	/* request property from ADS */
			err = client_get_prop_val(prop->name);
			if (err == AE_BUSY) {
				ada_prop_mgr_enqueue(prop);
			}
			break;
		}
		err = client_send_data(prop);
		break;

	case PROP_CB_DONE:
		if (prop->val) {		/* not a GET */
			prop_mgr_event(PME_PROP_SET, (void *)prop->name);
		}
		/* fall through */
	default:
		prop_mgr_sending = NULL;
		pm = prop->mgr;
		if (pm) {
			ASSERT(pm->send_done);
			pm->send_done(stat, client_get_failed_dests(),
			    prop->send_done_arg);
		} else if (prop->prop_mgr_done) {
			prop->prop_mgr_done(prop);
		}
		client_callback_pend(&prop_mgr_send_callback);
		err = AE_OK;
		break;
	}
	return err;
}

/*
 * Start send for next property on the queue.
 * This is called through a callback so it may safely drop the client_lock.
 */
static void prop_mgr_send_next(void *arg)
{
	struct prop_queue *qp = &prop_mgr_send_queue;
	struct prop *prop;

	ASSERT(client_locked);
	for (;;) {
		if (!prop_mgr_dest_mask) {
			break;
		}
		if (prop_mgr_sending) {
			break;
		}
		ada_lock(prop_mgr_lock);
		prop = STAILQ_FIRST(qp);
		if (!prop) {
			ada_unlock(prop_mgr_lock);
			break;
		}
		STAILQ_REMOVE_HEAD(qp, list);
		prop_mgr_sending = prop;
		ada_unlock(prop_mgr_lock);
		client_unlock();

		client_send_callback_set(prop_mgr_send_cb, prop->send_dest);

		client_lock();
	}
}

/*
 * Send a property.
 * The prop structure must be available until (*send_cb)() is called indicating
 * the value has been completely sent.
 */
enum ada_err ada_prop_mgr_send(const struct prop_mgr *pm, struct prop *prop,
			u8 dest_mask, void *cb_arg)
{
	if (!dest_mask) {
		return AE_INVAL_STATE;
	}
	prop->mgr = pm;
	prop->send_dest = dest_mask;
	prop->send_done_arg = cb_arg;
	ada_prop_mgr_enqueue(prop);
	return AE_IN_PROGRESS;
}

/*
 * Get a prop using a property manager.
 */
enum ada_err ada_prop_mgr_get(const char *name,
		enum ada_err (*get_cb)(struct prop *, void *arg, enum ada_err),
		void *arg)
{
	struct prop_mgr_node *pg;
	const struct prop_mgr *pm;
	enum ada_err err;

	if (!prop_name_valid(name)) {
		return AE_INVAL_NAME;
	}

	for (pg = prop_mgrs; pg; pg = pg->next) {
		pm = pg->mgr;
		if (!pm->get_val) {
			continue;
		}
		err = pm->get_val(name, get_cb, arg);
		if (err != AE_NOT_FOUND) {
			return err;
		}
	}
	return AE_NOT_FOUND;
}

/*
 * Set a prop using a property manager.
 */
enum ada_err ada_prop_mgr_set(const char *name, enum ayla_tlv_type type,
			const void *val, size_t val_len,
			size_t *offset, u8 src, void *set_arg)
{
	struct prop_mgr_node *pg;
	const struct prop_mgr *pm;
	enum ada_err err = AE_NOT_FOUND;

	if (!prop_name_valid(name)) {
		return AE_INVAL_NAME;
	}

	for (pg = prop_mgrs; pg; pg = pg->next) {
		pm = pg->mgr;
		if (!pm->prop_recv) {
			continue;
		}
		err = pm->prop_recv(name, type, val, val_len,
		    offset, src, set_arg);
		if (err != AE_NOT_FOUND) {
			if (err == AE_OK || err == AE_IN_PROGRESS) {
				prop_mgr_event(PME_PROP_SET, (void *)name);
			} else {
				client_log(LOG_WARN "%s: name %s err %d",
				    __func__, name, err);
			}
			break;
		}
	}
	return err;
}

/*
 * Returns 1 if the property type means the value has to be in quotes
 */
int prop_type_is_str(enum ayla_tlv_type type)
{
	return type == ATLV_UTF8 || type == ATLV_BIN || type == ATLV_SCHED ||
	    type == ATLV_LOC;
}

/*
 * Format a property value.
 * Returns the number of bytes placed into the value buffer.
 */
size_t prop_fmt(char *buf, size_t len, enum ayla_tlv_type type,
		void *val, size_t val_len, char **out_val)
{
	int rc;
	size_t i;
	s32 ones;
	unsigned int tenths;
	unsigned int cents;
	char *sign;

	*out_val = buf;
	switch (type) {
	case ATLV_INT:
		rc = snprintf(buf, len, "%ld", *(s32 *)val);
		break;

	case ATLV_UINT:
		rc = snprintf(buf, len, "%lu", *(u32 *)val);
		break;

	case ATLV_BOOL:
		rc = snprintf(buf, len, "%u", *(u8 *)val != 0);
		break;

	case ATLV_UTF8:
		/* for strings, use the original buffer */
		ASSERT(val_len <= TLV_MAX_STR_LEN);
		rc = val_len;
		*out_val = val;
		break;

	case ATLV_CENTS:
		ones = *(s32 *)val;
		sign = "";
		if (ones < 0 && ones != 0x80000000) {
			sign = "-";
			ones = -ones;
		}
		tenths = (unsigned)ones;
		cents = tenths % 10;
		tenths = (tenths / 10) % 10;
		ones /= 100;
		rc = snprintf(buf, len, "%s%ld.%u%u",
		    sign, ones, tenths, cents);
		break;

	case ATLV_BIN:
	case ATLV_SCHED:
		rc = net_base64_encode((u8 *)val, val_len, buf, &len);
		if (rc < 0) {
			log_put("prop_fmt: enc fail rc %d", rc);
			buf[0] = '\0';
			return 0;
		}
		rc = len;
		break;
	default:
		rc = 0;
		for (i = 0; i < val_len; i++) {
			rc += snprintf(buf + rc, len - rc, "%2.2x ",
			    *((unsigned char *)val + i));
		}
		break;
	}
	return rc;
}

/*
 * Return non-zero if property name is valid.
 * Valid names need no XML or JSON encoding.
 * Valid names include: alphabetic chars numbers, hyphen and underscore.
 * The first character must be alphabetic.  The max length is 27.
 *
 * This could use ctypes, but doesn't due to library license.
 */
int prop_name_valid(const char *name)
{
	const char *cp = name;
	char c;
	size_t len = 0;

	while ((c = *cp++) != '\0') {
		len++;
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			continue;
		}
		if (len > 1) {
			if (c >= '0' && c <= '9') {
				continue;
			}
			if (c == '_' || c == '-') {
				continue;
			}
		}
		return 0;
	}
	if (len == 0 || len >= PROP_NAME_LEN) {
		return 0;
	}
	return 1;
}

static void ada_prop_mgr_request_done(struct prop *prop)
{
	free(prop);
}

/*
 * Request a property (or all properties if name is NULL).
 */
enum ada_err ada_prop_mgr_request(const char *name)
{
	struct prop *prop;

	if (name && !prop_name_valid(name)) {
		return AE_INVAL_NAME;
	}

	prop = calloc(1, sizeof(*prop));
	if (!prop) {
		return AE_ALLOC;
	}

	/*
	 * GET request is indicated by the NULL val pointer.
	 * A NULL or empty name will indicate all to-device properties.
	 */
	prop->name = name;
	prop->send_dest = NODES_ADS;
	prop->prop_mgr_done = ada_prop_mgr_request_done;

	ada_prop_mgr_enqueue(prop);
	return 0;
}
