/*
 * Copyright 2014-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_PROP_MGR_H__
#define __AYLA_PROP_MGR_H__

#include <ayla/nameval.h>

enum prop_mgr_event {
	PME_TIME,		/* time parameters updated */
	PME_PROP_SET,		/* property value was set (and maybe changed) */
	PME_NOTIFY,		/* ANS notification received */
	/* values past PME_NOTIFY are sent only when the prop mgr is active */
	PME_ECHO_FAIL,		/* echo of property failed */
	PME_TIMEOUT,		/* timeout waiting for property manager */
};

/*
 * Optional event callback arg.
 */
union prop_mgr_event_arg {
	char *prop_name;		/* property name */
	void (*continue_recv)(void);	/* continue receiving data */
};

struct prop;
struct prop_recvd;

/*
 * Structure that a handler of properties uses to register with
 * the Ayla Device Client.
 */
struct prop_mgr {
	const char *name;

	/*
	 * Receive property value from ADS or app.
	 */
	enum ada_err (*prop_recv)(const char *name, enum ayla_tlv_type type,
			const void *val, size_t len,
			size_t *offset, u8 src, void *cb_arg);

	/*
	 * Callback to report success/failure of property post to ADS/apps.
	 * status will be PROP_CB_DONE on success.
	 * fail_mask contains a bitmask of failed destinations.
	 */
	void (*send_done)(enum prop_cb_status, u8 fail_mask, void *cb_arg);

	/*
	 * ADS/app wants to fetch a value of a property.
	 * Function must call (*get_cb) with the value of the property.
	 */
	enum ada_err (*get_val)(const char *name,
	    enum ada_err (*get_cb)(struct prop *, void *arg, enum ada_err),
	    void *arg);

	/*
	 * ADC reports a change in it's connectivity. Bit 0 is ADS, others
	 * are mobile clients.
	 */
	void (*connect_status)(u8 mask);

	/*
	 * ADC reports an event to all property managers.
	 */
	void (*event)(enum prop_mgr_event, const void *arg);
};

/*
 * Property manager uses this to register itself as a handler of properties.
 */
void ada_prop_mgr_register(const struct prop_mgr *mgr);

/*
 * Report connectivity status to all property managers.
 */
void prop_mgr_connect_sts(u8 mask);

/*
 * Send event to all interested property managers.
 */
void prop_mgr_event(enum prop_mgr_event, void *);

/*
 * Property manager reports it's ready to receive data.
 */
void ada_prop_mgr_ready(const struct prop_mgr *);

/*
 * Post a property to ADS/app. (*send_cb) is called when operation is done.
 */
enum ada_err ada_prop_mgr_send(const struct prop_mgr *, struct prop *,
			u8 dest_mask, void *cb_arg);

/*
 * Get a property from a property manager.
 * On success, eventually calls (*get_cb) with the value of the property.
 * Returns 0 on success.
 */
enum ada_err ada_prop_mgr_get(const char *name,
		enum ada_err (*get_cb)(struct prop *, void *arg, enum ada_err),
		void *arg);

/*
 * Set a prop using a property manager.
 */
enum ada_err ada_prop_mgr_set(const char *name, enum ayla_tlv_type type,
			const void *val, size_t val_len,
			size_t *offset, u8 src, void *set_arg);

/*
 * Request a property value from ADS.
 * A NULL name gets all to-device properties.
 */
enum ada_err ada_prop_mgr_request(const char *name);

extern const struct name_val prop_types[];

/*
 * Internal initialization call.
 */
void prop_mgr_init(void);

#endif /* __AYLA_PROP_MGR___ */
