/*
 * Copyright 2015-2016 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ADA_SPROP_H__
#define __AYLA_ADA_SPROP_H__

#define SPROP_NAME_MAX_LEN      20
#define SPROP_TABLE_ENTRIES     10

struct ada_sprop {
	const char *name;
	enum ayla_tlv_type type;
	void *val;
	size_t val_len;
	ssize_t (*get)(struct ada_sprop *, void *buf, size_t len);
	enum ada_err (*set)(struct ada_sprop *, const void *buf, size_t len);
	u8 send_req;	/* flag indicating to send once connected to cloud */
};

/*
 * Get an ATLV_INT or ATLV_CENTS type property from the
 * sprop structure.
 */
ssize_t ada_sprop_get_int(struct ada_sprop *, void *buf, size_t len);

/*
 * Get an ATLV_UINT type property from the sprop structure.
 */
ssize_t ada_sprop_get_uint(struct ada_sprop *, void *buf, size_t len);

/*
 * Get an ATLV_BOOL type property from the sprop structure.
 */
ssize_t ada_sprop_get_bool(struct ada_sprop *, void *buf, size_t len);

/*
 * Get an ATLV_UTF8 type property from the sprop structure.
 */
ssize_t ada_sprop_get_string(struct ada_sprop *, void *buf, size_t len);

/*
 * Set an ATLV_INT or ATLV_CENTS property value to the
 * value in *buf.
 */
enum ada_err ada_sprop_set_int(struct ada_sprop *, const void *buf, size_t len);

/*
 * Set an ATLV_UINT property value to the value in *buf.
 */
enum ada_err ada_sprop_set_uint(struct ada_sprop *,
				const void *buf, size_t len);

/*
 * Set an ATLV_BOOL property value to the value in *buf.
 */
enum ada_err ada_sprop_set_bool(struct ada_sprop *,
				const void *buf, size_t len);

/*
 * Set an ATLV_UTF8 property value to the value in *buf.
 */
enum ada_err ada_sprop_set_string(struct ada_sprop *,
				const void *buf, size_t len);

/*
 * Send property update.
 */
enum ada_err ada_sprop_send(struct ada_sprop *);

/*
 * Send a property update by name.
 */
enum ada_err ada_sprop_send_by_name(const char *);

/*
 * Register a table of properties to the generic prop_mgr.
 */
enum ada_err ada_sprop_mgr_register(char *name, struct ada_sprop *table,
		unsigned int entries);

/*
 * Mask of currently-connected destinations.
 */
extern u8 ada_sprop_dest_mask;

#endif /* __AYLA_ADA_SPROP_H__ */
