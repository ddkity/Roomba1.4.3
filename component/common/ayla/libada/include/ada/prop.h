/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_PROP_H__
#define __AYLA_PROP_H__

#include <ayla/tlv.h>
#include <ayla/nameval.h>
#include <sys/queue.h>

#define PROP_REQ_TIMEOUT 200	/* (ms) timeout for requests to MCU */
#define PROP_REQ_RETRY 4	/* retries per property request */

/*
 * For table of most recently received properties.
 */
#define PROP_NAME_LEN	28	/* maximum name length including NUL */
#define PROP_LOC_LEN	64	/* maximum loc/uri length including NUL */
#define PROP_VAL_LEN	255	/* maximum val len to/from MCU */
#define PROP_TYPE_LEN	8	/* max type string length */
#define PROP_DIR_LEN	8	/* max direction string length */
#define PROP_TOK_LEN	8	/* registration token length */

#define LONG_GET_REQ_SIZE	2048	/* Size of long get requests */

#define PROP_DPMETA_KEY_LEN	16	/* max len of dp metadata key */
#define PROP_DPMETA_VAL_LEN	32	/* max len of dp metadata value */
#define PROP_MAX_DPMETA		4	/* max num of dp metadata
					   key-value pairs */
struct prop_dp_meta {
	char key[PROP_DPMETA_KEY_LEN + 1];
	char value[PROP_DPMETA_VAL_LEN + 1];
};

/*
 * prop_get result.
 */
struct prop {
	const char *name;
	u8	fmt_flags;
	u8	echo:1;
	u8	send_dest;	/* destinations (internal field) */
	enum ayla_tlv_type type;
	void    *val;
	size_t	len;
	struct prop_dp_meta *dp_meta; /* ptr to datapoint metadata */

	/*
	 * prop_mgr_done() callback.  Optional.
	 * When a prop_mgr get_cb returns AE_IN_PROGRESS, this function
	 * will be called after the get is complete, at which time the
	 * property may be freed.
	 */
	void (*prop_mgr_done)(struct prop *);

	/*
	 * Internal fields - for use by ADA, not by applications.
	 */
	void *send_done_arg;	/* send_done() arg */
	STAILQ_ENTRY(prop) list; /* list linkage for prop_mgr */
	const struct prop_mgr *mgr;
};

STAILQ_HEAD(prop_queue, prop);		/* declares struct prop_queue */

ASSERT_COMPILE(prop_enum_tlv, sizeof(enum ayla_tlv_type) == 1);

struct prop_file_info {
	char location[TLV_MAX_STR_LEN / 2];
	char file[TLV_MAX_STR_LEN / 2];
};

/*
 * property being received from server
 */
struct prop_recvd {
	struct prop prop;
	char name[(PROP_LOC_LEN > PROP_NAME_LEN) ?
	    PROP_LOC_LEN : PROP_NAME_LEN];
	union {
		char val[TLV_MAX_STR_LEN + 1];	/* + 1 for '\0' */
		struct prop_file_info file_info;
	};
	enum ayla_tlv_type type;
	size_t offset;
	u8 is_file:1;	/* clear this flag only when safe to clear file_info */
	u8 src;
	void *arg;		/* request-specific arg (indicates req ID) */
};

enum prop_cb_status {
	PROP_CB_BEGIN,
	PROP_CB_CONTINUE,
	PROP_CB_DONE,
	PROP_CB_CONN_ERR,   /* conn_err nak */
	PROP_CB_CONN_ERR2,  /* conn_err nak with prop name */
	PROP_CB_INVAL_OFF_ERR,  /* inval offset nak */
	PROP_CB_OVERFLOW,  /* MCU can't consume */
	PROP_CB_UNEXP_OP,  /* unexpected operation from mcu */
	PROP_CB_ADS_ERR,   /* ADS gave 4xx status, failed to create datapoint */
};

extern u16 prop_req_id;

/*
 * Return non-zero if the name meets the requirements for a property name.
 */
int prop_name_valid(const char *name);

/*
 * Format a typed value into a buffer.
 */
size_t prop_fmt(char *buf, size_t len, enum ayla_tlv_type type,
		void *val, size_t val_len, char **out_val);

/*
 * Returns 1 if the property type means the value has to be in quotes for JSON.
 */
int prop_type_is_str(enum ayla_tlv_type type);

const char *prop_dp_put_get_loc(void);
enum ada_err prop_dp_put_close(enum prop_cb_status, void *);
enum ada_err prop_dp_put(enum prop_cb_status, void *);
enum ada_err prop_dp_req(enum prop_cb_status, void *);

extern const struct name_val prop_types[];

#endif /* __AYLA_PROP_H__ */
