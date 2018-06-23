/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <net/net.h>
#include <ada/server_req.h>
#include <ada/ada_conf.h>

#define CONFIG_PATH_LEN 100

/*
 * Get string config item.
 * Returns length of value or -1 on failure.
 */
int adap_conf_get(const char *name, void *buf, size_t len)
{
	return -1;
}

/*
 * Set config item, which may be in non-string format.
 * Returns 0 on success, -1 or error code on failure.
 */
int adap_conf_set(const char *path, const void *val, size_t len)
{
	int tok_len;
	char name[CONFIG_PATH_LEN];
	int rc = 0;
	unsigned long ulval;
	long lval;
	char *errptr;
	u8 u8val;
	enum conf_token tk[3];
	struct {
		struct ayla_tlv tlv;
		/* there will be padding here for alignment */
		union {
			u8 boolval;
			u32 ulval;
			s32 lval;
			char str[64];
			u8 key[CONF_OEM_KEY_MAX];
		};
	} buf;
	const void *valp;

	snprintf(name, sizeof(name), "%s", path);
	tok_len = conf_str_to_tokens(name, tk, ARRAY_LEN(tk));
	if (tok_len <= 0) {
		return tok_len;
	}

	buf.tlv.type = ATLV_BOOL;

	switch (tk[0]) {
	case CT_sys:
		if (tok_len != 2) {
			return -1;
		}
		switch (tk[1]) {
		case CT_setup_mode:
		case CT_dst_valid:
		case CT_dst_active:
			break;
		case CT_timezone:
			buf.tlv.type = ATLV_INT;
			break;
		case CT_dst_change:
			buf.tlv.type = ATLV_UINT;
			break;
		default:
			return -1;
		}
		break;
	case CT_client:
		if (tok_len != 3 ||
		    !(tk[1] == CT_server && tk[2] == CT_default)) {
			return -1;
		}
		break;
	case CT_oem:
		if (tok_len != 2 || tk[1] != CT_key) {
			return -1;
		}
		if (len > sizeof(buf.key)) {
			return -1;
		}
		buf.tlv.type = ATLV_FILE | (len >> 8);
		buf.tlv.len = (u8)len;
		memcpy(&buf.tlv + 1, val, len);
		goto set;
	case CT_wifi:
		if (tok_len != 2 || tk[1] != CT_setup_ios_app) {
			return -1;
		}
		buf.tlv.type = ATLV_UTF8;
		break;
	default:
		/* currently not supported */
		return -1;
	}

	switch (buf.tlv.type) {
	case ATLV_BOOL:
	case ATLV_UINT:
		ulval = strtoul(val, &errptr, 10);
		if (*errptr != '\0' || errptr == val) {
			goto err;
		}
		if (buf.tlv.type == ATLV_BOOL) {
			if (ulval > 1) {
				goto err;
			}
			u8val = ulval;
			valp = &u8val;
			buf.tlv.len = sizeof(u8val);
			break;
		}
		valp = &ulval;
		buf.tlv.len = sizeof(ulval);
		break;
	case ATLV_INT:
		lval = strtol(val, &errptr, 10);
		if (*errptr != '\0' || errptr == val) {
			goto err;
		}
		valp = &lval;
		buf.tlv.len = sizeof(lval);
		break;
	case ATLV_UTF8:
		rc = strlen(val);
		if (rc < 0 || rc > MAX_U8 || rc > sizeof(buf.str)) {
			goto err;
		}
		buf.tlv.len = rc;
		valp = val;
		break;
	default:
		goto err;
	}

	/*
	 * Value is in host order.  Copy to be immediately after TLV.
	 */
	memcpy(&buf.tlv + 1, valp, buf.tlv.len);
set:
	rc = conf_entry_set(CONF_OP_SRC_ADS, tk, tok_len, &buf.tlv);
	return rc;

err:
	server_log(LOG_WARN "ada_conf_set bad val");
	return -1;
}


/*
 * configuration table.
 */
const struct conf_entry * const conf_table[] = {
	&log_conf_entry,
	&conf_sys_id_entry,
	&conf_sys_conf_entry,
	&client_conf_entry,
	&conf_oem_entry,
	&sched_conf_entry,
	NULL
};
