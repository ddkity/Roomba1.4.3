/*
 * Copyright 2011-2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/base64.h>
#include <ayla/endian.h>
#include <ayla/http.h>
#include <ayla/log.h>
#include <ayla/nameval.h>
#include <ayla/conf.h>
#include <ayla/json.h>
#include <ayla/xml.h>
#include <jsmn.h>
#include <net/net.h>
#include <ayla/jsmn_get.h>
#include <ayla/malloc.h>
#include <ada/prop.h>
#include <ada/prop_mgr.h>
#include <ada/server_req.h>
#include "client_lock.h"

static void prop_page_close_cb(struct server_req *req)
{
	struct prop *prop = req->user_priv;

	if (prop && prop->prop_mgr_done) {
		prop->prop_mgr_done(prop);
		req->user_priv = NULL;
	}
}

/*
 * Send body of response for GET from property.json.
 */
static void prop_page_output(struct server_req *req)
{
	struct prop *prop;
	char fmt_val[BASE64_LEN_EXPAND(PROP_VAL_LEN) + 1];
	char *outval;
	const char *quote;

	prop = req->user_priv;
	ASSERT(prop);

	if (prop->len > PROP_VAL_LEN) {
		server_log(LOG_WARN "%s: long prop \"%s\" truncated "
		    "support TBD", __func__, prop->name);
		prop->len = PROP_VAL_LEN;
	}

	prop_fmt(fmt_val, sizeof(fmt_val), prop->type,
	    prop->val, prop->len, &outval);

	quote = prop_type_is_str(prop->type) ? "\"" : "";

	server_put(req,
	    "{\"name\":\"%s\","
	    "\"base_type\":\"%s\","
	    "\"value\":%s%s%s}",
	    prop->name, lookup_by_val(prop_types, prop->type),
	    quote, outval, quote);

	req->finish_write(req);
}

/*
 * This is the callback with the requested property value.
 */
static enum ada_err prop_page_get_cb(struct prop *prop, void *arg,
					enum ada_err error)
{
	struct server_req *req = arg;
	unsigned int status;
	char buf[SERVER_BUFLEN];	/* TBD temporary buffer for response */

	if (req->prop_abort) {
		server_free_aborted_req(req);
		return 0;
	}

	status = HTTP_STATUS_OK;
	if (error || !prop) {
		status = HTTP_STATUS_NOT_FOUND;
	}

	req->buf = buf;
	req->len = 0;
	req->put_head(req, status, server_content_json);
	if (prop) {
		req->user_priv = prop;
		server_continue(req, prop_page_output);
	} else {
		req->finish_write(req);
	}
	req->buf = NULL;
	if (req->err == AE_BUF) {
		req->close_cb = prop_page_close_cb;
		return AE_IN_PROGRESS;
	}
	return AE_OK;
}

/*
 * Get Property JSON for a single property.
 */
void prop_page_json_get_one(struct server_req *req)
{
	char name_buf[PROP_NAME_LEN];
	char *name;
	enum ada_err error;

	name = server_get_arg_by_name(req, "name", name_buf, sizeof(name_buf));
	if (!name) {
		server_put_status(req, HTTP_STATUS_BAD_REQ);
		return;
	}

	error = ada_prop_mgr_get(name, prop_page_get_cb, req);

	switch (error) {
	case AE_OK:
		break;
	case AE_IN_PROGRESS:
		req->user_in_prog = 1;
		break;
	case AE_NOT_FOUND:
		server_put_status(req, HTTP_STATUS_NOT_FOUND);
		break;
	default:
		server_put_status(req, HTTP_STATUS_INTERNAL_ERR);
		break;
	}
}
