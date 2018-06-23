/*
 * Copyright 2013-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/tlv.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/json.h>
#include <ayla/clock.h>
#include <ayla/conf_flash.h>
#include <ayla/parse.h>
#include <ayla/timer.h>
#include <jsmn.h>
#include <ayla/jsmn_get.h>
#include <ayla/http.h>
#include <ayla/xml.h>
#include <net/net.h>
#include <net/net_crypto.h>
#include <net/stream.h>
#include <net/http_client.h>
#include <ada/client.h>
#include <ada/ada_conf.h>
#include <ada/ada_lan_conf.h>
#include <ada/client_ota.h>
#include <ada/prop.h>
#include <ada/prop_mgr.h>
#include <ada/server_req.h>
#include "notify_int.h"
#include "client_int.h"
#include "client_lock.h"

#define CONFIG_JSON_PUT_TOKENS	40
#define CONFIG_TOK_LEN 10
#define CONFIG_NAME_LEN 100
#define CONFIG_VAL_LEN 100

/*
 * GET config.json
 */
void conf_json_get(struct server_req *req)
{
	struct ada_conf *cf = &ada_conf;
	char *name;
	char name_buf[CONFIG_NAME_LEN];
	char value[50];

	if (!req->admin) {
		server_put_status(req, HTTP_STATUS_NOT_FOUND);
		return;
	}

	name = server_get_arg_by_name(req, "name", name_buf, sizeof(name_buf));
	if (!name) {
		server_put_status(req, HTTP_STATUS_NOT_FOUND);
		return;
	}

	if (!strcmp(name, "sys/setup_mode")) {
		snprintf(value, sizeof(value), "%u", conf_setup_mode);
	} else if (!strcmp(name, "client/server/default")) {
		snprintf(value, sizeof(value), "%u", cf->conf_serv_override);
	} else {
		server_put_status(req, HTTP_STATUS_NOT_FOUND);
		return;
	}

	server_json_header(req);
	server_put(req, "{\"config\":{\"name\":\"%s\",\"val\":%s}}",
	    name, value);
}

/*
 * Iterator for config sub-object.
 */
static int conf_json_put_config(jsmn_parser *parser, jsmntok_t *obj, void *arg)
{
	char name[CONFIG_NAME_LEN];
	char val[CONFIG_VAL_LEN];
	struct ada_conf_ctx *ctx = arg;
	long lval;

	if (jsmn_get_string(parser, obj, "name", name, sizeof(name)) <= 0) {
		server_log(LOG_WARN "conf_json_put no name");
		return -1;
	}

	/*
	 * Get value as a string, which works even for integers.
	 */
	if (jsmn_get_string(parser, obj, "val", val, sizeof(val)) <= 0) {
		return -1;
	}

	/*
	 * Special case for timezone.  The service is giving us minutes east
	 * of UTC, but we use minutes west.
	 */
	if (!strcmp(name, "sys/timezone")) {
		if (jsmn_get_long(parser, obj, "val", &lval)) {
			return -1;
		}
		snprintf(val, sizeof(val), "%ld", -lval);
	}
	return ada_conf_set(ctx, name, val);
}

static void conf_json_put_close(struct server_req *req)
{
	struct ada_conf_ctx *ctx = req->prov_impl;

	ada_conf_close(ctx);
}

/*
 * PUT config.json
 */
static void conf_json_put_locked(struct server_req *req)
{
	jsmn_parser parser;
	jsmntok_t tokens[CONFIG_JSON_PUT_TOKENS];
	jsmntok_t *config;
	jsmnerr_t err;
	int dryrun;
	int rc;
	struct ada_conf_ctx *ctx = NULL;

	jsmn_init_parser(&parser, req->post_data, tokens, ARRAY_LEN(tokens));
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		server_log(LOG_WARN "conf_json_put jsmn err %d", err);
		goto inval;
	}
	config = jsmn_get_val(&parser, NULL, "config");
	if (!config) {
		server_log(LOG_WARN "conf_json_put no config array");
		goto inval;
	}
	ctx = ada_conf_dryrun_new();
	if (!ctx) {
		server_put_status(req, HTTP_STATUS_INTERNAL_ERR);
		return;
	}
	for (dryrun = 1; dryrun >= 0; dryrun--) {
		if (jsmn_array_iterate(&parser, config,
		    conf_json_put_config, ctx)) {
			server_log(LOG_WARN "conf_json_put failed");
			goto inval;
		}
		ada_conf_dryrun_off(ctx);
	}

	rc = ada_conf_commit(ctx);
	if (rc) {
		goto inval;
	}
	req->close_cb = conf_json_put_close;
	req->prov_impl = ctx;

	server_put_status(req, HTTP_STATUS_NO_CONTENT);
	return;

inval:
	ada_conf_abort(ctx);
	server_put_status(req, HTTP_STATUS_BAD_REQ);
}

void conf_json_put(struct server_req *req)
{
	client_lock();
	conf_json_put_locked(req);
	client_unlock();
}
