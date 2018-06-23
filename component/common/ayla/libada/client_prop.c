/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/http.h>
#include <ayla/xml.h>
#include <ayla/tlv.h>
#include <ayla/ayla_proto_mcu.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <ayla/clock.h>
#include <ayla/uri_code.h>
#include <ayla/nameval.h>
#include <ayla/parse.h>
#include <ayla/json.h>
#include <ayla/patch.h>
#include <ayla/random.h>
#include <ayla/timer.h>
#include <jsmn.h>

#include <net/net.h>
#include <net/net_crypto.h>
#include <ayla/jsmn_get.h>
#include <ada/prop.h>
#include <ada/server_req.h>
#include <net/stream.h>
#include <ada/ada_conf.h>
#include <ada/ada_lan_conf.h>
#include <ada/client.h>
#include <ada/prop_mgr.h>
#include "client_req.h"
#include <net/http_client.h>
#include <net/base64.h>
#include <ada/metric.h>
#include <ada/client_ota.h>
#include "notify_int.h"
#include "client_int.h"
#include "lan_int.h"

struct prop_recvd prop_recvd;		/* incoming property */

int client_prop_name(struct xml_state *sp, int argc, char **argv)
{
	struct prop_recvd *prop = &prop_recvd;

	if (argc == 1) {
		snprintf(prop->name, sizeof(prop->name) - 1, "%s",
		    argv[0]);
	}
	return 0;
}

int client_prop_val(struct xml_state *sp, int argc, char **argv)
{
	struct prop_recvd *prop = &prop_recvd;
	size_t len;
	size_t max_len;

	if (argc != 1) {
		return 0;
	}
	if (sizeof(prop->val) - 1 <= prop->offset) {
		return 0;
	}
	max_len = sizeof(prop->val) - 1 - prop->offset;

	len = strlen(argv[0]);
	if (len >= max_len) {
		len = max_len;
	}

	memcpy(prop->val + prop->offset, argv[0], len);
	((char *)prop->val)[prop->offset + len] = '\0';

	prop->offset += len;
	ASSERT(prop->offset < sizeof(prop->val));
	return 0;
}

const struct name_val prop_types[] = {
	{ .name = "boolean", .val = ATLV_BOOL },
	{ .name = "decimal", .val = ATLV_CENTS },
	{ .name = "integer", .val = ATLV_INT },
	{ .name = "numeric", .val = ATLV_INT },
	{ .name = "string", .val = ATLV_UTF8 },
	{ .name = "float", .val = ATLV_FLOAT },
	{ .name = "file", .val = ATLV_LOC },
	{ .name = "binary", .val = ATLV_BIN },
	{ .name = "schedule", .val = ATLV_SCHED },
	{ .name = NULL, .val = ATLV_INVALID }
};

static int client_prop_type(struct xml_state *sp, int argc, char **argv)
{
	struct prop_recvd *prop = &prop_recvd;

	if (argc == 1) {
		prop->type = lookup_by_name(prop_types, argv[0]);
	}
	return 0;
}

static int client_echo_prop_from_service(struct client_state *state)
{
	struct prop_recvd *prop = &prop_recvd;
	struct ada_lan_conf *lcf = &ada_lan_conf;

	if (!lcf->auto_echo) {
clear_prop:
		memset(prop, 0, sizeof(*prop));
		return 0;
	}

	state->echo_dest_mask = (state->valid_dest_mask & ~NODES_ADS);
	if (!state->echo_dest_mask) {
		/* echo not needed, only one valid dest */
		goto clear_prop;
	}
	state->echo_prop = prop;
	state->get_echo_inprog = 1;
	state->cont_recv_hc = &state->http_client;
	client_lan_cycle(state);

	return -1;
}

static int
client_accept_prop(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	struct prop_recvd *prop = &prop_recvd;
	enum ada_err rc;

	CLIENT_LOGF(LOG_DEBUG, "name=\"%s\" type=%s",
	    prop->name, lookup_by_val(prop_types, prop->type));
	log_bytes(MOD_LOG_CLIENT, LOG_SEV_DEBUG,
	    prop->val, strlen(prop->val), "val=");

	if (prop->type == ATLV_LOC && !strcmp(prop->val, "")) {
		goto clear_prop;
	}

	if (state->mcu_overflow) {
		CLIENT_LOGF(LOG_WARN, "%s dropped due to mcu overflow",
		    prop->name);
		goto clear_prop;
	}

	/* offset now is the point where prop.val needs to be sent from */
	prop->offset = 0;
	prop->arg = (void *)(state->request == CS_GET_VAL ||
	    state->request == CS_GET_ALL_VALS);
	prop->src = NODES_ADS;

	rc = client_prop_set(prop);
	if (rc == AE_BUF) {
		CLIENT_LOGF(LOG_DEBUG, "err_mem");
		return rc;	/* wait for prop_mgr to re-call */
	}
	if (rc != AE_OK || state->conn_state != CS_WAIT_GET) {
clear_prop:
		memset(prop, 0, sizeof(*prop));
		return 0;
	}
	return client_echo_prop_from_service(state);
}

static const struct xml_tag client_xml_prop_tags[] = {
	XML_TAG_WS("name", NULL, client_prop_name),
	XML_TAGF("value", XT_KEEP_WS | XT_GIVE_PARTIAL, NULL, client_prop_val),
	XML_TAG("base-type", NULL, client_prop_type),
	XML_TAG(NULL, NULL, NULL)
};

const struct xml_tag client_xml_prop[] = {
	XML_TAG("property", client_xml_prop_tags, client_accept_prop),
	XML_TAG("schedule", client_xml_prop_tags, client_accept_prop),
	XML_TAG(NULL, NULL, NULL)
};

enum ada_err client_prop_send_done(struct client_state *state, u8 success,
				void *arg, u8 dest, struct http_client *hc)
{
	struct prop_recvd *prop = &prop_recvd;
	enum ada_err (*prop_send_cb)(enum prop_cb_status, void *);
	enum ada_err rc = AE_OK;
	enum prop_cb_status status = PROP_CB_DONE;

	if (state->dest_mask && !(state->dest_mask & dest)) {
		return AE_OK;
	}
	prop_send_cb = state->prop_send_cb;
	state->dest_mask &= ~(dest);
	hc->prop_callback = 0;
	if (!prop_send_cb) {
		return AE_INVAL_VAL;
	}
	if (!success) {
		state->failed_dest_mask |= dest;
	}
	if (state->dest_mask) {
		return AE_OK;	/* still dests to send to */
	}
	state->prop_send_cb = NULL;
	if (state->unexp_op) {
		status = PROP_CB_UNEXP_OP;
		state->unexp_op = 0;
	} else if (state->mcu_overflow) {
		status = PROP_CB_OVERFLOW;
	} else if (state->failed_dest_mask) {
		status = PROP_CB_CONN_ERR;

		/*
		 * Indicate HTTP status 4xx as non-retriable.
		 */
		if (hc->hc_error == HC_ERR_HTTP_STATUS && (dest & NODES_ADS) &&
		    hc->http_state.status >= 400 && hc->http_status < 500) {
			status = PROP_CB_ADS_ERR;
		}
	}
	rc = prop_send_cb(status, arg);
	if (state->request == CS_GET_DP &&
	    rc == AE_IN_PROGRESS && status == PROP_CB_DONE) {
		/* more GETs needed to complete the dp fetch */
		/* don't clear out the wait_for_file_get and get_echo_inprog */
		return AE_OK;
	}
	if (rc != AE_OK) {
		state->prop_send_cb = prop_send_cb;
		state->dest_mask |= dest;
		if (status != PROP_CB_DONE) {
			rc = AE_OK; /* data_tlv will take care of the NAK */
		}
	}
	if (rc == AE_OK && (state->request == CS_GET_VAL ||
	    state->request == CS_GET_ALL_VALS ||
	    state->request == CS_GET_DP)) {
		state->get_echo_inprog = 0;
		if (state->request == CS_GET_DP) {
			state->wait_for_file_get = 0;
			prop->is_file = 0; /* prop_recvd can be overwritten */
		}
		client_lan_cycle(state);
	}
	return rc;
}

enum ada_err client_recv_prop_done(struct http_client *hc)
{
	struct client_state *state = &client_state;
	int success;

	if (hc->http_status == HTTP_STATUS_PAR_CONTENT) {
		state->partial_content = 1;
	}

	success = hc->http_status == HTTP_STATUS_OK ||
	    hc->http_status == HTTP_STATUS_PAR_CONTENT;
	client_prop_send_done(state, success, state->prop_send_cb_arg,
	    NODES_ADS, hc);
	client_tcp_recv_done(state);
	return AE_OK;
}

/*
 * Handle response for GET of a single property.
 */
enum ada_err client_recv_prop_val(struct http_client *hc, void *buf, size_t len)
{
	if (buf) {
		return client_recv_xml(hc, buf, len);
	}
	return client_recv_prop_done(hc);
}

/*
 * Get value of "name" from ADS. If name isn't given, get all props.
 */
enum ada_err client_get_prop_val(const char *name)
{
	struct client_state *state = &client_state;
	char uri[CLIENT_GET_REQ_LEN];
	struct http_client *hc;

	ASSERT(!state->http_lan);
	hc = client_req_ads_new();
	state->prop_send_cb_arg = hc;

	if (state->get_echo_inprog) {
		/*
		 * we're in the middle of doing ECHOs to LAN clients
		 * so the prop_recvd structure is being used. we need that
		 * structure to store prop information. So abort
		 * this operation for now and wait until we get called again.
		 */
		 return AE_BUSY;
	}
	if (!name || name[0] == '\0') {
		hc->client_tcp_recv_cb = client_recv_prop_cmds;
		state->request = CS_GET_ALL_VALS;
		snprintf(uri, sizeof(uri),
		    "/devices/%s/commands.xml?input=true",
		    state->client_key);

		xml_parse_init(&state->xml_state, client_xml_cmds);
	} else {
		hc->client_tcp_recv_cb = client_recv_prop_val;
		state->request = CS_GET_VAL;
		snprintf(uri, sizeof(uri),
		    "/devices/%s/properties/%s.xml",
		    state->client_key, name);

		xml_parse_init(&state->xml_state, client_xml_prop);
	}
	state->xml_init = 1;
	memset(&prop_recvd, 0, sizeof(prop_recvd));

	state->get_echo_inprog = 1;
	state->cmd.data = NULL;
	state->cmd.resource = NULL;

	client_req_start(hc, HTTP_REQ_GET, uri, NULL);
	return AE_OK;
}

/*
 * Send the prop thats current stored to the prop_mgr, then continue receiving
 * from http_client.
 */
static enum ada_err client_send_prop_continue(void *arg)
{
	struct client_state *state = (struct client_state *)arg;
	struct prop_recvd *prop = &prop_recvd;
	enum ada_err rc = AE_OK;

	if (state->mcu_overflow) {
		CLIENT_LOGF(LOG_WARN, "%s dropped due to mcu overflow",
		    prop->name);
		return rc;
	}

	if (prop->name[0] == '\0') {
		return AE_OK;
	}

	prop->arg = (void *)(state->request == CS_GET_VAL ||
	    state->request == CS_GET_ALL_VALS);
	prop->src = NODES_ADS;

	rc = client_prop_set(prop);

	if (rc == AE_BUF) {
		return rc;
	}

	client_log(LOG_DEBUG
	    "%s: name=\"%s\" val=\"%s\" type=%s",
	    __func__, prop->name, prop->val,
	    lookup_by_val(prop_types, prop->type));

	return client_echo_prop_from_service(state);
}

/*
 * Continue receiving from the http_client
 */
enum ada_err client_continue_recv(void *arg)
{
	struct client_state *state = &client_state;
	enum ada_err rc = AE_OK;

	switch (state->request) {
	case CS_GET_VAL:
	case CS_GET_ALL_VALS:
	case CS_GET_CMDS:
		rc = client_send_prop_continue(state);
		if (rc == AE_BUF) {
			return rc;
		}
		break;
	default:
		break;
	}
	if (state->cont_recv_hc) {
		http_client_continue_recv(state->cont_recv_hc);
	}
	return rc;
}

/*
 * Convert decimal input string to signed long.
 * String may or may not have digits after the decimal point.
 */
long client_prop_strtocents(const char *val, char **errptr)
{
	const char *cp = val;
	long cents = 0;
	int sign = 0;
	int dp = 0;
	char c;

	if (*cp == '-') {
		cp++;
		sign = 1;
	}
	for (cents = 0; *cp != '\0'; cp++) {
		c = *cp;
		if (c == '.') {
			dp = 1;
			continue;
		}
		if (c < '0' || c > '9') {
			break;		/* not a digit or decimal point */
		}
		c -= '0';
		if (dp) {
			switch (dp) {
			case 1:
				c *= 10;
				/* fall-through */
			case 2:
				cents += c;
				break;
			default: /* ignore more than 2 digits to right of dp */
				break;
			}
			dp++;
		} else {
			cents *= 10;
			cents += c * 100;
		}
	}
	*errptr = (char *)cp;
	return sign ? -cents : cents;
}

/*
 * client_prop_set()
 * Called by cloud client when receiving an update for a property.
 */
enum ada_err client_prop_set(struct prop_recvd *prop)
{
	char *errptr;
	long lval;
	unsigned long uval;
	const void *val_ptr;
	size_t val_len;
	unsigned char buf[PROP_VAL_LEN];
	size_t out_len;
	enum ayla_tlv_type type = prop->type;
	const char *name = prop->name;
	const char *val = prop->val;
	enum ada_err err;

	switch (type) {
	case ATLV_INT:
		lval = strtol(val, &errptr, 10);
		if (*errptr != '\0') {
			CLIENT_LOGF(LOG_WARN, "%s = \"%s\" bad int",
			    name, val);
			return AE_INVAL_VAL;
		}
		val_ptr = &lval;
		val_len = sizeof(lval);
		break;
	case ATLV_UINT:
		uval = strtoul(val, &errptr, 10);
		if (*errptr != '\0') {
			CLIENT_LOGF(LOG_WARN, "%s = \"%s\" bad uint",
			    name, val);
			return AE_INVAL_VAL;
		}
		val_ptr = &uval;
		val_len = sizeof(uval);
		break;
	case ATLV_BOOL:
		uval = strtoul(val, &errptr, 10);
		if (*errptr != '\0' || uval > 1) {
			CLIENT_LOGF(LOG_WARN, "%s = \"%s\" bad bool",
			    name, val);
			return AE_INVAL_VAL;
		}
		val_ptr = &uval;
		val_len = sizeof(uval);
		break;
	case ATLV_UTF8:
	case ATLV_LOC:
		val_ptr = val;
		val_len = strlen(val);
		break;
	case ATLV_CENTS:
		lval = client_prop_strtocents(val, &errptr);
		if (*errptr != '\0') {
			CLIENT_LOGF(LOG_WARN, "%s = \"%s\" bad decimal",
			    name, val);
			return AE_INVAL_VAL;
		}
		val_ptr = &lval;
		val_len = sizeof(lval);
		break;
	case ATLV_BIN:
	case ATLV_SCHED:
		out_len = sizeof(buf);
		if (net_base64_decode(val, strlen(val), buf, &out_len)) {
			CLIENT_LOGF(LOG_WARN, "bad decode");
			return AE_INVAL_VAL;
		}
		val_ptr = buf;
		val_len = out_len;
		break;
	case ATLV_NAME:
	default:
		CLIENT_LOGF(LOG_WARN, "name %s unhandled type %d", name, type);
		return AE_INVAL_VAL;
	}

	/*
	 * Copy binary value back to prop buffer.  It will fit.
	 * This will be needed in case of echos.
	 */
	if (val_ptr != prop->val) {
		ASSERT(val_len <= sizeof(prop->val));
		memcpy(prop->val, val_ptr, val_len);
		prop->prop.val = prop->val;
	}
	prop->prop.len = val_len;

	err = ada_prop_mgr_set(name, type, val_ptr, val_len,
	    &prop->offset, prop->src, prop->arg);
	if (err) {
		CLIENT_LOGF(LOG_WARN, "name %s err %d %s",
		    name, err, ada_err_string(err));
	}
	return err;
}

void client_prop_init(struct client_state *state)
{
	prop_mgr_init();
}
