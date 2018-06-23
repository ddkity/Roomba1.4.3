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
#include <ayla/base64.h>
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
#include <net/base64.h>
#include <net/net_crypto.h>
#include <ayla/wifi_error.h>
#include <ayla/wifi_status.h>
#include <ayla/jsmn_get.h>
#include <ayla/malloc.h>
#include <ada/prop.h>
#include <ada/server_req.h>
#include <net/stream.h>
#include <ada/ada_conf.h>
#include <ada/ada_lan_conf.h>
#include <ada/client.h>
#include "client_req.h"
#include <net/http_client.h>
#include <ayla/malloc.h>
#include <ada/metric.h>
#include <net/cm.h>
#include <ada/client_ota.h>
#include <ada/prop_mgr.h>
#include <ada/linker_text.h>
#include <ada/ada_wifi.h>
#include "notify_int.h"
#include "client_int.h"
#include "client_lock.h"
#include "client_timer.h"
#include "lan_int.h"
#include "ca_cert.h"
#ifndef AYLA_BC
#include "build.h"
#endif /* AYLA_BC */

/*
 * Flags for client info updates.
 */
#define CLIENT_UPDATE_MAJOR		(1 << 0)
#define CLIENT_UPDATE_MINOR		(1 << 1)
#define CLIENT_UPDATE_SWVER		(1 << 2)
#define CLIENT_UPDATE_LANIP		(1 << 3)
#define CLIENT_UPDATE_MODEL		(1 << 4)
#define CLIENT_UPDATE_SETUP		(1 << 5)
#define CLIENT_UPDATE_OEM		(1 << 6)
#define CLIENT_UPDATE_SSID		(1 << 7)
#define CLIENT_UPDATE_SETUP_LOCATION	(1 << 8)
#define CLIENT_UPDATE_PRODUCT_NAME	(1 << 9)
#define CLIENT_UPDATE_MAC		(1 << 10)
#define CLIENT_UPDATE_HW_ID		(1 << 11)
#define CLIENT_UPDATE_ALL	(CLIENT_UPDATE_MAJOR | CLIENT_UPDATE_MINOR | \
				CLIENT_UPDATE_SWVER | CLIENT_UPDATE_LANIP | \
				CLIENT_UPDATE_SSID | \
				CLIENT_UPDATE_MODEL | CLIENT_UPDATE_SETUP | \
				CLIENT_UPDATE_MAC | \
				CLIENT_UPDATE_SETUP_LOCATION)

#ifndef BUILD_SDK
#define BUILD_SDK "bc"
#endif

#ifdef BUILD_VERSION
const char ada_version_build[] = "ADA " ADA_VERSION BUILD_NAME " " BUILD_SDK
#ifdef SDK_VERSION
			"-" SDK_VERSION
#endif /* SDK_VERION */

			" " BUILD_DATE " " BUILD_TIME " "
#ifdef BUILD_ENV
			BUILD_ENV "/"
#endif /* BUILD_ENV */
			BUILD_VERSION;
#else
const char ada_version_build[] = "ADA-" BUILD_SDK " " ADA_VERSION BUILD_NAME;
#endif /* BUILD_VERSION */
const char ada_version[] = "ADA-" BUILD_SDK " " ADA_VERSION BUILD_NAME;

struct client_state client_state;

static void client_down_locked(void);
static void client_start(struct client_state *, struct http_client *);
static void client_commit_server(struct client_state *state);

static void client_send_next(struct http_client *, enum ada_err);
static void client_err_cb(struct http_client *);

static void client_get_ping(struct client_state *);
static void client_get_cmds(struct client_state *);
static int client_put_info(struct client_state *);

static int client_get_lanip_key(struct client_state *);
static int client_put_reg_window_start(struct client_state *);
static void client_cmd_put_rsp(struct client_state *, unsigned int status);
static void client_cmd_put(struct client_state *);
static void client_cmd_flush(struct server_req *, const char *);

enum client_cb_use {
	CCB_CONN_UPDATE,
	CCB_LANIP,
	CCB_GET_DEV_ID,
	CCB_COUNT		/* count of callbacks.  must be last */
};


#ifdef STATIC_WEB_CONTENT_IN_MEMORY

LINKER_TEXT_ARRAY_DECLARE(custom_css_txt);
LINKER_TEXT_SIZE_DECLARE(custom_css_txt);
LINKER_TEXT_ARRAY_DECLARE(regtoken_html_txt);
LINKER_TEXT_SIZE_DECLARE(regtoken_html_txt);
#endif

static const struct server_buf server_custom_css_buf =
	SERVER_BUF_INIT(custom_css_txt, "custom.css.txt", "text/css");

static const struct server_buf client_regtoken_html_buf =
	SERVER_BUF_INIT(regtoken_html_txt, "regtoken.html.txt",
	    "text/html; charset=UTF-8");

static struct net_callback client_cb[CCB_COUNT];

static void client_connectivity_update_cb(void *);
static void client_lanip_save(void *);
static void client_get_dev_id(void *);

struct client_cb_handler {
	void (*func)(void *);
};

/*
 * Initialization table for client callbacks in this file.
 */
static const struct client_cb_handler client_cb_handlers[] = {
	[CCB_CONN_UPDATE] = { .func = client_connectivity_update_cb },
	[CCB_LANIP] = { .func = client_lanip_save },
	[CCB_GET_DEV_ID] = { .func = client_get_dev_id },
};

/*
 * Client next step handlers.
 */
static int client_file_step(struct client_state *);
static int client_ping_step(struct client_state *);
static int client_cmd_put_step(struct client_state *);
static int client_cmd_step(struct client_state *);
static int client_put_cmd_sts(struct client_state *);
static int client_post_echo(struct client_state *);

u32 client_step_mask = ~(BIT(ADCP_REG_WINDOW_START));

static const struct client_step client_steps[ADCP_REQ_COUNT] = {
	[ADCP_PUT_FILE_PROP] = { .handler = client_file_step },
	[ADCP_GET_PING] = { .handler = client_ping_step },
	[ADCP_PUT_INFO] = { .handler = client_put_info },
	[ADCP_PUT_OTA_STATUS] = { .handler = client_put_ota_status },
	[ADCP_CMD_PUT] = { .handler = client_cmd_put_step },
	[ADCP_CMD_GET] = { .handler = client_cmd_step },
	[ADCP_POST_RESP] = { .handler = client_put_cmd_sts },
	[ADCP_LAN_REQ] = { .handler = client_get_lanip_key },
	[ADCP_REG_WINDOW_START] = { .handler = client_put_reg_window_start },
	[ADCP_LAN_CYCLE] = { .handler = client_lan_cycle },
	[ADCP_OTA_FETCH] = { .handler = client_ota_fetch_image },
	[ADCP_POST_ECHO] = { .handler = client_post_echo },
};

void client_log(const char *fmt, ...)
{
	ADA_VA_LIST args;

	ADA_VA_START(args, fmt);
	log_put_va(MOD_LOG_CLIENT, fmt, args);
	ADA_VA_END(args);
}

/*
 * Append HTTP URI arg to URI string in buffer.
 */
static void client_arg_add(char *uri, size_t uri_len, const char *fmt, ...)
	ADA_ATTRIB_FORMAT(3, 4);

static void client_arg_add(char *uri, size_t uri_len, const char *fmt, ...)
{
	ADA_VA_LIST args;
	size_t len;

	len = strlen(uri);
	if (len >= uri_len - 5) {	/* need room for at least "?x=y\0" */
		client_log(LOG_ERR
		    "arg_append: uri '%s' too long to append '%s'", uri, fmt);
#ifdef DEBUG /* don't crash release builds for this */
		ASSERT_NOTREACHED();
#endif /* DEBUG */
		return;
	}
	uri[len++] = (strchr(uri, '?') != NULL ? '&' : '?');
	ADA_VA_START(args, fmt);
	len += vsnprintf(uri + len, uri_len - 1 - len, fmt, args);
	uri[len] = '\0';
	ADA_VA_END(args);
}

/*
 * Maps server hostnames to region for both dev and OEM
 */
struct hostname_info {
	const char *region;		/* unique numeric region code */
	const char *domain;		/* region-specific domain name */
};

/*
 * Update this table to support new regions and server hostnames
 */
static const struct hostname_info server_region_table[] = {
	{ "US", "aylanetworks.com" },
	{ "CN", "ayla.com.cn" },
};
/* First hostname table entry is the default */
static const struct hostname_info *SERVER_HOSTINFO_DEFAULT =
	server_region_table;

/*
 * Register for callback when ADS reachability changes, or a new
 * connection attempt fails.
 * This callback is made inside the client thread, and must not block.
 * Multiple callbacks may be registered, and they'll all be called.
 * Callbacks may not be unregistered for now.
 */
void ada_client_event_register(void (*fn)(void *arg, enum ada_err), void *arg)
{
	struct client_state *state = &client_state;
	struct client_event_handler *hp;

	hp = calloc(1, sizeof(*hp));
	ASSERT(hp);
	client_lock();
	hp->arg = arg;
	hp->handler = fn;
	hp->next = state->event_head;
	state->event_head = hp;
	client_unlock();
}

/*
 * Send event (change in ADA connectivity status) with error code.
 * Handlers are called with the client_lock held, and must not block.
 */
static void client_event_send(enum ada_err err)
{
	struct client_state *state = &client_state;
	struct client_event_handler *hp;

	ASSERT(client_locked);
	for (hp = state->event_head; hp; hp = hp->next) {
		hp->handler(hp->arg, err);
	}
}

/*
 * Lookup an entry in the server_region_table by region code
 * Returns NULL if code is invalid.
 */
static const struct hostname_info *client_lookup_host(const char *region)
{
	int i;

	if (!region) {
		return NULL;
	}
	for (i = 0; i < ARRAY_LEN(server_region_table); ++i) {
		if (!strcasecmp(region, server_region_table[i].region)) {
			return server_region_table + i;
		}
	}
	return NULL;
}

/*
 * Update the connectivity status to the property managers.
 *
 * A callback is used to update the connectivity status so that the
 * lock can be safely dropped.  The prop_mgrs may call client functions
 * during the status update.
 */
static void client_connectivity_update_cb(void *arg)
{
	struct client_state *state = arg;

	state->current_request = NULL;
	client_unlock();
	prop_mgr_connect_sts(state->valid_dest_mask);
	client_lock();
}

void client_connectivity_update(void)
{
	struct client_state *state = &client_state;

	net_callback_enqueue(state->callback_queue[CQP_HIGH],
	    &client_cb[CCB_CONN_UPDATE]);
}

static int client_cmd_id(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	char *errptr;

	if (state->cmd_pending || state->ota.in_prog != COS_NONE) {
		return 0;
	}

	if (argc == 1) {
		state->cmd.id = (u32)strtoul(argv[0], &errptr, 10);
		if (*errptr != '\0') {
			client_log(LOG_ERR "bad cmd_id %s", argv[0]);
		}
	}
	return 0;
}

static int client_cmd_data(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	int len = 0;

	if (state->cmd_pending || state->ota.in_prog != COS_NONE) {
		return 0;
	}

	if (argc == 1) {
		if (state->cmd.resource) {
			len = strlen(state->cmd.resource);
			state->cmd.data = state->cmd.resource +
			    len + 1;
		} else {
			state->cmd.data = state->cmd.res_data;
		}
		snprintf(state->cmd.data, sizeof(state->cmd.res_data) -
		    len - 2, "%s", argv[0]);
	}
	return 0;
}

static int client_cmd_method(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (state->cmd_pending || state->ota.in_prog != COS_NONE) {
		return 0;
	}

	state->cmd.method[0] = '\0';
	if (argc == 1) {
		snprintf(state->cmd.method, sizeof(state->cmd.method) - 1,
		    "%s", argv[0]);
	}
	return 0;
}

static int client_cmd_resource(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	int len = 0;

	if (state->cmd_pending || state->ota.in_prog != COS_NONE) {
		return 0;
	}

	if (argc == 1) {
		if (state->cmd.data) {
			len = strlen(state->cmd.data);
			state->cmd.resource = state->cmd.data +
			    len + 1;
		} else {
			state->cmd.resource = state->cmd.res_data;
		}
		snprintf(state->cmd.resource, sizeof(state->cmd.res_data) -
		    len - 2, "/%s", argv[0]);
	}
	return 0;
}

static int client_cmd_uri(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (state->cmd_pending || state->ota.in_prog != COS_NONE) {
		return 0;
	}

	state->cmd.uri[0] = '\0';
	if (argc == 1) {
		snprintf(state->cmd.uri, sizeof(state->cmd.uri) - 1, "%s",
		    argv[0] + 1);
	}
	return 0;
}

/*
 * No-op finish_write() handler for a completion of OTA download.
 */
static enum ada_err client_cmd_finish_ota(struct server_req *req)
{
	return AE_OK;
}

static int client_accept_cmd(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	struct server_req *cmd_req = &state->cmd_req;
	char *resource = state->cmd.resource;
	const char *method = state->cmd.method;

	if (state->ota.in_prog != COS_NONE) {
		return 0; /* Later */
	}
	if (state->cmd_pending) {
		state->np_event = 1;
		return 0;	/* Only execute 1 cmd per get */
	}
	CLIENT_DEBUG(LOG_DEBUG,
	    "id=%lu method=%s resource=%s, uri=%s",
	    state->cmd.id, state->cmd.method, state->cmd.resource,
	    state->cmd.uri);
	CLIENT_DEBUG(LOG_DEBUG2, "data \"%s\"", state->cmd.data);
	/* XXX TBD handle OTA like other commands later */
	if (!strcmp(method, "PUT") && !strcmp(resource, "/ota.json")) {
		server_req_init(cmd_req);
		cmd_req->suppress_out = 1;
		cmd_req->post_data = state->cmd.data;

		cmd_req->put_head = client_cmd_put_head;
		cmd_req->write_cmd = client_cmd_flush;
		cmd_req->finish_write = client_cmd_finish_ota;

		client_ota_json_put(cmd_req);
		return 0;
	}
	state->cmd_pending = 1;

	return 0;
}

static int client_accept_dp_file(struct xml_state *sp, int argc, char **argv)
{
	struct prop_recvd *prop = &prop_recvd;

	if (argc == 1) {
		CLIENT_LOGF(LOG_DEBUG, "%s", argv[0]);
		/*
		 * store the s3 location in prop->val
		 */
		strncpy(prop->file_info.file, argv[0],
		    sizeof(prop->file_info.file) - 1);
		prop->is_file = 1;
	}
	return 0;
}

static int client_accept_dp_loc(struct xml_state *sp, int argc, char **argv)
{
	struct prop_recvd *prop = &prop_recvd;

	if (argc == 1) {
		CLIENT_LOGF(LOG_DEBUG, "%s", argv[0]);
		strncpy(prop->file_info.location, argv[0],
		    sizeof(prop->file_info.location) - 1);
	}
	return 0;
}

static int client_accept_dp(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	struct prop_recvd *prop = &prop_recvd;

	if (state->request == CS_GET_DP_LOC) {
		if (!prop->file_info.file[0]) {
			goto missing_info;
		}
		state->wait_for_file_get = 1;
		return 0;
	}
	if (!prop->file_info.location[0] || !prop->file_info.file[0]) {
missing_info:
		CLIENT_LOGF(LOG_WARN, "missing loc or file info");
		return AE_INVAL_VAL;
	}
	/*
	 * host mcu must immediately
	 * do a PUT after. client will not do any other operations
	 * until the host mcu does a PUT for the file property.
	 * If the host MCU tries to do any other op, a NAK will be
	 * returned (UNEXPECTED_OP).
	 */
	state->prop_send_cb_arg = prop->file_info.location;
	state->wait_for_file_put = 1;

	return 0;
}

static int client_parse_u32(u32 *vp, int argc, char **argv)
{
	unsigned long val;
	char *endptr;

	*vp = 0;
	if (argc == 1) {
		val = strtoul(argv[0], &endptr, 10);
		if (*endptr == '\0') {
			*vp = val;
			return 0;
		}
	}
	return -1;
}

static int client_parse_str(char *vp, size_t max_len, int argc, char **argv)
{
	size_t len;

	if (argc != 1) {
		return -1;
	}
	len = strlen(argv[0]);
	if (len > max_len - 1) {
		client_log(LOG_WARN "parse_str: len %zd is too long", len);
		vp[0] = '\0';
		return -1;
	}
	memcpy(vp, argv[0], len + 1);
	return 0;
}

static int client_api_major(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	u32 val;

	if (!client_parse_u32(&val, argc, argv) && val == CLIENT_API_MAJOR) {
		state->client_info_flags &= ~CLIENT_UPDATE_MAJOR;
	}
	return 0;
}

static int client_api_minor(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	u32 val;

	if (!client_parse_u32(&val, argc, argv) && val == CLIENT_API_MINOR) {
		state->client_info_flags &= ~CLIENT_UPDATE_MINOR;
	}
	return 0;
}

void client_clock_set(u32 new_time, enum clock_src src)
{
	u32 now;
	char buf[24];

	now = clock_utc();
	if (ABS(new_time - now) > CLIENT_TIME_FUDGE &&
	    !clock_set(new_time, src)) {
		clock_fmt(buf, sizeof(buf), now);
		client_log(LOG_INFO "clock was %s UTC", buf);
		clock_fmt(buf, sizeof(buf), new_time);
		client_log(LOG_INFO "clock now %s UTC", buf);
		prop_mgr_event(PME_TIME, NULL);
	}
}

static int client_set_time(struct xml_state *sp, int argc, char **argv)
{
	u32 val;

	if (!client_parse_u32(&val, argc, argv)) {
		client_clock_set(val, CS_SERVER);
	}
	return 0;
}

static int client_sw_version(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (argc == 1 && strcmp(argv[0], adap_conf_sw_build()) == 0) {
		state->client_info_flags &= ~CLIENT_UPDATE_SWVER;
	}

	return 0;
}

static int client_lan_enabled(struct xml_state *sp, int argc, char **argv)
{
	struct ada_lan_conf *lcf = &ada_lan_conf;

	lcf->enable = 0;
	if (argc == 1 && !strcmp(argv[0], "true")) {
		lcf->enable = 1;
	}
	return 0;
}

static int client_setup_location(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (state->setup_location == NULL) {
		state->client_info_flags &= ~CLIENT_UPDATE_SETUP_LOCATION;
	} else if (argc == 1 && !strcmp(argv[0], state->setup_location)) {
		state->client_info_flags &= ~CLIENT_UPDATE_SETUP_LOCATION;
	}

	return 0;
}

static int client_reg_flag(struct xml_state *sp, int argc, char **argv)
{
	struct ada_conf *cf = &ada_conf;
	u32 flag = 0;
	u8 reg_user;

	if (client_parse_u32(&flag, argc, argv)) {
		return 0;
	}
	reg_user = flag != 0;
	if (cf->reg_user ^ reg_user) {
		cf->reg_user = reg_user;
		client_conf_reg_persist();
		cf->event_mask &= ~(CLIENT_EVENT_UNREG | CLIENT_EVENT_REG);
		cf->event_mask |=
		    (reg_user ? CLIENT_EVENT_REG : CLIENT_EVENT_UNREG);
		adap_conf_reg_changed();
	}
	return 0;
}

static int client_reg_type(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	client_parse_str(state->reg_type, sizeof(state->reg_type) - 1,
	    argc, argv);
	return 0;
}

static int client_reg_token(struct xml_state *sp, int argc, char **argv)
{
	struct ada_conf *cf = &ada_conf;

	client_parse_str(cf->reg_token, sizeof(cf->reg_token) - 1, argc, argv);
	return 0;
}

static int client_lan_ip(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	ip_addr_t addr;

	if (argc != 1) {
		return 0;
	}
	if (ipaddr_aton(argv[0], &addr) &&
	    addr.addr == http_client_local_ip(&state->http_client)) {
		state->client_info_flags &= ~CLIENT_UPDATE_LANIP;
	}
	return 0;
}

static int client_model(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (argc != 1) {
		return 0;
	}
	if (!strcmp(argv[0], conf_sys_model)) {
		state->client_info_flags &= ~CLIENT_UPDATE_MODEL;
	}
	return 0;
}

static int client_oem(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (argc != 1 || strcmp(argv[0], oem)) {
		state->client_info_flags |= CLIENT_UPDATE_OEM;
	}
	return 0;
}

static int client_oem_model(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (argc != 1 || strcmp(argv[0], oem_model)) {
		state->client_info_flags |= CLIENT_UPDATE_OEM;
	}
	return 0;
}

/*
 * Get URI-encoded SSID, or empty string if none, into buffer.
 */
static void client_get_ssid_uri(char *buf, size_t len)
{
	char ssid[32];
	int slen;

	slen = adap_wifi_get_ssid(ssid, sizeof(ssid));
	*buf = '\0';
	if (slen > 0) {
		uri_encode(buf, len, ssid, slen, uri_arg_allowed_map);
	}
}

static int client_ssid(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	char ssid_uri[SSID_URI_LEN];

	if (argc != 1) {
		return 0;
	}
	client_get_ssid_uri(ssid_uri, sizeof(ssid_uri));
	if (!strcmp(argv[0], ssid_uri)) {
		state->client_info_flags &= ~CLIENT_UPDATE_SSID;
	}

	return 0;
}

static int client_recv_mac_addr(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	struct ada_conf *cf = &ada_conf;
	u8 mac[6];

	if (argc == 1 && !parse_mac(mac, argv[0]) &&
	    !memcmp(mac, cf->mac_addr, sizeof(mac))) {
		state->client_info_flags &= ~CLIENT_UPDATE_MAC;
	}
	return 0;
}

static int client_recv_hw_id(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	struct ada_conf *cf = &ada_conf;

	/* update if cloud has the value OR it is different */
	if (argc != 1 || strcmp(argv[0], cf->hw_id)) {
		state->client_info_flags |= CLIENT_UPDATE_HW_ID;
	}
	return 0;
}

static void client_listen_warn(struct timer *arg)
{
	struct client_state *state = &client_state;

	if ((state->valid_dest_mask & NODES_ADS) && !state->ads_listen) {
		client_log(LOG_WARN "listen not enabled");
	}
}

static int
client_accept_id(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	struct ada_conf *cf = &ada_conf;
	struct prop_recvd *prop = &prop_recvd;

	client_log(LOG_INFO "module name \"%s\" key %s.",
	    prop->name, prop->val);
	strncpy(state->client_key, prop->val, CLIENT_KEY_LEN - 1);
	if ((state->client_info_flags & CLIENT_UPDATE_PRODUCT_NAME) == 0) {
		strncpy(cf->host_symname, prop->name,
		    sizeof(cf->host_symname) - 1);
	}
	client_timer_set(&state->listen_timer, CLIENT_LISTEN_WARN_WAIT);

	return 0;
}

static int client_log_host(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (argc == 1) {
		snprintf(state->log_server.host,
		    sizeof(state->log_server.host) - 1, "%s", argv[0]);
	}
	return 0;
}

static int client_log_uri(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (argc == 1) {
		snprintf(state->log_server.uri,
		    sizeof(state->log_server.uri) - 1, "%s", argv[0]);
	}
	return 0;
}

static int client_log_protocol(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (argc == 1) {
		snprintf(state->log_server.protocol,
		    sizeof(state->log_server.protocol) - 1, "%s", argv[0]);
	}
	return 0;
}

static int
client_setup_logc(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;

	if (state->log_server.host[0] != '\0') {
		client_log(LOG_INFO "log_server: \"%s\" uri \"%s\" "
		    "protocol \"%s\"", state->log_server.host,
		    state->log_server.uri, state->log_server.protocol);
	}

	log_client_set(state->log_server.host, state->log_server.uri,
	    state->log_server.protocol);

	return 0;
}

/*
 * Allow log client enable/disable through reverse-rest
 */
void client_log_client_json_put(struct server_req *req)
{
	struct client_state *state = &client_state;
	jsmn_parser parser;
	jsmntok_t tokens[LOGCLIENT_JSON_PUT];
	jsmnerr_t err;
	long enable;
	char hostname[50];
	char uri[25];
	char protocol[8];
	const char logc_str[] = "log-client";
	const char abled[] = "abled";

	client_lock();
	jsmn_init_parser(&parser, req->post_data, tokens, LOGCLIENT_JSON_PUT);
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		server_log(LOG_WARN "%s jsmn err %d", __func__, err);
		goto inval;
	}
	if (jsmn_get_long(&parser, NULL, "enabled", &enable)) {
		goto inval;
	}
	if (!enable) {
		server_log(LOG_INFO "%s dis%s", logc_str, abled);
		log_client_enable(0);
		goto no_content;
	}
	if (jsmn_get_string(&parser, NULL, "host", hostname,
	    sizeof(hostname)) <= 0) {
		server_log(LOG_WARN "%s no host", __func__);
		goto inval;
	}
	if (jsmn_get_string(&parser, NULL, "uri", uri,
	    sizeof(uri)) <= 0) {
		server_log(LOG_WARN "%s no uri", __func__);
		goto inval;
	}
	if (jsmn_get_string(&parser, NULL, "protocol", protocol,
	    sizeof(protocol)) <= 0) {
		server_log(LOG_WARN "%s no protocol", __func__);
		goto inval;
	}
	strncpy(state->log_server.host, hostname,
	    sizeof(state->log_server.host) - 1);
	strncpy(state->log_server.uri, uri,
	    sizeof(state->log_server.uri) - 1);
	strncpy(state->log_server.protocol, protocol,
	    sizeof(state->log_server.protocol) - 1);
	log_client_set(state->log_server.host, state->log_server.uri,
	    state->log_server.protocol);
	log_client_enable(1);		/* TBD to persist? */
	server_log(LOG_INFO "%s en%s", logc_str, abled);
no_content:
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
	client_unlock();
	return;

inval:
	server_put_status(req, HTTP_STATUS_BAD_REQ);
	client_unlock();
}

static int client_ans_server(struct xml_state *sp, int argc, char **argv)
{
	if (argc != 1) {
		return 0;
	}
	np_set_server(argv[0]);

	return 0;
}

static int client_ans_cipher_key(struct xml_state *sp, int argc, char **argv)
{
	struct client_state *state = &client_state;
	size_t len;
	unsigned char buf[100];

	if (argc != 1) {
		return 0;
	}
	state->np_cipher_key_len = 0;
	len = sizeof(buf);
	if (net_base64_decode(*argv, strlen(*argv), buf, &len)) {
		CLIENT_LOGF(LOG_WARN, "decode failed");
		return 0;
	}
	if (len > NP_KEY_LEN) {
		len = NP_KEY_LEN;
	}
	memcpy(state->np_cipher_key, buf, len);
	state->np_cipher_key_len = len;

	return 0;
}

static const struct xml_tag client_xml_cmd_tags[] = {
	XML_TAG("id", NULL, client_cmd_id),
	XML_TAGF("data", XT_KEEP_WS, NULL, client_cmd_data),
	XML_TAG("method", NULL, client_cmd_method),
	XML_TAG("resource", NULL, client_cmd_resource),
	XML_TAG("uri", NULL, client_cmd_uri),
	XML_TAG(NULL, NULL, NULL)
};

static const struct xml_tag client_xml_cmd[] = {
	XML_TAG("cmd", client_xml_cmd_tags, client_accept_cmd),
	XML_TAG(NULL, NULL, NULL)
};

static const struct xml_tag client_xml_dp_loc[] = {
	XML_TAG("location", NULL, client_accept_dp_loc),
	XML_TAG("file", NULL, client_accept_dp_file),
	XML_TAG(NULL, NULL, NULL)
};

static const struct xml_tag client_xml_props_cmds[] = {
	XML_TAG("properties", client_xml_prop, NULL),
	XML_TAG("cmds", client_xml_cmd, NULL),
	XML_TAG("schedules", client_xml_prop, NULL),
	XML_TAG(NULL, NULL, NULL)
};

const struct xml_tag client_xml_cmds[] = {
	XML_TAG("commands", client_xml_props_cmds, NULL),
	XML_TAG("datapoint", client_xml_dp_loc, client_accept_dp),
	XML_TAG(NULL, NULL, NULL)
};

static const struct xml_tag client_xml_log_server_props[] = {
	XML_TAG("host", NULL, client_log_host),
	XML_TAG("uri", NULL, client_log_uri),
	XML_TAG("protocol", NULL, client_log_protocol),
	XML_TAG(NULL, NULL, NULL)
};

static const struct xml_tag client_xml_dev_props[] = {
	XML_TAG_WS("product-name", NULL, client_prop_name),
	XML_TAG("ans-cipher-key", NULL, client_ans_cipher_key),
	XML_TAG("api-major", NULL, client_api_major),
	XML_TAG("api-minor", NULL, client_api_minor),
	XML_TAG("ans-server", NULL, client_ans_server),
	XML_TAG("hwsig", NULL, client_recv_hw_id),
	XML_TAG_WS("sw-version", NULL, client_sw_version),
	XML_TAG("lan-ip", NULL, client_lan_ip),
	XML_TAG("mac", NULL, client_recv_mac_addr),
	XML_TAG("model", NULL, client_model),
	XML_TAG("oem", NULL, client_oem),
	XML_TAG("oem-model", NULL, client_oem_model),
	XML_TAG("key", NULL, client_prop_val),
	XML_TAG("registered", NULL, client_reg_flag),
	XML_TAG("registration-type", NULL, client_reg_type),
	XML_TAG("regtoken", NULL, client_reg_token),
	XML_TAG("ssid", NULL, client_ssid),
	XML_TAG("unix-time", NULL, client_set_time),
	XML_TAG("log-server", client_xml_log_server_props, client_setup_logc),
	XML_TAG("lan-enabled", NULL, client_lan_enabled),
	XML_TAG("setup-location", NULL, client_setup_location),
	XML_TAG(NULL, NULL, NULL)
};

static const struct xml_tag client_xml_id[] = {
	XML_TAG("device", client_xml_dev_props, client_accept_id),
	XML_TAG(NULL, NULL, NULL)
};

/*
 * Returns a mask of the failed destinations
 */
u8 client_get_failed_dests(void)
{
	struct client_state *state = &client_state;

	return state->failed_dest_mask;
}

/*
 * Close http_client request and make sure we're not called back.
 */
static void client_close(struct client_state *state)
{
	struct http_client *hc = &state->http_client;

	client_timer_cancel(&state->req_timer);
	http_client_abort(hc);
	state->request = CS_IDLE;
}

static void client_retry(struct client_state *state)
{
	struct http_client *hc = &state->http_client;

	client_close(state);
	state->conn_state = CS_WAIT_RETRY;

	if (state->retries < 1) {
		client_wait(state, CLIENT_RETRY_WAIT1);
	} else if (state->retries < CLIENT_TRY_THRESH) {
		http_client_set_retry_limit(hc, 2);
		client_wait(state, CLIENT_RETRY_WAIT2);
	} else {
		http_client_set_retry_limit(hc, 1);
		client_wait(state, CLIENT_RETRY_WAIT3);
	}
	if (state->retries < 255) {
		state->retries++;
	}
}

/*
 * Enable the log_client if the host has been given
 * and its not already enabled.
 */
static void client_logging(int enable)
{
	struct client_state *state = &client_state;

	if (state->log_server.host[0] == '\0') {
		return;
	}

	if (log_client_enable(enable)) {
		return;
	}

	if (enable) {
		client_log(LOG_INFO "enabling log client");
	} else {
		client_log(LOG_INFO "disabling log client");
	}
}

/*
 * Return start of host portion of URL string.
 */
static const char *client_url_host_start(const char *url)
{
	const char *host_start;

	host_start = strstr(url, "://");
	if (!host_start) {
		return NULL;
	}
	host_start += 3;	/* add 3 to get past the :// */
	return host_start;
}

/*
 * Return resource portion of URL string.
 */
static const char *client_url_resource(const char *url)
{
	const char *res;

	res = client_url_host_start(url);
	if (res) {
		res = strchr(res, '/');
	}
	return res;
}

/*
 * Set the server to whats used for file properties (i.e. S3)
 */
static int client_set_file_prop_server(struct client_state *state)
{
	struct prop_recvd *prop = &prop_recvd;
	struct http_client *hc = &state->http_client;
	const char *host_start;
	const char *host_end;
	int len;

	if (!prop->is_file) {
		return -1;
	}
	/* extract the hostname from the FILE url */
	host_start = client_url_host_start(prop->file_info.file);
	host_end = client_url_resource(prop->file_info.file);

	if (!host_start || !host_end || host_end == host_start) {
		client_log(LOG_ERR "no host found in %s", prop->file_info.file);
		return -1;
	}
	len = host_end - host_start;
	if (len > sizeof(hc->host) - 1) {
		len = sizeof(hc->host) - 1;
	}
	strncpy(hc->host, host_start, len);
	hc->host[len] = '\0';

	if (!strncmp(prop->file_info.file, "https", 5)) {
		hc->ssl_enable = 1;
	} else {
		hc->ssl_enable = 0;
	}
	hc->accept_non_ayla = 1;	/* file properties can talk to S3 */
	hc->client_auth = 0;

	return 0;
}

/*
 * Determine if the ADS client is allow to do a GET operation
 */
static int client_can_get(struct client_state *state)
{
	struct prop_recvd *prop = &prop_recvd;

	return !state->lan_cmd_pending &&
	    !state->get_echo_inprog && !state->cmd_rsp_pending &&
/* XXX  get_echo_inprog gets stuck on somehow -- XXXX */
	    state->ads_listen && !state->http_client.prop_callback &&
	    !prop->is_file;
}

/*
 * Check if we're done with echoes.
 * If we were doing a GET from ADS, continue.
 */
void client_finish_echo(struct client_state *state, u8 finished_id)
{
	if (!state->get_echo_inprog) {
		return;
	}
	state->echo_dest_mask &= ~(finished_id);
	if (!state->echo_dest_mask) {
		if (state->conn_state == CS_WAIT_GET) {
			memset(&prop_recvd, 0, sizeof(prop_recvd));
			client_continue_recv(state);
		} else {
			state->get_echo_inprog = 0;
			client_wakeup();
		}
	}
}

static void client_notify_stop(struct client_state *state)
{
	np_stop();
	state->np_up = 0;
	state->np_started = 0;
}

/*
 * TCP timeout for handling ADS polling
 */
static void client_poll(struct timer *timer)
{
	struct client_state *state = &client_state;

	state->np_event = 1;

	/*
	 * try to re-connect to the ANS server. if the server name has changed
	 * ANS will change a "change event" request causing us to do a GET dsn
	 */
	client_notify_stop(state);
	np_retry_server();
	client_wakeup();
}

static void client_start_polling(struct client_state *state)
{
	struct ada_conf *cf = &ada_conf;
	u32 delay = cf->poll_interval * 1000;

	if (!timer_active(&state->poll_timer) && delay) {
		client_log(LOG_DEBUG2 "wait: poll %lu", delay);
		client_timer_set(&state->poll_timer, delay);
	}
}

/*
 * Receive for PUT or POST that does not expect data.
 */
static enum ada_err client_recv_drop(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;

	if (buf) {
		hc->recv_consumed += len;
	} else {
		client_tcp_recv_done(state);
	}
	return AE_OK;
}

/*
 * Start HTTP request.
 * This shares the same HTTP client between ADS and AIS.
 * This must be called before starting the http_client request.
 */
struct http_client *client_req_new(enum client_connect_target tgt)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;

	ASSERT(client_locked);
	if ((hc->state != HCS_IDLE && hc->state != HCS_KEEP_OPEN) ||
	    state->tgt != tgt) {
		client_close(state);
	}
	if (state->tgt != tgt) {
		switch (tgt) {
		case CCT_IMAGE_SERVER:
		case CCT_LAN:
		case CCT_REMOTE:
			client_ota_server(state);
			break;
		case CCT_FILE_PROP_SERVER:
			client_set_file_prop_server(state);
			break;
		case CCT_ADS:
		case CCT_ADS_HTTP:
		default:
			client_commit_server(state);
			if (tgt == CCT_ADS_HTTP) {
				hc->client_auth = 0;
				hc->ssl_enable = 0;
				hc->host_port = HTTP_CLIENT_SERVER_PORT;
			}
			if (!CLIENT_HAS_KEY(state)) {
				log_client_reset();
			}
			break;
		}
		state->tgt = tgt;
	}

	state->conn_state = CS_WAIT_CONN;
	state->xml_init = 0;

	hc->sending_chunked = 0;
	hc->prop_callback = 0;
	hc->user_in_prog = 0;
	hc->content_len = 0;
	hc->body_len = 0;
	hc->sent_len = 0;
	hc->body_buf_len = 0;

	hc->client_tcp_recv_cb = client_recv_drop;
	hc->client_err_cb = client_err_cb;
	hc->client_send_data_cb = NULL;
	state->cont_recv_hc = hc;

	hc->req_len = 0;
	hc->req_part = 0;

	return hc;
}

struct http_client *client_req_ads_new(void)
{
	return client_req_new(CCT_ADS);
}

static struct http_client *client_req_file_new(void)
{
	return client_req_new(CCT_FILE_PROP_SERVER);
}

/*
 * Start HTTP request.
 * Called with lock held.  Drops lock momentarily.
 */
void client_req_start(struct http_client *hc, enum http_method method,
		const char *resource, const struct http_hdr *header)
{
	struct client_state *state = &client_state;
	const char *method_str;
	char req[CLIENT_GET_REQ_LEN];	 /* request without args */
	char buf[HTTP_MAX_TEXT];
	size_t len;
	char *cp;
	int auth_len;
	char pub_key[CLIENT_CONF_PUB_KEY_LEN];
	int pub_key_len;
	struct http_hdr hdrs[2];
	int hcnt = 0;

	ASSERT(client_locked);
	switch (method) {
	case HTTP_REQ_GET:
		method_str = "GET";
		break;
	case HTTP_REQ_PUT:
		method_str = "PUT";
		break;
	case HTTP_REQ_POST:
		method_str = "POST";
		break;
	default:
		ASSERT_NOTREACHED();
	}

	client_log(LOG_DEBUG "req_start %s %s", method_str, resource);

	if (header) {
		hdrs[hcnt++] = *header;		/* struct copy */
	}

	if (hc->client_auth) {
		/*
		 * If we have the auth key, use it.  Otherwise present the
		 * client auth field which should yield the auth key.
		 * If the key doesn't work, we'll clear it out and retry.
		 */
		if (hc->auth_hdr[0] != '\0') {
			hdrs[hcnt].name = HTTP_CLIENT_KEY_FIELD;
			hdrs[hcnt++].val = hc->auth_hdr;
		} else {
			/*
			 * The pseudo-header for authentication does not
			 * include the args, unfortunately.  Form psuedo header.
			 */
			snprintf(req, sizeof(req), "%s %s?",
			    method_str, resource);
			cp = strchr(req, '?');
			ASSERT(cp);		/* should find final '?' */
			if (cp) {
				*cp = '\0';
			}

			len = snprintf(buf, sizeof(buf), "%s ",
			    HTTP_CLIENT_AUTH_VER);

			pub_key_len = adap_conf_pub_key_get(pub_key,
			    sizeof(pub_key));
			if (pub_key_len <= 0) {
				goto no_auth;
			}
			auth_len = client_auth_gen(pub_key, pub_key_len,
			    buf + len, sizeof(buf) - len, req);
			if (auth_len <= 0) {
				goto no_auth;
			}
			hdrs[hcnt].name = HTTP_CLIENT_INIT_AUTH_HDR;
			hdrs[hcnt++].val = buf;
		}
	}
	client_unlock();
	http_client_req(hc, method, resource, hcnt, hdrs);
	client_lock();
	return;

no_auth:
	client_log(LOG_ERR "pub_key failure");
	state->conn_state = CS_ERR;
	ASSERT(client_locked);
}

/*
 * Handle response from a file datapoint request.
 */
static enum ada_err client_recv_dp(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;
	struct recv_payload recv_payload;
	enum ada_err err = AE_OK;

	if (buf) {
		state->auth_fails = 0;
		if (state->mcu_overflow) {
			CLIENT_LOGF(LOG_WARN, "GET_DP drop: mcu ovrflow");
			return err;
		}
		if (!len) {
			client_wait(state, CLIENT_PROP_WAIT);
			return err;
		}
		if (!state->prop_send_cb) {
			return AE_INVAL_STATE;
		}
		recv_payload.data = buf;
		recv_payload.len = len;
		recv_payload.consumed = 0;
		err = state->prop_send_cb(PROP_CB_CONTINUE, &recv_payload);
		client_wait(state, CLIENT_PROP_WAIT);
		hc->recv_consumed = recv_payload.consumed;
		return AE_OK;
	}
	return client_recv_prop_done(hc);
}

/*
 * Start a GET or POST command through a property-subsystem callback.
 */
static void client_prop_cmd_send(struct client_state *state)
{
	state->http_lan = NULL;
	state->conn_state = CS_WAIT_PROP;
	state->prop_send_cb(PROP_CB_BEGIN, NULL);
}

#ifdef CLIENT_STEP_SET_EN	/* make array non-constant if enabling this */
/*
 * Set up for a "next_step" callback at a given priority.
 */
void client_step_set(enum client_req_pri pri, int (*fn)(struct client_state *))
{
	struct client_step *step;
	int (*pending)(struct client_state *);

	ASSERT(pri < ARRAY_LEN(client_steps));
	step = &client_steps[pri];
	pending = step->handler;
	ASSERT(!pending || pending == fn);
	step->handler = fn;
}
#endif /* CLIENT_STEP_SET_EN */

/*
 * Call the all handlers in priority order until one returns 0 (success).
 */
static int client_req_next(struct client_state *state)
{
	int (*handler)(struct client_state *);
	const struct client_step *tp;
	u32 mask;
	u32 enabled_steps;

	/*
	 * If the device ID is not set, or there's been an error,
	 * restrict to those steps not always needing ADS connectivity.
	 */
	enabled_steps = client_step_mask;
	if (!CLIENT_HAS_KEY(state) ||
	    (state->conn_state == CS_ERR || state->conn_state == CS_DOWN)) {
		enabled_steps &= ADCP_STEPS_WITH_NO_ADS;
		if (state->conn_state == CS_DOWN) {
			enabled_steps &= ~BIT(ADCP_GET_PING);
		}
	}

	for (tp = client_steps, mask = 1;
	     tp < &client_steps[ARRAY_LEN(client_steps)];
	     tp++, mask <<= 1) {
		if (enabled_steps & mask) {
			handler = tp->handler;
			if (!handler) {
				continue;
			}
			if (handler && !handler(state)) {
				return 0;
			}
		}
	}
	return -1;
}

static int client_file_step(struct client_state *state)
{
	if (state->prop_send_cb == prop_dp_put ||
	    state->prop_send_cb == prop_dp_req) {
		client_prop_cmd_send(state);
		return 0;
	}
	return -1;
}

static int client_ping_step(struct client_state *state)
{
	if (!state->serv_conn && (CLIENT_HAS_KEY(state) || state->ping_time)) {
		client_get_ping(state);
		return 0;
	}
	return -1;
}

static int client_cmd_put_step(struct client_state *state)
{
	if (state->cmd_pending && !state->cmd_rsp_pending) {
		client_cmd_put(state);
		return 0;
	}
	return -1;
}

static int client_cmd_step(struct client_state *state)
{
	int can_get;

	can_get = client_can_get(state) && state->np_event;

	if (state->prefer_get && can_get) {
		client_get_cmds(state);
		return 0;
	}
	if (state->prop_send_cb && (state->dest_mask & NODES_ADS)) {
		client_prop_cmd_send(state);
		return 0;
	}
	if (can_get) {
		client_get_cmds(state);
		return 0;
	}
	return -1;
}

/*
 * TCP callback for next client step
 */
static void client_next_step(void *arg)
{
	struct client_state *state = &client_state;
	struct net_callback_queue **cbqp;
	struct net_callback *cb;

repeat:
	ASSERT(client_locked);

	switch (state->conn_state) {
	/*
	 * The following states are handled as general ADS or LAN next steps.
	 */
	case CS_WAIT_EVENT:
	case CS_ERR:
	case CS_DOWN:
		break;
	/*
	 * No new requests can be generated in the following states.
	 */
	case CS_DISABLED:
	case CS_WAIT_PROP:
	case CS_WAIT_PROP_RESP:
		return;

	/*
	 * All other states are LAN-only.
	 */
	default:
		client_lan_cycle(state);
		return;
	}

	if (!http_client_is_ready(&state->http_client)) {
		client_lan_cycle(state);
		return;
	}

	/*
	 * If we already have a current callback that's incomplete, recall it.
	 * We don't clear the pending flag to avoid missing new events.
	 */
	cb = state->current_request;
	if (cb) {
		cb->func(cb->arg);
		return;
	}

	/*
	 * Call first callback in the queue.
	 * This will start a request, so return until next callback.
	 */
	for (cbqp = state->callback_queue;
	    cbqp < &state->callback_queue[CQP_COUNT]; cbqp++) {
		cb = net_callback_dequeue(*cbqp);
		if (cb) {
			state->current_request = cb;
			ASSERT(cb->pending);
			cb->pending = 0;
			cb->func(cb->arg);
			goto repeat;	/* for synchronous client */
		}
	}

	if (!client_req_next(state)) {
		goto repeat;		/* for synchronous client */
	}

	/*
	 * Nothing to do but wait.
	 */
	if (!state->np_up && state->conn_state == CS_WAIT_EVENT) {
		state->poll_ads = 1;
		client_start_polling(state);
	} else {
		state->poll_ads = 0;
		client_timer_cancel(&state->poll_timer);
	}
}

/*
 * Wakeup client to evaluate state.
 * Called with lock held.
 */
void client_wakeup(void)
{
	struct client_state *state = &client_state;

	ASSERT(client_locked);
	client_callback_pend(&state->next_step_cb);
}

/*
 * Callback from when HTTP client is done with all requests.
 * Done with current receive.  Decide whether to reconnect or wait.
 * May be called from any thread.
 */
static void client_next_step_cb(struct http_client *hc)
{
	client_wakeup();
}

static void client_lanip_save(void *arg)
{
	ada_conf_lanip_save();
	client_log(LOG_DEBUG "lanip saved");
}

/*
 * Parse the lanip information (key, key_id, keep_alive)
 */
static int client_lanip_json_parse(char *json_str)
{
	struct ada_lan_conf *lcf = &ada_lan_conf;
	jsmn_parser parser;
	jsmntok_t tokens[CLIENT_LANIP_JSON];
	jsmntok_t *lanip;
	jsmnerr_t err;
	char status[10];
	unsigned long tmp_key_id;
	unsigned long tmp_keep_alive;
	unsigned long tmp_auto_sync;
	char tmp_key[CLIENT_LANIP_KEY_SIZE + 1];

	jsmn_init_parser(&parser, json_str, tokens, CLIENT_LANIP_JSON);
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		CLIENT_LOGF(LOG_WARN, "jsmn err %d", err);
		return -1;
	}
	lanip = jsmn_get_val(&parser, NULL, "lanip");
	if (!lanip) {
		CLIENT_LOGF(LOG_WARN, "no lanip");
		return -1;
	}
	if (jsmn_get_string(&parser, lanip, "status",
	    status, sizeof(status)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad status");
		return -1;
	}
	if (strcmp(status, "enable")) {
		client_log(LOG_DEBUG "lan mode disabled");
		lcf->enable = 0;
		goto save;
	}
	if (jsmn_get_ulong(&parser, lanip, "lanip_key_id",
	    &tmp_key_id) || tmp_key_id > MAX_U16) {
		CLIENT_LOGF(LOG_WARN, "bad lanip_key_id");
		return -1;
	}
	if (jsmn_get_string(&parser, lanip, "lanip_key",
	    tmp_key, sizeof(tmp_key)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad lanip_key");
		return -1;
	}
	if (jsmn_get_ulong(&parser, lanip, "keep_alive",
	    &tmp_keep_alive) || tmp_keep_alive > MAX_U16) {
		CLIENT_LOGF(LOG_WARN, "bad keep_alive");
		return -1;
	}
	if (jsmn_get_ulong(&parser, lanip, "auto_sync", &tmp_auto_sync) ||
	    !tmp_auto_sync) {
		lcf->auto_echo = 0;
	} else {
		lcf->auto_echo = 1;
	}
	lcf->enable = 1;
	lcf->lanip_key_id = (u16)tmp_key_id;
	lcf->keep_alive = (u16)tmp_keep_alive;
	memcpy(lcf->lanip_key, tmp_key, sizeof(tmp_key));

save:
	client_callback_pend(&client_cb[CCB_LANIP]);
	return 0;
}

/*
 * Connectivity to service has just come up. Notify host mcu and setup client.
 */
static void client_server_conn_up(struct client_state *state,
				    struct http_client *hc)
{
	http_client_set_retry_limit(hc, -1);
	if (!(state->valid_dest_mask & NODES_ADS)) {
		state->valid_dest_mask |= NODES_ADS;
		client_connectivity_update();
		np_retry_server();
	}
	state->serv_conn = 1;
}

/*
 * Timeout for retrying the command request.
 */
static void client_cmd_timeout(struct timer *arg)
{
	struct client_state *state = &client_state;

	state->np_event = 1;
	client_wakeup();
}

void client_tcp_recv_done(struct client_state *state)
{
	struct http_client *hc = &state->http_client;

	ASSERT(client_locked);
	if (!hc->hc_error && hc->client_auth) {
		state->auth_fails = 0;
	}
	state->current_request = NULL;
	state->retries = 0;
	state->connect_time = clock_ms();
	state->request = CS_IDLE;
	state->conn_state = CS_WAIT_EVENT;
	client_wakeup();
}

/*
 * receive of XML data.
 */
enum ada_err client_recv_xml(struct http_client *hc, void *buf, size_t len)
{
	struct client_state *state = &client_state;
	enum ada_err err = AE_OK;
	int rc;

	state->auth_fails = 0;
	client_wait(state, CLIENT_PROP_WAIT);

	ASSERT(state->xml_init);
	rc = xml_parse(&state->xml_state, buf, len);
	if (rc < 0) {
		client_log(LOG_WARN "XML parse failed");
		state->conn_state = CS_ERR;
		err = AE_INVAL_VAL;
	} else if (rc != len) {
		hc->recv_consumed = rc;
		err = AE_BUF;
	}
	return err;
}

static void client_req_close(struct server_req *req)
{
	net_callback_pend(req->tcpip_cb);
	if (req->close_cb) {
		req->close_cb(req);
	}
}

static enum ada_err client_recv_cmd_put(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;

	if (buf) {
		hc->recv_consumed += len;
		return AE_OK;
	}
	client_req_close(&state->cmd_req);
	state->cmd_pending = 0;
	free((void *)hc->body_buf); /* allocated in client_rev_rest_put() */
	hc->body_buf = NULL;

	client_tcp_recv_done(state);
	return AE_OK;
}

static enum ada_err client_recv_sts_put(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;

	if (buf) {
		return client_recv_drop(hc, buf, len);
	}

	/*
	 * Command status reported. We're ready to
	 * apply the patch now.
	 */
	client_ota_save_done(state);
	client_tcp_recv_done(state);
	if (state->ota_server.uri) {
		free(state->ota_server.uri);
		state->ota_server.uri = NULL;
	}

	return AE_OK;
}

static enum ada_err client_recv_lanip(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;

	if (buf) {
		memcpy(state->buf + state->recved_len, buf, len);
		state->recved_len += len;
		return AE_OK;
	}
	state->buf[state->recved_len] = '\0';
	client_lanip_json_parse(state->buf);
	client_tcp_recv_done(state);
	return AE_OK;
}

/*
 * Notify client that a 206 (partial content) was received
 * in the previous get. So re-mark the np_event flag.
 */
void client_notify_if_partial(void)
{
	struct client_state *state = &client_state;

	client_lock();
	if (state->partial_content) {
		state->partial_content = 0;
		state->np_event = 1;
	}
	client_unlock();
}

static void client_get_dev_id_pend(struct client_state *state)
{
	net_callback_enqueue(state->callback_queue[CQP_HIGH],
	    &client_cb[CCB_GET_DEV_ID]);
}

/*
 * Handle event callback from client_notify.
 */
static void client_notify_cb(void *arg)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;
	enum notify_event event;

	ASSERT(client_locked);

	event = np_event_get();
	switch (event) {
	case NS_EV_CHANGE:
		client_log(LOG_INFO "ANS change event");
		client_get_dev_id_pend(state);
		state->np_up = 0;
		state->np_started = 0;
		break;
	case NS_EV_DOWN:
	case NS_EV_DOWN_RETRY:
		if (!state->np_up && state->poll_ads) {
			goto ansdown;
		}
		if (!state->poll_ads) {
			state->serv_conn = 0;
			/* clear dns cache before checking ads connectivity */
			net_dns_delete_host(hc->host);
		}
ansdown:
		if (state->np_up) {
			client_log(LOG_WARN "ANS down event");
		} else {
			client_log(LOG_WARN "ANS reg/reach fail");
		}
		state->np_up = 0;
		state->np_started = 0;
		state->np_any_event = 1;
		break;
	case NS_EV_DNS_PASS:
		if (state->np_started) {
			break;
		}
		state->np_started = 1;
		np_start(state->np_cipher_key, state->np_cipher_key_len);
		break;
	case NS_EV_CHECK:
		client_log(LOG_INFO "ANS check event");
		if (state->wait_for_file_put || state->wait_for_file_get) {
			/*
			 * tell the host mcu that there's a pending update
			 * so he can abort the file operation if he wants
			 */
			prop_mgr_event(PME_NOTIFY, NULL);
		}
		/* fall through */
	default:
		state->np_up = 1;
		state->np_event = 1;
		state->poll_ads = 0;
		state->np_up_once = 1;
		state->np_any_event = 1;
		client_timer_cancel(&state->poll_timer);
		break;
	}
	client_wakeup();
}

/*
 * Notifier event.
 *
 * In the multi-threaded model, this called in the TCP/IP thread
 * and must not take the client_lock, since it is sometimes held
 * when needing TCP/IP thread services.  So, just post the event
 * and queue a callback for the client thread.
 */
static void client_notify(void)
{
	struct client_state *state = &client_state;

	client_callback_pend(&state->notify_cb);
}

/*
 * TCP timeout for handling re-connect or retry.
 */
static void client_timeout(struct timer *timer)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;

	switch (state->conn_state) {
	case CS_DOWN:
	case CS_DISABLED:
		client_down_locked();
		break;
	case CS_WAIT_EVENT:
	case CS_WAIT_RETRY:
		state->conn_state = CS_WAIT_EVENT;
		client_wakeup();
		break;
	default:
		if (!http_client_is_ready(hc)) {
			http_client_abort(hc);
			hc->hc_error = HC_ERR_TIMEOUT;
			client_err_cb(hc);
			return;
		}
		client_close(state);
		state->conn_state = CS_WAIT_EVENT;
		client_wakeup();
		break;
	}
}

/*
 * Schedule reconnect/retry after wait.
 */
void client_wait(struct client_state *state, u32 delay)
{
	client_timer_cancel(&state->req_timer);	/* in case of reset/commit */

	ASSERT(client_locked);
	switch (state->conn_state) {
	case CS_WAIT_RETRY:
		CLIENT_DEBUG(LOG_DEBUG2, "RETRY");
		break;
	case CS_WAIT_EVENT:
	case CS_WAIT_ID:
	case CS_WAIT_INFO_PUT:
	case CS_WAIT_GET:
	case CS_WAIT_OTA_GET:
	case CS_WAIT_POST:
	case CS_WAIT_ECHO:
	case CS_WAIT_CMD_PUT:
	case CS_WAIT_OTA_PUT:
	case CS_WAIT_CMD_STS_PUT:
	case CS_WAIT_PING:
	case CS_WAIT_REG_WINDOW:
	case CS_WAIT_CONN:
		break;
	default:
		CLIENT_DEBUG(LOG_DEBUG2, "bad state %x", state->conn_state);
		break;
	}
	if (delay) {
		client_timer_set(&state->req_timer, delay);
	}
}

/*
 * Receive for device ID request.
 */
static enum ada_err client_recv_index(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;

	ASSERT(client_locked);
	if (buf) {
		return client_recv_xml(hc, buf, len);
	}

	if (CLIENT_HAS_KEY(state)) {
		client_server_conn_up(state, hc);
		if (conf_was_reset) {
			conf_was_reset = 0;
			ada_conf_persist_reset();
		}
		client_logging(1);
		if (!state->client_info_flags) {
			client_event_send(0);
		}
	} else {
		client_get_dev_id_pend(state);
	}
	client_tcp_recv_done(state);
	return AE_OK;
}

/*
 * GET device ID.
 */
static void client_get_dev_id(void *arg)
{
	struct client_state *state = arg;
	struct ada_conf *cf = &ada_conf;
	struct http_client *hc;
	char req[CLIENT_GET_REQ_LEN];
	static u8 certs_loaded;

	if (!certs_loaded) {
		certs_loaded = 1;
		stream_certs_load(CA_CERT, CA_CERT_SIZE);
	}
	if (state->conn_state == CS_ERR || state->ping_time) {
		state->current_request = NULL;
		return;
	}

	client_notify_stop(state);

	client_log(LOG_INFO "get DSN %s", conf_sys_dev_id);

	state->client_key[0] = '\0';
	state->client_info_flags |= CLIENT_UPDATE_ALL;

	if (state->setup_token[0] == '\0') {
		state->client_info_flags &= ~CLIENT_UPDATE_SETUP;
	}

	snprintf(req, sizeof(req) - 1, "/dsns/%s.xml", conf_sys_dev_id);

	if (conf_was_reset) {
		client_arg_add(req, sizeof(req), "reset=1");
	}
	if (cf->test_connect) {
		client_arg_add(req, sizeof(req), "test=1");
	}
	if (log_snap_saved) {
		client_arg_add(req, sizeof(req), "snapshot=%u", log_snap_saved);
	}

	hc = client_req_ads_new();
	ASSERT(hc);
	hc->client_tcp_recv_cb = client_recv_index;
	state->conn_state = CS_WAIT_ID;
	state->request = CS_GET_INDEX;

	memset(&prop_recvd, 0, sizeof(prop_recvd));
	xml_parse_init(&state->xml_state, client_xml_id);
	state->xml_init = 1;

	client_req_start(hc, HTTP_REQ_GET, req, NULL);
}

/*
 * GET lanip_key from service
 */
static int client_get_lanip_key(struct client_state *state)
{
	struct ada_lan_conf *lcf = &ada_lan_conf;
	struct http_client *hc;
	char uri[CLIENT_GET_REQ_LEN];

	if (!lcf->enable || CLIENT_LANIP_HAS_KEY(lcf)) {
		return -1;
	}
	hc = client_req_ads_new();
	hc->client_tcp_recv_cb = client_recv_lanip;
	state->conn_state = CS_WAIT_LANIP_GET;
	state->request = CS_GET_LANIP;
	state->recved_len = 0;

	snprintf(uri, sizeof(uri), "/devices/%s/lan.json", state->client_key);
	client_req_start(hc, HTTP_REQ_GET, uri, &http_hdr_content_json);
	return 0;
}

/*
 * Handle response from GET /commands.
 */
enum ada_err client_recv_cmds(struct http_client *hc, void *payload, size_t len)
{
	struct client_state *state = &client_state;

	if (payload) {
		return client_recv_xml(hc, payload, len);
	}

	client_log(LOG_DEBUG "client_recv_cmds GET done");

	client_timer_cancel(&state->cmd_timer);

	state->get_cmds_fail = 0;
	state->prefer_get = 0;
	state->get_all = 0;
	if (hc->http_status == HTTP_STATUS_PAR_CONTENT) {
		state->partial_content = 1;
	}
	state->get_echo_inprog = 0;
	client_tcp_recv_done(state);
	return AE_OK;
}

/*
 * Handle response for GET of commands for property subsystem.
 */
enum ada_err client_recv_prop_cmds(struct http_client *hc,
				void *buf, size_t len)
{
	enum ada_err err;

	err = client_recv_cmds(hc, buf, len);
	if (buf || err != AE_OK) {
		return err;
	}
	return client_recv_prop_done(hc);
}

/*
 * GET /commands from service.
 */
static void client_get_cmds(struct client_state *state)
{
	struct http_client *hc;
	int signal;

	/* XXX used to set these only after the send finished without errors */
	state->get_echo_inprog = 1;	/* inhibit GETs from LAN clients */
	state->cmd.data = NULL;
	state->cmd.resource = NULL;
	state->np_event = 0;
	state->mcu_overflow = 0;

	hc = client_req_ads_new();
	ASSERT(hc);
	hc->client_tcp_recv_cb = client_recv_cmds;
	state->conn_state = CS_WAIT_GET;

	snprintf(state->buf, sizeof(state->buf) - 1,
	    "/devices/%s/commands.xml", state->client_key);

	if (state->get_all) {
		client_arg_add(state->buf, sizeof(state->buf), "input=true");
	}
	if (state->poll_ads && state->np_any_event) {
		client_arg_add(state->buf, sizeof(state->buf), "polling=%u",
		    state->np_up_once ? 1 : 2);
	}
	if (!adap_net_get_signal(&signal)) {
		client_arg_add(state->buf, sizeof(state->buf), "signal=%d",
		    signal);
	}

	memset(&prop_recvd, 0, sizeof(prop_recvd));
	xml_parse_init(&state->xml_state, client_xml_cmds);
	state->xml_init = 1;
	state->request = CS_GET_CMDS;

	client_req_start(hc, HTTP_REQ_GET, state->buf, NULL);
}

/*
 * Given a location in format, <prop_id>/<dp_id>.xml, returns a string
 * in the format properties/<prop_id>/datapoints/<dp_id>.xml
 */
static int client_convert_loc_to_url_str(const char *loc,
	char *dest, int dest_len)
{
	char prop_id[PROP_LOC_LEN + 1];
	char *dp_id;

	dp_id = strrchr(loc, '/');
	if (!dp_id) {
		return AE_INVAL_VAL;
	}
	strncpy(prop_id, loc, dp_id - loc);
	prop_id[dp_id - loc] = '\0';
	snprintf(dest, dest_len, "/properties%s/datapoints%s",
	    prop_id, dp_id);

	return 0;
}

/*
 * Handle response for PUT of a file datapoint.
 */
static enum ada_err client_recv_dp_put(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;

	if (buf) {
		hc->recv_consumed += len;
		return AE_OK;
	}
	if (state->request == CS_PUT_DP_CLOSE) {
		state->wait_for_file_put = 0;
	}
	return client_recv_prop_done(hc);
}

/*
 * Close FILE DP put. The location is in the format: <prop_id>/<dp_id>.xml
 * We need to do a PUT on <prop_id>/datapoints/<dp_id>.xml
 */
enum ada_err client_close_dp_put(const char *loc)
{
	struct client_state *state = &client_state;
	struct http_client *hc;

	if (client_convert_loc_to_url_str(loc, state->xml_buf,
	    sizeof(state->xml_buf))) {
		return AE_INVAL_VAL;
	}

	hc = client_req_ads_new();
	state->request = CS_PUT_DP_CLOSE;
	hc->client_tcp_recv_cb = client_recv_dp_put;
	snprintf(state->buf, sizeof(state->buf),
	    "/devices/%s%s",
	    state->client_key, state->xml_buf);

	client_req_start(hc, HTTP_REQ_PUT, state->buf, NULL);

	/* erase prop_recvd since DP put is complete */
	memset(&prop_recvd, 0, sizeof(prop_recvd));
	return AE_OK;
}

/*
 * Send dp put to server.
 */
enum ada_err client_send_dp_put(const u8 *prop_val, size_t prop_val_len,
	const char *prop_loc, u32 offset, size_t tot_len, u8 eof)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;
	struct prop_recvd *prop = &prop_recvd;
	enum ada_err err = AE_OK;

	eof |= (tot_len == prop_val_len);

	if (hc->client_tcp_recv_cb != client_recv_dp_put) {	 /* XXX */
		hc = client_req_file_new();
		state->request = CS_PUT_DP;
		hc->client_send_data_cb = client_send_post;
		hc->client_tcp_recv_cb = client_recv_dp_put;
		hc->sending_chunked = 1;	/* XXX not exactly chunked */
		hc->chunked_eof = eof;
		hc->body_len = tot_len;

		prop->is_file = 0;	/* prop_recvd can be overwritten */

		client_req_start(hc, HTTP_REQ_PUT,
		    client_url_resource(prop->file_info.file),
		    &http_hdr_content_stream);
	} else {
		err = http_client_send(hc, prop_val, prop_val_len);
		if (err != AE_OK) {
			CLIENT_DEBUG(LOG_DEBUG, "write err %d",
			    err);
			return err;
		}
		if (eof) {
			hc->chunked_eof = 1;
			hc->client_send_data_cb = NULL;
		}
	}

	return err;
}

/*
 * Indicate to the service that MCU has fetched the dp.
 */
enum ada_err client_send_dp_fetched(const char *prop_loc)
{
	struct client_state *state = &client_state;
	struct http_client *hc;
	size_t xml_len;
	char url_str[PROP_LOC_LEN + 40];

	if (client_convert_loc_to_url_str(prop_loc, url_str, sizeof(url_str))) {
		return AE_INVAL_VAL;
	}

	xml_len = snprintf(state->xml_buf, sizeof(state->xml_buf),
	    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	    "<datapoint><fetched>true</fetched></datapoint>");

	hc = client_req_ads_new();
	hc->client_tcp_recv_cb = client_recv_dp_put;
	hc->body_buf = state->xml_buf;
	hc->body_buf_len = xml_len;
	hc->body_len = xml_len;
	state->request = CS_PUT_DP_FETCH;

	snprintf(state->buf, sizeof(state->buf),
	    "/devices/%s%s", state->client_key, url_str);
	client_req_start(hc, HTTP_REQ_PUT, state->buf, &http_hdr_content_xml);
	return AE_OK;
}

static enum ada_err client_recv_post_done(struct http_client *hc)
{
	struct client_state *state = &client_state;
	enum ada_err err;

	err = client_prop_send_done(state, 1, state->prop_send_cb_arg,
	    NODES_ADS, hc);
	if (err == AE_BUF) {
		return err;
	}
	state->prefer_get = 1;
	client_tcp_recv_done(state);
	return err;
}

static enum ada_err client_recv_echo(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;

	if (buf) {
		return client_recv_drop(hc, buf, len);
	}
	client_finish_echo(state, NODES_ADS);
	state->prefer_get = 1;
	client_tcp_recv_done(state);
	return AE_OK;
}

static enum ada_err client_recv_post(struct http_client *hc,
					void *buf, size_t len)
{
	if (buf) {
		return client_recv_drop(hc, buf, len);
	}
	return client_recv_post_done(hc);
}

/*
 * Send changed data to server.
 * This might be called repeatedly after AE_BUF (buffer full) errors.
 * Callbacks will have hc->prop_callback set.
 *
 * The agent_echo flag indicates this is an echo by the agent, as opposed to by
 * the property manager or host app.
 */
static enum ada_err client_send_data_int(struct prop *prop, int agent_echo)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = state->http_lan;
	struct http_client *hc;
	ssize_t val_len;
	size_t len;
	enum ada_err err = AE_OK;
	char uri[CLIENT_GET_REQ_LEN];
	const char start_tag[] = "<datapoint><value>";
	const char end_tag[] = "</value></datapoint>";
	size_t consumed;
	int sending_end_tag;
	char fmt_val[BASE64_LEN_EXPAND(PROP_VAL_LEN) + 1];
	char *value;
	size_t value_len;

	ASSERT(prop);
	ASSERT(prop->name);

	if (lan) {
		return client_send_lan_data(lan, prop, agent_echo);
	}

	value_len = prop_fmt(fmt_val, sizeof(fmt_val), prop->type,
	    prop->val, prop->len, &value);

	val_len = xml_encode(NULL, 0, value, value_len, &consumed);
	if (val_len < 0 || consumed != value_len) {
		CLIENT_LOGF(LOG_WARN, "xml_enc err");
		CLIENT_LOGF(LOG_DEBUG,
		    "name=\"%s\" val=\"%s\" type=%s",
		    prop->name, value, lookup_by_val(prop_types, prop->type));
		return AE_INVAL_VAL;
	}

	len = 0;
	hc = &state->http_client;
	if (!hc->prop_callback) {
		hc = client_req_ads_new();
		hc->body_len = val_len + sizeof(start_tag) - 1 +
		    sizeof(end_tag) - 1;
		memcpy(state->buf, start_tag, sizeof(start_tag) - 1);
		len = sizeof(start_tag) - 1;
		state->long_val_index = 0;
	}

	/*
	 * XML-encode the value to the buffer, as much as will fit..
	 * Append the trailer to the final buffer (perhaps otherwise empty).
	 */
	sending_end_tag = 0;
	do {
		consumed = 0;
		if (state->long_val_index < value_len) {
			val_len = xml_encode(state->buf + len,
			    sizeof(state->buf) - len,
			    value + state->long_val_index, value_len -
			    state->long_val_index, &consumed);
			if (val_len < 0) {
				CLIENT_LOGF(LOG_WARN, "xml_enc err");
				return AE_INVAL_VAL;
			}
			len += val_len;
		}
		if (state->long_val_index + consumed >= value_len &&
		    sizeof(end_tag) - 1 < sizeof(state->buf) - len) {
			memcpy(state->buf + len, end_tag, sizeof(end_tag) - 1);
			len += sizeof(end_tag) - 1;
			sending_end_tag = 1;
		}

		/*
		 * Send request and first part of buffer.
		 */
		if (hc->prop_callback == 0) {
			state->request = CS_POST_DATA;
			hc->body_buf = state->buf;
			hc->body_buf_len = len;
			if (agent_echo) {
				state->conn_state = CS_WAIT_ECHO;
				hc->client_tcp_recv_cb = client_recv_echo;
			} else {
				hc->client_tcp_recv_cb = client_recv_post;
			}
			if (!sending_end_tag) {
				hc->client_send_data_cb = client_send_post;
			}

			state->long_val_index = consumed;

			snprintf(uri, sizeof(uri),
			    "/devices/%s/properties/%s/datapoints.xml%s",
			    state->client_key, prop->name,
			    prop->echo ? "?echo=true" : "");

			client_req_start(hc, HTTP_REQ_POST, uri,
			    &http_hdr_content_xml);
			return AE_OK;
		}

		/*
		 * In send callback.  Send next part of buffer.
		 */
		err = http_client_send(hc, state->buf, len);
		if (err != AE_OK) {
			CLIENT_LOGF(LOG_DEBUG, "write err %d\n", err);
			return err;
		}
		state->long_val_index += consumed;
		len = 0;
	} while (!sending_end_tag);

	hc->client_send_data_cb = NULL;
	hc->prop_callback = 0;
	return AE_OK;
}

enum ada_err client_send_data(struct prop *prop)
{
	return client_send_data_int(prop, 0);
}

/*
 * Send dp loc request to server.
 */
enum ada_err client_send_dp_loc_req(const char *name,
				const struct prop_dp_meta *meta)
{
	struct client_state *state = &client_state;
	struct http_client *hc;

	if (state->get_echo_inprog) {
		/*
		 * we're in the middle of doing ECHOs to LAN clients
		 * so the prop_recvd structure is being used. we need that
		 * structure to store FILE url information. So abort
		 * this operation for now and wait until we get called again.
		 */
		 return AE_BUSY;
	}
	state->prop_send_cb_arg = NULL;

	hc = client_req_ads_new();
	hc->client_tcp_recv_cb = client_recv_prop_val;
	xml_parse_init(&state->xml_state, client_xml_cmds);
	state->xml_init = 1;
	state->conn_state = CS_WAIT_POST;
	state->request = CS_POST_DP_LOC;

	snprintf(state->buf, sizeof(state->buf),
	    "/devices/%s/properties/%s/datapoints.xml",
	    state->client_key, name);

	client_req_start(hc, HTTP_REQ_POST, state->buf, NULL);
	return AE_OK;
}

/*
 * Fetch the s3 location of the file datapoint
 */
enum ada_err client_get_dp_loc_req(const char *prop_loc)
{
	struct client_state *state = &client_state;
	struct http_client *hc;

	if (state->get_echo_inprog) {
		/*
		 * we're in the middle of doing ECHOs to LAN clients
		 * so the prop_recvd structure is being used. we need that
		 * structure to store FILE url information. So abort
		 * this operation for now and wait until we get called again.
		 */
		 return AE_BUSY;
	}
	if (client_convert_loc_to_url_str(prop_loc,
	    state->xml_buf, sizeof(state->xml_buf))) {
		return AE_INVAL_VAL;
	}

	hc = client_req_ads_new();
	hc->client_tcp_recv_cb = client_recv_prop_cmds;

	state->request = CS_GET_DP_LOC;
	state->prop_send_cb_arg = hc;
	state->get_echo_inprog = 1;
	snprintf(state->buf, sizeof(state->buf), "/devices/%s%s",
	    state->client_key, state->xml_buf);

	memset(&prop_recvd, 0, sizeof(prop_recvd));
	xml_parse_init(&state->xml_state, client_xml_cmds);
	state->xml_init = 1;

	client_req_start(hc, HTTP_REQ_GET, state->buf, &http_hdr_content_xml);
	return AE_OK;
}

/*
 * Fetch the datapoint at the location and offset.
 */
enum ada_err client_get_dp_req(const char *prop_loc, u32 data_off, u32 data_end)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;
	struct prop_recvd *prop = &prop_recvd;
	struct http_hdr range_hdr;

	hc = client_req_file_new();
	state->request = CS_GET_DP;
	hc->client_tcp_recv_cb = client_recv_dp;
	state->prop_send_cb_arg = hc;

	snprintf(state->buf, sizeof(state->buf),
	    "bytes=%lu-%lu",
	    data_off, data_end);
	range_hdr.name = "Range";
	range_hdr.val = state->buf;

	client_req_start(hc, HTTP_REQ_GET,
	    client_url_resource(prop->file_info.file), &range_hdr);
	state->get_echo_inprog = 1;
	return AE_OK;
}

/*
 * Handle response from GET /ping.
 */
static enum ada_err client_recv_ping(struct http_client *hc,
					void *payload, size_t len)
{
	struct client_state *state = &client_state;

	if (payload) {
		/*
		 * Ping should not contain payload_len > 1. If it does,
		 * it means we aren't talking to our service.
		 */
		if (len > 1) {
			return AE_INVAL_VAL;
		}
	} else {
		if (hc->http_time) {
			client_clock_set(hc->http_time, CS_HTTP);
		}
		state->ping_time = 0;
		if (CLIENT_HAS_KEY(state)) {
			client_server_conn_up(state, hc);
		} else {
			client_get_dev_id_pend(state);
		}
		client_tcp_recv_done(state);
	}
	return AE_OK;
}

/*
 * Send a ping to service to check for connectivity
 */
static void client_get_ping(struct client_state *state)
{
	struct http_client *hc;
	char uri[20];

	hc = client_req_new(CCT_ADS_HTTP);
	ASSERT(hc);
	hc->client_tcp_recv_cb = client_recv_ping;
	state->conn_state = CS_WAIT_PING;
	state->request = CS_PING;
	snprintf(uri, sizeof(uri), "/ping");
	if (state->ping_time) {
		client_arg_add(uri, sizeof(uri), "time=1");
	}
	client_req_start(hc, HTTP_REQ_GET, uri, NULL);
}

/*
 * Generate body of PUT of client info.
 * Fill provided buffer and return the length used.
 * This may be done once to determine the content-length and a second time
 * to generate the data.
 * Len must be long enough for oem_data + all flags, around 600 bytes.
 */
static size_t client_gen_info_data(struct client_state *state,
					char *buf, size_t buf_len)
{
	struct ada_conf *cf = &ada_conf;
	char ip[30];
	size_t xml_len;
	u16 flags;
	size_t outlen;
	char ssid_uri[SSID_URI_LEN];
	char oem_key[CONF_OEM_KEY_MAX];
	const u8 *mac;
	int oem_key_len;
	size_t head_len;

	flags = state->client_info_flags;

	xml_len = snprintf(buf, buf_len,
	    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	    "<device>");
	head_len = xml_len;
	if (flags & (CLIENT_UPDATE_MAJOR | CLIENT_UPDATE_MINOR)) {
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<api-major>%u</api-major>"
		    "<api-minor>%u</api-minor>",
		    CLIENT_API_MAJOR, CLIENT_API_MINOR);
	}
	if (flags & CLIENT_UPDATE_SWVER) {
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<sw-version>%s</sw-version>", adap_conf_sw_build());
	}
	if ((flags & CLIENT_UPDATE_LANIP) && netif_default) {
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<lan-ip>%s</lan-ip>",
		    ipaddr_ntoa_r(&netif_default->ip_addr, ip, sizeof(ip)));
	}
	if (flags & CLIENT_UPDATE_MODEL) {
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<model>%s</model>", conf_sys_model);
	}
	if (flags & CLIENT_UPDATE_SETUP) {
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<setup-token>%s</setup-token>", state->setup_token);
	}
	if (flags & CLIENT_UPDATE_SETUP_LOCATION && state->setup_location) {
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<setup-location>%s</setup-location>",
		    state->setup_location);
	}
	if (flags & CLIENT_UPDATE_SSID) {
		client_get_ssid_uri(ssid_uri, sizeof(ssid_uri));
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<ssid>%s</ssid>", ssid_uri);
	}
	if (flags & CLIENT_UPDATE_PRODUCT_NAME) {
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<product-name>%s</product-name>",
		    cf->host_symname);
	}
	if (flags & CLIENT_UPDATE_OEM) {
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<oem>%s</oem>"
		    "<oem-model>%s</oem-model>",
		    oem, oem_model);
		oem_key_len = adap_conf_oem_key_get(oem_key, sizeof(oem_key));
		if (oem_key_len > 0) {
			xml_len += snprintf(buf + xml_len, buf_len - xml_len,
			    "<oem-key>");
			outlen = buf_len - xml_len;
			if (net_base64_encode(oem_key, oem_key_len,
			    buf + xml_len, &outlen)) {
				client_log(LOG_ERR "oem_key: encode fail");
				outlen = 0;
			}
			xml_len += outlen;
			xml_len += snprintf(buf + xml_len, buf_len - xml_len,
			    "</oem-key>");
		}
	}
	if (flags & CLIENT_UPDATE_MAC) {
		mac = cf->mac_addr;
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<mac>%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x</mac>",
		    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	if (flags & CLIENT_UPDATE_HW_ID) {
		xml_len += snprintf(buf + xml_len, buf_len - xml_len,
		    "<hwsig>%s</hwsig>", cf->hw_id);
	}
	if (xml_len == head_len) {
		return 0;
	}
	xml_len += snprintf(buf + xml_len, buf_len - xml_len, "</device>");
	return xml_len;
}

/*
 * Handle response from PUT info
 */
static enum ada_err client_recv_info(struct http_client *hc,
					void *payload, size_t len)
{
	struct client_state *state = &client_state;

	if (!payload) {
		state->client_info_flags = 0;
		client_event_send(0);
		client_tcp_recv_done(state);
	}
	return AE_OK;
}

/*
 * See if any client info received is incorrect and
 * should be updated to the server.
 */
static int client_put_info(struct client_state *state)
{
	struct http_client *hc;
	char uri[CLIENT_GET_REQ_LEN];

	if (!state->client_info_flags) {
		return -1;
	}
	hc = client_req_ads_new();
	ASSERT(hc);
	hc->client_tcp_recv_cb = client_recv_info;
	state->conn_state = CS_WAIT_INFO_PUT;
	state->request = CS_PUT_INFO;

	/*
	 * Generate data to determine content-len.
	 */
	hc->body_len = client_gen_info_data(state,
	    state->xml_buf, sizeof(state->xml_buf));
	if (!hc->body_len) {
		state->client_info_flags = 0;
		state->conn_state = CS_WAIT_EVENT;
		return -1;
	}
	hc->body_buf = state->xml_buf;
	hc->body_buf_len = hc->body_len;

	snprintf(uri, sizeof(uri), "/devices/%s.xml", state->client_key);
	client_req_start(hc, HTTP_REQ_PUT, uri, &http_hdr_content_xml);
	return 0;
}

/*
 * Put reset.json
 * Parses a reset command. Schedules a reset for the module.
 */
void client_reset_json_put(struct server_req *req)
{
	client_lock();
	req->tcpip_cb = &ada_conf_reset_cb;
	if (server_get_bool_arg_by_name(req, "factory")) {
		ada_conf_reset_factory = 1;
	}
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
	client_unlock();
}

/*
 * Put lanip.json
 * Sets lanip key according to the tokens given.
 */
void client_lanip_json_put(struct server_req *req)
{
	client_lock();
	if (client_lanip_json_parse(req->post_data)) {
		server_put_status(req, HTTP_STATUS_BAD_REQ);
	} else {
		server_put_status(req, HTTP_STATUS_NO_CONTENT);
	}
	client_unlock();
}

static void client_cmd_put_rsp(struct client_state *state, unsigned int status)
{
	struct http_client *hc = &state->http_client;
	char uri[CLIENT_GET_REQ_LEN];

	if (state->tgt == CCT_LAN) {
		snprintf(uri, sizeof(uri), "/ota_status.json?status=%u",
		    status);
	} else {
		snprintf(uri, sizeof(uri),
		    "/devices/%s/%s?cmd_id=%lu&status=%u",
		    state->client_key, state->cmd.uri, state->cmd.id, status);
	}

	client_req_start(hc, HTTP_REQ_PUT, uri, &http_hdr_content_json);
}

/*
 * Send the PUT header for an ADS command response
 * Arg body_len is the anticipated length of the entire response.  It is used
 * only if the http_client request has not already started.
 */
static void client_rev_rest_put(struct client_state *state,
				const void *buf, size_t len, size_t body_len)
{
	struct server_req *req = &state->cmd_req;
	struct http_client *hc = &state->http_client;
	unsigned int status;
	void *data;

	if (req->req_impl) {
		if (len) {
			client_lock();
			req->err = http_client_send(hc, buf, len);
			if (req->err == AE_OK) {
				state->cmd.output_len += req->len;
			}
			client_unlock();
		}
		return;
	}

	status = req->http_status;
	if (!status || status == HTTP_STATUS_OK) {
		data = malloc(len);
		if (!data) {
			req->err = AE_BUF;
			return;
		}
		memcpy(data, buf, len);
	} else {
		data = NULL;
		len = 0;
		body_len = 0;
	}

	client_lock();
	req->req_impl = hc;
	hc->body_buf = data;
	hc->body_buf_len = len;
	hc->body_len = body_len;

	hc->client_send_data_cb = http_client_send_pad;
	hc->client_tcp_recv_cb = client_recv_cmd_put;

	state->conn_state = CS_WAIT_CMD_PUT;

	client_cmd_put_rsp(state, status);
	client_unlock();
}

/*
 * Command to flush cmd data from server to ADS
 * The message or req->buf may be on the stack, so they must
 * be copied to something more persistent for the send callback.
 */
static void client_cmd_flush(struct server_req *req, const char *msg)
{
	struct client_state *state = &client_state;
	const char *data;
	size_t len;

	if (req->suppress_out || req->len == 0 || req->err != AE_OK) {
		return;
	}

	if ((req->len + state->cmd.output_len) > (MAX_CMD_RESP - 1)) {
		return;
	}

	data = msg ? msg : req->buf;
	len = req->len;
	client_rev_rest_put(state, data, len, MAX_CMD_RESP);
	req->len = 0;
}

/*
 * Drop the header for a reverse-REST request.
 * Remember the status for later.
 */
void client_cmd_put_head(struct server_req *req, unsigned int status,
				const char *content_type)
{
	req->http_status = (u16)status;
}

/*
 * Start a PUT for a command status report - delayed response for rev-REST
 */
static int client_put_cmd_sts(struct client_state *state)
{
	struct http_client *hc;

	if (state->ota.in_prog != COS_CMD_STATUS || !state->ota.http_status) {
		return -1;
	}
	if (state->ota_server.lan) {
		hc = client_req_new(CCT_LAN);
	} else {
		hc = client_req_ads_new();
	}
	state->conn_state = CS_WAIT_CMD_STS_PUT;
	hc->client_tcp_recv_cb = client_recv_sts_put;
	client_cmd_put_rsp(state, state->ota.http_status);
	return 0;
}

/*
 * Handle response from PUT info
 */
static enum ada_err client_reg_window_recv(struct http_client *hc,
				void *payload, size_t len)
{
	struct client_state *state = &client_state;

	if (!payload) {
		client_step_disable(ADCP_REG_WINDOW_START);
		client_tcp_recv_done(state);
	}
	return AE_OK;
}

/*
 * Send PUT for register window start.
 */
static int client_put_reg_window_start(struct client_state *state)
{
	struct http_client *hc;
	char uri[CLIENT_GET_REQ_LEN];

	hc = client_req_ads_new();
	ASSERT(hc);
	hc->client_tcp_recv_cb = client_reg_window_recv;
	state->conn_state = CS_WAIT_REG_WINDOW;
	state->request = CS_PUT_INFO;

	/*
	 * Generate data to determine content-len.
	 */
	hc->body_buf = "{}";
	hc->body_buf_len = 2;
	hc->body_len = 2;

	snprintf(uri, sizeof(uri), "/devices/%s/start_reg_window.json",
	    state->client_key);
	client_req_start(hc, HTTP_REQ_PUT, uri, &http_hdr_content_json);
	return 0;
}

/*
 * Put registration.json
 * Notification of user registration change.
 */
void client_registration_json_put(struct server_req *req)
{
	struct ada_conf *cf = &ada_conf;
	jsmn_parser parser;
	jsmntok_t tokens[CLIENT_REG_JSON_TOKENS];
	jsmntok_t *reginfo;
	jsmnerr_t err;
	char status[4];
	int changed = 0;

	client_lock();

	/* Ignore empty PUTs */
	if (req->post_data == NULL) {
		goto err;
	}

	/* Extract the status from the JSON registration record */
	jsmn_init_parser(&parser, req->post_data, tokens, ARRAY_LEN(tokens));
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		CLIENT_LOGF(LOG_WARN, "jsmn err %d", err);
		goto err;
	}
	reginfo = jsmn_get_val(&parser, NULL, "registration");
	if (!reginfo) {
		CLIENT_LOGF(LOG_WARN, "no registration");
		goto err;
	}
	if (jsmn_get_string(&parser, reginfo, "status",
	    status, sizeof(status)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad reg status");
		goto err;
	}

	/* Update ther user registration status and send event */
	cf->event_mask &= ~(CLIENT_EVENT_UNREG | CLIENT_EVENT_REG);
	if (!strcmp(status, "0")) {
		/* Deregistration */
		changed = cf->reg_user;
		cf->reg_user = 0;
		cf->event_mask |= CLIENT_EVENT_UNREG;
	} else if (!strcmp(status, "1")) {
		/* First registration */
		changed = !cf->reg_user;
		cf->reg_user = 1;
		cf->event_mask |= CLIENT_EVENT_REG;
	} else if (!strcmp(status, "2")) {
		/* Re-registration */
		if (cf->reg_user) {
			cf->reg_user = 0;
			adap_conf_reg_changed();
		}
		cf->reg_user = 1;
		cf->event_mask |= (CLIENT_EVENT_REG | CLIENT_EVENT_UNREG);
		changed = 1;
	}

	/* If config changed, save state and notify MCU */
	if (changed) {
		client_conf_reg_persist();
		adap_conf_reg_changed();
	}
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
	client_unlock();
	return;

err:
	server_put_status(req, HTTP_STATUS_BAD_REQ);
	client_unlock();
}

/*
 * Finish the command response for ADS
 */
static enum ada_err client_cmd_finish_put(struct server_req *req)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;

	client_rev_rest_put(state, req->buf, req->len, hc->body_buf_len);
	return AE_OK;
}

/*
 * Start a reverse-REST command to the internal server.
 * state->cmd and state->cmd_req have been partly set up with the request.
 * This is called for LAN mode as well as for ADS commands.
 */
void client_rev_rest_cmd(struct http_client *hc, u8 cmd_priv)
{
	struct client_state *state = &client_state;
	struct server_req *cmd_req = &state->cmd_req;
	const char *method = state->cmd.method;
	char *resource = state->cmd.resource;
	const struct url_list *tt;
	char buf[SERVER_BUFLEN];

	memset(&prop_recvd, 0, sizeof(prop_recvd));
	cmd_req->buf = buf;
	cmd_req->post_data = state->cmd.data;
	state->cmd.output_len = 0;

	CLIENT_LOGF(LOG_DEBUG2, "resource %s", resource);

	tt = server_find_handler(cmd_req, resource, server_parse_method(method),
	    cmd_priv);
	ASSERT(tt);
	cmd_req->url = tt;

	/*
	 * Start reverse-REST request.
	 * Drop client lock during the reverse-REST.
	 * The client won't re-use cmd_req because either cmd_pending or
	 * lan_cmd_pending are set.
	 */
	ASSERT(state->cmd_pending || state->lan_cmd_pending);
	client_unlock();
	tt->url_op(cmd_req);
	if (!cmd_req->user_in_prog && cmd_req->err == AE_OK) {
		CLIENT_LOGF(LOG_DEBUG2, "finish write");
		cmd_req->finish_write(cmd_req);
	}
	client_lock();
}

/*
 * Execute the cmd request from ADS or LAN.  The cmd will PUT back the result
 */
static void client_cmd_put(struct client_state *state)
{
	struct server_req *cmd_req = &state->cmd_req;
	struct http_client *hc;

	server_req_init(cmd_req);
	ASSERT(client_locked);
	cmd_req->put_head = client_cmd_put_head;
	cmd_req->write_cmd = client_cmd_flush;
	cmd_req->finish_write = client_cmd_finish_put;
	cmd_req->admin = 1;
	hc = client_req_ads_new();

	client_rev_rest_cmd(hc, ADS_REQ);
}

/*
 * Common error handling for client send callbacks.
 */
static void client_send_next(struct http_client *hc, enum ada_err err)
{
	struct client_state *state = &client_state;

	if (hc->user_in_prog) {
		return;
	}
	if (err == AE_OK) {
		if (hc->sending_chunked && !hc->chunked_eof) {
			client_prop_send_done(state, 1, NULL, NODES_ADS, hc);
			return;
		}
		hc->sending_chunked = 0;
		if (state->conn_state == CS_WAIT_GET) {
			state->np_event = 0;
		}
		http_client_send_complete(hc);
	} else if (err != AE_BUF) {
		if (state->conn_state == CS_WAIT_POST &&
		    err != AE_BUSY) {
			/* non-recoverable error */
			client_prop_send_done(state, 0, NULL, NODES_ADS, hc);
		}
		hc->prop_callback = 0;
		client_retry(state);
	}
}

/*
 * Start a POST for sending echo of a property.
 */
static int client_post_echo(struct client_state *state)
{
	struct prop_recvd *echo_prop;
	struct prop *prop;

	if (!(state->echo_dest_mask & NODES_ADS)) {
		return -1;
	}
	echo_prop = state->echo_prop;
	ASSERT(echo_prop);
	state->http_lan = NULL;

	prop = &echo_prop->prop;
	prop->name = echo_prop->name;
	prop->val = echo_prop->val;
	prop->len = echo_prop->prop.len;
	prop->type = echo_prop->type;
	prop->echo = 1;

	client_send_data_int(prop, 1);
	return 0;
}

/*
 * Send callback for additional property POST data.
 */
void client_send_post(struct http_client *hc)
{
	struct client_state *state = &client_state;
	enum ada_err err;

	state->conn_state = CS_WAIT_POST;
	hc->prop_callback = 1;
	state->http_lan = NULL;
	/* note: this callback might actually do a GET */
	err = state->prop_send_cb(PROP_CB_BEGIN, NULL);
	client_send_next(hc, err);
}

/*
 * Reset the mcu overflow flag (in case its set)
 */
void client_reset_mcu_overflow(void)
{
	client_state.mcu_overflow = 0;
}

/*
 * There are properties to send.
 * This is called by the prop module when a property changes value.
 */
void client_send_callback_set(enum ada_err (*callback)(enum prop_cb_status stat,
				void *arg), u8 dest_mask)
{
	struct client_state *state = &client_state;
	struct ada_lan_conf *lcf = &ada_lan_conf;
	struct http_client *hc = &state->http_client;
	struct prop_recvd *prop = &prop_recvd;

	if (!callback) {
		return;
	}
	client_lock();
	state->prop_send_cb = callback;
	state->failed_dest_mask = 0;
	state->mcu_overflow = 0;

	if (state->conn_state == CS_WAIT_POST &&
	    hc->sending_chunked == 1) {
		/* in the middle of a FILE property upload */
		state->dest_mask = NODES_ADS;
		client_send_post(hc);
		goto unlock;
	}
	state->dest_mask = state->valid_dest_mask;
	if (!dest_mask && !lcf->enable) {
		/* Try sending to ADS even if we're not connected */
		state->dest_mask |= NODES_ADS;
	} else if (dest_mask) {
		state->dest_mask &= dest_mask;
		state->failed_dest_mask = dest_mask &
		    ~state->valid_dest_mask;
	}

	if (callback == prop_dp_put && (!state->wait_for_file_put ||
	    !prop->is_file ||
	    strcmp(prop_dp_put_get_loc(), prop->file_info.location))) {
		/* if host mcu tries to do a dp put without us expecting it */
		goto unexp_op;
	}
	if (state->wait_for_file_put && (callback != prop_dp_put &&
	    callback != prop_dp_put_close)) {
unexp_op:
		/*
		 * the host MCU must follow a DP create with a DP put
		 * at that same location
		 * if the user doesn't, reply back with a nak and clear
		 * state the mcu must now do "create" again if it wants
		 * to post up a dp
		 */
		state->wait_for_file_put = 0;
		state->unexp_op = 1;
		client_prop_send_done(state, 0, NULL, state->dest_mask, hc);
		goto unlock;
	}

	if (!state->dest_mask) {
		client_connectivity_update();
		client_prop_send_done(state, 0, NULL, 0, hc);
		goto unlock;
	}
	if (state->dest_mask & NODES_ADS) {
		http_client_set_retry_limit(hc, -1);
		if (state->conn_state == CS_WAIT_RETRY ||
		    state->conn_state == CS_WAIT_CONN) {
			client_close(state);
			state->conn_state = CS_WAIT_EVENT;
		}
	}
	client_wakeup();
unlock:
	client_unlock();
}

/*
 * Aborts any ongoing file operations
 */
void client_abort_file_operation(void)
{
	struct client_state *state = &client_state;
	struct prop_recvd *prop = &prop_recvd;

	client_lock();
	if (state->tgt == CCT_FILE_PROP_SERVER && state->wait_for_file_get) {
		state->get_echo_inprog = 0;
	}
	client_close(state);
	state->conn_state = CS_WAIT_EVENT;
	state->wait_for_file_put = 0;
	state->wait_for_file_get = 0;
	prop->is_file = 0;
	state->prop_send_cb = NULL;
	state->dest_mask = 0;
	state->failed_dest_mask = 0;
	client_wakeup();
	client_unlock();
}

/*
 * Callback from TCP when connection fails or gets reset.
 * If its an HTTP error, ask prop to send a NAK to MCU.
 * Otherwise, retry forever.
 */
static void client_err_cb(struct http_client *hc)
{
	struct client_state *state = &client_state;
	struct ada_lan_conf *lcf = &ada_lan_conf;

	ASSERT(client_locked);
	client_timer_cancel(&state->req_timer);

	if (state->conn_state == CS_WAIT_GET) {
		state->get_echo_inprog = 0;
		state->np_event = 1;
		//state->get_all = 1; /* properties might've been dropped */
		state->get_all = 0;
		if (state->get_cmds_fail) {
			/*
			 * protection against the case where GET cmds
			 * keeps failing. reset the np_event flag
			 * after some time and try again.
			 */
			client_timer_set(&state->cmd_timer,
			    CLIENT_CMD_RETRY_WAIT);
			state->np_event = 0;
			goto next_step;
		}
		state->get_cmds_fail = 1;
	}

	/*
	 * if an error occurs while doing a DP PUT, clear out all state from
	 * module. the host mcu must restart the dp
	 */
	if (state->wait_for_file_put || state->wait_for_file_get) {
		state->wait_for_file_put = 0;
		state->wait_for_file_get = 0;
		memset(&prop_recvd, 0, sizeof(prop_recvd));
	}

	switch (hc->hc_error) {
	case HC_ERR_CONN_CLSD:
		/* connection closed at the same time we were trying a req */
		/* so just try the request again */
		goto next_step;
		break;
	case HC_ERR_TIMEOUT:
		/*
		 * DEV-1911: Timeout may have happened due trying to echo
		 * prop to LAN in this case don't set mcu_overflow
		 */
		if (!state->get_echo_inprog) {
			state->mcu_overflow = 1;
		}
		if (state->request == CS_GET_CMDS) {
			prop_mgr_event(PME_TIMEOUT, NULL);
		} else {
			client_prop_send_done(state, 0, NULL, NODES_ADS, hc);
		}
		goto next_step;
		break;
	case HC_ERR_HTTP_STATUS:
		/*
		 * If authentication failed, clear out the auth header
		 * to force re-authentication.
		 * Also, fix the time if it's provided.
		 */
		if (hc->http_state.status == HTTP_STATUS_UNAUTH &&
		    hc->client_auth) {
			if (state->tgt == CCT_IMAGE_SERVER) {
				state->ota.auth_fail = 1;
			}
			if (hc->server_time) {
				client_clock_set(hc->server_time, CS_SERVER);
			} else if (hc->auth_hdr[0] == '\0') {
				client_log(LOG_WARN "permanent auth failure");
				goto auth_error;
			}
			hc->auth_hdr[0] = '\0';
			goto next_step;
		}
		/* fall-through */
	case HC_ERR_HTTP_PARSE:
	case HC_ERR_HTTP_REDIR:
		switch (state->conn_state) {
		case CS_WAIT_OTA_GET:
			ada_ota_report_int(state->ota.type, PB_ERR_GET);
			break;
		case CS_WAIT_CMD_PUT:
			state->cmd_pending = 0;
			break;
		case CS_WAIT_OTA_PUT:
			ada_ota_report_int(state->ota.type, 0);
			break;
		case CS_WAIT_CMD_STS_PUT:
			client_ota_set_sts_rpt(state, HTTP_STATUS_OK);
			break;
		case CS_WAIT_LANIP_GET:
			lcf->enable = 0;
			break;
		case CS_WAIT_ID:
			client_get_dev_id_pend(state);
			goto retry;
		case CS_WAIT_ECHO:
		case CS_WAIT_GET:
		case CS_WAIT_PING:
		case CS_WAIT_REG_WINDOW:
			goto retry;
		default:
			client_prop_send_done(state, 0, hc, NODES_ADS, hc);
			break;
		}
next_step:
		client_req_close(&state->cmd_req);
		state->request = CS_IDLE;
		state->conn_state = CS_WAIT_EVENT;
		client_wakeup();
		break;
	default:
		if (state->tgt == CCT_IMAGE_SERVER || state->tgt == CCT_LAN ||
		    state->tgt == CCT_REMOTE) {
			if (state->retries > 5) {
				if (state->tgt == CCT_LAN) {
					/*
					 * For LAN OTA we send status to LAN
					 * server. So drop status if connection
					 * fails.
					 */
					state->ota.http_status = 0;
					state->ota_server.lan = 0;
					client_ota_cleanup(state);
				} else {
					ada_ota_report_int(state->ota.type,
					    PB_ERR_CONNECT);
				}
			}
			client_retry(state);
			break;
		}
retry:
		if (state->conn_state == CS_WAIT_CONN) {
			client_event_send(AE_NOTCONN);
			net_dns_delete_host(hc->host);	/* redo DNS */
			net_dns_servers_rotate();
		}
		state->ads_listen = 0;
		if (state->valid_dest_mask & NODES_ADS) {
			state->valid_dest_mask &= ~NODES_ADS;
			client_connectivity_update();
			client_notify_stop(state);
			state->serv_conn = 0;
		}
		client_prop_send_done(state, 0, NULL, NODES_ADS, hc);
		if (state->echo_dest_mask & NODES_ADS) {
			prop_mgr_event(PME_ECHO_FAIL, state->echo_prop->name);
		}
		client_finish_echo(state, NODES_ADS);
		state->serv_conn = 0;

		if (state->tgt == CCT_ADS && hc->hc_error == HC_ERR_CONNECT &&
		    clock_source() <= CS_HTTP) {
			state->current_request = NULL;
			state->ping_time = 1;
			state->request = CS_IDLE;
			state->conn_state = CS_WAIT_EVENT;
			client_wakeup();
			break;
		}

		if (state->ota.in_prog == COS_IN_PROG &&
		    state->ota_server.lan) {
			client_wakeup();	/* allow LAN activity */
		} else if (state->conn_state != CS_ERR) {
			client_retry(state);
		}
		break;
	}
	return;

	/*
	 * On authentication or other errors, ADS is unreachable, but LAN could
	 * still be used.
	 */
auth_error:
	if (state->conn_state == CS_WAIT_ID) {
		client_get_dev_id_pend(state);
	}
	hc->hc_error = WIFI_ERR_CLIENT_AUTH;
	client_tcp_recv_done(state);
	state->auth_fails++;
	if (state->auth_fails >= CLIENT_AUTH_FAILS) {
		state->conn_state = CS_ERR;
	}
	goto retry;
}

/*
 * Returns non-zero if the client is disabled or not configured.
 */
static int client_disabled(struct client_state *state)
{
	struct http_client *hc = &state->http_client;
	struct ada_conf *cf = &ada_conf;

	if (!cf->enable || hc->host[0] == '\0') {
		client_close(state);
		client_notify_stop(state);
		state->conn_state = CS_DISABLED;
		state->valid_dest_mask &= ~NODES_ADS;
		return -1;
	}
	return 0;
}

/*
 * Start client state machine by getting ADS host DNS address.
 */
static void client_start(struct client_state *state, struct http_client *hc)
{
	if (client_disabled(state)) {
		return;
	}

	state->conn_state = CS_WAIT_CONN;
	hc->sending_chunked = 0;
	hc->prop_callback = 0;
	hc->user_in_prog = 0;
	http_client_start(hc);
}

/*
 * Set the server name.
 * This determines whether to use the configured server
 * or the OEM-specific server name in release builds.
 */
static void client_commit_server(struct client_state *state)
{
	struct http_client *hc = &state->http_client;
	struct ada_conf *cf = &ada_conf;
	const struct hostname_info *host_entry;

	if (client_conf_server_change_en() && cf->conf_server[0] != '\0') {
		snprintf(hc->host, sizeof(hc->host), "%s", cf->conf_server);
	} else {
		host_entry = client_lookup_host(cf->region);
		if (!host_entry) {
			host_entry = SERVER_HOSTINFO_DEFAULT;
		}

		if (oem[0] && oem_model[0] && !cf->conf_serv_override) {
			snprintf(hc->host, sizeof(hc->host),
			    CLIENT_SERVER_HOST_OEM_FMT,
			    oem_model, oem, host_entry->domain);
		} else {
			snprintf(hc->host, sizeof(hc->host),
			    CLIENT_SERVER_HOST_DEF_FMT, host_entry->domain);
		}
	}
	hc->ssl_enable = 1;
	hc->host_port = cf->conf_port;
	hc->accept_non_ayla = 0;
	hc->client_auth = 1;
}

int client_set_server(const char *host)
{
	struct client_state *state = &client_state;
	struct ada_conf *cf = &ada_conf;
	size_t len;

	len = strlen(host);
	if (len > sizeof(cf->conf_server) - 1) {
		return -1;
	}
	client_lock();
	memcpy(cf->conf_server, host, len);
	cf->conf_server[len] = '\0';
	client_commit_server(state);
	client_unlock();
	return 0;
}

/*
 * Set region for server.
 * Returns non-zero on error.
 */
int client_set_region(const char *region)
{
	struct ada_conf *cf = &ada_conf;
	const struct hostname_info *new_host;

	if (region[0] == '\0') {
		cf->region = NULL;
		return 0;
	}
	new_host = client_lookup_host(region);
	if (!new_host) {
		return -1;
	}
	cf->region = new_host->region;
	return 0;
}

/*
 * Allow client to fetch prop and cmd updates from ADS
 */
void client_enable_ads_listen(void)
{
	struct client_state *state = &client_state;

	client_lock();
	if ((state->valid_dest_mask & NODES_ADS) && !state->ads_listen) {
		client_log(LOG_INFO "listen enabled");
		client_timer_cancel(&state->cmd_timer);
		state->ads_listen = 1;
		client_wakeup();
	}
	client_unlock();
}

/*
 * Clear out any state left over from an earlier connection.
 */
static void client_reset(struct client_state *state)
{
	struct http_client *hc = &state->http_client;
	struct ada_conf *cf = &ada_conf;

	client_timer_cancel(&state->req_timer);
	client_timer_cancel(&state->cmd_timer);
	client_timer_cancel(&state->poll_timer);
	client_timer_cancel(&state->listen_timer);

	http_client_reset(hc, MOD_LOG_CLIENT, client_metric_get());
	hc->client_send_data_cb = NULL;
	hc->client_err_cb = client_err_cb;
	hc->client_tcp_recv_cb = NULL;
	hc->client_next_step_cb = client_next_step_cb;
	state->client_key[0] = '\0';
	cf->reg_token[0] = '\0';
	state->get_all = cf->get_all;
	state->np_event = 1;
	state->np_any_event = 0;
	state->np_up_once = 0;
	state->ads_listen = 0;
	state->auth_fails = 0;
	state->retries = 0;
	state->buf_len = 0;
	state->wait_for_file_put = 0;
	state->wait_for_file_get = 0;
	client_notify_stop(state);
	client_close(state);
	client_commit_server(state);
}

/*
 * Reset the connection to the server, if up
 * Called when the OEM ID, OEM model, or region change.
 */
void client_server_reset(void)
{
	struct client_state *state = &client_state;

	client_lock();
	if (state->conn_state != CS_DOWN) {
		client_reset(state);
		client_connectivity_update_cb(state);	/* unlocks / relocks */
		client_start(state, &state->http_client);
	}
	client_unlock();
}

/*
 * Indicate that the configuration may have been changed by the platform.
 */
void client_commit(void)
{
	struct client_state *state = &client_state;

	client_lock();
	client_reset(state);
	if (state->conn_state != CS_DOWN) {
		client_start(state, &state->http_client);
	}
	client_unlock();
}

/*
 * Set the hardware ID if the platform didn't set it.
 */
static void client_init_hw_id_default(struct ada_conf *cf)
{
	int hw_id_len = 17;
	char *hw_id;
	const u8 *mac;

	mac = cf->mac_addr;
	if (!cf->hw_id || !cf->hw_id[0]) {
		hw_id = malloc(hw_id_len);
		if (!hw_id) {
			client_log(LOG_ERR "ada_conf.hw_id not set");
			return;
		}
		snprintf(hw_id, hw_id_len,
		    "mac-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x",
		    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		cf->hw_id = hw_id;
	}
}

/*
 * ada_client_up - start connection to service.
 * Returns non-zero if disabled or not configured.
 */
int ada_client_up(void)
{
	struct client_state *state = &client_state;
	struct ada_conf *cf = &ada_conf;
	char ip[30];
	const u8 *mac;

	if (!conf_sys_dev_id[0]) {
		client_log(LOG_ERR "conf_sys_dev_id not set");
		return -1;
	}
	mac = cf->mac_addr;
	if (!(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5])) {
		client_log(LOG_ERR "ada_conf.mac_addr not set");
		return -1;
	}
	client_lock();
	if (state->conn_state != CS_DOWN && state->conn_state != CS_DISABLED) {
		client_unlock();
		return 0;
	}
	client_reset(state);
	if (client_disabled(state)) {
		client_unlock();
		return -1;
	}
	client_event_send(AE_IN_PROGRESS);
	CLIENT_LOGF(LOG_INFO, "IP %s",
	    ipaddr_ntoa_r(&netif_default->ip_addr, ip, sizeof(ip)));
	client_get_dev_id_pend(state);
	state->conn_state = CS_WAIT_EVENT;
	client_wakeup();
	client_unlock();
	return 0;
}

static void client_down_locked(void)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;

	client_notify_stop(state);
	state->conn_state = CS_DOWN;
	state->current_request = NULL;
	hc->client_err_cb = NULL;
	client_prop_send_done(state, 0, NULL, state->valid_dest_mask, hc);
	client_close(state);
	client_logging(0);
	client_lan_reset(state);
	state->valid_dest_mask = 0;
	state->failed_dest_mask = 0;
	state->echo_dest_mask = 0;
	state->get_echo_inprog = 0;
	state->lan_cmd_pending = 0;
	client_connectivity_update();
}

void ada_client_down(void)
{
	client_lock();
	client_down_locked();
	client_unlock();
}

static const struct url_list client_urls[] = {
	URL_GET_ARG("/client", server_send_static, LOC_REQ | REQ_KEEPOPEN,
	    &client_regtoken_html_buf),
	URL_GET("/config.json", conf_json_get, ADS_REQ),
	URL_PUT("/config.json", conf_json_put, ADS_REQ),
	URL_PUT("/logclient.json", client_log_client_json_put, ADS_REQ),
	URL_GET("/regtoken.json", client_json_regtoken_get, LOC_REQ | APP_REQ),
	URL_GET("/status.json", client_json_status_get,
	    REQ_SOFT_AP | APP_ADS_REQS),
	URL_GET_ARG("/style.css", server_send_static,
	    LOC_REQ | REQ_KEEPOPEN | REQ_SOFT_AP, &server_custom_css_buf),
	URL_GET("/time.json", client_json_time_get, APP_ADS_REQS),
	URL_PUT("/getdsns.json", client_json_getdsns_put, ADS_REQ),
	URL_PUT("/time.json", client_json_time_put, REQ_SOFT_AP),
	URL_GET("/property.json", prop_page_json_get_one, APP_REQ),
	URL_PUT("/lanip.json", client_lanip_json_put, ADS_REQ),
#ifndef DISABLE_LAN_OTA
	URL_PUT("/lanota.json", client_lanota_json_put, LOC_REQ | REQ_SOFT_AP),
#endif
	URL_PUT("/registration.json", client_registration_json_put, ADS_REQ),
	URL_PUT("/reset.json", client_reset_json_put, ADS_REQ),
	{ 0 }
};

void client_init(void)
{
	struct client_state *state = &client_state;
	struct ada_conf *cf = &ada_conf;
	struct ada_lan_conf *lcf = &ada_lan_conf;
	const struct client_cb_handler *cbh;
	unsigned int i;

	client_log(LOG_INFO LOG_EXPECTED "%s", ada_version_build);

	client_init_hw_id_default(cf);

	cf->conf_port = HTTP_CLIENT_SERVER_PORT_SSL;
	cf->poll_interval = CLIENT_POLL_INTERVAL;
	lcf->keep_alive = CLIENT_LAN_KEEPALIVE;

	/*
	 * Allocate request queues.
	 */
	state->callback_queue[CQP_HIGH] =
	    net_callback_queue_new(CLIENT_HIGH_QLEN);
	state->callback_queue[CQP_DEF] =
	    net_callback_queue_new(CLIENT_DEF_QLEN);
	state->callback_queue[CQP_LOW] =
	    net_callback_queue_new(CLIENT_LOW_QLEN);

	/*
	 * Init timers.
	 */
	timer_init(&state->cmd_timer, client_cmd_timeout);
	timer_init(&state->listen_timer, client_listen_warn);
	timer_init(&state->poll_timer, client_poll);
	timer_init(&state->req_timer, client_timeout);
	timer_init(&state->lan_reg_timer, client_lan_reg_timeout);

	/*
	 * Initialize callbacks.
	 */
	for (cbh = client_cb_handlers, i = 0; i < ARRAY_LEN(client_cb_handlers);
	     cbh++, i++) {
		if (cbh->func) {
			net_callback_init(&client_cb[i], cbh->func, state);
		}
	}
	state->aes_dev = adc_aes_open();

	np_init(client_notify);
	log_client_init();
	net_callback_init(&state->next_step_cb, client_next_step, NULL);
	net_callback_init(&state->notify_cb, client_notify_cb, NULL);
	client_prop_init(state);
	server_add_urls(client_urls);
	client_lan_init();
}

/*
 * Get config page
 */
void client_page_get(struct server_req *req)
{
	struct ada_conf *cf = &ada_conf;

	if (!client_conf_server_change_en()) {
		server_get_not_found(req);
		return;
	}
	server_banner(req, "Service Configuration");
	char *prod_checked = "";
	char *stage_checked = "";
	char *other_checked = "";
	if (strcmp(cf->conf_server, CLIENT_SERVER_DEFAULT) == 0) {
		prod_checked = "checked";
	} else if (strcmp(cf->conf_server, CLIENT_SERVER_STAGE) == 0) {
		stage_checked = "checked";
	} else {
		other_checked = "checked";
	}

	server_put(req, "<br><table>"
	    "<caption><h4>Device Service Configuration</h4></caption>\n"
	    "<tr><td>DSN<td>%s\n"
	    "<form method=post>\n"
	    "<tr><td>Server Host Name"
	    "<td><input type=\"radio\" name=host value=\"prod\" "
	    "%s /> Production (" CLIENT_SERVER_DEFAULT ")\n"
	    "<tr><td>"
	    "<td><input type=\"radio\" name=host value=\"stage\" "
	    "%s /> Staging (" CLIENT_SERVER_STAGE ")\n"
	    "<tr><td>"
	    "<td><input type=\"radio\" name=host value=\"other\" "
	    "%s /> Other <input name=custom_host size=40 value=\"%s\">\n"
	    "<tr><td>Poll Interval<td>"
	    "<input name=poll_interval size=4 value=\"%u\">"
	    "seconds (0 to disable)\n"
	    "<tr><td>Enable Data Service"
	    "<td><input type=checkbox name=enable%s>\n"
	    "</table>\n"
	    "<br><input type=submit><br>\n"
	    "</form>\n"
	    "</body></html>\n",
	    conf_sys_dev_id,
	    prod_checked, stage_checked, other_checked,
	    cf->conf_server, cf->poll_interval,
	    cf->enable ? " checked" : "");
}

/*
 * Post config changes.
 */
void client_page_post(struct server_req *req)
{
	struct ada_conf *cf = &ada_conf;
	char *host;
	long poll = 0;
	char buf[100];

	if (!client_conf_server_change_en()) {
		server_get_not_found(req);
		return;
	}

	cf->enable = server_get_bool_arg_by_name(req, "enable");

	if (!server_get_long_arg_by_name(req, "poll_interval", &poll)) {
		if (poll > MAX_U16 || (poll != 0 && poll < CLIENT_POLL_MIN)) {
			poll = CLIENT_POLL_MIN;
			client_log(LOG_WARN "page_post: bad poll_interval");
		}
		cf->poll_interval = poll;
	}

	host = server_get_arg_by_name(req, "host", buf, sizeof(buf));
	if (strcmp(host, "prod") == 0) {
		client_set_server(CLIENT_SERVER_DEFAULT);
	} else if (strcmp(host, "stage") == 0) {
		client_set_server(CLIENT_SERVER_STAGE);
	} else {
		string_strip(host, cf->conf_server,
		    sizeof(cf->conf_server) - 1);
	}

	host = server_get_arg_by_name(req, "custom_host", buf, sizeof(buf));
	if (host) {
		snprintf(cf->conf_server, sizeof(cf->conf_server), "%s", host);
	}

	cf->poll_interval = poll;
	client_commit();
	client_page_get(req);
}

void client_json_status_get(struct server_req *req)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;
	struct ada_conf *cf = &ada_conf;
	char sys_mac[20];
	enum ada_wifi_features features;

	features = adap_wifi_features_get();
	format_mac(cf->mac_addr, sys_mac, sizeof(sys_mac));
	server_json_header(req);
	server_put(req, "{\"DSN\":\"%s\","	/* "DSN" for compatibility */
	    "\"dsn\":\"%s\","			/* "dsn" is standard */
	    "\"model\":\"%s\","
	    "\"api_version\":\"1.0\","
	    "\"device_service\":\"%s\","
	    "\"mac\":\"%s\","
	    "\"last_connect_mtime\":%ld,"
	    "\"mtime\":%ld,"
	    "\"version\":\"%s\","
	    "\"build\":\"%s\","
	    "\"features\":["
	    "%s%s%s"
	    "\"rsa-ke\""
	    "]}",
	    conf_sys_dev_id, conf_sys_dev_id, conf_sys_model,
	    hc->host, sys_mac, state->connect_time,
	    clock_ms(), adap_conf_sw_version(), adap_conf_sw_build(),
	    (features & AWF_SIMUL_AP_STA) ? "\"ap-sta\"," : "",
	    (features & AWF_WPS) ? "\"wps\"," : "",
	    (features & AWF_WPS_APREG) ? "\"wps-apreg\"," : "");
}

void client_json_regtoken_get(struct server_req *req)
{
	struct client_state *state = &client_state;
	struct ada_conf *cf = &ada_conf;
	char buf[CLIENT_CONF_REG_TOK_LEN + 4];
	const char *reg_token = "null";

	server_json_header(req);

	client_lock();
	if (cf->reg_token[0] != '\0' &&
	    strcasecmp(state->reg_type, "Display")) {
		snprintf(buf, sizeof(buf), "\"%s\"", cf->reg_token);
		reg_token = buf;
	}
	server_put(req,
	    "{\"regtoken\":%s,\"registered\":%u,\"registration_type\":\"%s\","
	    "\"host_symname\":\"%s\"}",
	    reg_token, cf->reg_user, state->reg_type,
	    cf->host_symname);
	client_unlock();
}

void client_json_time_get(struct server_req *req)
{
	char buf[24];
	u32 utc_time = clock_utc();

	clock_fmt(buf, sizeof(buf), clock_local(&utc_time));
	server_json_header(req);
	server_put(req, "{\"time\":%lu,\"mtime\":%lu,\"set_at_mtime\":%lu,"
	    "\"clksrc\":%d,\"localtime\":\"%s\",\"timezone\":%d,"
	    "\"daylight_active\":%u,\"daylight_change\":%lu}",
	    utc_time, clock_ms(), clock_set_mtime, clock_source(), buf,
	    timezone_info.valid ? timezone_info.mins : 0,
	    daylight_info.valid ? daylight_info.active : 0,
	    daylight_info.valid ? daylight_info.change : 0);
}

void client_json_time_put(struct server_req *req)
{
	jsmn_parser parser;
	unsigned long val;
	jsmntok_t tokens[4];
	jsmnerr_t err;

	jsmn_init_parser(&parser, req->post_data, tokens, 4);
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		CLIENT_LOGF(LOG_WARN, "jsmn err %d", err);
		goto inval;
	}
	if (jsmn_get_ulong(&parser, NULL, "time", &val)) {
		CLIENT_LOGF(LOG_WARN, "bad time");
		goto inval;
	}
	CLIENT_DEBUG(LOG_DEBUG2, "val %lu", val);
	client_lock();
	client_clock_set(val, CS_LOCAL);
	client_unlock();
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
	return;
inval:
	server_put_status(req, HTTP_STATUS_BAD_REQ);
}

/*
 * Refetch of key requested, after completing this command.
 */
void client_json_getdsns_put(struct server_req *req)
{
	struct client_state *state = &client_state;

	client_lock();
	client_get_dev_id_pend(state);
	client_unlock();
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
}

enum wifi_error client_status(void)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;
	enum wifi_error error;

	switch (hc->hc_error) {
	case HC_ERR_NONE:
		error = WIFI_ERR_CLIENT_TIME;
		break;
	case HC_ERR_DNS:
		error = WIFI_ERR_CLIENT_DNS;
		break;
	case HC_ERR_MEM:
		error = WIFI_ERR_MEM;
		break;
	case HC_ERR_CLIENT_AUTH:
		error = WIFI_ERR_CLIENT_AUTH;
		break;
	default:
		error = WIFI_ERR_TIME;
		break;
	}
	return error;
}

/*
 * Return the server name being used.
 * This is not necessarily the one that's configured.
 */
const char *client_host(void)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &state->http_client;
	struct ada_conf *cf = &ada_conf;

	if (!cf->enable) {
		return "";
	}
	return hc->host;
}

void client_set_setup_token(const char *token)
{
	struct client_state *state = &client_state;

	client_lock();
	snprintf(state->setup_token, sizeof(state->setup_token) - 1,
	    "%s", token);
	state->client_info_flags |= CLIENT_UPDATE_SETUP;
	client_unlock();
}

void client_set_setup_location(char *token)
{
	struct client_state *state = &client_state;

	/* free has no effect if setup_location is null */
	free(state->setup_location);
	state->setup_location = token;
}

void client_set_sym_hostname(char *name, int len)
{
	struct client_state *state = &client_state;
	struct ada_conf *cf = &ada_conf;

	client_lock();
	if (len >= sizeof(cf->host_symname) - 1) {
		len = sizeof(cf->host_symname) - 1;
	}
	memcpy(cf->host_symname, name, len);
	cf->host_symname[len] = '\0';
	state->client_info_flags |= CLIENT_UPDATE_PRODUCT_NAME;
	client_unlock();
}

/*
 * Return current connectivy information
 */
u8 client_get_connectivity_mask(void)
{
	return client_state.valid_dest_mask;
}

/*
 * Return 1 if the LAN mode is enabled in client
 */
int client_lanmode_is_enabled(void)
{
	return ada_lan_conf.enable;
}

/*
 * Start registration window.
 * This may be called in another thread.
 */
void client_reg_window_start(void)
{
	client_lock();
	client_log(LOG_DEBUG "reg start pending %u",
	   client_step_is_enabled(ADCP_REG_WINDOW_START));
	client_step_enable(ADCP_REG_WINDOW_START);
	client_wakeup();
	client_unlock();
}
