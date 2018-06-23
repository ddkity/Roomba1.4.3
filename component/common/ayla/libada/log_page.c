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
#include <sys/types.h>

#include <ayla/utypes.h>
#include <ayla/endian.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/clock.h>
#include <ayla/uri_code.h>
#include <ayla/xml.h>
#include <ayla/json.h>
#include <ayla/tlv.h>
#include <ayla/parse.h>
#include <ayla/http.h>
#include <jsmn.h>
#include <ayla/jsmn_get.h>
#include <ada/prop.h>
#include <net/net.h>
#include <net/ada_mbuf.h>
#include <ada/server_req.h>
#include <ada/log_page.h>
#include <ayla/conf.h>
#include <ada/ada_conf.h>

#define LOG_SNAP_CT	20		/* maximum snapshot infos */

const char * const log_sevs[] = LOG_SEVS;

#define LOG_MASK_ALL	(BIT(LOG_SEV_LIMIT) - 1)
#define LOG_MASK_USED	(LOG_MASK_ALL & ~(BIT(LOG_SEV_NONE) | \
			    BIT(LOG_SEV_FAIL) | BIT(LOG_SEV_PASS)))

/*
 * Number of on-stack JSMN tokens needed for PUT of mods.json.
 * Overall Structure = 3 tokens
 * Each Severity Level = 3 tokens
 * Each Mod's Structure = 5 tokens
 * Total # of Tokens = (3 + (int)__MOD_LOG_LIMIT * 5 * (int)LOG_SEV_LIMIT * 3)
 * Total too big. Limit changes to 1 mod per PUT. mod can be "all" to change
 * all mods.
 */
#define LOG_TOKENS	(3 + 5 * (int)LOG_SEV_LIMIT * 3)

static void log_page_iterate(struct server_req *req, u8 snapshot, u32 lines,
		void (*func)(struct server_req *req, struct log_msg_head *head,
		    const char *msg, void *arg), void *arg)
{
	struct log_msg_head *head;
	struct ada_mbuf *mbuf;
	size_t len;
	size_t tlen;
	char *msg;
	int rc = 0;
	char *bp;

	/*
	 * Get log into scratch mbuf.
	 */
	mbuf = ada_mbuf_alloc(LOG_SIZE);
	if (!mbuf) {
		return;
	}
	bp = ada_mbuf_payload(mbuf);
	len = log_buf_get(snapshot, lines, bp, ada_mbuf_len(mbuf), 0);
	if (len < sizeof(*head) + sizeof(struct log_msg_tail)) {
		goto out;
	}
	do {
		head = (struct log_msg_head *)bp;
		if (head->magic != LOG_V2_MAGIC) {
			break;
		}
		msg = (char *)(head + 1);
		tlen = head->len + sizeof(*head) + sizeof(struct log_msg_tail);
		if (tlen > len) {
			msg = "--- invalid log header ---";
			rc = -1;
		} else {
			bp += tlen;
			len -= tlen;
		}
		func(req, head, msg, arg);
	} while (rc == 0 && len > sizeof(*head) + sizeof(struct log_msg_tail));
out:
	ada_mbuf_free(mbuf);
}

/*
 * Iterator called for each log line to produce HTML log page.
 */
static void log_page_get_html(struct server_req *req,
	 struct log_msg_head *head, const char *msg, void *arg)
{
	ssize_t hlen;
	ssize_t xlen;
	char line[LOG_LINE];
	register const char *modname;

	hlen = head->len;
	do {
		xlen = xml_encode(line, sizeof(line), msg, hlen, NULL);
		if (xlen < 0) {
			hlen -= 10;
		}
	} while (xlen < 0 && hlen > 0);
	msg = line;
	if (xlen < 0) {
		msg = "--- line encoding too long ---";
	}
	modname = log_mod_get_name(head->mod_nr);
	server_put(req, "<tr>"
	    "<td align=right>%lu<td>%s<td>%s<td>%s\n",
	    head->mtime, log_sev_get(head->sev),
	    modname ? modname : "", msg);
}

/*
 * Get log.
 */
void log_page_get(struct server_req *req)
{
	char time_buf[22];
	long snapshot = 0;

	server_get_long_arg_by_name(req, "snapshot", &snapshot);
	if (snapshot < 0 || snapshot > LOG_SNAP_CT) {
		goto invalid;
	}

	server_banner(req, "Device Log");
	clock_fmt(time_buf, sizeof(time_buf), clock_utc());
	server_put(req,
	    "<table>"
	    "<tr><td>system time<td>%s"
	    "<tr><td>up time<td>%lu ms"
	    "<tr><td>build<td>%s"
	    "</table>"
	    "<hr>\n",
	    time_buf, clock_ms(),
	    adap_conf_sw_build());
	server_put_pure(req,
	    "<div id=\"log\"><table><caption><h4>Log Messages</h4></caption>"
	    "<thead><tr><th>Time (ms)<th>Severity<th>Sub-system<th>Message"
	    "<tbody>\n");
	log_page_iterate(req, snapshot, LOG_SIZE, log_page_get_html, NULL);
	server_put_pure(req, "</table></div><hr><p>"
	    "<a href=log>refresh</a><p></body></html>\n");
	return;

invalid:
	server_put_status(req, HTTP_STATUS_BAD_REQ);
}

/*
 * Function called for each log line to produce JSON log output.
 */
static void log_page_line_json(struct server_req *req,
	 struct log_msg_head *head, const char *msg, void *arg)
{
	char line[LOG_LINE];
	ssize_t hlen;
	const char **sep = arg;
	register const char *modname;

	hlen = head->len;
	do {
		if (json_format_string(line, sizeof(line), msg, hlen, 1)) {
			break;
		}
		hlen -= 10;
	} while (hlen > 0);
	msg = line;
	if (hlen <= 0) {
		msg = "--- line encoding too long ---";
	}
	modname = log_mod_get_name(head->mod_nr);
	server_put(req, "%s{\"mtime\":%lu,\"mod\":\"%s\",\"severity\":\"%s\","
	    "\"text\":\"%s\"}",
	    *sep, head->mtime, modname ? modname : "",
	    log_sev_get(head->sev), msg);
	*sep = ",";
}

void log_page_json_get(struct server_req *req)
{
	const char *sep = "";
	long lines = MAX_S32;
	long snapshot = 0;

	server_get_long_arg_by_name(req, "snapshot", &snapshot);
	if (snapshot < 0 || snapshot > LOG_SNAP_CT) {
		goto error;
	}
	server_get_long_arg_by_name(req, "count", &lines);
	if (lines <= 0) {
		lines = MAX_S32;
	}

	server_json_header(req);
	server_put(req, "{\"logs\": [");
	log_page_iterate(req, snapshot, lines, log_page_line_json, &sep);
	server_put(req, "]}");
	return;
error:
	server_put_status(req, HTTP_STATUS_BAD_REQ);
}

/*
 * Get log_mods.json
 */
void log_page_mods_json_get(struct server_req *req)
{
	struct log_mod *mod;
	unsigned int mod_nr;
	enum log_sev sev;
	const char *sep = "";
	const char *mod_name;

	server_json_header(req);
	server_put(req, "{\"mods\":[");
	sep = "";
	for (mod = log_mods, mod_nr = 0; mod_nr < LOG_MOD_CT; mod_nr++, mod++) {
		mod_name = log_mod_names[mod_nr];
		if (!mod_name) {
			continue;
		}
		server_put(req, "%s{\"name\":\"%s\",\"levels\":",
		    sep, mod_name);
		sep = "[";
		for (sev = 0; sev < LOG_SEV_LIMIT; sev++) {
			if (!(LOG_MASK_USED & (1 << sev))) {
				continue;
			}
			server_put(req, "%s{\"%s\":%d}",
			    sep, log_sevs[sev], (mod->mask & (1 << sev)) != 0);
			sep = ",";
		}
		server_put(req, "]}");
	}
	server_put(req, "]}");
}

struct log_mask_change {
	u32 value;
	u32 mask;
};

/*
 * Handle one level of a log levels change PUT message.
 * The obj should contain a string naming the level,
 * followed by a boolean value.
 */
static int log_page_mods_json_level(jsmn_parser *parser,
	jsmntok_t *obj, void *arg)
{
	struct log_mask_change *change = arg;
	char level[20];		/* severity level */
	enum log_sev sev;
	jsmntok_t *tok;
	ssize_t len;
	u32 mask;
	unsigned long on;

	if (obj->type != JSMN_OBJECT ||
	    obj + 2 >= parser->tokens + parser->num_tokens) {
		server_log(LOG_WARN "mods_put level non-obj");
		return -1;
	}
	tok = obj + 1;
	if (tok->type != JSMN_STRING) {
		server_log(LOG_WARN "mods_put no level string");
		return -1;
	}
	len = uri_decode_n(level, sizeof(level) - 1,
	    parser->js + tok->start, tok->end - tok->start);
	if (len < 0) {
		server_log(LOG_WARN "mods_put bad level string");
		return -1;
	}
	for (sev = 0; sev < LOG_SEV_LIMIT; sev++) {
		if (log_sevs[sev] && !strcmp(log_sevs[sev], level)) {
			mask = 1 << sev;
			goto found;
		}
	}
	if (strcmp("all", level)) {
		server_log(LOG_WARN "mods_put unknown level \"%s\"", level);
		return 0;	/* ignore for future compatibility */
	}
	mask = LOG_MASK_USED;

	/*
	 * get value.
	 */
found:
	tok++;
	if (jsmn_get_ulong(parser, obj, level, &on)) {
		server_log(LOG_WARN "mods_put level \"%s\": bad value", level);
		return -1;
	}
	change->mask |= mask;
	if (on) {
		change->value |= mask;
	} else {
		change->value &= ~mask;
	}
	return 0;
}

/*
 * Iterator to handle put of log_mods.json mods sub-object.
 */
static int log_page_mods_json_mods(jsmn_parser *parser,
	jsmntok_t *obj, void *dryrun)
{
	jsmntok_t *tok;
	char name[20];		/* module name */
	ssize_t len;
	struct log_mask_change change;
	int rc;

	/*
	 * Get name token.
	 */
	tok = jsmn_get_val(parser, obj, "name");
	if (!tok) {
		server_log(LOG_WARN "mods_put no name");
		return -1;
	}
	len = uri_decode_n(name, sizeof(name) - 1,
	    parser->js + tok->start, tok->end - tok->start);
	if (len < 0) {
		server_log(LOG_WARN "mods_put name failed decode");
		return -1;
	}
	name[len] = '\0';


	/*
	 * Get levels array.
	 */
	tok = jsmn_get_val(parser, obj, "levels");
	if (!tok || tok->type != JSMN_ARRAY) {
		server_log(LOG_WARN "mods_put no levels array");
		return -1;
	}
	change.value = 0;
	change.mask = 0;
	rc = jsmn_array_iterate(parser, tok,
	    log_page_mods_json_level, &change);
	if (rc || dryrun) {
		return rc;
	}
	server_log(LOG_DEBUG "mods_put name \"%s\" change value %lx mask %lx",
	    name, change.value, change.mask);
	if (log_mask_change(name, change.value, change.mask & ~change.value)) {
		server_log(LOG_WARN "mods_put name \"%s\" lookup failed", name);
		return 0;	/* ignore for forward compatibility */
	}
	return 0;
}

/*
 * Put log_mods.json
 * Sets log levels according to the tokens given.
 */
void log_page_mods_json_put(struct server_req *req)
{
	jsmn_parser parser;
	jsmntok_t tokens[LOG_TOKENS];
	jsmntok_t *mods;
	jsmnerr_t err;
	long dryrun;

	jsmn_init_parser(&parser, req->post_data, tokens, LOG_TOKENS);
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		server_log(LOG_WARN "mods_put jsmn err %d", err);
		goto inval;
	}
	mods = jsmn_get_val(&parser, NULL, "mods");
	if (!mods) {
		server_log(LOG_WARN "mods_put no mods array");
		goto inval;
	}
	for (dryrun = 1; dryrun >= 0; dryrun--) {
		if (jsmn_array_iterate(&parser, mods,
		    log_page_mods_json_mods, (void *)dryrun)) {
			server_log(LOG_WARN "mods_put mods array failed");
			goto inval;
		}
	}
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
	return;
inval:
	server_put_status(req, HTTP_STATUS_BAD_REQ);
}

/*
 * Get log_snapshots.json
 */
void log_page_snaps_json_get(struct server_req *req)
{
	struct log_snap snap[LOG_SNAP_CT];
	const char *sep;
	int count;
	int indx;

	server_json_header(req);
	server_put(req, "{\"log_snapshots\":");
	count = log_snap_stat(snap, LOG_SNAP_CT);
	if (count <= 0) {
		server_put(req, "null}");
		return;
	}
	if (count > LOG_SNAP_CT) {
		count = LOG_SNAP_CT;
	}
	sep = "[";
	for (indx = 0; indx < count; indx++) {
		server_put(req,
		    "%s{\"snapshot\":%u,\"time\":%lu,\"size\":%lu}",
		    sep, indx + 1, snap[indx].time, snap[indx].size);
		sep = ",";
	}
	server_put(req, "]}");
}

/*
 * Delete log_snapshots.json
 */
void log_page_snaps_json_delete(struct server_req *req)
{
	log_snap_erase();
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
}

static const struct url_list log_page_get_urls[] = {
	URL_GET("/logs.json", log_page_json_get, APP_ADS_REQS),
	{ 0 }
};

/*
 * Init pages for getting logs.
 */
void log_page_get_init(void)
{
	server_add_urls(log_page_get_urls);
}

static const struct url_list log_page_mods_urls[] = {
	URL_GET("/log_mods.json", log_page_mods_json_get, APP_ADS_REQS),
	URL_PUT("/log_mods.json", log_page_mods_json_put, ADS_REQ),
	{ 0 }
};

/*
 * Init pages for controlling log levels.
 */
void log_page_mods_init(void)
{
	server_add_urls(log_page_mods_urls);
}

static const struct url_list log_page_snaps_urls[] = {
	URL_GET("/log_snapshots.json", log_page_snaps_json_get, APP_ADS_REQS),
	URL_DELETE("/log_snapshots.json", log_page_snaps_json_delete,
	    ADS_REQ),
	{ 0 }
};

/*
 * Init pages to get snapshots.
 */
void log_page_snaps_init(void)
{
	server_add_urls(log_page_snaps_urls);
}
