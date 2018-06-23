/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
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
#include <ayla/conf.h>
#include <ayla/clock.h>
#include <ayla/json.h>
#include <ayla/endian.h>
#include <ayla/json.h>
#include <ayla/wifi_status.h>
#include <ayla/timer.h>
#include <jsmn.h>
#include <ayla/jsmn_get.h>
#include <net/stream.h>
#include <ada/client.h>
#include <ada/prop.h>
#include <ada/server_req.h>
#include <ada/ada_wifi.h>
#include <net/http_client.h>
#include <net/net_crypto.h>
#include <ada/client_ota.h>
#include <ada/ada_lan_conf.h>
#include "notify_int.h"
#include "client_int.h"
#include "client_timer.h"
#include "client_lock.h"

#define LOG_CLIENT_BLACKHOLE_TIME	1000
#define LOG_CLIENT_LOOP_CNT_MAX		3

enum log_client_conn_state {
	LCS_DOWN,
	LCS_DISABLED,	/* network up but client not enabled */
	LCS_WAIT_CONN,	/* wait for connection to service */
	LCS_WAIT_POST,	/* waiting for POST response */
	LCS_WAIT_EVENT,	/* waiting for event or polling interval */
	LCS_WAIT_RETRY,	/* waiting to retry after connection or I/O error */
	LCS_BLACKHOLE,	/* dropping messages */
	LCS_ERR,	/* unable to continue due to error */
};

struct log_client_state {
	enum log_client_conn_state conn_state;
	u8 enable:1;			/* enable log client connections */
	u8 retries;			/* number of attempts to send log */
	u8 loop_cnt;			/* # the times we've had more to send */
	char *uri;
	char buf[LOG_LINE*2];
	struct net_callback callback;
	struct timer timer;
	struct http_client http_client;
};

static struct log_client_state log_client_state;
static void log_client_next_step_cb(struct http_client *hc);
static void log_client_wait(struct log_client_state *, u32);

static void log_client_log(const char *fmt, ...)
{
	ADA_VA_LIST args;

	ADA_VA_START(args, fmt);
	log_put_va(MOD_LOG_LOGGER | LOG_MOD_NOSEND, fmt, args);
	ADA_VA_END(args);
}

/*
 * Close PCB and make sure we're not called back.
 */
static void log_client_close(struct log_client_state *state)
{
	struct http_client *hc = &state->http_client;

	client_timer_cancel(&state->timer);
	http_client_abort(hc);
}

/*
 * Start client state machine by getting ADS host DNS address.
 */
static void log_client_start(struct log_client_state *state)
{
	struct http_client *hc = &state->http_client;

	if (!state->enable || hc->host[0] == '\0') {
		log_client_close(state);
		state->conn_state = LCS_DISABLED;
		return;
	}
	state->retries = 0;
	if (!http_client_is_ready(hc)) {
		return;
	}
	if (state->conn_state == LCS_WAIT_CONN) {
		return;
	}

	hc->body_buf_len = snprintf(state->buf, sizeof(state->buf),
	    "{\"dsn\":\"%s\", \"logs\":[", conf_sys_dev_id);
	hc->body_buf = state->buf;
	hc->body_len = LOG_SIZE;	/* fixed size of output */

	client_unlock();
	http_client_req(hc, HTTP_REQ_POST, state->uri, 1,
	    &http_hdr_content_json);
	client_lock();
	if (hc->req_pending) {
		state->conn_state = LCS_WAIT_CONN;
	}
}

/*
 * TCP timeout for handling re-connect or retry.
 */
static void log_client_timeout(struct timer *timer)
{
	struct log_client_state *state = &log_client_state;

	switch (state->conn_state) {
	case LCS_WAIT_RETRY:
		state->conn_state = LCS_WAIT_EVENT;
		log_client_next_step_cb(&state->http_client);
		break;
	case LCS_BLACKHOLE:
		state->conn_state = LCS_WAIT_EVENT;
		log_buf_reset();
		break;
	default:
		state->conn_state = LCS_ERR;
		log_client_log(LOG_ERR "timeout: unexpected state %x\n",
		    state->conn_state);
		log_client_close(state);
	}
}

/*
 * Schedule reconnect/retry after wait.
 * Called with lock held.
 */
static void log_client_wait(struct log_client_state *state, u32 delay)
{
	client_timer_cancel(&state->timer);

	switch (state->conn_state) {
	case LCS_WAIT_RETRY:
		log_client_log(LOG_DEBUG "wait: RETRY");
		break;
	case LCS_BLACKHOLE:
		log_client_log(LOG_DEBUG "wait: BLACKHOLE");
		break;
	default:
		log_client_log(LOG_DEBUG "wait: unexpected state %x",
		    state->conn_state);
		return;
	}
	if (delay) {
		client_timer_set(&state->timer, delay);
	}
}

static void log_client_retry(struct log_client_state *state)
{
	log_client_close(state);

	if (state->retries < 1) {
		state->conn_state = LCS_WAIT_RETRY;
		log_client_wait(state, CLIENT_RETRY_WAIT1);
	} else {
		log_client_log(LOG_ERR
		    "Unable to connect to log-service..abort..");
		log_client_enable(0);
	}
	if (state->retries < 255) {
		state->retries++;
	}
}

/*
 * Done with current receive.  Decide whether to reconnect or wait.
 * Called with lock held.
 */
static void log_client_next_step_cb(struct http_client *hc)
{
	struct log_client_state *state = &log_client_state;

	if (state->conn_state != LCS_WAIT_EVENT) {
		return;
	}
	if (log_buf_more_to_service()) {
		if (state->loop_cnt < LOG_CLIENT_LOOP_CNT_MAX) {
			log_client_start(state);
			state->loop_cnt++;
		} else {
			state->conn_state = LCS_BLACKHOLE;
			state->loop_cnt = 0;
			log_buf_reset();
			log_client_wait(state, LOG_CLIENT_BLACKHOLE_TIME);
		}
	} else {
		state->loop_cnt = 0;
	}
}

/*
 * Function called for each log line to produce JSON log output.
 */
static size_t log_client_json_log(struct log_msg_head *head,
				char *msg, char *json_msg, u8 comma_needed)
{
	char line[LOG_LINE*2];
	char *line_ptr;

	line_ptr = json_format_string(line, sizeof(line), msg, head->len, 1);
	if (!line_ptr) {
		snprintf(line, sizeof(line), "--- line encoding too long ---");
	}
	snprintf(json_msg, sizeof(line),
	    "%s{\"time\":\"%lu\",\"mod\":\"%s\","
	    "\"level\":\"%s\", \"text\":\"%s\"}",
	    (comma_needed) ? "," : "", head->time,
	    log_mod_get_name(head->mod_nr), log_sev_get(head->sev), line_ptr);
	return strlen(json_msg);
}


/*
 * Post logs to server.
 */
static enum ada_err log_client_post_logs(struct log_client_state *state,
			    struct http_client *hc)
{
	struct log_msg_head *head;
	char log_info[LOG_LINE + sizeof(*head) + sizeof(struct log_msg_tail)];
	char json_msg[LOG_LINE*2];
	size_t len;
	char *msg;
	enum ada_err err;
	u32 padding_needed;

	/*
	 * Add wifi connection history to logs if not already added.
	 */
	adap_wifi_show_hist(1);

	if (hc->req_part <= 1) {
		while (log_buf_more_to_service()) {
			len = log_buf_get(0, 1, log_info, sizeof(log_info), 1);

			if (len < sizeof(*head) +
			    sizeof(struct log_msg_tail)) {
				return AE_INVAL_VAL;
			}
			head = (struct log_msg_head *)log_info;
			msg = (char *)(head + 1);

			/*
			 * Format log line.
			 * req_part == 1 means leading comma needed
			 */
			len = log_client_json_log(head, msg, json_msg,
			    hc->req_part);

			if (hc->sent_len + len > LOG_SIZE - 2) {
				break;
			}
			err = http_client_send(hc, json_msg, len);
			if (err != AE_OK) {
				return err;
			}
			hc->req_part = 1;
			log_buf_incr_serv_out();
		}
		hc->req_part = 2;
	}

	if (hc->req_part == 2) {
		err = http_client_send(hc, "]}", 2);
		if (err != AE_OK) {
			return err;
		}
		hc->req_part = 3;
	}

	if (hc->req_part == 3) {
		if (hc->sent_len > LOG_SIZE) {
			log_client_log(LOG_WARN
			    "post_logs: len of json too big..dropping logs");
			return AE_LEN;
		}
		memset(state->buf, ' ', sizeof(state->buf));
		do {
			padding_needed = LOG_SIZE - hc->sent_len;
			if (padding_needed > sizeof(state->buf)) {
				padding_needed = sizeof(state->buf);
			}
			err = http_client_send(hc, state->buf, padding_needed);
			if (err != AE_OK) {
				return err;
			}
		} while (hc->sent_len < LOG_SIZE);
		hc->req_part = 4;
	}
	return AE_OK;
}

/*
 * Callback from TCP when connected.
 */
static void log_client_send_data_cb(struct http_client *hc)
{
	struct log_client_state *state = &log_client_state;
	enum ada_err err;

	state->conn_state = LCS_WAIT_POST;
	err = log_client_post_logs(state, hc);

	if (err == AE_OK) {
		http_client_send_complete(hc);
	} else if (err != AE_BUF) {
		log_client_retry(state);
	}
}

/*
 * Callback from TCP when non-encrypted data received
 */
static enum ada_err log_client_tcp_recv_cb(struct http_client *hc,
					void *payload, size_t payload_len)
{
	struct log_client_state *state = &log_client_state;

	if (!payload) {
		state->conn_state = LCS_WAIT_EVENT;
		state->retries = 0;
	}
	return AE_OK;
}

/*
 * Callback from TCP when connection fails or gets reset.
 * The PCB is freed by the caller.
 */
static void log_client_err_cb(struct http_client *hc)
{
	struct log_client_state *state = &log_client_state;

	client_timer_cancel(&state->timer);

	switch (hc->hc_error) {
	case HC_ERR_HTTP_PARSE:
	case HC_ERR_HTTP_REDIR:
	case HC_ERR_HTTP_STATUS:
	case HC_ERR_CONN_CLSD:
		state->conn_state = LCS_WAIT_EVENT;
		log_client_next_step_cb(hc);
		break;
	default:
		log_client_retry(state);
		break;
	}
}

/*
 * Callback when a new log needs to be sent up to the service.
 */
static void log_client_send_log(void *arg)
{
	struct log_client_state *state = arg;
	struct http_client *hc = &state->http_client;

	log_client_next_step_cb(hc);
}

/*
 * Must call with interrupts disabled.
 */
void log_client_trycallback(void)
{
	struct log_client_state *state = &log_client_state;

	if (state->enable && state->conn_state == LCS_WAIT_EVENT) {
		client_callback_pend(&state->callback);
	}
}

/*
 * Return non-zero if the log client host has been set.
 */
int log_client_host_set(void)
{
	struct log_client_state *state = &log_client_state;
	struct http_client *hc = &state->http_client;

	return hc->host[0] != '\0';
}

int log_client_enable(int enable)
{
	struct log_client_state *state = &log_client_state;
	struct http_client *hc = &state->http_client;

	if (enable == state->enable) {
		return -1;
	}

	if (enable && log_client_conf_enabled) {
		if (hc->host[0] == '\0') {
			log_client_log(LOG_WARN
			    "logc enable: no host given, can't connect");
			return -1;
		}
		state->enable = 1;
		if (state->conn_state == LCS_DISABLED ||
		    state->conn_state == LCS_DOWN) {
			state->conn_state = LCS_WAIT_EVENT;
			log_client_next_step_cb(hc);
		}
		return 0;
	} else if (!enable) {
		state->enable = 0;
		log_client_close(state);
		state->conn_state = LCS_DISABLED;
		return 0;
	}
	return -1;
}

/*
 * Clear out any state left over from an earlier connection.
 */
void log_client_reset(void)
{
	struct log_client_state *state = &log_client_state;
	struct http_client *hc = &state->http_client;

	client_timer_cancel(&state->timer);
	http_client_reset(hc, MOD_LOG_LOGGER | LOG_MOD_NOSEND, NULL);
	state->conn_state = LCS_DOWN;
	hc->host[0] = '\0';
	state->retries = 0;
	log_client_enable(0);
}

const char *log_client_host(void)
{
	struct log_client_state *state = &log_client_state;
	struct http_client *hc = &state->http_client;

	if (!state->enable) {
		return "";
	}
	return hc->host;
}

/*
 * log client command.
 */
void log_client_cli(int argc, char **argv)
{
	struct log_client_state *state = &log_client_state;
	struct http_client *hc = &state->http_client;

	if (argc == 1) {
		printcli("log-client current state: %s server \"%s\"",
		    state->enable ? "enabled" : "disabled",
		    hc->host);
		printcli("log-client config: %s",
		    log_client_conf_enabled ? "enabled" : "disabled");
		goto usage;
	}
	if (!mfg_or_setup_mode_ok()) {
		return;
	}
	if (argc < 2) {
usage:
		printcli("usage: log-client <enable|disable>");
		return;
	}
	if (!strcmp(argv[1], "enable")) {
		log_client_conf_enabled = 1;
		log_client_enable(1);
	} else if (!strcmp(argv[1], "disable")) {
		log_client_conf_enabled = 0;
		log_client_enable(0);
	} else {
		goto usage;
	}
}

u8 log_client_enabled(void)
{
	return log_client_state.enable;
}

void log_client_init(void)
{
	struct log_client_state *state = &log_client_state;

	net_callback_init(&state->callback, log_client_send_log, state);
	timer_init(&state->timer, log_client_timeout);
}

void log_client_set(const char *host, char *uri, const char *protocol)
{
	struct log_client_state *state = &log_client_state;
	struct http_client *hc = &state->http_client;

	log_client_close(state);
	log_client_reset();
	if (host[0] == '\0') {
		return;
	}
	snprintf(hc->host, sizeof(hc->host), "%s", host);

	state->uri = uri;
	hc->ssl_enable = (strcmp(protocol, "http") != 0);
	hc->client_send_data_cb = log_client_send_data_cb;
	hc->client_err_cb = log_client_err_cb;
	hc->client_tcp_recv_cb = log_client_tcp_recv_cb;
	hc->client_next_step_cb = log_client_next_step_cb;
}
