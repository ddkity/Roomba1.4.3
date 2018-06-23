/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
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

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/http.h>
#include <ayla/clock.h>
#include <ayla/parse.h>
#include <ayla/tlv.h>
#include <ayla/parse.h>
#include <ayla/timer.h>

#include <ada/err.h>
#include <net/net.h>
#include <ada/client.h>
#include <net/stream.h>
#include <ada/server_req.h>
#include <net/http_client.h>
#include <ada/metric.h>

#include "client_timer.h"
#include "client_lock.h"

#ifndef MOD_DEBUG_IO
#define MOD_DEBUG_IO			/* temporarily enable in all builds */
#define HTTP_CLIENT_DEBUG_EN
#endif

/*
 * Macro to make logging easier
 */
#define HTTP_CLIENT_LOGF(_hc, _level, _format, ...) \
	http_client_log(_hc, _level "%s: " _format, __func__, ##__VA_ARGS__)

#ifdef HTTP_CLIENT_DEBUG_EN
#define HTTP_CLIENT_DEBUG(_hc, _level, _format, ...) \
	HTTP_CLIENT_LOGF(_hc, _level, _format, ##__VA_ARGS__)
#else
#define HTTP_CLIENT_DEBUG(_hc, _level, _format, ...)
#endif /* HTTP_CLIENT_DEBUG_EN */

static const char http_client_ctype[] = "Content-Type";

const struct http_hdr http_hdr_content_xml = {
	.name = http_client_ctype,
	.val = "application/xml"
};
const struct http_hdr http_hdr_content_json = {
	.name = http_client_ctype,
	.val = "application/json"
};
const struct http_hdr http_hdr_content_stream = {
	.name = http_client_ctype,
	.val = "application/octet-stream"
};

static void http_client_connect(struct http_client *);
static void http_client_timeout(struct timer *arg);
static void http_client_log(struct http_client *, const char *fmt, ...)
	ADA_ATTRIB_FORMAT(2, 3);

/*
 * Prints log messages for the mod_log_id of this http_client.
 */
static void http_client_log(struct http_client *hc, const char *fmt, ...)
{
	ADA_VA_LIST args;
	ADA_VA_START(args, fmt);
	log_put_va(hc->mod_log_id, fmt, args);
	ADA_VA_END(args);
}

/*
 * Return non-zero if the http_client is ready to start a request.
 */
int http_client_is_ready(struct http_client *hc)
{
	return hc->state == HCS_IDLE || hc->state == HCS_KEEP_OPEN;
}

/*
 * Return non-zero if the http_client is ready to send data.
 */
int http_client_is_sending(struct http_client *hc)
{
	return hc->state == HCS_SEND;
}

/*
 * Return http_metrics if enabled.
 */
static struct http_metrics *http_client_http_metrics(struct http_client *hc)
{
	struct http_metrics *metrics;

	if (hc->metrics) {
		metrics = &hc->metrics->http;
		if (sizeof(metrics->buf) && metrics->status.enable) {
			return metrics;
		}
	}
	return NULL;
}

/*
 * Return ssl_metrics if enabled
 */
static struct ssl_metrics *http_client_ssl_metrics(struct http_client *hc)
{
	struct ssl_metrics *metrics;

	if (hc->metrics) {
		metrics = &hc->metrics->ssl;
		if (sizeof(metrics->buf) && metrics->status.enable) {
			return metrics;
		}
	}
	return NULL;
}

/*
 * Return tcp_metrics if enabled
 */
static struct tcp_metrics *http_client_tcp_metrics(struct http_client *hc)
{
	struct tcp_metrics *metrics;

	if (hc->metrics) {
		metrics = &hc->metrics->tcp;
		if (sizeof(metrics->buf) && metrics->status.enable) {
			return metrics;
		}
	}
	return NULL;
}

/*
 * Parses the content length of the http header. If found, sets content_given.
 */
static void http_client_parse_len(struct http_state *sp, int argc, char **argv)
{
	struct http_client *hc =
	    CONTAINER_OF(struct http_client, http_state, sp);
	unsigned long len;
	char *errptr;

	if (argc >= 1) {
		len = strtoul(argv[0], &errptr, 10);
		if (*errptr != '\0' || len >= MAX_U32) {
			HTTP_CLIENT_LOGF(hc, LOG_WARN, "bad len %s", argv[0]);
			return;
		}
		hc->content_len = len;
		hc->content_given = 1;
	}
}

/*
 * Parses Connection type in the header if given.
 */
static void http_client_parse_conn(struct http_state *sp, int argc, char **argv)
{
	struct http_client *hc =
	    CONTAINER_OF(struct http_client, http_state, sp);

	if (argc >= 1) {
		if (!strcasecmp(argv[0], "close")) {
			hc->conn_close = 1;
		} else if (strcasecmp(argv[0], "keep-alive")) {
			HTTP_CLIENT_LOGF(hc, LOG_WARN, "bad conn head %s",
			    argv[0]);
		}
	}
}

/*
 * Parse Date field.
 */
static void http_client_parse_date(struct http_state *sp, int argc, char **argv)
{
	struct http_client *hc =
	    CONTAINER_OF(struct http_client, http_state, sp);
	u32 date;

	if (!parse_http_date(&date, argc, argv)) {
		hc->http_time = date;
		//add by yujunwu
		client_clock_set(hc->http_time, CS_SERVER);
	}
}

/*
 * Parses encoding type in the header if given.
 */
static void http_client_parse_encoding(struct http_state *sp, int argc,
					char **argv)
{
	struct http_client *hc =
	    CONTAINER_OF(struct http_client, http_state, sp);
	struct http_metrics *metrics;

	if (argc >= 1) {
		if (!strcasecmp(argv[0], "chunked")) {
			hc->chunked_enc = 1;
			metrics = http_client_http_metrics(hc);
			if (metrics) {
				metrics->current->chunked_enc = 1;
			}
		} else {
			HTTP_CLIENT_LOGF(hc, LOG_WARN, "bad enc %s", argv[0]);
		}
	}
}

static void http_client_parse_key(struct http_state *sp, int argc,
					char **argv)
{
	struct http_client *hc =
	    CONTAINER_OF(struct http_client, http_state, sp);
	size_t len;

	if (argc >= 1) {
		len = snprintf(hc->auth_hdr, sizeof(hc->auth_hdr),
		    HTTP_CLIENT_AUTH_VER " %s", argv[0]);
		if (len >= sizeof(hc->auth_hdr)) {
			HTTP_CLIENT_LOGF(hc, LOG_WARN, "auth hdr too long");
		}
	}
}

static void http_client_parse_time(struct http_state *sp, int argc,
					char **argv)
{
	struct http_client *hc =
	    CONTAINER_OF(struct http_client, http_state, sp);
	unsigned long server_time;
	char *errptr;

	if (argc >= 1) {
		server_time = strtoul(argv[0], &errptr, 10);
		if (*errptr != '\0' || server_time >= MAX_U32) {
			HTTP_CLIENT_LOGF(hc, LOG_WARN, "bad time %s", argv[0]);
			return;
		}
		hc->server_time = server_time;
	}
}

/*
 * Parses the range header of the http response if given. If found,
 * sets range_given and range_bytes.
 */
static void http_client_parse_range(struct http_state *sp, int argc,
				    char **argv)
{
	struct http_client *hc =
	    CONTAINER_OF(struct http_client, http_state, sp);
	unsigned long bytes;
	char *errptr;

	if (argc >= 2) {
		errptr = strchr(argv[1], '/');
		if (!errptr) {
			goto bad_range;
		}
		bytes = strtoul(errptr + 1, &errptr, 10);
		if (*errptr != '\0' || bytes >= MAX_U32) {
bad_range:
			HTTP_CLIENT_LOGF(hc, LOG_WARN, "bad range %s", argv[0]);
			return;
		}
		hc->range_bytes = bytes;
		hc->range_given = 1;
	}
}

/*
 * An array of the http tags that need to be parsed when http header is read.
 */
static const struct http_tag http_client_http_tags[] = {
	{ .name = "Content-Length", http_client_parse_len },
	{ .name = "Connection", http_client_parse_conn },
	{ .name = "transfer-encoding", http_client_parse_encoding },
	{ .name = "Content-Range", http_client_parse_range },
	{ .name = "Date", http_client_parse_date },
	{ .name = HTTP_CLIENT_KEY_FIELD, http_client_parse_key },
	{ .name = HTTP_CLIENT_TIME_FIELD, http_client_parse_time },
	{ .name = NULL }
};

/*
 * Schedule reconnect/retry after wait.
 */
static void http_client_wait(struct http_client *hc, u32 delay)
{
	client_timer_cancel(&hc->hc_timer); /* in case of reset/commit */
	HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "state = %x", hc->state);
	switch (hc->state) {
	case HCS_CONN:
	case HCS_CONN_TCP:
	case HCS_WAIT_RETRY:
	case HCS_OPEN:
	case HCS_KEEP_OPEN:
	case HCS_SEND:
	case HCS_HEAD:
	case HCS_CONTENT:
	case HCS_WAIT_TCP_SENT:
	case HCS_WAIT_CLI_RECV:
		break;
	default:
		HTTP_CLIENT_LOGF(hc, LOG_ERR, "unexpected state %x",
		    hc->state);
		break;
	}
	if (delay) {
		client_timer_set(&hc->hc_timer, delay);
	}
}

static void http_client_abort_err(struct http_client *hc)
{
	http_client_abort(hc);
	if (hc->client_err_cb) {
		hc->client_err_cb(hc);
	}
}

/*
 * Set the retry_limit
 */
void http_client_set_retry_limit(struct http_client *hc, int limit)
{
	if (limit < 0 || limit > MAX_U8) {
		/* Use Default */
		hc->retry_limit = HTTP_CLIENT_TRY_COUNT;
	} else {
		hc->retry_limit = (u8)limit;
	}
}

/*
 * Set the wait time between retries
 */
void http_client_set_retry_wait(struct http_client *hc, int wait)
{
	if (wait < 0 || wait > MAX_U16) {
		/* Use Default */
		hc->retry_wait = HTTP_CLIENT_RETRY_WAIT;
	} else {
		hc->retry_wait = (u16)wait;
	}
}

/*
 * Set the wait time for a connection
 */
void http_client_set_conn_wait(struct http_client *hc, int wait)
{
	if (wait < 0 || wait > MAX_U16) {
		/* Use Default */
		hc->conn_wait = HTTP_CLIENT_CONN_WAIT;
	} else {
		hc->conn_wait = (u16)wait;
	}
}

/*
 * Retries up to HTTP_CLIENT_TRY_COUNT. Otherwise, it calls the err cb.
 */
static void http_client_retry(struct http_client *hc)
{
	if (++hc->retries <= hc->retry_limit) {
		HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "retry %u", hc->retries);
		hc->state = HCS_WAIT_RETRY;
		http_client_wait(hc, hc->retry_wait);
	} else {
		http_client_abort_err(hc);
	}
}

/*
 * Store the hc_error in the metric and log
 */
static void http_client_hc_err_log(struct http_client *hc)
{
	struct http_metrics *metrics;
	struct ssl_metrics *ssl_metrics;
	struct tcp_metrics *tcp_metrics;

	if (!hc->metrics) {
		return;
	}

	metrics = http_client_http_metrics(hc);
	if (metrics) {
		metrics->current->hc_error = hc->hc_error;
		metric_log_http_reqs(hc->mod_log_id, metrics, 0);
	}

	ssl_metrics = http_client_ssl_metrics(hc);
	if (ssl_metrics) {
		metric_log_ssl_reqs(hc->mod_log_id, ssl_metrics, 0);
	}

	tcp_metrics = http_client_tcp_metrics(hc);
	if (tcp_metrics) {
		metric_log_tcp_reqs(hc->mod_log_id, tcp_metrics, 0);
	}
}

/*
 * Close PCB and go to idle
 */
static void http_client_idle_close(struct http_client *hc)
{
	enum ada_err err;
	struct stream_pcb *pcb;

	client_timer_cancel(&hc->hc_timer);
	pcb = hc->pcb;

	if (!pcb) {
		goto idle;
	}
	HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "pcb %p", pcb);
	err = stream_close(pcb);
	if (err != AE_OK) {
		HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "err %d", err);
		hc->hc_error = HC_ERR_CLOSE;
	}
	hc->pcb = NULL;
idle:
	http_client_hc_err_log(hc);
	if (hc->state != HCS_CONN && hc->state != HCS_WAIT_RETRY) {
		/* If we're retrying a connection, don't reset retries. */
		hc->retries = 0;
	}
	hc->state = HCS_IDLE;
}

/*
 * Start a new hc if a request is pending. Otherwise reset the retry and
 * hand control back to the parent.
 */
static void http_client_start_pending(struct http_client *hc)
{
	hc->hc_error = HC_ERR_NONE;
	if (hc->req_pending) {
		http_client_start(hc);
	} else {
		hc->retries = 0;
		if (hc->client_next_step_cb) {
			hc->client_next_step_cb(hc);
		}
	}
}

/*
 * Close PCB, go to idle, and restart if there is a request pending.
 */
static void http_client_close(struct http_client *hc)
{
	ASSERT(client_locked);
	http_client_idle_close(hc);
	http_client_start_pending(hc);
}

/*
 * Close PCB, go to idle, clear the request pending.
 */
void http_client_abort(struct http_client *hc)
{
	http_client_idle_close(hc);
	hc->req_pending = 0;
	hc->retries = 0;
}

/*
 * TCP timeout for handling re-connect or retry.
 */
static void http_client_timeout(struct timer *arg)
{
	struct http_client *hc =
	    CONTAINER_OF(struct http_client, hc_timer, arg);
	struct http_metrics *metrics;

	if (hc->state != HCS_KEEP_OPEN) {
		metrics = http_client_http_metrics(hc);
		if (metrics) {
			metrics->current->timeout = hc->state;
		}
	}

	switch (hc->state) {
	case HCS_CONN:
		if (stream_tcp_is_established(hc->pcb)) {
			hc->state = HCS_CONN_TCP;
			http_client_wait(hc,
			    hc->conn_wait - HTTP_CLIENT_TCP_WAIT);
		} else {
			goto ssl_failure;
		}
		break;
	case HCS_CONN_TCP:
ssl_failure:
		if (++hc->retries > hc->retry_limit) {
			HTTP_CLIENT_LOGF(hc, LOG_WARN, "ssl conn fail");
			goto err_close;
		}
	case HCS_WAIT_RETRY:
		HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "retry %u", hc->retries);
		hc->state = HCS_WAIT_RETRY;
		http_client_close(hc);
		break;
	case HCS_OPEN:
	case HCS_SEND:
	case HCS_WAIT_TCP_SENT:
	case HCS_HEAD:
	case HCS_CONTENT:
		HTTP_CLIENT_LOGF(hc, LOG_WARN, "state %x", hc->state);
		goto err_close;
		break;
	case HCS_KEEP_OPEN:
		HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "client doesn't need conn");
		http_client_close(hc);
		break;
	case HCS_WAIT_CLI_RECV:
		HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "client too slow to consume");
		hc->hc_error = HC_ERR_TIMEOUT;
		goto err_close;
		break;
	default:
		HTTP_CLIENT_LOGF(hc, LOG_ERR,
		    "unexpected state %x", hc->state);
		goto err_close;
		break;
	}
	return;

err_close:
	http_client_abort_err(hc);
}

/*
 * Consume part of a payload.
 */
static size_t http_client_consume(struct http_client *hc, void **payload_v,
				size_t *len, int consumed)
{
	struct http_metrics *metrics = http_client_http_metrics(hc);
	char **payload = (char **)payload_v;

	*payload += consumed;
	*len -= consumed;
	if (metrics) {
		metrics->current->rx_bytes += consumed;
	}
	return consumed;
}

/*
 * Callback from TCP when non-encrypted head data is received
 */
static size_t
http_client_tcp_recv(void *arg, struct stream_pcb *pcb,
		void *payload, size_t len)
{
	struct http_client *hc = arg;
	int off = 0;
	u32 status;
	size_t consumed = 0;
	enum ada_err err;
	struct http_metrics *metrics;
	u32 excess_cutoff = 0;
	u8 *bp;

	switch (hc->state) {
	case HCS_HEAD:
	case HCS_CONTENT:
	case HCS_CHUNKED_HEAD:
	case HCS_SEND:
	case HCS_WAIT_TCP_SENT:
	case HCS_WAIT_CLI_RECV:
		break;
	default:
		/* unexpected recv, drop packet */
		if (payload || len) {
			HTTP_CLIENT_LOGF(hc, LOG_WARN,
			    "unexp recv %d bytes state %u", len, hc->state);
		}
		return len;
	}
	if (pcb != hc->pcb) {
		HTTP_CLIENT_LOGF(hc, LOG_WARN, "recv for pcb %p, cur pcb %p",
		    pcb, hc->pcb);
		return len;
	}
	switch (hc->state) {
	case HCS_HEAD:
	case HCS_CONTENT:
	case HCS_CHUNKED_HEAD:
	case HCS_SEND:
	case HCS_WAIT_TCP_SENT:
		break;
	case HCS_WAIT_CLI_RECV:
		return 0;
	default:
		return len;
	}

	client_timer_cancel(&hc->hc_timer);
	metrics = http_client_http_metrics(hc);

	if (!payload) {
		HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "conn closed by server");
		goto close;
	}

	if (!len) {
		return len;
	}

	if (metrics && !metrics->current->recv_start) {
		metrics->current->recv_start = clock_ms();
	}

	log_bytes(hc->mod_log_id, LOG_SEV_DEBUG2, payload, len, "http_rx");

	if (hc->state == HCS_HEAD) {
http_parse:
		off = http_parse(&hc->http_state, payload, len);
		if (off < 0) {
			HTTP_CLIENT_LOGF(hc, LOG_WARN, "HCS_HEAD parse fail");
			hc->hc_error = HC_ERR_HTTP_PARSE;
			goto error_close;
		}
		consumed += http_client_consume(hc, &payload, &len, off);

		if (hc->http_state.state != HS_DONE) {
			return consumed;
		}

		/*
		 * HTTP parse is complete, check status and call client_recv_cb.
		 */
		status = hc->http_state.status;
		hc->http_status = status;
		if (metrics) {
			metrics->current->http_status = status;
		}
		HTTP_CLIENT_DEBUG(hc, LOG_DEBUG, "HTTP status = %lu", status);

		switch (status) {
		case HTTP_STATUS_OK:
		case HTTP_STATUS_CREATED:
		case HTTP_STATUS_PAR_CONTENT:
			break;
		case HTTP_STATUS_NO_CONTENT:
			goto close;
		case HTTP_STATUS_CONTINUE:
			http_parse_init(&hc->http_state,
			    http_client_http_tags);
			goto http_parse;
			break;
		default:
			if (status >= HTTP_STATUS_REDIR_MIN &&
			    status <= HTTP_STATUS_REDIR_MAX) {
				hc->hc_error = HC_ERR_HTTP_REDIR;
			} else {
				hc->hc_error = HC_ERR_HTTP_STATUS;
			}
			if (hc->host[0] == '\0') {
				bp = (u8 *)&hc->host_addr.addr;
				HTTP_CLIENT_LOGF(hc, LOG_DEBUG,
				    "HTTP status %lu recved from %u.%u.%u.%u",
				    status, bp[0], bp[1], bp[2], bp[3]);
			} else {
				HTTP_CLIENT_LOGF(hc, LOG_DEBUG,
				    "HTTP status %lu recved from %s",
				    status, hc->host);
			}
			goto error_close;
			break;
		}
		hc->state = HCS_CONTENT;
		if (!len) {
			goto close_or_open;
		}
	}
	if (hc->chunked_enc && hc->content_given) {
		/* can't give content length + chunked encoding */
		HTTP_CLIENT_LOGF(hc, LOG_WARN,
		    "content & chunked headers given");
		goto error_close;
	}
	if (hc->content_given && len > hc->content_len) {
		/* recved more than specified in content length */
		/* cut off the excess */
		HTTP_CLIENT_LOGF(hc, LOG_WARN,
		    "len expect %lu, got %zd", hc->content_len, len);
		excess_cutoff = len - hc->content_len;
		len = hc->content_len;
	}

	if (hc->chunked_enc && !hc->content_len &&
	    hc->state != HCS_CHUNKED_HEAD) {
chunk_head_init:
		hc->state = HCS_CHUNKED_HEAD;
		http_chunk_init(&hc->http_state, NULL);
	}

	if (hc->state == HCS_CHUNKED_HEAD) {
		off = http_parse(&hc->http_state, payload, len);
		if (off < 0) {
			HTTP_CLIENT_LOGF(hc, LOG_WARN, "CHUNK_HEAD parse fail");
			hc->hc_error = HC_ERR_HTTP_PARSE;
			goto error_close;
		}
		consumed += http_client_consume(hc, &payload, &len, off);
		if (hc->http_state.state != HS_DONE) {
			return consumed;
		}
		hc->content_len = hc->http_state.status;
		if (hc->content_len == 0) {
			consumed += http_client_consume(hc, &payload, &len,
			    len);
			goto open;
		}
		hc->state = HCS_CONTENT;
		if (!len) {
			return consumed;
		}
	}
	if (hc->chunked_enc && len > hc->content_len) {
		err = hc->client_tcp_recv_cb(hc, payload, hc->content_len);
		if (err == AE_INVAL_VAL) {
			goto error_close;
		}
		if (err == AE_BUF) {
			goto err_recv_mem;
		}
		consumed += http_client_consume(hc, &payload, &len,
		    hc->content_len);
		hc->content_len = 0;
		goto chunk_head_init;
	}
	err = hc->client_tcp_recv_cb(hc, payload, len);
	if (err == AE_INVAL_VAL) {
		goto error_close;
	}
	if (err == AE_BUF) {
		goto err_recv_mem;
	}
	if (hc->content_given || hc->chunked_enc) {
		hc->content_len -= len;
	}

	consumed += http_client_consume(hc, &payload, &len, len);

close_or_open:
	if (hc->content_given && !hc->content_len) {
		if (hc->conn_close || excess_cutoff) {
close:
			if (metrics) {
				metrics->current->recv_done = clock_ms();
			}
			http_client_idle_close(hc);
			hc->client_tcp_recv_cb(hc, NULL, 0);
			hc->hc_error = HC_ERR_NONE;
			http_client_start_pending(hc);
		} else {
open:
			hc->state = HCS_KEEP_OPEN;
			hc->hc_error = HC_ERR_NONE;
			if (metrics) {
				metrics->current->recv_done = clock_ms();
				metrics->current->keep_open = 1;
				metric_log_http_reqs(hc->mod_log_id,
				    metrics, 0);
			}
			http_client_wait(hc, HTTP_CLIENT_KEEP_OPEN_WAIT);
			hc->client_tcp_recv_cb(hc, NULL, 0);
			http_client_start_pending(hc);
		}
	}

	return consumed + excess_cutoff;

error_close:
	consumed += http_client_consume(hc, &payload, &len, len);
	http_client_abort_err(hc);
	return consumed + excess_cutoff;

err_recv_mem:
	hc->state = HCS_WAIT_CLI_RECV;
	consumed += http_client_consume(hc, &payload, &len, hc->recv_consumed);
	if (hc->content_given || hc->chunked_enc) {
		hc->content_len -= hc->recv_consumed;
	}
	http_client_wait(hc, HTTP_CLIENT_MCU_WAIT);
	return consumed + excess_cutoff;
}

/*
 * Interface for the client to ask http_client to start receiving
 * server data again.
 */
void http_client_continue_recv(struct http_client *hc)
{
	if (hc->state != HCS_WAIT_CLI_RECV) {
		hc->client_tcp_recv_cb(hc, NULL, 0);
		http_client_start_pending(hc);
	} else {
		hc->state = HCS_CONTENT;
		stream_resume(hc->pcb);
	}
}

/*
 * Send callback for portion of buffer.
 * This part is never sent with chunked encoding.
 */
static int http_client_req_send(struct http_client *hc,
				const void *buf, size_t *lenp)
{
	enum ada_err err;
	size_t len;

	len = *lenp;
	if (!len) {
		return 0;
	}
	err = http_client_send(hc, buf, len);
	if (err == AE_BUF) {
		return -1;
	}
	*lenp = 0;
	if (err != AE_OK) {
		hc->hc_error = HC_ERR_SEND;
		hc->client_err_cb(hc);
		return -1;
	}
	return 0;
}

/*
 * Call the client's send callback
 */
static void http_client_issue_send_cb(struct http_client *hc)
{
	hc->state = HCS_OPEN;
	hc->req_pending = 0;
	http_client_wait(hc, HTTP_CLIENT_OPEN_WAIT);
	hc->hc_error = HC_ERR_SEND;

	if (http_client_req_send(hc, hc->req_buf, &hc->req_len)) {
		return;
	}
	if (http_client_req_send(hc, hc->body_buf, &hc->body_buf_len)) {
		return;
	}

	if (hc->client_send_data_cb) {
		hc->client_send_data_cb(hc);
	} else {
		http_client_send_complete(hc);
	}
}

/*
 * Setup the open state for this HTTP conneciton
 */
static void http_client_open_setup(struct http_client *hc)
{
	hc->content_len = 0;
	hc->content_given = 0;
	hc->conn_close = 0;
	hc->chunked_enc = 0;
	hc->range_given = 0;
	hc->recv_consumed = 0;
	hc->http_status = 0;
	http_parse_init(&hc->http_state, http_client_http_tags);
	stream_sent(hc->pcb, NULL);
	http_client_issue_send_cb(hc);
}

/*
 * Callback from TCP when non-encrypted head data is received
 */
static enum ada_err
http_client_tcp_sent(void *arg, struct stream_pcb *pcb, u16 len)
{
	struct http_client *hc = arg;

	if (hc->state == HCS_WAIT_TCP_SENT) {
		http_client_open_setup(hc);
	}
	return AE_OK;
}

/*
 * Interface for the client to send data on the stream to the server.
 */
enum ada_err http_client_send(struct http_client *hc, const void *buf,
    u16_t len)
{
	enum ada_err err = AE_NOTCONN;
	struct http_metrics *metrics = http_client_http_metrics(hc);

	ASSERT(hc->state == HCS_OPEN || hc->state == HCS_SEND);
	if (hc->state == HCS_OPEN || hc->state == HCS_SEND) {
		client_timer_cancel(&hc->hc_timer);
		hc->state = HCS_SEND;

		log_bytes(hc->mod_log_id, LOG_SEV_DEBUG2, buf, len, "http_tx");

		err = stream_write(hc->pcb, buf, len, 0);
		if (err == AE_OK) {
			hc->sent_len += len;
			if (metrics) {
				metrics->current->tx_bytes += len;
			}
		} else if (err == AE_BUF) {
			hc->state = HCS_WAIT_TCP_SENT;
			hc->hc_error = HC_ERR_SEND;
			http_client_wait(hc, HTTP_CLIENT_MEM_WAIT);
			stream_sent(hc->pcb, http_client_tcp_sent);
		}
	}
	return err;
}

/*
 * Send blank padding if needed for PUT or POST.
 * Indicates body is complete.
 * The buffer may be used for padding.
 * This implementaton can send the shorter body without padding.
 * This can be set as a send_data_cb function.
 */
void http_client_send_pad(struct http_client *hc)
{
	size_t padding_needed;
	enum ada_err err;
	char buf[512];
	size_t len = sizeof(buf);

	if (hc->sending_chunked || hc->sent_len < 0) {
		return;
	}

	memset(buf, ' ', len);

	while (hc->sent_len < hc->body_len) {
		padding_needed = hc->body_len - hc->sent_len;
		if (padding_needed > len) {
			padding_needed = len;
		}
		err = http_client_send(hc, buf, padding_needed);
		if (err != AE_OK) {
			return;
		}
	}
	http_client_send_complete(hc);
}

/*
 * Callback from http_client_connect when TCP is connected
 */
static enum ada_err http_client_connected(void *arg, struct stream_pcb *pcb,
    enum ada_err err)
{
	struct http_client *hc = arg;
	struct http_metrics *metrics;

	if (err != AE_OK) {
		if (err == AE_CERT_EXP) {
			hc->hc_error = HC_ERR_CONNECT;
			hc->retries = hc->retry_limit;
		}
		http_client_retry(hc);
	} else {
		metrics = http_client_http_metrics(hc);
		if (metrics) {
			metrics->current->client_connected = clock_ms();
		}
		HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "pcb %p", pcb);
		http_client_open_setup(hc);
	}
	return err;
}

/*
 * Interface for the client to complete the send request.
 * This should only be called from the send callback when it has completed the
 * final send.
 */
void http_client_send_complete(struct http_client *hc)
{
	struct http_metrics *metrics;

	ASSERT(hc->state == HCS_SEND);
	if (hc->state == HCS_SEND) {
		metrics = http_client_http_metrics(hc);
		if (metrics) {
			metrics->current->send_done = clock_ms();
		}
		hc->state = HCS_HEAD;
		stream_output(hc->pcb);
		hc->hc_error = HC_ERR_RECV;
		hc->server_time = 0;
		http_client_wait(hc, HTTP_CLIENT_RECV_WAIT);
	}
}

/*
 * Callback from TCP when connection fails or gets reset.
 * The PCB is freed by the caller.
 */
static void http_client_err(void *arg, enum ada_err err)
{
	struct http_client *hc = arg;

	if (hc->state == HCS_CONN ||
	    hc->state == HCS_CONN_TCP) {

		/*
		 * Don't retry on certificate errors due to unknown time.
		 */
		if (hc->ssl_enable && clock_source() <= CS_DEF) {
			goto err_close;
		}
		http_client_retry(hc);
		return;
	}
	HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "err %d pcb %p", err, hc->pcb);
	if (err == AE_CLSD || err == AE_RST) {
		if (hc->state == HCS_KEEP_OPEN ||
		    hc->state == HCS_IDLE) {
			http_client_idle_close(hc);
			return;
		}
		hc->hc_error = HC_ERR_CONN_CLSD;
		if (!hc->http_status && (hc->state == HCS_SEND ||
		    hc->state == HCS_HEAD || hc->state == HCS_WAIT_TCP_SENT)) {
			goto err_close;
		}
		if (hc->state == HCS_HEAD ||
		    hc->state == HCS_CHUNKED_HEAD ||
		    hc->state == HCS_CONTENT ||
		    hc->state == HCS_WAIT_CLI_RECV) {
			http_client_idle_close(hc);
			hc->client_tcp_recv_cb(hc, NULL, 0);
			http_client_start_pending(hc);
			return;
		}
	} else {
		HTTP_CLIENT_LOGF(hc, LOG_ERR, "err %d pcb %p", err, hc->pcb);
		if (err == AE_ABRT || err == AE_NOTCONN) {
			/*dns_delete_by_name(hc->host); XXX */
			hc->req_pending = 1;
			http_client_retry(hc);
			return;
		}
	}
err_close:
	http_client_abort_err(hc);
}

/*
 * DNS resolved callback.
 */
static void http_client_dns_cb(struct net_dns_req *req)
{
	struct http_client *hc = CONTAINER_OF(struct http_client, dns_req, req);
	struct http_metrics *metrics;
	const char *name = req->hostname;
	u8 *bp;

	/*
	 * Client may have changed hosts or state while DNS was outstanding.
	 */
	client_lock();
	if (hc->state != HCS_DNS || strcmp(name, hc->host)) {
		HTTP_CLIENT_DEBUG(hc, LOG_DEBUG, "host %s ignored", name);
		client_unlock();
		return;
	}
	if (req->addr) {
		metrics = http_client_http_metrics(hc);
		if (metrics) {
			metrics->current->dns_resolve = clock_ms();
		}
		if (hc->host_addr.addr != req->addr) {
			bp = (u8 *)&req->addr;
			http_client_log(hc, LOG_INFO
			    "DNS: host %s at %u.%u.%u.%u",
			    name, bp[0], bp[1], bp[2], bp[3]);
			hc->host_addr.addr = req->addr;
		}
		hc->hc_error = HC_ERR_CONNECT;
		http_client_connect(hc);
	} else {
		hc->host_addr.addr = 0;
		HTTP_CLIENT_LOGF(hc, LOG_WARN, "host %s failed", name);
		http_client_abort_err(hc);
	}
	client_unlock();
}

/*
 * Get the IP address of the DNS
 */
static void http_client_getdnshostip(struct http_client *hc)
{
	struct net_dns_req *req = &hc->dns_req;
	err_t err;

	req->hostname = hc->host;
	req->callback = http_client_dns_cb;

	err = net_dns_lookup(req);
	if (err) {
		hc->hc_error = HC_ERR_SEND;
		http_client_retry(hc);
	}
}

/*
 * Update the http metric status and clear out the current metric to store new
 * information.
 */
static void http_client_init_metric(struct http_client *hc)
{
	struct http_metrics *metrics = http_client_http_metrics(hc);

	if (metrics) {
		memset(metrics->current, 0, sizeof(*metrics->current));
		metrics->current->http_start = clock_ms();
	}
}

/*
 * Start a new http connect if we're in idle.
 * Otherwise, set the req_pending bit.
 */
void http_client_start(struct http_client *hc)
{
	ASSERT(hc->client_tcp_recv_cb);
	if (hc->host[0] != '\0') {
		hc->req_pending = 1;
		if (hc->state == HCS_KEEP_OPEN) {
			hc->req_part = 0;
			http_client_init_metric(hc);
			http_client_open_setup(hc);
		} else if (hc->state == HCS_IDLE) {
			hc->state = HCS_DNS;
			hc->req_part = 0;
			http_client_init_metric(hc);
			hc->hc_error = HC_ERR_DNS;
			http_client_getdnshostip(hc);
		}
	}
}

void http_client_req(struct http_client *hc, enum http_method method,
    const char *resource, int hcnt, const struct http_hdr *hdrs)
{
	const char *method_str;
	size_t len;
	char *cp;
	int i;

	if (!hc->hc_initialized) {
		timer_init(&hc->hc_timer, http_client_timeout);
		hc->hc_initialized = 1;
	}
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

	len = snprintf(hc->req_buf, sizeof(hc->req_buf),
	    "%s %s HTTP/1.1\r\n"
	    "Host: %s\r\n",
	    method_str, resource, hc->host);

	if (!hc->sending_chunked) {		/* never chunked for now */
		len += snprintf(hc->req_buf + len, sizeof(hc->req_buf) - len,
		    "Content-Length: %u\r\n", hc->body_len);
	}

	for (i = 0; i < hcnt; i++) {
		len += snprintf(hc->req_buf + len, sizeof(hc->req_buf) - len,
		    "%s: %s\r\n",
		    hdrs[i].name, hdrs[i].val);
	}

	if (len >= sizeof(hc->req_buf) - 3) {
		HTTP_CLIENT_LOGF(hc, LOG_ERR, "req too long");
		return;
	}

	cp = hc->req_buf + len;
	cp[0] = '\r';
	cp[1] = '\n';
	cp[2] = '\0';		/* NUL for debug only, not sent */
	hc->req_len = len + 2;	/* don't include NUL in len */
	hc->sent_len = 0 - hc->req_len;	/* tricky.  counts body length only */
	client_lock();
	http_client_start(hc);
	client_unlock();
}

/*
 * Update the ssl/tcp metric status and clear out the current metric to store
 * new information.
 */
static void http_client_init_ssltcp_metric(struct http_client *hc)
{
	struct ssl_metrics *ssl_metrics = http_client_ssl_metrics(hc);
	struct tcp_metrics *tcp_metrics = http_client_tcp_metrics(hc);

	if (ssl_metrics) {
		memset(ssl_metrics->current, 0, sizeof(*ssl_metrics->current));
	}
	if (tcp_metrics) {
		memset(tcp_metrics->current, 0, sizeof(*tcp_metrics->current));
	}
}

/*
 * Establish connection.
 */
static void http_client_connect(struct http_client *hc)
{
	struct stream_pcb *pcb;
	enum ada_err err;
	struct http_metrics *metrics;
	struct ssl_metrics *ssl_metrics = http_client_ssl_metrics(hc);
	struct tcp_metrics *tcp_metrics = http_client_tcp_metrics(hc);

	if (!hc->host_addr.addr) {
		HTTP_CLIENT_LOGF(hc, LOG_WARN, "null ip");
		http_client_retry(hc);
		return;
	}
	hc->state = HCS_CONN;

	http_client_init_ssltcp_metric(hc);
	pcb = stream_new(hc->ssl_enable ? &hc->sess_id : NULL,
	    hc->accept_non_ayla,
	    ssl_metrics ? ssl_metrics->current : NULL,
	    tcp_metrics ? tcp_metrics->current : NULL);
	if (!pcb) {
		HTTP_CLIENT_LOGF(hc, LOG_WARN, "cannot alloc PCB");
		http_client_retry(hc);
		return;
	}
	hc->pcb = pcb;
	HTTP_CLIENT_DEBUG(hc, LOG_DEBUG2, "pcb %p", pcb);

	stream_log_set(pcb, hc->mod_log_id);

	stream_arg(pcb, hc);
	stream_recv(pcb, http_client_tcp_recv);
	stream_err(pcb, http_client_err);

	err = stream_connect(pcb, hc->host, &hc->host_addr,
	    !hc->ssl_enable ?
	    hc->host_port : HTTP_CLIENT_SERVER_PORT_SSL,
	    http_client_connected);
	if (err != AE_OK) {
		metrics = http_client_http_metrics(hc);
		if (metrics) {
			metrics->current->tcp_conn_err = err;
		}
		HTTP_CLIENT_LOGF(hc, LOG_WARN, "err %d", err);
		goto close;
	}

	/* If timeout waiting for connect, retry */
	http_client_wait(hc, (hc->ssl_enable) ?
	    HTTP_CLIENT_TCP_WAIT : hc->conn_wait);
	return;
close:
	http_client_retry(hc);
}

void http_client_reset(struct http_client *hc, enum mod_log_id mod_id,
	struct https_metrics *metrics)
{
	client_timer_cancel(&hc->hc_timer);
	hc->host_addr.addr = 0;
	hc->hc_error = HC_ERR_NONE;
	hc->state = HCS_IDLE;
	hc->mod_log_id = mod_id;
	hc->sending_chunked = 0;
	hc->chunked_eof = 0;
	hc->prop_callback = 0;
	hc->req_part = 0;
	hc->metrics = metrics;
	hc->conn_wait = HTTP_CLIENT_CONN_WAIT;
	hc->retry_limit = HTTP_CLIENT_TRY_COUNT;
	hc->retry_wait = HTTP_CLIENT_RETRY_WAIT;
	hc->http_time = 0;
	stream_ssl_init_id(&hc->sess_id);
}

u32 http_client_local_ip(struct http_client *hc)
{
	return stream_local_ip(hc->pcb)->addr;
}
