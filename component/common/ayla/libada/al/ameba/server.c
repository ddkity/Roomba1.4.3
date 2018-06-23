/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#define HAVE_UTYPES
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <FreeRTOS.h>
#include <httpd/httpd.h>
#include <sys/queue.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ada/task_label.h>
#include <ayla/endian.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/uri_code.h>
#include <ayla/http.h>
#include <ayla/parse.h>

#include <net/net.h>
#include <ada/prop.h>
#include <ayla/malloc.h>
#include <ada/server_req.h>
#include <ada/ada_wifi.h>

#ifdef AYLA_WIFI_SUPPORT
#include <adw/wifi.h>
#endif

static xSemaphoreHandle in_prog_lock;

#if 1 /* def MOD_DEBUG_IO */
#define server_io_debug(buf, len, ...) \
	    log_bytes(MOD_LOG_SERVER, LOG_SEV_DEBUG2, buf, len, \
	    ##__VA_ARGS__)
#else
#define server_io_debug(buf, len, ...)
#endif

#define DEFAULT_RESPONSE_HEADER \
	"Connection: close\r\n" \
	"Transfer-Encoding: chunked\r\n" \
	"\r\n"

void server_free_aborted_req(struct server_req *req)
{
	if (req->user_in_prog) {
		xSemaphoreGive(in_prog_lock);
	}
	req->user_in_prog = 0;
}

static char *server_get_arg(struct server_req *req, const char *name,
    char *buf, size_t len)
{
	const char *arg;
	const char *val;
	const char *next;
	const char *endp;
	size_t name_len = strlen(name);
	size_t vlen;
	ssize_t rc;
	struct httpd_conn *conn;
	char *result;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;

	if (httpd_request_get_query_key(conn, name, &result)) {
		return NULL;
	}

	if (strlen(result) < len) {
		strcpy(buf, result);
		httpd_free(result);
		return buf;
	}

	httpd_free(result);
	return NULL;
}

enum ada_err server_complete(struct server_req *req)
{
	struct httpd_conn *conn;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;

	if (req->head_sent) {
		if (httpd_response_write_data(conn, "0\r\n\r\n", 5) != 5) {
			req->err = AE_ERR;
		}
	}
	if (!req->user_in_prog && req->tcpip_cb) {
		net_callback_pend(req->tcpip_cb);
	}
	return AE_OK;
}

static void server_call_resume(struct server_req *req)
{
	xSemaphoreGive(in_prog_lock);
}

void server_resume(struct server_req *req, void (*resume)(struct server_req *))
{
	req->put_count = 0;
	req->puts_done = 0;
	req->resume = server_call_resume;
	req->sec_arg = (void *)resume;
}

void server_continue(struct server_req *req,
		void (*resume)(struct server_req *))
{
	server_resume(req, resume);
	resume(req);
}

static int server_send(struct server_req *req, const char *msg, size_t len)
{
	struct httpd_conn *conn;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;

	server_io_debug(msg, len, "server tx");
	return httpd_response_write_data(conn, msg, len) != len;
}

/*
 * Print a line into a web response.
 */
void server_put_flush(struct server_req *req, const char *msg)
{
	if (req->suppress_out) {
		return;
	}
	if (!msg) {
		msg = req->buf;
	}
	req->write_cmd(req, msg);
}

/*
 * Read body data for PUT or POST into req->buf.
 * Returns:
 *	> 0 if body is not complete
 *	0 if body is complete
 *	< 0 if read has error
 */
int server_read(struct server_req *req)
{
	struct httpd_conn *conn;
	size_t len;
	int rc;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;

	len = req->content_len;
	if (len == 0) {
		return 0;
	}
	if (len > SERVER_BUFLEN - 1) {
		server_log(LOG_WARN "read: content len over %u",
		    SERVER_BUFLEN);
		req->state = REQ_ERR;
		return -1;
	}
	if (len <= req->len) {
		server_log(LOG_WARN "read: short buf len %u min %u",
		    (unsigned int)len, (unsigned int)req->len);
		return 0;
	}
	len -= req->len;

	while (req->len < req->content_len) {
		rc = httpd_request_read_data(conn, req->buf + req->len, len);
		if (rc < 0) {
			server_log(LOG_WARN "read: rc %d", rc);
			req->state = REQ_ERR;
			return -1;
		}
		if (rc) {
			server_io_debug(req->buf + req->len, rc, "server rx");
			req->len += rc;
			req->buf[req->len] = '\0';
		}
	}
	return 0;
}

static const char *server_method_names[] = {
	[REQ_GET] = "GET",
	[REQ_GET_HEAD] = "HEAD",
	[REQ_POST] = "POST",
	[REQ_PUT] = "PUT",
	[REQ_DELETE] = "DELETE",
};

static int server_req_add(struct server_req **req)
{
	*req = malloc(sizeof(**req));
	if (*req == NULL) {
		server_log(LOG_WARN "accept: failed to alloc req size %zd",
		    sizeof(**req));
		return ERR_MEM;
	}
	memset(*req, 0, sizeof(**req));
	return ERR_OK;
}

static void server_put_head(struct server_req *req, unsigned int status,
			const char *hdr_msg)
{
	struct httpd_conn *conn;
	char status_str[80];
	int err;
	int len;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;

	snprintf(status_str, sizeof(status_str), "%u %s", status,
	    server_status_msg(status));
	len = snprintf(req->buf, SERVER_BUFLEN, "HTTP/1.1 %u %s\r\n",
	    status, server_status_msg(status));
	if (server_send(req, req->buf, len)) {
		goto out;
	}

	if (hdr_msg) {
		if (server_send(req, hdr_msg, strlen(hdr_msg))) {
			goto out;
		}
	}

	if (server_send(req, DEFAULT_RESPONSE_HEADER,
	    sizeof(DEFAULT_RESPONSE_HEADER)-1)) {
		goto out;
	}

	req->head_sent = 1;
	if (req->method == REQ_GET_HEAD) {
		req->suppress_out = 1;
	}
	return;

out:
	req->err = AE_CLSD;	/* should translate the error */
}

static void server_req_free(struct server_req *req)
{
	if (req->static_alloc) {
		return;
	}
	if (req->pcb) {
		free(req->pcb);
		req->pcb = NULL;
	}
	free(req);
}

static void server_flush(struct server_req *req, const char *msg)
{
	struct httpd_conn *conn;
	char buf[25];
	int err;
	int len;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;

	if (req->len == 0 || req->err != AE_OK || req->suppress_out) {
		return;
	}
	if (!msg) {
		msg = req->buf;
	}
	server_io_debug(msg, req->len, "server tx chunk");

	len = snprintf(buf, sizeof(buf), "%x\r\n", req->len);
	if (httpd_response_write_data(conn, buf, len) != len) {
		req->err = AE_ERR;
		goto out;
	}
	if (httpd_response_write_data(conn, msg, req->len) != req->len) {
		req->err = AE_ERR;
		goto out;
	}
	if (httpd_response_write_data(conn, "\r\n", 2) != 2) {
		req->err = AE_ERR;
	}
out:
	req->len = 0;
}

enum server_method server_req_method(struct server_req *req)
{
	enum server_method method;
	struct httpd_conn *conn;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;
	for (method = REQ_BAD; method < ARRAY_LEN(server_method_names);
	    method++) {
		if (httpd_request_is_method(conn,
		    server_method_names[method])) {
			return method;
		}
	}
	return REQ_BAD;
}

int server_req_is_version(struct server_req *req, const char *version)
{
	struct httpd_conn *conn;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;

	return strlen(version) == conn->request.version_len &&
	    memcmp(conn->request.version, version,
	    conn->request.version_len) == 0;
}

int server_req_resource(struct server_req *req, char *buf, size_t buf_size)
{
	struct httpd_conn *conn;
	int rc = 0;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;

	if (buf_size < conn->request.path_len - 1) {
		buf_size = conn->request.path_len - 1;
		rc = -1;
	}
	memcpy(buf, conn->request.path, conn->request.path_len);
	buf[conn->request.path_len] = '\0';
	return rc;
}

int server_req_header(struct server_req *req, const char *header,
	char *buf, size_t size)
{
	struct httpd_conn *conn;
	char *value;
	int rc;

	AYLA_ASSERT(req->req_impl);
	conn = (struct httpd_conn *)req->req_impl;

	rc = httpd_request_get_header_field(conn, header, &value);
	if (rc == 0) {
		if (strlen(value) + 1 > size) {
			rc = -1;
		} else {
			strcpy(buf, value);
		}
		httpd_free(value);
	}
	return rc;
}

static void server_handler(struct httpd_conn *conn)
{
	void (*resume_func)(struct server_req *);
	enum server_method method;
	struct server_req *req;
	const struct url_list *tt;
	u8 priv;
	int rc;
	int len;

	ASSERT(conn);

	log_thread_id_set(TASK_LABEL_WEBSERVER);

	if (server_req_add(&req)) {
		server_log(LOG_WARN "req alloc failed");
		httpd_response_internal_server_error(conn, "No memory!");
		httpd_conn_close(conn);
		return;
	}

	req->req_impl = conn;
	req->put_head = server_put_head;
	req->write_cmd = server_flush;
	req->get_arg_by_name = server_get_arg;

	method = server_req_method(req);
	if (method == REQ_BAD) {
		httpd_response_bad_request(conn, "Unsupport method!");
		goto req_free;
	}

	adap_wifi_stayup();

	len = sizeof(req->resource) - 1;
	if (len > conn->request.path_len) {
		len = conn->request.path_len;
	}
	memcpy(req->resource, conn->request.path, len);
	req->resource[len] = '\0';
	server_log(LOG_DEBUG "<%d> server request: %s %s", conn->sock,
	    server_method_names[method], req->resource);

	priv = LOC_REQ;
	if (adap_wifi_in_ap_mode()) {
		priv |= REQ_SOFT_AP;
	}
	tt = server_find_handler(req, req->resource, method, priv);
	ASSERT(tt);

	req->pcb = net_tcp_alloc_set(conn->sock);
	if (!req->pcb) {
		server_log(LOG_WARN "req pcb alloc failed");
		goto req_free;
	}

	req->url = tt;
	req->state = REQ_INIT;
	req->head_sent = 0;

	server_req(req);

	rc = req->err;
	if (rc) {
		server_log(LOG_DEBUG "handler rc %d", rc);
		if (req->user_in_prog) {
			if (!in_prog_lock) {
				vSemaphoreCreateBinary(in_prog_lock);
				xSemaphoreTake(in_prog_lock,
				    portMAX_DELAY);
			}

			/*
			 * Now wait until the producer of the data
			 * is ready with the response
			 */
			xSemaphoreTake(in_prog_lock, portMAX_DELAY);
			resume_func = (void(*)(struct server_req *))
			    req->sec_arg;
			resume_func(req);
			if (req->finish_write) {
				req->finish_write(req);
			}
			rc = 0;
		} else if (req->head_sent) {
			rc = 0;
		} else {
			httpd_response_internal_server_error(conn, NULL);
		}
	}

req_free:
	server_req_free(req);
	server_log(LOG_DEBUG "<%d> server connection closed", conn->sock);
	httpd_conn_close(conn);
}

void server_reg_urls(const struct url_list *list)
{
	const struct url_list *item;
	const char *url_list;

	for (item = list; item->url; item++) {
		ASSERT(item->url);
		switch (item->method) {
		case REQ_GET:
		case REQ_POST:
		case REQ_PUT:
		case REQ_DELETE:
			break;
		default:
			ASSERT_NOTREACHED();
		}
		httpd_reg_page_callback(item->url, server_handler);
	}
}

/*
 * Determine whether host from incoming request match our IP or IPv6 address.
 */
int server_host_match(const struct server_req *req, const char *host)
{
	return ipaddr_addr(host) == xnetif[0].ip_addr.addr;
}

void httpd_response_not_found(struct httpd_conn *conn, char *msg)
{
	char msg_buf[200];

	if (adap_wifi_in_ap_mode()) {
		server_handler(conn);
		return;
	}

	if (msg == NULL) {
		memset(msg_buf, 0, sizeof(msg_buf));
		sprintf(msg_buf, "Page Not Found\r\n");
		memcpy(msg_buf + strlen(msg_buf), conn->request.path,
		    conn->request.path_len);
		msg = msg_buf;
	}

	httpd_response_write_header_start(conn, "404 Not Found",
	    "text/plain", strlen(msg));
	httpd_response_write_header_finish(conn);
	httpd_response_write_data(conn, msg, strlen(msg));
}

void server_up(void)
{
	static u8 http_server_is_up;

	if (http_server_is_up == 0) {
		http_server_is_up = 1;
		httpd_setup_idle_timeout(5);
		if (httpd_start(80, 5, 8192, HTTPD_THREAD_SINGLE,
		    HTTPD_SECURE_NONE) != 0) {
			log_put(LOG_ERR "Can not start HTTP server");
			httpd_clear_page_callbacks();
		}
		httpd_setup_debug(HTTPD_DEBUG_OFF);
	}
}
