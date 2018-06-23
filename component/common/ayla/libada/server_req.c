/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/queue.h>

#include <ayla/utypes.h>
#include <ayla/endian.h>
#include <ayla/assert.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/ayla_proto_mcu.h>
#include <ayla/clock.h>
#include <ayla/conf.h>
#include <ayla/uri_code.h>
#include <ayla/xml.h>
#include <ayla/http.h>
#include <ayla/cmd.h>
#include <ayla/parse.h>
#include <ayla/wifi_status.h>
#include <ayla/nameval.h>

#include <ada/err.h>
#include <ada/ada_conf.h>
#include <ada/prop.h>
#include <net/net.h>
#include <ada/server_req.h>
#include <ada/ada_wifi.h>
#include <ayla/malloc.h>

const char server_content_json[] = "Content-Type: text/json\r\n";
const char server_content_html[] = "Content-Type: text/html\r\n";

/*
 * Pointer to function returning function pointer for handler.
 */
void (*(*server_redir_handler_get)(struct server_req *, const char *user_agent))
	(struct server_req *);

static const struct name_val server_status[] = {
	{ "OK",				HTTP_STATUS_OK },
	{ "Accepted",			HTTP_STATUS_ACCEPTED },
	{ "No Content",			HTTP_STATUS_NO_CONTENT },
	{ "Bad Request",		HTTP_STATUS_BAD_REQ },
	{ "Found",			HTTP_STATUS_FOUND },
	{ "Forbidden",			HTTP_STATUS_FORBID },
	{ "Not Found",			HTTP_STATUS_NOT_FOUND },
	{ "Not Acceptable",		HTTP_STATUS_NOT_ACCEPT },
	{ "Conflict",			HTTP_STATUS_CONFLICT },
	{ "Precondition failed",	HTTP_STATUS_PRECOND_FAIL },
	{ "Too Many Requests",		HTTP_STATUS_TOO_MANY },
	{ "Internal Server Error",	HTTP_STATUS_INTERNAL_ERR },
	{ "Service Unavailable",	HTTP_STATUS_SERV_UNAV },
	{ NULL, 0 }
};

const char *server_status_msg(unsigned int status)
{
	const char *msg;

	msg = lookup_by_val(server_status, status);
	return msg ? msg : "";
}

void server_log(const char *fmt, ...)
{
	ADA_VA_LIST args;

	ADA_VA_START(args, fmt);
	log_put_va(MOD_LOG_SERVER, fmt, args);
	ADA_VA_END(args);
}

static const char server_not_found_body[] =
	"<!doctype html>\n"
	"<html><head><title>404 - Page not found</title></head><body>\n"
	"<h1>Page not found.</h1>\n"
	"<p><a href=\"/\">Return to home page</a></p>\n"
	"</body>\n</html>\n";

int (*server_not_found_hook)(struct server_req *req);

void server_get_not_found(struct server_req *req)
{
	if (server_not_found_hook && !server_not_found_hook(req)) {
		return;
	}
	req->put_head(req, HTTP_STATUS_NOT_FOUND, server_content_html);
	if (req->admin) {
		return;		/* no body for reverse-REST */
	}
	server_put_pure_len(req,
	    server_not_found_body, sizeof(server_not_found_body) - 1);
}

/*
 * Put format text into buffer and flush
 */
void server_put(struct server_req *req, const char *fmt, ...)
{
	va_list args;
	int len;

	va_start(args, fmt);
	len = vsnprintf(req->buf, SERVER_BUFLEN - 1, fmt, args);
	if (len >= SERVER_BUFLEN) {
		server_log(LOG_ERR "server result for %s truncated.  len %d",
		    req->resource, len);
		len = SERVER_BUFLEN - 1;
	}
	req->len = len;
	va_end(args);
	server_put_flush(req, NULL);
}

/*
 * Output a pure message, one that can be zero-copied and won't change.
 */
void server_put_pure_len(struct server_req *req, const char *msg, size_t len)
{
	req->len = len;
	server_put_flush(req, msg);
}

/*
 * Output a pure message, one that can be zero-copied and won't change.
 */
void server_put_pure(struct server_req *req, const char *msg)
{
	server_put_pure_len(req, msg, strlen(msg));
}

/*
 * Write JSON HTTP header.
 */
void server_json_header(struct server_req *req)
{
	if (req->http_status != HTTP_STATUS_BAD_REQ) {
		req->put_head(req, HTTP_STATUS_OK, server_content_json);
	} else {
		server_put_status(req, HTTP_STATUS_BAD_REQ);
	}
}

/*
 * Get an allocated copy of named arg from server request. Caller must free
 * returned buffer.
 */
char *server_get_dup_arg_by_name(struct server_req *req, const char *name)
{
	return server_get_arg_by_name(req, name, NULL, 0);
}

/*
 * Get value of named arg from server request to the supplied buffer.
 */
char *server_get_arg_by_name(struct server_req *req, const char *name,
				char *buf, size_t len)
{
	const char *arg;
	const char *val;
	const char *next;
	const char *endp;
	size_t name_len = strlen(name);
	size_t vlen;
	ssize_t rc;

	if (req->get_arg_by_name) {
		return req->get_arg_by_name(req, name, buf, len);
	}

	arg = strchr(req->resource, '?');
	if (!arg) {
		return NULL;
	}
	arg++;
	for (endp = arg + strlen(arg); arg < endp; arg = next) {
		val = strchr(arg, '=');
		if (!val) {
			break;
		}
		val++;
		next = strchr(arg, '&');
		if (next) {
			vlen = next - val;
			next++;
		} else {
			vlen = endp - val;
			next = endp;
		}
		if (val >= next || arg + name_len + 1 != val) {
			continue;
		}
		if (strncmp(arg, name, name_len)) {
			continue;
		}
		if (buf == NULL) {
			buf = (char *) malloc(vlen + 1);
			if (buf == NULL) {
				break;
			}
			len = vlen + 1;
		}
		rc = uri_decode_n(buf, len, val, vlen);
		if (rc < 0 || rc >= len) {
			break;
		}
		return buf;
	}
	return NULL;
}

/*
 * Get long argument with default of 0.
 * Returns non-zero on error.  Fills in *valp with value, or 0 on error.
 */
int server_get_long_arg_by_name(struct server_req *req, const char *name,
		 long *valp)
{
	char buf[20];
	char *cp;
	char *errptr;
	long val;

	*valp = 0;
	cp = server_get_arg_by_name(req, name, buf, sizeof(buf));
	if (!cp) {
		return -1;
	}
	val = strtoul(cp, &errptr, 0);
	if (*errptr != '\0') {
		return -1;
	}
	*valp = val;
	return 0;
}

/*
 * Get boolean argument with default of 0.
 * Ignores errors.  Missing or improper URL query strings are ignored.
 */
u8 server_get_bool_arg_by_name(struct server_req *req, const char *name)
{
	long val;

	server_get_long_arg_by_name(req, name, &val);
	return val != 0;
}

/*
 * Handle a received packet for a request.
 */
void server_req(struct server_req *req)
{
	const struct url_list *tt;
	char buf[SERVER_BUFLEN];
	unsigned long len;
	char *line;
	char *url;
	char *cp;
	char *endptr;
	char *version;
	char *msg;
	void (*redir)(struct server_req *) = NULL;
	size_t res_len;
	u8 priv;
	int rc;

#ifdef ENABLE_HTTP_HEADER_PARSE
	if (req->state == REQ_INIT) {
		line = server_get_line(req, buf, sizeof(buf));
		if (!line) {
			goto out;	/* full line not received yet */
		}
		server_log(LOG_DEBUG "req init: %s", line);
		url = strchr(line, ' ');
		if (!url) {
			msg = "no space after method";
			goto error;
		}
		*url++ = '\0';		/* terminate method */
		req->method = server_parse_method(line);

		version = strchr(url, ' ');
		if (!version) {
			msg = "no version";
			goto error;
		}
		res_len = version - url;
		*version++ = '\0';		/* terminate url */
		if (!strcmp(version, "HTTP/1.1")) {
			req->keep_open = 1;
		}

		/*
		 * Copy URI including query string fit to the resource buffer.
		 * If it doesn't fit, copy what will fit, and it should get
		 * a 404 error, assuming none of the supported URLs are that
		 * long.
		 */
		if (res_len > sizeof(req->resource) - 1) {
			res_len = sizeof(req->resource) - 1;
			server_log(LOG_DEBUG "req: resource too long");
		}
		memcpy(req->resource, url, res_len);
		req->resource[res_len] = '\0';

		priv = LOC_REQ;
		if (adap_wifi_in_ap_mode()) {
			priv |= REQ_SOFT_AP;
		}
#ifdef HOMEKIT
		if (req->sec_arg) {
			priv |= REQ_HAP;
		}
#endif
		tt = server_find_handler(req, url, req->method, priv);
		if (!tt) {
			server_log(LOG_WARN "req unsupported");
			return;
		}
		req->url = tt;
		req->state = REQ_HEAD;
		req->content_len = 0;
	}

	while (req->state == REQ_HEAD) {
		line = server_get_line(req, buf, sizeof(buf));
		if (line == NULL) {
			return;
		}

		/*
		 * An empty line ends the header.
		 */
		if (*line == '\0') {
			req->state = REQ_DATA;
			break;
		}
		server_log(LOG_DEBUG2 "req line: %s", line);
		cp = strchr(line, ':');
		if (cp) {
			*cp++ = '\0';
			while (*cp == ' ') {
				cp++;
			}
			if (strcmp(line, "Content-Length") == 0) {
				len = strtoul(cp, &endptr, 10);
				if (*endptr != '\0') {
					server_log(LOG_WARN "req: "
					   "invalid clen '%s'\n", cp);
					msg = "invalid clen";
					goto error;
				}
				req->content_len = len;
			} else if (strcasecmp(line, "User-Agent") == 0) {
				if (server_redir_handler_get) {
					redir = server_redir_handler_get(req,
					    cp);
				}
			} else if (strcmp(line, "Host") == 0) {
				req->host_present = 1;
				req->host_match = server_host_match(req, cp);
				if (!req->host_match) {
					server_log(LOG_DEBUG2
					    "host %s no match", cp);
				}
			}
		}
	}
#else
	if (req->state == REQ_INIT) {
		req->method = server_req_method(req);
		if (server_req_is_version(req, "HTTP/1.1")) {
			req->keep_open = 1;
		}
		if (server_req_resource(req, req->resource,
		    sizeof(req->resource))) {
			server_log(LOG_DEBUG "req: resource too long");
		}
		priv = LOC_REQ;
		if (adap_wifi_in_ap_mode()) {
			priv |= REQ_SOFT_AP;
		}
#ifdef HOMEKIT
		if (req->sec_arg) {
			priv |= REQ_HAP;
		}
#endif
		tt = server_find_handler(req, req->resource, req->method,
		    priv);
		if (!tt) {
			msg = "req unsupported";
			goto error;
		}
		req->content_len = 0;
		if (!server_req_header(req, "Content-Length", buf,
		    sizeof(buf))) {
			len = strtoul(buf, &endptr, 10);
			if (*endptr != '\0') {
				server_log(LOG_WARN "req: "
				   "invalid clen '%s'\n", buf);
				msg = "invalid clen";
				goto error;
			}
			req->content_len = len;
		}
		if (!server_req_header(req, "User-Agent", buf, sizeof(buf))) {
			if (server_redir_handler_get) {
				redir = server_redir_handler_get(req,
				    buf);
			}
		}
		if (!server_req_header(req, "Host", buf, sizeof(buf))) {
			req->host_present = 1;
			req->host_match = server_host_match(req, buf);
			if (!req->host_match) {
				server_log(LOG_DEBUG2
				    "host %s no match", buf);
			}
		}

		req->url = tt;
		req->state = REQ_DATA;
	}
#endif

	if (req->state == REQ_DATA) {
		req->buf = buf;
		req->post_data = buf;
		if (req->url->req_flags & REQ_NO_BUF) {
			/*
			 * Special PUT handler for files will handle
			 * data from buf as it arrives.  We call it again
			 * below after request is complete.
			 */
			server_read(req);
			req->url->url_op(req);
			if (req->state == REQ_ERR) {
				return;
			}
			if (req->len < req->content_len) {
				goto out;
			}
		} else {
			rc = server_read(req);
			if (rc) {
				if (rc < 0) {
					msg = "short body";
					goto error;
				}
				goto out;
			}
		}
		req->state = REQ_READY;
	}

	if (req->state == REQ_READY) {
		req->buf = buf;
		req->len = 0;
		req->err = AE_OK;
		req->finish_write = server_complete;
		if (req->host_present == 1 && req->host_match == 0) {
			if (redir) {
				server_continue(req, redir);
			} else {
				server_continue(req, server_get_not_found);
			}
		} else {
			server_continue(req, req->url->url_op);
		}
		if (!req->user_in_prog) {
			server_complete(req);
		}
	}
out:
	req->buf = NULL;	/* on-stack buffer must no longer be used */
	return;

error:
	server_log(LOG_WARN "malformed req: %s", msg);
	req->state = REQ_ERR;
}

static const struct url_list server_url_not_found = {
	.url_op = server_get_not_found
};

static struct url_list const *server_url_groups[SERVER_URL_GROUPS];

static const struct name_val server_methods[] = {
	{ "GET", REQ_GET },
	{ "POST", REQ_POST },
	{ "PUT", REQ_PUT },
	{ "DELETE", REQ_DELETE },
	{ "HEAD", REQ_GET_HEAD },
	{ NULL, REQ_BAD }
};

void server_add_urls(const struct url_list *urls)
{
	int i;

	for (i = 0; i < SERVER_URL_GROUPS - 1; i++) {
		if (server_url_groups[i] == urls) {
			return;
		}
		if (!server_url_groups[i]) {
			server_url_groups[i] = urls;
			server_reg_urls(urls);
			return;
		}
	}
	server_log(LOG_ERR "add_urls failed");
}

enum server_method server_parse_method(const char *method)
{
	return lookup_by_name(server_methods, method);
}

/*
 * Find the URL list entry for the given URL based on the URL and method.
 * Also sets the method enum and resource string.
 * Returns the default not-found handler if the URL is not matched.
 */
const struct url_list *server_find_handler(struct server_req *req,
			const char *url, enum server_method method, u8 priv)
{
	const struct url_list *tt;
	const char *url_end;
	int i;
	size_t len;

	req->method = method;
	if (method == REQ_GET_HEAD) {
		method = REQ_GET;	/* find the GET handler */
	}
	if (url != req->resource) {
		snprintf(req->resource, sizeof(req->resource) - 1, "%s", url);
	}

	url_end = strchr(url, '?');
	if (url_end) {
		len = url_end - url;
	} else {
		len = strlen(url);
	}

	for (i = 0; i < SERVER_URL_GROUPS; i++) {
		tt = server_url_groups[i];
		if (!tt) {
			break;
		}
		for (; tt->url; tt++) {
			if (method == tt->method &&
			    tt->url &&
			    strlen(tt->url) == len &&
			    !strncmp(url, tt->url, len) &&
			    (tt->req_flags & priv)) {
				return tt;
			}
		}
	}
	return &server_url_not_found;
}

void server_put_status(struct server_req *req, unsigned int status)
{
	req->put_head(req, status, NULL);
}

void server_req_init(struct server_req *req)
{
	memset(req, 0, sizeof(*req));
	req->static_alloc = 1;
}
