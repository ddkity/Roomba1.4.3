/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_SERVER_REQ_H__
#define __AYLA_SERVER_REQ_H__

#ifndef AMEBA
#define ENABLE_HTTP_HEADER_PARSE
#endif

#include <ayla/server_file.h>
#include <ada/err.h>
#include <net/ipaddr_fmt.h>
#include <sys/queue.h>

/*
 * AP-mode IP address and mask.
 */
#define SERVER_AP_IP	((192U << 24) | (168 << 16) | 1) /* 192.168.0.1)/16 */
#define SERVER_AP_NETMASK 0xffff0000U

#define HTTPD_PORT	80

#define SERVER_BUFLEN 1024	/* size of onstack buffer */
#ifndef TCP_MSS
#define TCP_MSS 536
#endif
#define SERVER_SND_BUF	(4 * TCP_MSS)	/* extra space to fit large web page */

#define SERVER_URI_LEN	256	/* max URI length including query string */
#define SERVER_URL_GROUPS 16	/* max number of URL tables */

/*
 * method.
 */
enum server_method {
	REQ_BAD = 0,
	REQ_GET,
	REQ_GET_HEAD,
	REQ_POST,
	REQ_PUT,
	REQ_DELETE,
};

/*
 * Request flags.
 */
#define LOC_REQ		0x01	/* Allow local request (not encrypted) */
#define APP_REQ		0x02	/* Allow app request (encrypted) */
#define ADS_REQ		0x04	/* Allow ADS request (encrypted) */
#define REQ_NO_BUF	0x08	/* Send data to handler without buffering */
#define REQ_KEEPOPEN	0x10	/* Can do another http req in same connection */
#define REQ_SOFT_AP	0x20	/* Allow unencrypted access in SoftAP mode */
#define REQ_HAP		0x40	/* HomeKit HAP encryption required */

#define APP_ADS_REQS		(APP_REQ | ADS_REQ)
#define ALL_REQS		(LOC_REQ | APP_REQ | ADS_REQ | REQ_SOFT_AP)

struct prop;
struct server_req;

struct url_list {
	enum server_method method;
	u8 req_flags;
	const char *url;
	void (*url_op)(struct server_req *);
	const void *arg;
};

/*
 * Macros for initializing url_list tables.
 */
#define URL_GET(url, func, flags) { REQ_GET, flags, url, func }
#define URL_GET_ARG(url, func, flags, arg) { REQ_GET, flags, url, func, arg }
#define URL_PUT(url, func, flags) { REQ_PUT, flags, url, func }
#define URL_POST(url, func, flags) { REQ_POST, flags, url, func }
#define URL_DELETE(url, func, flags) { REQ_DELETE, flags, url, func }

/*
 * Per-request state.
 */
struct server_req {
	/* linkage on list of active requests */
	LIST_ENTRY(server_req) siblings;
	char resource[SERVER_URI_LEN];	/* file or page name including query */
	const struct url_list *url;
	enum {
		REQ_INIT,
		REQ_HEAD,
		REQ_DATA,
		REQ_READY,
		REQ_DONE,
		REQ_ERR,
		REQ_CLOSING,
	} state;
	enum server_method method;
	struct net_tcp *pcb;
	void *req_impl;		/* for private use by requestor */
	void *prov_impl;	/* for private use by content provider */
	struct ada_mbuf *mbuf;	/* received buffers */
	char *post_data;	/* PUT or POST data, if any */
	u16 content_len;	/* for post, the content length value */
	char *buf;		/* stack scratch buffer, size SERVER_BUFLEN */
	size_t len;		/* used bytes in buffer */

	/* Function to put header of response */
	void (*put_head)(struct server_req *req, unsigned int status,
			const char *content_type);

	/* Function to flush data to tcp_write */
	void (*write_cmd)(struct server_req *req, const char *msg);

	/* Function to call after all writes for a req are complete */
	enum ada_err (*finish_write)(struct server_req *req);

	u8 host_match:1;	/* hostname in request matches ours */
	u8 host_present:1;	/* hostname present in request */
	u8 suppress_out:1;	/* suppress output (for HEAD requests) */
	u8 static_alloc:1;	/* statically allocated request, not on list */
	u8 head_sent:1;		/* HTTP header completely sent */

	/*
	 * Support for properties.  Other clients may use these, too.
	 */
	u8 prop_first:1;	/* output preamble */
	u8 prop_end:1;		/* output postamble */
	u8 prop_timeout:1;	/* indicates timeout occurred */
	u8 prop_abort:1;        /* underlying TCP connection gone. Abort */

	u8 mobile:1;		/* indicates request by mobile device */
	u8 admin:1;		/* indicates this req has admin privs */
	u8 apple:1;             /* indicates request by apple device */
	u8 keep_open:1;		/* HTTP 1.1 connection */
	u8 ios_ver:4;           /* indicates iOS version of request (5,6,7) */
	u8 user_in_prog:1;	/* user has dependent request in progress */
	u16 http_status;	/* status for reverse-REST, zero means 200 */
	s8 req_timer;		/* Time req has been active */

	enum ada_err err;	/* error, if any, that occurred on last write */

	/*
	 * Support for continuing a get request after a put fails due to
	 * lack of space in the TCP layer.
	 * We track how many puts have been done successfully, and skip that
	 * many puts on the recall.
	 */
	void (*resume)(struct server_req *); /* continuation function for get */
	u16 put_count;		/* count of puts called since call or resume */
	u16 puts_done;		/* count of puts already queued without err */
	void *user_priv;	/* private state when get function resumed */
	size_t user_offset;	/* private offset for get function */
	struct net_callback *tcpip_cb; /* optional tcpip_cb after close */
	void *sec_arg;
	void (*close_cb)(struct server_req *); /* server close callback */
	char *(*get_arg_by_name)(struct server_req *req, const char *name,
		char *buf, size_t len);
};

#ifdef STATIC_WEB_CONTENT_IN_MEMORY
/*
 * Static web pages are inside addressable memory.
 */

#ifdef XXD_BIN_TO_C
struct server_buf {
	const char *content_type;
	const void *buf;
	unsigned int *len;
};

#define SERVER_BUF_INIT(text, resource, type) { \
	.buf = LINKER_TEXT_START(text),		\
	.len = &LINKER_TEXT_SIZE(text),		\
	.content_type = type,			\
		}

#else
struct server_buf {
	const char *content_type;
	const void *buf;
	size_t len;
};

#define SERVER_BUF_INIT(text, resource, type) { \
	.buf = LINKER_TEXT_START(text),		\
	.len = (size_t)LINKER_TEXT_SIZE(text),	\
	.content_type = type,			\
}
#endif

#else
/*
 * Static web pages are stored as 'resource' files inside flash.
 */
struct server_buf {
	const char *content_type;
	const char *file;
};

#define SERVER_BUF_INIT(text, resource, type) { \
	.file = resource,			\
	.content_type = type,			\
}
#endif /* STATIC_WEB_CONTENT_IN_MEMORY */


/*
 * Start server.
 * Call when network interface comes up.
 */
void server_up(void);

/*
 * Enable server redirection
 */
void server_enable_redir(void);

/*
 * Hook for URLs which are not otherwise found.
 * The function pointed to here is called if no handler is registered
 * for the URL.  If this hook handles the request successfully, it returns 0.
 */
extern int (*server_not_found_hook)(struct server_req *);

/*
 * Macro to make logging easier
 */
#define SERVER_LOGF(_level, _format, ...) \
	server_log(_level "%s: " _format, __func__, ##__VA_ARGS__)

void server_log(const char *fmt, ...) ADA_ATTRIB_FORMAT(1, 2);

/*
 * Handler for new data on the request
 */
void server_req(struct server_req *);

#ifdef ENABLE_HTTP_HEADER_PARSE
/*
 * Get a line from the header of the request.
 */
char *server_get_line(struct server_req *, char *buf, size_t len);
#else
/*
 * Get method from HTTPD library.
 */
enum server_method server_req_method(struct server_req *req);

/*
 * Get method from http daemon
 */
int server_req_is_version(struct server_req *req, const char *version);

/*
 * Get resource from http daemon
 */
int server_req_resource(struct server_req *req, char *buf, size_t buf_size);

/*
 * Get header from http daemon
 */
int server_req_header(struct server_req *req, const char *header,
	char *buf, size_t bufsize);
#endif

/*
 * Add URLs to be handled.
 */
void server_add_urls(const struct url_list *);

/*
 * Register URLs with lower-level
 */
void server_reg_urls(const struct url_list *);

/*
 * Determine if host address matches.
 */
int server_host_match(const struct server_req *, const char *host);

/*
 * Put HTTP response with no body.
 */
void server_put_status(struct server_req *req, unsigned int status);

/*
 * Get status message from status code.
 */
const char *server_status_msg(unsigned int status);

/*
 * Handle a GET request for a static page.
 * The contents are described by the url->arg pointing to a struct server_buf.
 */
void server_send_static(struct server_req *);

/*
 * Allow the platform or app to handle a GET request for a URL (static image).
 * Returns 0 if the page was successfully provided.
 * On error, the caller provides a built-in default static page.
 */
int adap_server_file_get(struct server_req *);

/*
 * Put common HTML elements at top of generated pages.
 */
void server_banner(struct server_req *, const char *title);
void server_put_flush(struct server_req *req, const char *msg);
void server_put_pure(struct server_req *, const char *);
void server_put_pure_len(struct server_req *req, const char *msg, size_t len);
void server_put(struct server_req *, const char *fmt, ...)
	ADA_ATTRIB_FORMAT(2, 3);
char *server_get_arg_by_name(struct server_req *, const char *name,
				char *buf, size_t len);
int server_get_long_arg_by_name(struct server_req *, const char *name,
		 long *valp);
u8 server_get_bool_arg_by_name(struct server_req *, const char *name);
char *server_get_dup_arg_by_name(struct server_req *, const char *name);
char *server_get_arg_len(struct server_req *, char **valp, size_t *);
void server_redir(struct server_req *req);
void server_resume(struct server_req *, void (*resume)(struct server_req *));
void server_continue(struct server_req *, void (*resume)(struct server_req *));
void server_close(struct server_req *req);
const struct url_list *server_find_handler(struct server_req *req,
			const char *url, enum server_method, u8 priv);
void server_free_aborted_req(struct server_req *req);
void server_get_not_found(struct server_req *req);
int server_read(struct server_req *);
enum server_method server_parse_method(const char *method);

static inline void server_close_when_done(struct server_req *req)
{
	req->keep_open = 0;
}

/*
 * Hook for platform to look at user-agent and perhaps request re-direct.
 * Set this to the function that returns the handler function for redirect.
 */
extern void (*(*server_redir_handler_get)
	(struct server_req *, const char *user_agent))(struct server_req *);

/*
 * Close if OK.
 */
enum ada_err server_complete(struct server_req *);

extern u32 server_conn_time;	/* last connection time in ms */

void client_page_get(struct server_req *);
void client_page_post(struct server_req *);
void client_json_getdsns_put(struct server_req *);
void client_json_regtoken_get(struct server_req *);
void client_json_status_get(struct server_req *);
void client_json_time_get(struct server_req *);
void client_json_time_put(struct server_req *);
void client_lanip_json_put(struct server_req *);
void client_registration_json_put(struct server_req *);
void client_reset_json_put(struct server_req *);
const char *client_get_sym_hostname(void);
void client_set_sym_hostname(char *name, int len);

void metric_config_json_get(struct server_req *);
void metric_config_json_put(struct server_req *);

void client_ota_json_put(struct server_req *);
void client_lanota_json_put(struct server_req *);

/*
 * JSON interfaces.
 */
void server_json_header(struct server_req *);

/*
 * Allow log client enable/disable through reverse-rest
 */
void client_log_client_json_put(struct server_req *req);

/*
 * Initialize a staticly-allocated server request.
 */
void server_req_init(struct server_req *);

extern const char server_content_json[];
extern const char server_content_html[];
extern const char server_html_head[];
extern const char server_json_head[];

#endif /* __AYLA_SERVER_REQ_H__ */
