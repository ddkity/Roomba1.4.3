/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_HTTP_CLIENT_H__
#define __AYLA_HTTP_CLIENT_H__

#include <net/net.h>

#define HTTP_CLIENT_SERVER_PORT	80
#define HTTP_CLIENT_SERVER_PORT_SSL	443

#define HTTP_CLIENT_BUF_LEN	640	/* buffer size for initial request */

#define HTTP_CLIENT_TCP_WAIT	7000	/* TCP connect wait, millsecs */
#define HTTP_CLIENT_CONN_WAIT	30000	/* TCP+SSL connect wait, millsecs */
#define HTTP_CLIENT_RETRY_WAIT	10000	/* retry wait, milliseconds */
#define HTTP_CLIENT_TRANS_WAIT  10000	/* TCP send/recv wait, milliseconds */
#define HTTP_CLIENT_RECV_WAIT  20000	/* TCP Recv wait, milliseconds */
#define HTTP_CLIENT_OPEN_WAIT    3000	/* TCP Open Wait */
#define HTTP_CLIENT_MEM_WAIT    60000	/* TCP ERR_MEM Wait */
#define HTTP_CLIENT_KEEP_OPEN_WAIT    20000	/* TCP Keep Open Wait */
#define HTTP_CLIENT_MCU_WAIT    15000	/* TCP Wait for MCU to consume recv */
#define HTTP_CLIENT_TRY_COUNT	3	/* tries before giving up on server */
#define HTTP_LOC_CLIENT_TRY_COUNT 2	/* tries before giving up on loc cli */

/*
 * Values used only for device service client authorization.
 */
#define HTTP_CLIENT_AUTH_KEY_LEN 40	/* max length of auth key incl NUL */
#define HTTP_CLIENT_AUTH_LINE_LEN 64	/* max length of auth line with CR LF */
#define HTTP_CLIENT_INIT_AUTH_HDR	"x-Ayla-client-auth"
#define HTTP_CLIENT_AUTH_VER	"Ayla1.0"
#define HTTP_CLIENT_TIME_FIELD	"x-Ayla-server-time"
#define HTTP_CLIENT_KEY_FIELD	"x-Ayla-auth-key"	/* temporal auth */
#define HTTP_CLIENT_TEMP_AUTH	HTTP_CLIENT_KEY_FIELD ": " HTTP_CLIENT_AUTH_VER

enum http_method {
	HTTP_REQ_NONE = 0,
	HTTP_REQ_GET,
	HTTP_REQ_PUT,
	HTTP_REQ_POST,
};

enum http_client_state {
	HCS_IDLE,
	HCS_DNS,	/* resolving host name */
	HCS_CONN,	/* wait for connection to service */
	HCS_CONN_TCP,	/* have tcp conn, waiting for ssl */
	HCS_SEND,	/* waiting for send to complete */
	HCS_HEAD,	/* receiving HTTP headers */
	HCS_CHUNKED_HEAD, /* receiving chunked size */
	HCS_CONTENT,	/* receiving HTTP content */
	HCS_OPEN,	/* ready to send data */
	HCS_KEEP_OPEN,	/* done with prev, ready for another request */
	HCS_WAIT_RETRY,	/* waiting to retry after connection or I/O error */
	HCS_WAIT_TCP_SENT, /* waiting for tcp sent callback */
	HCS_WAIT_CLI_RECV, /* waiting for client recv callback */
	HCS_COMPLETE,	/* waiting to do completion callback then idle */
};

enum http_client_error {
	HC_ERR_NONE = 0,
	HC_ERR_DNS,
	HC_ERR_MEM,
	HC_ERR_CONNECT,
	HC_ERR_SEND,
	HC_ERR_RECV,
	HC_ERR_HTTP_PARSE,
	HC_ERR_HTTP_REDIR,
	HC_ERR_HTTP_STATUS,
	HC_ERR_CLOSE,
	HC_ERR_CLIENT_AUTH,
	HC_ERR_CONN_CLSD,
	HC_ERR_TIMEOUT,
};

struct http_client {
	enum http_client_state state;
	struct stream_pcb *pcb;		/* connecting stream */
	char host[80];			/* server host name or IP address */
	ip_addr_t host_addr;		/* server ip address */
	void *parent;			/* parent of the http_client struct */
	enum http_client_error hc_error; /* potential http client error */
	struct stream_ssl_id sess_id;	/* SSL session ID */
	struct http_state http_state;
	enum mod_log_id mod_log_id;
	u8 retries;
	u8 ssl_enable:1;
	u8 client_auth:1;	/* use client authentication header */
	u8 req_pending:1;
	u8 content_given:1;	/* has the content-length been given? */
	u8 chunked_enc:1;       /* server resp contains chunked encoding */
	u8 conn_close:1;        /* server resp contains connection close */
	u8 range_given:1;	/* server resp contains the range */
	u8 sending_chunked:1;   /* set to 1 if we're sending a long */
	u8 chunked_eof:1;       /* set to 1 if we sent eof of long */
	u8 prop_callback:1;	/* set to 1 if cli running prop_cb */
	u8 user_in_prog:1;	/* send is waiting for user progress */
	u8 accept_non_ayla:1;	/* accept cert from non_ayla (stream_mssl) */
	u8 req_part;		/* part # of the current request */
	u16 host_port;          /* port # of host (for LAN support) */
	u32 range_bytes;	/* # of bytes given in the range header */
	u32 content_len;	/* expected content-length of incoming tcp */
	const void *body_buf;	/* put/post data, if any */
	size_t body_buf_len;	/* length of PUT/POST buf data not yet sent */
	size_t body_len;	/* content length for PUT/POST */
	ssize_t sent_len;	/* body length already sent */
	u32 http_status;	/* http status code from service response */
	u8 retry_limit;		/* # of retries limit */
	u16 retry_wait;		/* wait time between retries (in millisecs) */
	u16 conn_wait;		/* wait time for a connection (in millisecs) */
	size_t recv_consumed;	/* # of bytes consumed by client of tcp_recv */
	u32 server_time;	/* time from server, if given */
	u32 http_time;		/* time from HTTP header, if given and valid */
	char auth_hdr[HTTP_CLIENT_AUTH_LINE_LEN];   /* auth header value */

	/* Function Pointers For Callbacks to Client */
	void (*client_send_data_cb)(struct http_client *);
	void (*client_err_cb)(struct http_client *);
	enum ada_err (*client_tcp_recv_cb)(struct http_client *, void *,
	    size_t);
	void (*client_next_step_cb)(struct http_client *);

	size_t req_len;		/* len of data in req_buf */
	char req_buf[HTTP_CLIENT_BUF_LEN];
#ifdef AMEBA
	struct timer hc_timer;
	int hc_initialized;
#endif /* AMEBA */
#ifdef WMSDK
	void *timer;
	int session;
	void *content;		/* dynamic body buffer */
	struct net_callback completion_cb;
#endif /* WMSDK */
#ifdef QCA4010_SDK
	struct timer hc_timer;
	int hc_initialized;
#endif
	struct https_metrics *metrics; /* optional connection metrics */
	struct net_dns_req dns_req;
};

void http_client_start(struct http_client *);

/*
 * Extra headers
 */
struct http_hdr {
	const char *name;
	const char *val;
};

extern const struct http_hdr http_hdr_content_json;
extern const struct http_hdr http_hdr_content_stream;
extern const struct http_hdr http_hdr_content_xml;

int http_client_is_ready(struct http_client *);
int http_client_is_sending(struct http_client *);
void http_client_req(struct http_client *, enum http_method method,
    const char *resource, int hcnt, const struct http_hdr *hdrs);
void http_client_abort(struct http_client *);
enum ada_err http_client_send(struct http_client *, const void *, u16_t);
void http_client_send_pad(struct http_client *);
void http_client_send_complete(struct http_client *);
void http_client_reset(struct http_client *, enum mod_log_id,
	struct https_metrics *);
void http_client_continue_recv(struct http_client *);
void http_client_set_conn_wait(struct http_client *hc, int wait);
void http_client_set_retry_wait(struct http_client *hc, int wait);
void http_client_set_retry_limit(struct http_client *hc, int limit);
u32 http_client_local_ip(struct http_client *hc);

#endif /* __AYLA_HTTP_CLIENT_H__ */
