/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_METRIC_H__
#define __AYLA_METRIC_H__

#define DEF_BURST_FREQ		50
#define CLIENT_METRIC_SIZE	10
#define HTTP_METRIC_SIZE	10
#define SSL_METRIC_SIZE		10
#define TCP_METRIC_SIZE		10

struct client_metric_req {
	u32 client_start;		/* time of client start (ms) */
	u32 send_start;			/* time of send start (ms) */
	u32 send_end;			/* time of send end (ms) */
	u32 recv_start;			/* time of recv start (ms) */
	u32 recv_end;			/* time of recv end (ms) */
	enum client_http_req request;	/* request issued by client */
	enum client_conn_state timeout;	/* state of client if timeout event */
};

struct http_metric_req {
	u32 http_start;		/* time of http_client start (ms) */
	u32 dns_resolve;	/* time of dns resolve (ms) */
	u32 client_connected;	/* time of client connected (ms) */
	u32 send_done;		/* time of send completion */
	u32 recv_start;		/* time of init receive */
	u32 recv_done;		/* time of req completion */
	u32 http_status;	/* http status code of the connection */
	u32 tx_bytes;		/* bytes sent this connection */
	u32 rx_bytes;		/* bytes received this connection */
	err_t tcp_conn_err;	/* callback from tcp when conn fails or rsts */
	enum http_client_state timeout; /* state if timeout event */
	enum http_client_error hc_error; /* error state if error occured */
	u8  chunked_enc:1;	/* flag if response used chunked_enc */
	u8  keep_open:1;	/* flag if keep_open after recv_done */
};

struct ssl_metric_conn {
	u32 connect_start;	/* time of connection start (ms) */
	u32 handshake_done;	/* time of completion of handshake */
	u32 tx_bytes;		/* bytes sent this connection */
	u32 rx_bytes;		/* bytes received this connection */
	u32 connect_close;	/* time of connection close (ms) */
	int libssl_err;		/* last bad ssl matrixssl/cyassl code */
};

struct tcp_metric_conn {
	u32 connect_start;	/* time of connection start (ms) */
	u8 nrtx;		/* number of retransmissions */
	err_t connect_err;	/* connect error code */
	err_t wrt_err;		/* write error code */
	err_t output_err;	/* output error code */
	err_t close_err;	/* close error code */
	err_t bind_err;		/* bind error code */
};

struct status_info {
	u16 burst_freq;
	u16 num_reqs;
	u8 out_count;
	u8 in;
	u8 init_print:1;
	u8 enable:1;
};

struct client_metrics {
	struct client_metric_req buf[CLIENT_METRIC_SIZE];
	struct client_metric_req *current;
	struct status_info status;
};

struct http_metrics {
	struct http_metric_req buf[HTTP_METRIC_SIZE];
	struct http_metric_req *current;
	struct status_info status;
};

struct ssl_metrics {
	struct ssl_metric_conn buf[SSL_METRIC_SIZE];
	struct ssl_metric_conn *current;
	struct status_info status;
};

struct tcp_metrics {
	struct tcp_metric_conn buf[TCP_METRIC_SIZE];
	struct tcp_metric_conn *current;
	struct status_info status;
};

struct https_metrics {
	struct http_metrics http;
	struct ssl_metrics ssl;
	struct tcp_metrics tcp;
};

struct cli_list {
	const char *metric;
	int (*metric_op)(const char *flag, u32 val);
	struct status_info *(*metric_get_status)(void);
};

void metric_log_client_reqs(u8 mod_nr, struct client_metrics *metrics,
			    u8 fce);
void metric_log_http_reqs(u8 mod_nr, struct http_metrics *metrics, u8 fce);
void metric_log_ssl_reqs(u8 mod_nr, struct ssl_metrics *metrics, u8 fce);
void metric_log_tcp_reqs(u8 mod_nr, struct tcp_metrics *metrics, u8 fce);
void metric_cli(int argc, char **argv);

#endif /* __AYLA_METRIC_H__ */
