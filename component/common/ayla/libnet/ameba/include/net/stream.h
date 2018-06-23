/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_NET_STREAM_H__
#define __AYLA_NET_STREAM_H__

#include <net/net.h>

struct stream_ssl_id {
	int i;
};

struct stream_pcb;
struct stream_ssl_id;
struct ssl_metric_conn;
struct tcp_metric_conn;

enum ada_err stream_close(struct stream_pcb *);

void stream_init(void);
void stream_certs_load(const void *certs, size_t size);
const ip_addr_t *stream_local_ip(struct stream_pcb *);
const ip_addr_t *stream_remote_ip(struct stream_pcb *);
enum ada_err stream_write(struct stream_pcb *, const void *, u16_t len,
    u8_t apiflags);
enum ada_err stream_output(struct stream_pcb *);
struct stream_pcb *stream_new(struct stream_ssl_id *sess_id,
	int accept_non_ayla, struct ssl_metric_conn *ssl_metric,
	struct tcp_metric_conn *tcp_metric);
enum ada_err stream_connect(struct stream_pcb *, char *, ip_addr_t *,
    u16_t port, enum ada_err (*connected)(void *, struct stream_pcb *,
	enum ada_err));
void stream_arg(struct stream_pcb *, void *arg);
void stream_recv(struct stream_pcb *,
		size_t (*recv)(void *, struct stream_pcb *, void *, size_t));
void stream_resume(struct stream_pcb *);
void stream_sent(struct stream_pcb *pcb_arg,
    enum ada_err (*sent)(void *, struct stream_pcb *, u16 len));
void stream_err(struct stream_pcb *, void (*err)(void *, enum ada_err));
void stream_ssl_init_id(struct stream_ssl_id *);
int stream_tcp_is_established(struct stream_pcb *mpcb);
void stream_log_set(struct stream_pcb *, enum log_mod_id log_mod_option);

#endif /* __AYLA_NET_STREAM_H__ */
