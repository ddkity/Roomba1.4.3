/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#define HAVE_UTYPES
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <FreeRTOS.h>
#include <task.h>
#include <lwip/sockets.h>
#include <lwip/tcpip.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ada/task_label.h>
#include <ayla/clock.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/tlv.h>
#include <ayla/http.h>
#include <ayla/parse.h>
#include <ayla/timer.h>
#include <ayla/nameval.h>
#include <ayla/malloc.h>

#include <net/net.h>
#include <net/stream.h>
#include <net/ada_mbuf.h>
#include <net/net_crypto.h>

#include <ada/client.h>
#include <net/http_client.h>
#include <ada/metric.h>

#include "ada_lock.h"
#include "ca_cert.h"
#include "client_timer.h"

#define stream_type(sp)		((sp)->enable ? "TLS" : "TCP")
#define stream_socket(sp)	((sp)->enable ? (sp)->ssl_fd.fd : (sp)->sock)

#define STREAM_STACK_DEBUG	1

#define STREAM_SSL_INBUF_LEN	6000
#define STREAM_SSL_OUTBUF_LEN	3500
#define STREAM_RX_SZ		1500
#define STREAM_RX_BUF_LIM	3	/* max buffers before pausing stream */

#define STREAM_HTTPS_LINGER	3	/* seconds to keep TCP in FIN_WAIT */
#define STREAM_HTTP_LINGER	1	/* seconds to keep TCP in FIN_WAIT */
#define STREAM_SOCK_RETRY_TIME	12000	/* ms of socket retry time */

#define STREAM_TASK_STACKSZ_TLS	((5 * 1024) / sizeof(portSTACK_TYPE))
#define STREAM_TASK_STACKSZ	((4 * 1024 + 512) / sizeof(portSTACK_TYPE))

#define STREAM_TASK_PRIO	(tskIDLE_PRIORITY+1)
#define STREAM_TASK_PRIO_NOPREEMPT 0	/* best priority is lowest */

#define STREAM_TX_STACK_MAGIC	0xef	/* threadx stack guard */
#define STREAM_SOCK_INVAL	(-1)	/* zero is a valid handle */
#define STREAM_RX_WAIT		101101	/* microsecs to wait in select */

#define STREAM_TCP_CONN_TIMEOUT 20	/* TCP connection timeout, seconds */

#if STREAM_STACK_DEBUG
static int stream_max_depth;
#endif

static struct ada_lock *stream_lock;
static struct stream_pcb *stream_pcbs;
static mbedtls_x509_crt ca_certs_chain;
static int ca_certs_inited;

struct stream_pcb {
#if STREAM_STACK_DEBUG
	u8 guard_zone[128];	/* xxx */
#endif
	struct stream_pcb *next;
	const char *host;
	u8 id;			/* identifier for error messages only */
	u8 enable:1;		/* ssl_enable set at time of create */
	u8 connect_req:1;	/* connect requested */
	u8 rx_req:1;		/* receive requested (connected) */
	u8 send_req:1;
	u8 rx_paused:1;		/* client flow control pause for receive */
	u8 rx_closed:1;		/* received EOF */
	u8 tx_closed:1;		/* shutdown transmit side */
	u8 accept_non_ayla:1;	/* accept non-ayla certificates */
	u8 rx_event:1;
	u8 connected_event:1;
	u8 close_event:1;
	u8 ssl_connected:1;
	union {
		/* Mbedtls context - socket for https */
		mbedtls_ssl_context ssl;
		/* socket for http */
		int sock;
	};
	union {
		/* Mbedtls memroy for TLS session */
		struct {
			mbedtls_net_context ssl_fd;
			mbedtls_ssl_config ssl_cfg;
		};
	};
	ip_addr_t local_ip;
	ip_addr_t remote_ip;
	u16 remote_port;
	struct net_callback cb;
	/* SSL *ssl; */
	u32 refcnt;
	enum ada_err (*connected)(void *, struct stream_pcb *, enum ada_err);
	size_t (*stream_recv)(void *, struct stream_pcb *, void *, size_t);
	enum ada_err (*stream_sent)(void *, struct stream_pcb *, u16 len);
	void (*err)(void *, enum ada_err);
	void *arg;
	struct ada_mbuf *rx_buf;
	struct ada_mbuf *tx_buf;
	int tx_off;
	int tx_sent;
	int rx_bytes;
	enum ada_err rx_err;
	struct ssl_metric_conn *ssl_metric;
	struct tcp_metric_conn *tcp_metric;
	enum log_mod_id log_option;

	/*
	 * Task to handle this PCB's blocking SSL and TCP I/O.
	 */
	TaskHandle_t task;
};

/* static SSL_CTX *stream_ssl_ctx; */

static enum ada_err stream_connect_sync(struct stream_pcb *);
static void stream_remove(struct stream_pcb *);

static void stream_log(struct stream_pcb *sp, const char *fmt, ...)
	ADA_ATTRIB_FORMAT(2, 3)
{
	ADA_VA_LIST args;
	char buf[LOG_LINE];		/* 200 bytes on stack */
	enum log_mod_id mod = MOD_LOG_SSL;

	if (sp) {
		ASSERT(fmt[0] & LOG_BASE);	/* start with sev code */
		ASSERT(!(fmt[1] & LOG_BASE));	/* only one severity code */
		snprintf(buf, sizeof(buf), "%c[%u]%s",
		    fmt[0], sp->id, &fmt[1]);
		fmt = buf;
		mod |= sp->log_option;
	}
	ADA_VA_START(args, fmt);
	log_put_va(mod, fmt, args);
	ADA_VA_END(args);
}

static void stream_stack_check(struct stream_pcb *sp)
{
	/* RTLTODO Add stack check code */
}

void stream_log_set(struct stream_pcb *sp, enum log_mod_id log_mod_option)
{
	sp->log_option = log_mod_option & ~LOG_MOD_MASK;
}

static void stream_hold_locked(struct stream_pcb *sp)
{
	sp->refcnt++;
	ASSERT(sp->refcnt);
}

static void stream_hold(struct stream_pcb *sp)
{
	ada_lock(stream_lock);
	stream_hold_locked(sp);
	ada_unlock(stream_lock);
}

static void stream_release(struct stream_pcb *sp)
{
	ASSERT(sp->refcnt);
	ada_lock(stream_lock);
	stream_stack_check(sp);
	if (!--sp->refcnt) {
		stream_remove(sp);
		ASSERT(sp->next == NULL);
		ASSERT(stream_pcbs != sp);
		ASSERT(!sp->cb.pending);
#if STREAM_STACK_DEBUG
		memset(sp->guard_zone, 0x77, sizeof(sp->guard_zone));
#endif
		ayla_free(sp);
	}
	ada_unlock(stream_lock);
}

static void stream_add(struct stream_pcb *sp)
{
	static u8 index;

	ada_lock(stream_lock);
	sp->id = ++index;
	sp->next = stream_pcbs;
	stream_pcbs = sp;
	ada_unlock(stream_lock);
}

static void stream_remove(struct stream_pcb *sp)
{
	struct stream_pcb *tmp;

	if (sp == stream_pcbs) {
		stream_pcbs = sp->next;
	} else if (stream_pcbs) {
		for (tmp = stream_pcbs; tmp->next; tmp = tmp->next) {
			if (tmp->next == sp) {
				tmp->next = sp->next;
				break;
			}
		}
	}
	sp->next = NULL;
}

static void stream_event_pend(struct stream_pcb *sp)
{
	if (!sp->cb.pending)  {
		stream_hold_locked(sp);
		client_callback_pend(&sp->cb);
	}
}

/*
 * Send data to peer for SSL.
 * Called with lock held.
 */
static enum ada_err stream_tx(struct stream_pcb *sp)
{
	struct ada_mbuf *m;
	char *p;
	int len;
	int tlen;

	if ((sp->enable && !sp->ssl_connected) ||
	    (!sp->enable && sp->sock == STREAM_SOCK_INVAL)) {
		stream_log(sp, LOG_WARN "%s: %s not connected sock",
		    __func__, stream_type(sp));
		return AE_NOTCONN;
	}
	if (!sp->tx_buf) {
		stream_log(sp, LOG_WARN "%s: no buf", __func__);
		return AE_BUF;
	}
	m = sp->tx_buf;
	p = ada_mbuf_payload(m);
	p += sp->tx_off;
	len = ada_mbuf_len(m) - sp->tx_off;
	tlen = len;

	if (!sp->enable) {
		len = send(sp->sock, p, len, 0);
	} else {
		len = mbedtls_ssl_write(&sp->ssl, p, len);
	}
	stream_stack_check(sp);
	if (len < 0) {
		stream_log(sp, LOG_WARN "%s:%d error %d",
		    stream_type(sp), stream_socket(sp), len);
		if (len == -23) {	/* lower-level IP stack error */
			return AE_CLSD;
		}
		return AE_ERR;
	}
	if (tlen != len) {
		stream_log(sp, LOG_WARN "%s:%d Sent %d/%d bytes",
		    stream_type(sp), stream_socket(sp), len, tlen);
	}
	sp->tx_off += len;
	if (sp->tx_off == ada_mbuf_len(m)) {
		ada_mbuf_free(m);
		sp->tx_buf = NULL;
	}
	sp->tx_sent += len;
	return AE_OK;
}

/*
 * Close the stream.
 * Runs in the stream task.
 * Called with lock held, but drops it during SDK calls which may block.
 */
static void stream_close_sync(struct stream_pcb *sp)
{
	stream_log(sp, LOG_DEBUG "%s:%d socket closed",
	    stream_type(sp), stream_socket(sp));

	if (sp->enable) {
		if (sp->ssl_fd.fd != STREAM_SOCK_INVAL) {
			mbedtls_ssl_free(&sp->ssl);
			mbedtls_ssl_config_free(&sp->ssl_cfg);
			mbedtls_net_free(&sp->ssl_fd);
			sp->ssl_fd.fd = STREAM_SOCK_INVAL;
			sp->ssl_connected = 0;
		}
	} else {
		if (sp->sock != STREAM_SOCK_INVAL) {
			close(sp->sock);
			sp->sock = STREAM_SOCK_INVAL;
		}
	}
}

/*
 * Close both the TCP and SSL sides of the stream.
 * This also releases the PCB, which usually frees it.
 */
enum ada_err stream_close(struct stream_pcb *sp)
{
	ada_lock(stream_lock);
	stream_log(sp, LOG_DEBUG2 "%s:%d To close rx=%d tx=%d err=%s",
	    stream_type(sp), stream_socket(sp), sp->rx_closed, sp->tx_closed,
	    ada_err_string(sp->rx_err));

	/*
	 * Cancel callbacks.  Callbacks during close can cause hangs.
	 */
	sp->err = NULL;
	sp->stream_recv = NULL;
	sp->stream_sent = NULL;
	sp->connected = NULL;
	sp->tx_closed = 1;
	sp->rx_closed = 1;

	ada_unlock(stream_lock);
	return AE_OK;
}

/*
 * The SSL handshake is complete. Invoke the callback, if set.
 */
static void stream_connected(struct stream_pcb *sp)
{
	if (sp->connected) {
		if (sp->ssl_metric && !sp->ssl_metric->handshake_done) {
			sp->ssl_metric->handshake_done = time_now();
		}
		sp->connected(sp->arg, (struct stream_pcb *)sp, sp->rx_err);
		sp->connected = NULL;
	}
}

/*
 * Handle received data in client_thread.
 */
static void stream_rx(struct stream_pcb *sp)
{
	struct ada_mbuf *m;
	struct ada_mbuf *next;
	int closed;
	size_t (*stream_recv)(void *, struct stream_pcb *, void *, size_t);
	size_t rx_len;
	size_t tlen;
	void *arg;
	void *buf;

	ada_lock(stream_lock);
	if (sp->rx_paused) {
		sp->rx_paused = 0;
	}
	while (!sp->rx_paused) {
		m = sp->rx_buf;
		if (!m) {
			closed = sp->rx_closed;
			stream_recv = sp->stream_recv;
			arg = sp->arg;
			ada_unlock(stream_lock);
			if (closed && stream_recv) {
				stream_recv(arg, sp, NULL, 0);
			}
			return;
		}
		tlen = ada_mbuf_len(m);
		buf = tlen ? ada_mbuf_payload(m) : NULL;
		ada_unlock(stream_lock);
		if (!sp->stream_recv) {
			ada_mbuf_free(m);
			sp->rx_buf = NULL;
			return;
		}
		rx_len = sp->stream_recv(sp->arg, sp, buf, tlen);
		ada_lock(stream_lock);
		if (rx_len < tlen) {
			stream_log(sp, LOG_DEBUG
			    "%s:%d pausing rx. processed %d/%d byte(s)",
			    stream_type(sp), stream_socket(sp), rx_len, tlen);
			sp->rx_paused = 1;
		}
		ada_mbuf_header(m, -rx_len);
		if (ada_mbuf_len(m) == 0) {
			next = m->next;
			m->next = NULL;
			ada_mbuf_free(m);
			sp->rx_buf = next;
		}
		if (sp->ssl_metric) {
			sp->ssl_metric->rx_bytes += rx_len;
		}
	}
	ada_unlock(stream_lock);
}

/*
 * Clear pause condition and send received plaintext data to the client.
 */
void stream_resume(struct stream_pcb *sp)
{
	stream_hold(sp);
	stream_rx(sp);		/* this clears rx_paused and resumes thread */
	stream_release(sp);
}

/*
 * Notify that stream peer has closed the connection.  Data may still be
 * pending to be read, after which the close notification should be given.
 */
static void stream_recv_closed(struct stream_pcb *sp)
{
	sp->rx_closed = 1;
	sp->rx_event = 1;
	stream_event_pend(sp);
}

/*
 * Read from TCP or SSL.
 * Called with lock held but drops the lock during SDK calls.
 */
static void stream_recv_sync(struct stream_pcb *sp)
{
	struct ada_mbuf *m;
	int len;
	int sock;
	int count;

	m = ada_mbuf_alloc(STREAM_RX_SZ);
	ASSERT(m);

	if (sp->enable) {
		if (!sp->ssl_connected) {
			goto err;
		}
		ada_unlock(stream_lock);
		len = mbedtls_ssl_read(&sp->ssl, ada_mbuf_payload(m),
		    STREAM_RX_SZ);
		stream_stack_check(sp);
		ada_lock(stream_lock);

		if (len <= 0) {
			if (len < 0) {
				stream_log(sp, LOG_WARN "TLS:%d err=-0x%x",
				    sp->ssl_fd.fd, -len);
			}
			sp->ssl_connected = 0;	/* assume SSL closed it */
			goto err;
		} else {
			stream_log(sp, LOG_DEBUG2
			    "TLS:%d Received %d byte(s) at mbuf %p",
			    sp->ssl_fd.fd, len, m);
		}
	} else {
		sock = sp->sock;
		if (sock == STREAM_SOCK_INVAL) {
			goto err;
		}
		ada_unlock(stream_lock);
		len = recv(sock, ada_mbuf_payload(m), STREAM_RX_SZ, 0);
		ada_lock(stream_lock);
		if (len <= 0) {
			if (len < 0) {
				stream_log(sp, LOG_WARN "TCP:%d err=%d", sock,
				    len);
			}
			goto err;
		} else {
			stream_log(sp, LOG_DEBUG2
			    "TCP:%d Received %d byte(s) at mbuf %p",
			    sock, len, m);
		}
	}
	sp->rx_bytes += len;
	ada_mbuf_trim(m, len);
	if (sp->tcp_metric) {
		sp->tcp_metric->nrtx += len;
	}
	if (sp->rx_buf) {
		ada_mbuf_cat(sp->rx_buf, m);

		/*
		 * Count buffers to decide whether to pause receive.
		 */
		for (count = 0, m = sp->rx_buf; m;
			m = m->next) {
			count++;
		}
		if (count >= STREAM_RX_BUF_LIM) {
			sp->rx_paused = 1;
		}
	} else {
		sp->rx_buf = m;
	}
	sp->rx_event = 1;
	stream_event_pend(sp);
	return;
err:
	ada_mbuf_free(m);
	stream_recv_closed(sp);
}

/*
 * socket closed by error or EOF on read.
 * Present callback.
 */
static void stream_closed(struct stream_pcb *sp)
{
	void (*err_cb)(void *, enum ada_err);
	size_t (*stream_recv)(void *, struct stream_pcb *, void *, size_t);
	enum ada_err err;

	ada_lock(stream_lock);
	err = sp->rx_err;
	err_cb = sp->err;
	stream_recv = sp->stream_recv;
	sp->rx_err = 0;
	sp->err = NULL;
	sp->stream_recv = NULL;
	ada_unlock(stream_lock);

	if (err && err_cb && !stream_recv) {
		err_cb(sp->arg, err);
	} else if (stream_recv) {
		stream_recv(sp->arg, sp, NULL, 0);
	}
}

static void stream_event_cb(void *arg)
{
	struct stream_pcb *sp = (struct stream_pcb *)arg;

	if (sp->rx_event) {
		sp->rx_event = 0;
		stream_rx(sp);
	}
	if (sp->connected_event) {
		sp->connected_event = 0;
		stream_connected(sp);
	}
	if (sp->close_event) {
		sp->close_event = 0;
		stream_closed(sp);
		stream_release(sp);		/* release for close */
	}
	stream_release(sp);
}

static int stream_select(int sock, unsigned long max_wait_us)
{
	fd_set read_fds;
	struct timeval tmo;
	int rc;

	FD_ZERO(&read_fds);
	FD_SET(sock, &read_fds);

	tmo.tv_sec = 0;
	tmo.tv_usec = max_wait_us;

	rc = select(sock + 1, &read_fds, NULL, NULL, &tmo);
	if (rc && FD_ISSET(sock, &read_fds)) {
		return 1;
	}
	return 0;
}

/*
 * Stream idle loop runs for in active stream PCB's thread.
 * This runs without a lock while it blocks in each SSL call.
 */
static void stream_idle(unsigned long arg)
{
	enum ada_err err = 0;
	struct stream_pcb *sp = (struct stream_pcb *)arg;
	int sock = STREAM_SOCK_INVAL;
	UINT rc;
	UINT old_threshold;

	log_thread_id_set(TASK_LABEL_STREAM);
	taskstat_dbg_start();

	ada_lock(stream_lock);
	while (!sp->rx_closed) {
		ASSERT(sp->refcnt);
		if (sp->connect_req) {
			err = stream_connect_sync(sp);
			sp->connect_req = 0;
			if (err != AE_OK) {
				break;
			}
		} else if (sp->rx_req && !sp->rx_paused) {
			ada_unlock(stream_lock);
			if (!stream_select(stream_socket(sp),
			    STREAM_RX_WAIT)) {
				vTaskDelay(100);
				ada_lock(stream_lock);
			} else {
				ada_lock(stream_lock);
				stream_recv_sync(sp);
			}
			continue;
		} else {
			ada_unlock(stream_lock);
			vTaskDelay(100);
			ada_lock(stream_lock);
		}
	}

	while (!sp->tx_closed) {
		ada_unlock(stream_lock);
		vTaskDelay(100);
		ada_lock(stream_lock);
	}

	/*
	 * Close socket.
	 */
	err = sp->rx_err;
	stream_log(sp, LOG_DEBUG2 "thread closing err=%s",
	    ada_err_string(err));
	stream_close_sync(sp);
	stream_log(sp, LOG_DEBUG2 "thread exits err=%s",
	    ada_err_string(err));

	/*
	 * Disable preemption until* we are done with the stack.
	 */
	/* rc = tx_thread_preemption_change(&sp->task,
	    STREAM_TASK_PRIO_NOPREEMPT, &old_threshold);
	if (rc != TX_SUCCESS) {
		stream_log(sp, LOG_ERR "preempt change rc %u", rc);
	} */

	/*
	 * Issue close event which causes thread and stack to be freed after
	 * we exit.
	 */
	sp->close_event = 1;
	stream_event_pend(sp);
	ada_unlock(stream_lock);

	log_thread_id_unset();

	/*
	 * The stream will be released by the close event.
	 */
	taskstat_dbg_stop();
	vTaskDelete(NULL);
}

/*
 * Initialize the SSL library.
 */
void stream_init(void)
{
	stream_lock = ada_lock_create("stream");
	ASSERT(stream_lock);
}

void stream_certs_load(const void *certs, size_t size)
{
	struct raw_der_cert *der_cert = (struct raw_der_cert *)certs;
	int err;

	mbedtls_x509_crt_init(&ca_certs_chain);
	while (der_cert->name) {
		err = mbedtls_x509_crt_parse_der(&ca_certs_chain,
		    der_cert->cert, der_cert->size);
		if (!err) {
			ca_certs_inited = 1;
			stream_log(NULL, LOG_DEBUG "Load \"%s\" successfully",
			    der_cert->name);
		} else {
			stream_log(NULL, LOG_ERR
			    "Load \"%s\" failed, errcode=-0x%x",
			    der_cert->name, -err);
		}
		der_cert++;
	}
}

/*
 * Create a new SSL stream.  Not connected yet.
 */
struct stream_pcb *stream_new(struct stream_ssl_id *sess_id,
	int accept_non_ayla, struct ssl_metric_conn *ssl_metric,
	struct tcp_metric_conn *tcp_metric)
{
	struct stream_pcb *sp;
	int rc;

	sp = (struct stream_pcb *)ayla_calloc(1, sizeof(*sp));
	if (!sp) {
		stream_log(sp, LOG_WARN "%s: calloc failed", __func__);
		return NULL;
	}
	sp->sock = STREAM_SOCK_INVAL;

	sp->ssl_metric = ssl_metric;
	sp->tcp_metric = tcp_metric;
	if (sp->ssl_metric) {
		sp->ssl_metric->connect_start = time_now();
	}
	if (sp->tcp_metric) {
		sp->tcp_metric->connect_start = time_now();
	}

	if (sess_id) {
		sp->enable = 1;
	}
	sp->accept_non_ayla = accept_non_ayla;

	net_callback_init(&sp->cb, stream_event_cb, sp);
	sp->local_ip = netif_default->ip_addr;

	sp->refcnt = 1;		/* hold until close event */
	stream_add(sp);

	stream_log(sp, LOG_DEBUG2 "new %s PCB=%p", stream_type(sp), sp);

#if STREAM_STACK_DEBUG
	memset(sp->guard_zone, 0x55, sizeof(sp->guard_zone));
#endif

	if (xTaskCreate(stream_idle,
	    "A_Stream",
	    sp->enable ? STREAM_TASK_STACKSZ_TLS : STREAM_TASK_STACKSZ,
	    sp,
	    STREAM_TASK_PRIO,
	    &sp->task) != pdPASS) {
		stream_log(sp, LOG_ERR "Can not create stream task");
		stream_release(sp);
		return NULL;
	}

	return sp;
}

void stream_ssl_init_id(struct stream_ssl_id *sess_id)
{
}

const ip_addr_t *stream_local_ip(struct stream_pcb *pcb)
{
	return &pcb->local_ip;
}

const ip_addr_t *stream_remote_ip(struct stream_pcb *pcb)
{
	return &pcb->remote_ip;
}

/*
 * encode and send data.
 */
enum ada_err stream_write(struct stream_pcb *sp, const void *buf, u16_t len,
    u8_t flags)
{
	struct ada_mbuf *m;
	enum ada_err err;		/* caller ignores this */

	if (sp->tx_buf) {
		stream_log(sp, LOG_DEBUG2 "%s: tx paused", __func__);
		return AE_BUF;
	}
	m = ada_mbuf_alloc(len);
	if (!m) {
		stream_log(sp, LOG_DEBUG2 "%s: can't alloc buf", __func__);
		return AE_BUF;
	}
	memcpy(ada_mbuf_payload(m), buf, len);
	ada_lock(stream_lock);
	sp->tx_buf = m;
	sp->tx_off = 0;

	stream_log(sp, LOG_DEBUG2 "%s:%d sent %u byte(s)", stream_type(sp),
	    stream_socket(sp), len);
	err = stream_tx(sp);
	ada_unlock(stream_lock);
	if (err) {
		stream_log(sp, LOG_DEBUG2 "%s: ret err %d", __func__, err);
	}
	return err;
}

enum ada_err stream_output(struct stream_pcb *sp)
{
	return AE_OK;
}

static int stream_ssl_verify(struct stream_pcb *sp,
	mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
	return 0;
}

/*
 * Callback after TCP connected.  Start SSL negotiation.
 */
static enum ada_err stream_tcp_connected(struct stream_pcb *sp)
{
	enum ada_err conn_err;
	int rc = 0;
	int retries;

	conn_err = sp->rx_err;
	stream_log(sp, LOG_DEBUG "%s:%d Connected err=%s", stream_type(sp),
	    stream_socket(sp), ada_err_string(conn_err));
	if (conn_err) {
		goto err;
	}
	if (sp->enable) {
		mbedtls_ssl_init(&sp->ssl);
		mbedtls_ssl_config_init(&sp->ssl_cfg);

		mbedtls_ssl_set_bio(&sp->ssl, &sp->ssl_fd, mbedtls_net_send,
		    mbedtls_net_recv, NULL); /* RTLTODO: timeout */
		rc = mbedtls_ssl_config_defaults(&sp->ssl_cfg,
		    MBEDTLS_SSL_IS_CLIENT,
		    MBEDTLS_SSL_TRANSPORT_STREAM,
		    MBEDTLS_SSL_PRESET_DEFAULT);
		if (rc) {
			stream_log(sp, LOG_ERR
			    "mbedtls_ssl_config_defaults fail err=%d", rc);
			conn_err = AE_ERR;
			goto err;
		}
		ASSERT(ca_certs_inited);
		if (ca_certs_inited) {
			mbedtls_ssl_conf_ca_chain(&sp->ssl_cfg,
			    &ca_certs_chain, NULL);
			mbedtls_ssl_conf_authmode(&sp->ssl_cfg,
			    MBEDTLS_SSL_VERIFY_REQUIRED);
			mbedtls_ssl_conf_verify(&sp->ssl_cfg,
			    stream_ssl_verify, sp);
		} else {
			mbedtls_ssl_conf_authmode(&sp->ssl_cfg,
			    MBEDTLS_SSL_VERIFY_NONE);
		}
		mbedtls_ssl_conf_rng(&sp->ssl_cfg, adc_rng_random_fill, NULL);
		rc = mbedtls_ssl_setup(&sp->ssl, &sp->ssl_cfg);
		ada_unlock(stream_lock);
		while ((rc = mbedtls_ssl_handshake(&sp->ssl)) != 0) {
			if ((rc != MBEDTLS_ERR_SSL_WANT_READ &&
				rc != MBEDTLS_ERR_SSL_WANT_WRITE &&
				rc != MBEDTLS_ERR_NET_RECV_FAILED) ||
				retries >= 3) {
				stream_log(sp, LOG_ERR
				    "mbedtls_ssl_handshake fail, err=-0x%x",
				    -rc);
				conn_err = AE_CERT_EXP;
				ada_lock(stream_lock);
				goto err;
			}
			retries++;
		}
		ada_lock(stream_lock);
		stream_log(sp, LOG_DEBUG "TLS:%d ciphersuit %s",
		    sp->ssl_fd.fd, mbedtls_ssl_get_ciphersuite(&sp->ssl));
		sp->ssl_connected = 1;
	}
	sp->rx_req = 1;
	sp->connected_event = 1;
	stream_event_pend(sp);
	return AE_OK;
err:
	sp->rx_err = conn_err;
	if (sp->enable) {
		if (sp->ssl_fd.fd != STREAM_SOCK_INVAL) {
			mbedtls_ssl_free(&sp->ssl);
			mbedtls_ssl_config_free(&sp->ssl_cfg);
			mbedtls_net_free(&sp->ssl_fd);
			sp->ssl_fd.fd = STREAM_SOCK_INVAL;
		}
	} else {
		if (sp->sock != STREAM_SOCK_INVAL) {
			close(sp->sock);
			sp->sock = STREAM_SOCK_INVAL;
		}
	}
	sp->connected_event = 1;	/* report connect error */
	stream_event_pend(sp);
	return conn_err;
}

enum ada_err stream_connect(struct stream_pcb *sp, char *hostname,
    ip_addr_t *ip, u16_t port,
    enum ada_err (*connected)(void *, struct stream_pcb *, enum ada_err))
{
	stream_log(sp, LOG_DEBUG "%s is connecting to %s:%d", stream_type(sp),
	    hostname, port);

	sp->host = hostname;
	sp->remote_ip = *ip;
	sp->remote_port = port;
	sp->connected = connected;
	ASSERT(!sp->connect_req);
	sp->connect_req = 1;
	sp->ssl_connected = 0;
	return AE_OK;
}

static enum ada_err stream_connect_sync(struct stream_pcb *sp)
{
	char buf_port[10];
	unsigned int tdelay;
	unsigned int delay;
	int rc;
	struct sockaddr_in s_in;

	if (sp->enable) {
		/* HTTPS session */
		mbedtls_net_init(&sp->ssl_fd);
		snprintf(buf_port, sizeof(buf_port), "%u", sp->remote_port);
		ada_unlock(stream_lock);
		rc = mbedtls_net_connect(&sp->ssl_fd, sp->host, buf_port,
		    MBEDTLS_NET_PROTO_TCP);
		ada_lock(stream_lock);
		if (rc) {
			stream_log(sp, LOG_ERR
			    "mbedtls_net_connect fail, err=-0x%x", -rc);
			sp->rx_err = AE_TIMEOUT;
		}
	} else {
		/* HTTP session */
		/*
		 * If this fails, it could be there are sockets waiting
		 * in FIN_WAIT or lingering, waiting for final packets.
		 * Sleep and retry for up to 12 seconds total.
		 *
		 * The retry interval starts at 100 ms.  After 500 ms,
		 * increase by 50% each time until it is greater than 800 ms.
		 * This is mainly to slow down debug messages from the SDK
		 * while remaining responsive in case the wait is short.
		 * The delays used will be:  100, 150, 337, 505, 757, 1135.
		 */
		ada_unlock(stream_lock);
		delay = 100;
		for (tdelay = 0; tdelay < STREAM_SOCK_RETRY_TIME;
		    tdelay += delay) {
			sp->sock = socket(AF_INET, SOCK_STREAM, 0);
			if (sp->sock != STREAM_SOCK_INVAL) {
				break;
			}
			if (tdelay > 500 && delay < 800) {
				delay += delay / 2;
			}
			vTaskDelay(delay);
		}
		ada_lock(stream_lock);

		if (sp->sock == STREAM_SOCK_INVAL) {
			stream_log(sp, LOG_WARN "%s: socket failed rc %d",
			    __func__, sp->sock);
			sp->rx_err = AE_TIMEOUT;
			goto connected;
		}

		stream_log(sp, LOG_DEBUG2 "TCP:%d socket is created",
		    sp->sock);
		memset(&s_in, 0, sizeof(s_in));
		s_in.sin_family = AF_INET;
		s_in.sin_port = htons(sp->remote_port);
		s_in.sin_addr.s_addr = sp->remote_ip.addr;

		ada_unlock(stream_lock);
		rc = connect(sp->sock, (struct sockaddr *)&s_in, sizeof(s_in));
		ada_lock(stream_lock);
		stream_stack_check(sp);
		if (sp->tcp_metric) {
			sp->tcp_metric->connect_err = rc;
		}
		if (rc) {
			stream_log(sp, LOG_ERR "TCP:%s connect fail err=%d",
			    sp->sock, rc);
			sp->rx_err = AE_TIMEOUT;
		}
	}
connected:
	return stream_tcp_connected(sp);
}

void stream_arg(struct stream_pcb *sp, void *arg)
{
	sp->arg = arg;
}

void stream_recv(struct stream_pcb *sp,
	size_t (*stream_recv)(void *, struct stream_pcb *, void *, size_t))
{
	sp->stream_recv = stream_recv;
}

void stream_sent(struct stream_pcb *sp,
    enum ada_err (*stream_sent)(void *, struct stream_pcb *, u16 len))
{
	sp->stream_sent = stream_sent;
}

void stream_err(struct stream_pcb *sp, void (*err)(void *, enum ada_err))
{
	sp->err = err;
}

int stream_tcp_is_established(struct stream_pcb *sp)
{
#ifdef notyet
	return net_tcp_is_established(sp->tcp);
#else
	return 0;
#endif
}
