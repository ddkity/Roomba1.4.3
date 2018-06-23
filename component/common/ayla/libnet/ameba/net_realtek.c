/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#define HAVE_UTYPES
#include <stdlib.h>
#include <string.h>

#include <lwip/ip.h>
#include <sockets.h>
#include <at_cmd/atcmd_wifi.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ada/task_label.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/timer.h>
#include <net/net.h>
#include <net/ada_mbuf.h>
#include <net/ipaddr_fmt.h>
#include <ayla/malloc.h>

#include "ada_lock.h"
#include "client_timer.h"
#include "client_lock.h"

#define NET_UDP_MAX_SZ		1480	/* max RX frame size */
#define NET_UDP_TASK_STACKSZ	((3 * 1024 + 512) / sizeof(portSTACK_TYPE))
#define NET_UDP_TASK_PRIO	(tskIDLE_PRIORITY+1)
#define NET_SOCK_INVALID	(-1)

#define NET_TIMER_TASK_STACKSZ	((3 * 1024 + 512) / sizeof(portSTACK_TYPE))
#define NET_TIMER_TASK_PRIO	(tskIDLE_PRIORITY+1)
#define NET_QUEUE_LEN		20	/* max callbacks on queue */

#define	TX_NO_WAIT	0

struct net_tcp;
struct net_udp;

/*
 * Struct used for both UDP and TCP PCBs.
 */
struct net_pcb {
	int sock;
	u8 refcnt;
	u8 type;
	u8 rx_event:1;
	u8 tx_event:1;
	u8 ex_event:1;
	u8 is_v6:1;	/* using IPv6 */
	union {
		void (*udp_recv)(void *arg, struct net_udp *,
		    struct ada_mbuf *, ip_addr_t *from_ip, u16 from_port);
		enum ada_err (*tcp_recv)(void *arg, struct net_tcp *,
		    struct ada_mbuf *, enum ada_err);
	};
	void *recv_arg;
	enum ada_err (*connected)(void *, struct net_tcp *, enum ada_err);
	enum ada_err (*net_accept)(void *arg, struct net_tcp *, enum ada_err);

	void (*tcp_sent)(void *arg, struct net_tcp *, u16 len);
	u16 pending_send_len;

	union {
		struct sockaddr local_sa;
		struct sockaddr_in local_sa_in;
	};
	union {
		struct sockaddr remote_sa;
		struct sockaddr_in remote_sa_in;
	};
	TAILQ_ENTRY(net_pcb) list;
	struct net_callback cb;
};

struct net_udp {			/* semi-opaque structure for socket */
	struct net_pcb pcb;		/* must be only member */
};

struct net_tcp {			/* semi-opaque structure for socket */
	struct net_pcb pcb;		/* must be only member */
};

static struct netif net_netif_null;	/* empty netif */

/*struct netif *netif_default = &net_netif_null; */

static TaskHandle_t net_poll_task;
static TAILQ_HEAD(, net_pcb) net_pcbs;
static struct ada_lock *net_pcb_lock;

static TaskHandle_t net_timer_task;
static struct ada_lock *net_timer_lock;
static struct timer_head net_timers;
static struct net_callback_queue *net_queue;

static void net_pcb_event(void *arg);
static void net_poll_wait(unsigned long arg);
static void net_timer_wait(unsigned long arg);

void net_init(void)
{
	int rc;
	static u8 done;

	if (done) {
		return;
	}
	done = 1;

	TAILQ_INIT(&net_pcbs);
	net_pcb_lock = ada_lock_create("net_pcbs");
	ASSERT(net_pcb_lock);

	if (xTaskCreate(net_poll_wait, "A_NetPoll", NET_UDP_TASK_STACKSZ,
	    NULL, NET_UDP_TASK_PRIO, &net_poll_task) != pdPASS) {
		ASSERT(0);
	}

	net_queue = net_callback_queue_new(NET_QUEUE_LEN);
	ASSERT(net_queue);

	net_timer_lock = ada_lock_create("net_timer_lock");
	ASSERT(net_timer_lock);
	if (xTaskCreate(net_timer_wait, "A_NetTime",
	    NET_TIMER_TASK_STACKSZ, NULL,
	    NET_TIMER_TASK_PRIO, &net_timer_task) != pdPASS) {
		ASSERT(0);
	}
}

/*
 * Initialize a pre-allocated tcpip_msg as a callback msg.
 *
 * The callback function must clear the pending flag.
 * Be sure not to free the callback while it is pending.
 */
void net_callback_init(struct net_callback *cb, void (*func)(void *), void *arg)
{
	cb->pending = 0;
	cb->func = func;
	cb->arg = arg;
}

/*
 * Create a queue for callback handlers.
 */
struct net_callback_queue *net_callback_queue_new(unsigned int len)
{
	xQueueHandle *cbq;

	cbq = xQueueCreate(len, sizeof(struct net_callback *));
	return (struct net_callback_queue *)cbq;
}

/*
 * Queue a callback on a specific queue.
 * Does not block if the queue is full.
 * Returns non-zero on failure.
 */
int net_callback_enqueue(struct net_callback_queue *nq,
    struct net_callback *cb)
{
	QueueHandle_t cbq = (QueueHandle_t)nq;

	if (cb->pending) {
		return 0;
	}
	cb->pending = 1;
	xQueueSendFromISR(cbq, &cb, TX_NO_WAIT);
	return 0;
}

/*
 * Like net_callback_enqueue but queues to the front of the queue.
 */
int net_callback_enqueue_first(struct net_callback_queue *nq,
				struct net_callback *cb)
{
	QueueHandle_t *cbq = (QueueHandle_t *)nq;
	int rc;

	if (!cb || cb->pending) {
		return 0;
	}
	cb->pending = 1;
	if (!xQueueSendToFront(cbq, &cb, TX_NO_WAIT)) {
		return -1;
	}
	return 0;
}

/*
 * Dequeue from a callback queue.
 * Returns NULL immediately if queue is empty.
 */
struct net_callback *net_callback_dequeue(struct net_callback_queue *nq)
{
	QueueHandle_t *cbq = (QueueHandle_t *)nq;
	struct net_callback *cb;
	int rc;

	cb = NULL;
	rc = xQueueReceive(cbq, &cb, TX_NO_WAIT);
	if (!rc) {
		cb = NULL;
	}
	return cb;
}

/*
 * Handle general net timers and callbacks.
 */
static void net_timer_wait(unsigned long arg)
{
	struct timer *timer;
	struct net_callback *ac;
	int delay;

	log_thread_id_set(TASK_LABEL_NETTIMER);
	taskstat_dbg_start();

	while (1) {
		ada_lock(net_timer_lock);
		delay = timer_delta_get(&net_timers);
		if (!delay) {
			timer = timer_first_dequeue(&net_timers);
			ada_unlock(net_timer_lock);
			ASSERT(timer);
			if (timer) {
				timer_run(timer);
			}
			continue;
		}
		ada_unlock(net_timer_lock);
		ac = net_callback_wait(net_queue, delay);
		if (ac) {
			ASSERT(ac->pending);
			ac->pending = 0;
			ac->func(ac->arg);
		}
	}
}

static void net_timer_set_locked(struct timer *timer, unsigned long ms)
{
	int delay;

	delay = timer_delta_get(&net_timers);
	timer_set(&net_timers, timer, ms);
	if (delay < 0 || ms < delay) {
		vTaskResume(net_timer_task);
	}
}

void net_timer_set(struct timer *timer, unsigned long ms)
{
	ada_lock(net_timer_lock);
	net_timer_set_locked(timer, ms);
	ada_unlock(net_timer_lock);
}

void net_timer_cancel(struct timer *timer)
{
	ada_lock(net_timer_lock);
	timer_cancel(&net_timers, timer);
	ada_unlock(net_timer_lock);
}

void net_callback_pend(struct net_callback *cb)
{
	net_callback_enqueue(net_queue, cb);
}

/*
 * Dequeue from a callback queue, waiting if necessary.
 * Returns NULL on timeout.
 */
struct net_callback *net_callback_wait(struct net_callback_queue *nq, int ms)
{
	QueueHandle_t *cbq = (QueueHandle_t *)nq;
	struct net_callback *cb;
	unsigned long ticks = ms * portTICK_RATE_MS;
	signed portBASE_TYPE rc;

	if (ms < 0) {
		ticks = portMAX_DELAY;
	}

	cb = NULL;
	rc = xQueueReceive(cbq, &cb, ticks);
	if (rc) {
		ASSERT(cb);
	} else {
		cb = NULL;
	}
	return cb;
}

/*
 * Return non-zero if IPv4 address is on a local network.
 */
int net_ipv4_is_local(const ip_addr_t *ip)
{
	struct netif *net;

	for (net = netif_list; net; net = net->next) {
		if (!ip_addr_isany(&net->netmask) &&
		    !ip_addr_netcmp(ip, &net->ip_addr, &net->netmask)) {
			return 1;
		}
	}
	return 0;
}

/*
 * Return pointer to IPv4 address in network order, given sockaddr..
 */
static const ip_addr_t *net_ipv4_addr(struct sockaddr_in *sin)
{
	if (sin->sin_family != AF_INET) {
		return NULL;
	}
	return (const ip_addr_t *)&sin->sin_addr;
}

/*
 * DNS resolved callback.
 */
static void net_dns_cb(const char *name, ip_addr_t *ipaddr, void *arg)
{
	struct net_dns_req *req = arg;

	if (ipaddr) {
		req->addr = ipaddr->addr;
	}
	net_callback_pend(&req->net_dns_cb);
}

const ip_addr_t *net_tcp_local_ip(struct net_tcp *tcp)
{
	struct sockaddr_in *sin;
	struct ip_addr  ipaddr;
	struct ip_addr  mask;
	struct ip_addr  gw;
	int sock_err = 0;
	size_t err_len = sizeof(sock_err);

	sin = &tcp->pcb.local_sa_in;
	sin->sin_family = AF_INET;

	if (getsockopt(tcp->pcb.sock, SOL_SOCKET, SO_TYPE,
	    &sock_err, &err_len) || sin->sin_addr.s_addr == 0) {
		IP4_ADDR(&ipaddr, GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);
		IP4_ADDR(&mask, NETMASK_ADDR0, NETMASK_ADDR1,
		    NETMASK_ADDR2, NETMASK_ADDR3);
		IP4_ADDR(&gw, GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);
		sin->sin_addr.s_addr = ntohl(ipaddr.addr);
	}
	return net_ipv4_addr(sin);
}

const ip_addr_t *net_tcp_remote_ip(struct net_tcp *tcp)
{
	return net_ipv4_addr(&tcp->pcb.remote_sa_in);
}

static void net_dns_helper(struct net_dns_req *req)
{
	req->callback(req);
}

enum ada_err net_dns_lookup(struct net_dns_req *req)
{
	int rc;
	uint32_t addr;
	err_t err;

	net_callback_init(&req->net_dns_cb, net_dns_helper, req);
	req->addr = 0;
	err = dns_gethostbyname(req->hostname,
	    (ip_addr_t *)&req->addr, net_dns_cb, req);
	if (err == ERR_INPROGRESS) {
		return 0;
	}
	if (err == ERR_MEM) {
		return err;
	}
	net_callback_pend(&req->net_dns_cb);
	return 0;
}

/*	net_dns_getserver will be called in ADW	*/
ip_addr_t net_dns_getserver(u8 index)
{
	return dns_getserver(index);
}

static void net_pcb_hold(struct net_pcb *pcb)
{
	pcb->refcnt++;
}

static void net_pcb_release(struct net_pcb *pcb)
{
	ada_lock(net_pcb_lock);
	ASSERT(pcb->refcnt);
	if (--pcb->refcnt == 0) {
		TAILQ_REMOVE(&net_pcbs, pcb, list);
		ada_unlock(net_pcb_lock);
		free(pcb);
		return;
	}
	ada_unlock(net_pcb_lock);
}

/*
 * Bind a PCB to an address and port.
 * TBD: allow binding to a particular interface where possible.
 */
static enum ada_err net_pcb_bind(struct net_pcb *pcb, ip_addr_t *addr, u16 port)
{
	struct sockaddr_in *s_in;
	int rc;

	s_in = &pcb->local_sa_in;
	memset(s_in, 0, sizeof(*s_in));
	s_in->sin_family = AF_INET;
	s_in->sin_port = htons(port);
	if (addr) {
		s_in->sin_addr.s_addr = addr->addr;
	}
	rc = bind(pcb->sock, (struct sockaddr *)s_in, sizeof(*s_in));
	if (rc) {
		log_err(LOG_MOD_DEFAULT, "%s: sock %d err %d",
		    __func__, pcb->sock, rc);
		return AE_ERR;
	}
	return AE_OK;
}

/*
 * Create a PCB to represent the state of a socket.
 */
static struct net_pcb *net_pcb_attach(int sock, int type)
{
	struct net_pcb *pcb;
	unsigned long n = 1;

	pcb = calloc(1, sizeof(*pcb));
	if (!pcb) {
		close(sock);
		return NULL;
	}
	pcb->sock = sock;
	pcb->type = type;
	lwip_ioctl(sock, FIONBIO, (void *)(&n));
	net_callback_init(&pcb->cb, net_pcb_event, pcb);

	ada_lock(net_pcb_lock);
	net_pcb_hold(pcb);
	TAILQ_INSERT_HEAD(&net_pcbs, pcb, list);
	ada_unlock(net_pcb_lock);
	return pcb;
}

/*
 * Make a new PCB for the given type of socket.
 */
static struct net_pcb *net_pcb_new(int type)
{
	int sock;

	sock = socket(AF_INET, type, 0);
	if (sock == -1) {
		return NULL;
	}
	return net_pcb_attach(sock, type);
}

/*
 * UDP
 */
struct net_udp *net_udp_new(void)
{
	return (struct net_udp *)net_pcb_new(SOCK_DGRAM);
}

enum ada_err net_udp_bind(struct net_udp *udp, ip_addr_t *addr, u16 port)
{
	return net_pcb_bind(&udp->pcb, addr, port);
}

enum ada_err net_udp_connect(struct net_udp *udp, ip_addr_t *addr, u16 port)
{
	struct sockaddr_in *s_in;

	s_in = &udp->pcb.remote_sa_in;
	s_in->sin_family = AF_INET;
	s_in->sin_port = htons(port);
	s_in->sin_addr.s_addr = addr->addr;
	return AE_OK;
}

void net_udp_recv(struct net_udp *udp,
		void (*recv)(void *arg, struct net_udp *, struct ada_mbuf *m,
		ip_addr_t *from_ip, u16 from_port),
		void *recv_arg)
{
	struct net_pcb *pcb = &udp->pcb;

	pcb->udp_recv = recv;
	pcb->recv_arg = recv_arg;
}

enum ada_err net_udp_send(struct net_udp *udp, struct ada_mbuf *m)
{
	int len;

	len = sendto(udp->pcb.sock,
	    ada_mbuf_payload(m), ada_mbuf_len(m), 0,
	    &udp->pcb.remote_sa, sizeof(struct sockaddr_in));

	if (len != ada_mbuf_len(m)) {
		return AE_ERR;
	}
	return AE_OK;
}

/*
 * Send to specified destination on specified netif.
 * XXX TBD ignoring netif for now. SDK does not support that.
 */
enum ada_err net_udp_sendto_if(struct net_udp *udp, struct ada_mbuf *m,
		ip_addr_t *to, u16 port, struct netif *netif)
{
	int len;
	struct sockaddr_in s_in;

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = AF_INET;
	s_in.sin_port = htons(port);
	s_in.sin_addr.s_addr = to->addr;

	len = sendto(udp->pcb.sock,
	    ada_mbuf_payload(m), ada_mbuf_len(m), 0,
	    (struct sockaddr *)&s_in, sizeof(s_in));
	if (len != ada_mbuf_len(m)) {
		return AE_ERR;
	}
	return AE_OK;
}

static void net_pcb_close(struct net_pcb *pcb)
{
	int rc;
	int sock;

	ada_lock(net_pcb_lock);
	sock = pcb->sock;
	pcb->sock = NET_SOCK_INVALID;
	ada_unlock(net_pcb_lock);

	if (sock == NET_SOCK_INVALID) {
		return;
	}
	rc = close(sock);
	if (rc) {
		log_err(LOG_MOD_DEFAULT, "%s: sock %d rc %d",
		    __func__, sock, rc);
	}
}

static void net_pcb_remove(struct net_pcb *pcb)
{
	net_pcb_close(pcb);
	net_pcb_release(pcb);
}

void net_udp_remove(struct net_udp *udp)
{
	udp->pcb.udp_recv = NULL;
	net_pcb_remove(&udp->pcb);
}

void net_udp_set_v6(struct net_udp *udp, int v6)
{
	udp->pcb.is_v6 = v6;
}

int net_udp_is_v6(struct net_udp *udp)
{
	return udp->pcb.is_v6;
}

/*
 * Handle possible new connection.
 */
static void net_pcb_accept_new(struct net_pcb *pcb)
{
	struct net_pcb *new_pcb;
	struct sockaddr_in from;
	int fromlen = sizeof(from);
	int sock;

	sock = accept(pcb->sock, (struct sockaddr *)&from, &fromlen);
	if (sock < 0) {
		/* occurs when extraneous ex events are given on listen sock */
		return;
	}
	new_pcb = net_pcb_attach(sock, SOCK_STREAM);
	if (!new_pcb) {
		log_err(LOG_MOD_DEFAULT, "%s: pcb alloc failed", __func__);
		return;
	}
	log_debug(LOG_MOD_DEFAULT, "%s: alloc pcb %p sock %d port %u",
	    __func__, new_pcb, sock, ntohs(from.sin_port));

	new_pcb->remote_sa_in = from;		/* struct copy */
	new_pcb->local_sa_in = pcb->local_sa_in;
	pcb->net_accept(pcb->recv_arg, (struct net_tcp *)new_pcb, AE_OK);
}

static void net_pcb_event(void *arg)
{
	struct net_pcb *pcb = arg;
	struct net_tcp *tcp;
	struct net_udp *udp;
	struct ada_mbuf *m;
	struct sockaddr_in from;
	int len;
	int slen;
	u16 sent_len;
	ip_addr_t addr;
	u16_t port;

	/*
	 * This is called while holding the client_lock, but the server sockets
	 * don't expect it to be held.  Release it on TCP sockets only.
	 */
	if (pcb->type == SOCK_STREAM) {
		client_unlock();
		tcp = arg;
		udp = NULL;
	} else {
		tcp = NULL;
		udp = arg;
	}

	/*
	 * handle exception events (accept and connected).
	 */
	if (pcb->ex_event) {
		pcb->ex_event = 0;
		if (pcb->net_accept) {
			net_pcb_accept_new(pcb);
		}
		if (pcb->connected) {
			pcb->connected(pcb->recv_arg,
			    (struct net_tcp *)pcb, 0);
		}
	}

	if (pcb->tx_event) {
		pcb->tx_event = 0;
		sent_len = pcb->pending_send_len;
		pcb->pending_send_len = 0;
		if (pcb->tcp_sent) {
			pcb->tcp_sent(pcb->recv_arg, tcp, sent_len);
		}
	}

	/*
	 * Handle receive events.
	 * Perhaps the client should supply the buffer, too.
	 */
	if (pcb->rx_event) {
		pcb->rx_event = 0;
		while (pcb->udp_recv) {	/* udp_recv is union with tcp_recv */
			m = ada_mbuf_alloc(NET_UDP_MAX_SZ);
			if (!m) {
				break;
			}
			slen = sizeof(from);
			if (tcp) {
				len = recv(pcb->sock,
				    ada_mbuf_payload(m), ada_mbuf_len(m), 0);
				addr.addr = 0;
				port = 0;
			} else {
				len = recvfrom(pcb->sock,
				    ada_mbuf_payload(m), ada_mbuf_len(m), 0,
				    (struct sockaddr *)&from, &slen);
				addr.addr = from.sin_addr.s_addr;
				port = ntohs(from.sin_port);
			}
			if (len <= 0) {
				ada_mbuf_free(m);
				break;
			}
			ada_mbuf_trim(m, len);
			if (tcp) {
				pcb->tcp_recv(pcb->recv_arg, tcp, m, AE_OK);
			} else {
				pcb->udp_recv(pcb->recv_arg, udp, m,
				    &addr, port);
			}
		}
	}
	net_pcb_release(pcb);
	if (tcp) {
		client_lock();
	}
}

/*
 * Pend a callback for TCP or UDP socket.
 * Called with lock held.
 */
static void net_pcb_pend(struct net_pcb *pcb)
{
	if (!pcb->cb.pending) {
		net_pcb_hold(pcb);
		client_callback_pend(&pcb->cb);
	}
}

struct net_tcp *net_tcp_new(void)
{
	return (struct net_tcp *)net_pcb_new(SOCK_STREAM);
}

enum ada_err net_tcp_connect(struct net_tcp *tcp, ip_addr_t *addr, u16 port,
				enum ada_err (*connected)(void *,
				struct net_tcp *, enum ada_err))
{
	struct net_pcb *pcb = &tcp->pcb;
	struct sockaddr_in *s_in;
	int rc;

	s_in = &pcb->remote_sa_in;
	s_in->sin_family = AF_INET;
	s_in->sin_port = htons(port);
	s_in->sin_addr.s_addr = addr->addr;

	rc = lwip_connect(pcb->sock, (struct sockaddr *)s_in, sizeof(s_in));
	if (rc) {
		log_err(LOG_MOD_DEFAULT, "%s: sock %d err %d",
		    __func__, pcb->sock, rc);
		return AE_ERR;
	}
	return AE_OK;
}

enum ada_err net_tcp_bind(struct net_tcp *tcp, ip_addr_t *addr, u16 port)
{
	return net_pcb_bind(&tcp->pcb, addr, port);
}

struct net_tcp *net_tcp_listen(struct net_tcp *tcp, int backlog)
{
	struct net_pcb *pcb = &tcp->pcb;
	int rc;

	rc = lwip_listen(pcb->sock, backlog);
	if (rc) {
		log_err(LOG_MOD_DEFAULT, "%s: sock %d err %d",
		    __func__, pcb->sock, rc);	/* XXX */
		return NULL;
	}
	return tcp;
}

void net_tcp_accept(struct net_tcp *tcp,
		enum ada_err (*accept)(void *arg, struct net_tcp *,
		enum ada_err))
{
	tcp->pcb.net_accept = accept;
}

void net_tcp_recv(struct net_tcp *tcp,
		enum ada_err (*recv)(void *arg,
			struct net_tcp *, struct ada_mbuf *, enum ada_err))
{
	tcp->pcb.tcp_recv = recv;
}

void net_tcp_arg(struct net_tcp *tcp, void *arg)
{
	tcp->pcb.recv_arg = arg;
}

void net_tcp_err(struct net_tcp *tcp, void (*err_cb)(void *arg, err_t err))
{
	/* XXX TBD - no err callbacks yet */
}

void net_tcp_recved(struct net_tcp *tcp, u16 len)
{
	/* XXX */
}

enum ada_err net_tcp_write(struct net_tcp *tcp,
	const void *buf, u16 len, u8 apiflags)
{
	struct net_pcb *pcb = &tcp->pcb;
	int rc;

	if (pcb->sock == NET_SOCK_INVALID) {
		return AE_ERR;
	}
	rc = send(pcb->sock, (char *)buf, len, 0);
	if (rc == len) {
		pcb->pending_send_len += len;
	} else {
		log_debug(LOG_MOD_DEFAULT,
		    "%s: sock %d buf %p len %u port %u rc %d",
		    __func__, pcb->sock, buf, len,
		    ntohs(pcb->remote_sa_in.sin_port), rc);
		if (rc == -100) {
			return AE_BUF;
		}
		net_pcb_close(pcb);
		return AE_ERR;
	}
	return AE_OK;
}

enum ada_err net_tcp_output(struct net_tcp *tcp)
{
	return AE_OK;
}

void net_tcp_remove(struct net_tcp *tcp)
{
	net_pcb_remove(&tcp->pcb);
}

int net_tcp_sock(struct net_tcp *tcp)
{
	return tcp->pcb.sock;
}

enum ada_err net_tcp_close(struct net_tcp *tcp)
{
	struct net_pcb *pcb = &tcp->pcb;

	pcb->tcp_recv = NULL;
	pcb->connected = NULL;
	pcb->net_accept = NULL;
	net_pcb_remove(pcb);
	return AE_OK;
}

void net_tcp_abort(struct net_tcp *tcp)
{
	net_tcp_close(tcp);
}

void net_tcp_sent(struct net_tcp *tcp,
	void (*sent_cb)(void *, struct net_tcp *, u16 len))
{
	struct net_pcb *pcb = &tcp->pcb;

	pcb->tcp_sent = sent_cb;
}

void net_tcp_set_v6(struct net_tcp *tcp, int v6)
{
	tcp->pcb.is_v6 = v6;
}

int net_tcp_v6(struct net_tcp *tcp)
{
	return tcp->pcb.is_v6;
}

static void net_poll_wait(unsigned long arg)
{
	fd_set read_fds;
	fd_set write_fds;
	fd_set ex_fds;
	struct timeval tmo;
	struct net_pcb *pcb;
	unsigned long sock_limit;	/* max sock + 1 */

	log_thread_id_set(TASK_LABEL_NETPOLL);
	taskstat_dbg_start();

	while (1) {
		tmo.tv_sec = 0;
		tmo.tv_usec = 111111;	/* XXX default delay */
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		FD_ZERO(&ex_fds);

		ada_lock(net_pcb_lock);
		while (TAILQ_EMPTY(&net_pcbs)) {
			ada_unlock(net_pcb_lock);
			vTaskDelay(100);
			ada_lock(net_pcb_lock);
		}
		sock_limit = 0;
		TAILQ_FOREACH(pcb, &net_pcbs, list) {
			if (pcb->sock == NET_SOCK_INVALID || pcb->cb.pending) {
				continue;
			}
			if (pcb->udp_recv) {	/* union with tcp_recv */
				FD_SET(pcb->sock, &read_fds);
				if (pcb->sock >= sock_limit) {
					sock_limit = pcb->sock + 1;
				}
			}
			if (pcb->connected || pcb->net_accept) {
				FD_SET(pcb->sock, &ex_fds);
				FD_SET(pcb->sock, &read_fds);
				if (pcb->sock >= sock_limit) {
					sock_limit = pcb->sock + 1;
				}
			}
			if (pcb->pending_send_len && pcb->tcp_sent) {
				FD_SET(pcb->sock, &write_fds);
				if (pcb->sock >= sock_limit) {
					sock_limit = pcb->sock + 1;
				}
			}
		}
		ada_unlock(net_pcb_lock);

		if (sock_limit) {
			if (select(sock_limit, &read_fds, &write_fds, &ex_fds,
			    &tmo)) {
				ada_lock(net_pcb_lock);
				TAILQ_FOREACH(pcb, &net_pcbs, list) {
					if (pcb->sock == NET_SOCK_INVALID) {
						continue;
					}
					if (FD_ISSET(pcb->sock, &read_fds)) {
						pcb->rx_event = 1;
						net_pcb_pend(pcb);
					}
					if (FD_ISSET(pcb->sock, &write_fds)) {
						pcb->tx_event = 1;
						net_pcb_pend(pcb);
					}
					if (FD_ISSET(pcb->sock, &ex_fds)) {
						pcb->ex_event = 1;
						net_pcb_pend(pcb);
					}
				}
				ada_unlock(net_pcb_lock);
			}
		} else {
			vTaskDelay(100);
		}
	}
}

/*
 * IGMP
 */
static enum ada_err net_igmp_change(struct net_udp *udp, ip_addr_t *if_addr,
				ip_addr_t *group_addr, int op)
{
	struct ip_mreq {
		uint32_t addr;
		uint32_t if_addr;
	} group;
	int rc;

	group.addr = group_addr->addr;
	group.if_addr = if_addr->addr;

	rc = setsockopt(udp->pcb.sock, SOL_SOCKET, op,
	    &group, sizeof(group));
	if (rc) {
		return AE_ERR;
	}
	return AE_OK;
}

enum ada_err net_igmp_joingroup(struct net_udp *udp, ip_addr_t *if_addr,
		ip_addr_t *group)
{
	return net_igmp_change(udp, if_addr, group, IP_ADD_MEMBERSHIP);
}

#ifdef IP_DROP_MEMBERSHIP
enum ada_err net_igmp_leavegroup(struct net_udp *udp,
			ip_addr_t *if_addr, ip_addr_t *group)
{
	return net_igmp_change(udp, if_addr, group, IP_DROP_MEMBERSHIP);
}
#endif /* IP_DROP_MEMBERSHIP */

/*
 * IP address functions.
 */
int net_addr_cmp(int is_v6, const ipX_addr_t *a, const ipX_addr_t *b)
{
	if (is_v6) {
		ASSERT_NOTREACHED();
	}
	return ((const ip_addr_t *)a)->addr == ((const ip_addr_t *)b)->addr;
}

void net_addr_set_zero(int is_v6, ipX_addr_t *addr)
{
	if (is_v6) {
		ASSERT_NOTREACHED();
	}
	((ip_addr_t *)addr)->addr = 0;
}

int net_addr_conflict_check(u32 addr1, u32 mask1, u32 addr2, u32 mask2)
{
	u32 diff = addr1 ^ addr2;

	return !(diff & mask1) || !(diff & mask2);
}

/*
 * TCP functions.
 */
struct net_tcp *net_tcp_alloc_set(int s)
{
	struct tcp_pcb *pcb;
	struct net_tcp *tcp;

	pcb = sock_get_pcb(s);
	if (!pcb) {
		return NULL;
	}

	tcp = ayla_calloc(1, sizeof(*tcp));
	if (!tcp) {
		return NULL;
	}

	tcp->pcb.sock = s;
	tcp->pcb.is_v6 = 0;

	tcp->pcb.local_sa_in.sin_family = AF_INET;
	tcp->pcb.local_sa_in.sin_addr.s_addr = pcb->local_ip.addr;
	tcp->pcb.local_sa_in.sin_port = pcb->local_port;

	tcp->pcb.remote_sa_in.sin_family = AF_INET;
	tcp->pcb.remote_sa_in.sin_addr.s_addr = pcb->remote_ip.addr;
	tcp->pcb.remote_sa_in.sin_port = pcb->remote_port;

	return tcp;
}
