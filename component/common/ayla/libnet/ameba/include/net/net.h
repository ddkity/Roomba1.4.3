/*
 * Copyright 2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_NET_H__
#define __AYLA_NET_H__


#include <sys/socket.h>

#include <lwip/err.h>
#include <lwip/raw.h>
#include <lwip/udp.h>
#include <lwip/dns.h>
#include <lwip/tcpip.h>
#include <lwip/tcp_impl.h>
#include <lwip/tcp.h>
#include "lwip/ip_addr.h"
#include <lwip_netconf.h>
#include <lwip/netif.h>

#include <sys/queue.h>

extern struct netif xnetif[NET_IF_NUM];

#define ipX_addr_t	ip_addr_t
#define ipX_addr_set(is_ipv6, dest, src)	ip_addr_set(dest, src)


#ifdef NET_IPV6
static inline ip_addr_t *ipX_2_ip(ipX_addr_t *addr)
{
	return &addr->ip4;
}

#else
static inline ip_addr_t *ipX_2_ip(ipX_addr_t *addr)
{
	return (ip_addr_t *)addr;
}

#endif /* NET_IPV6 */


static inline ipX_addr_t *ip_2_ipX(ip_addr_t *addr)
{
	return (ipX_addr_t *)addr;
}

int net_addr_conflict_check(u32 addr1, u32 mask1, u32 addr2, u32 mask2);


/*
 * Netif.
 */
#define net_netif_is_link_up	netif_is_link_up
#define net_netif_is_up		netif_is_up

#define net_netif_set_link_down	netif_set_link_down
#define net_netif_set_link_up	netif_set_link_up

#define net_netif_set_down	netif_set_down
#define net_netif_set_up	netif_set_up

#define net_netif_set_default	netif_set_default
#define net_netif_set_hostname	netif_set_hostname


struct ada_mbuf;

/*
 * Common network interfaces.
 * There are separate implementations of these for each network stack.
 */

/*
 * Initialize network layer.
 */
void net_init(void);

/*
 * Callback interface.
 */
struct net_callback {
	u8 pending;
	void (*func)(void *);
	void *arg;
};

/*
 * Initialize a pre-allocated tcpip_msg as a callback msg.
 * The callback function must clear the pending flag.
 * Be sure not to free the callback while it is pending.
 */
void net_callback_init(struct net_callback *, void (*func)(void *), void *arg);
void net_callback_pend(struct net_callback *);

static inline void net_callback_queue_set(u8 queue_index)
{
}

struct net_callback_queue;		/* semi-opaque structure */

/*
 * Create a queue for callback handlers.
 */
struct net_callback_queue *net_callback_queue_new(unsigned int len);

/*
 * Queue a callback on a specific queue.
 */
int net_callback_enqueue(struct net_callback_queue *, struct net_callback *);

/*
 * Dequeue from a callback queue.
 * Returns NULL immediately if queue is empty.
 */
struct net_callback *net_callback_dequeue(struct net_callback_queue *);

/*
 * Dequeue from a callback queue, waiting if necessary.
 * Waits indefinitely if ms is less than 0.
 * Returns NULL on timeout.
 */
struct net_callback *net_callback_wait(struct net_callback_queue *nq, int ms);

/*
 * Network timers.
 */
struct timer;
void net_timer_set(struct timer *timer, unsigned long delay_ms);
void net_timer_cancel(struct timer *);

/*
 * DNS.
 */
struct net_dns_req {
	const char *hostname;
	u8 done;
	enum ada_err error;
	be32 addr;
	void (*callback)(struct net_dns_req *);
	struct net_callback net_dns_cb;
};

/*
 * Lookup hostname. with IP address.
 * Callback in request structure delivers result.
 * The callback may be called synchronously or later.
 */
enum ada_err net_dns_lookup(struct net_dns_req *);

/*
 * Cancel lookup request.
 * It may not always be possible to cancel the request, but this cancels the
 * callback and allows the caller to free the request if desired.
 */
void net_dns_cancel(struct net_dns_req *);

/*
 * Delete a host from any DNS cache, if possible.
 */
static inline void net_dns_delete_host(const char *hostname)
{
}

/*
 * Rotate DNS servers, if possible.
 */
static inline void net_dns_servers_rotate(void)
{
}

ip_addr_t net_dns_getserver(u8 index);

/*
 * TCP functions.
 */

struct net_tcp;			/* semi-opaque structure for socket */

struct net_tcp *net_tcp_new(void);
int net_tcp_sock(struct net_tcp *);
enum ada_err net_tcp_bind(struct net_tcp *, ip_addr_t *, u16 port);
struct net_tcp *net_tcp_listen(struct net_tcp *, int backlog);
void net_tcp_accept(struct net_tcp *,
		enum ada_err (*accept)(void *arg, struct net_tcp *,
		enum ada_err));
enum ada_err net_tcp_connect(struct net_tcp *, ip_addr_t *, u16,
		enum ada_err (*connected)(void *arg,
		struct net_tcp *, enum ada_err));
void net_tcp_recv(struct net_tcp *,
		enum ada_err (*recv)(void *arg, struct net_tcp *,
			struct ada_mbuf *, enum ada_err));
void net_tcp_arg(struct net_tcp *, void *arg);
void net_tcp_send(struct net_tcp *, u16);
void net_tcp_recved(struct net_tcp *, u16);
enum ada_err net_tcp_close(struct net_tcp *);
void net_tcp_abort(struct net_tcp *);
void net_tcp_abandon(struct net_tcp *, int reset);
enum ada_err net_tcp_write(struct net_tcp *, const void *, u16 len, u8 flags);
enum ada_err net_tcp_output(struct net_tcp *);
void net_tcp_sent(struct net_tcp *,
		void (*sent_cb)(void *, struct net_tcp *, u16 len));
void net_tcp_err(struct net_tcp *,
		void (*err_cb)(void *arg, err_t err));

const ip_addr_t *net_tcp_local_ip(struct net_tcp *);
const ip_addr_t *net_tcp_remote_ip(struct net_tcp *);

int net_tcp_is_established(struct net_tcp *);

#define net_tcp_accepted(tcp) do {} while (0)
#define	net_tcp_set_sndbuf(tcp, size) do {(void)(tcp); (void)(size); } while (0)
#define net_tcp_sndqueuelen(tcp) 1500

int net_tcp_v6(struct net_tcp *);
void net_tcp_set_v6(struct net_tcp *, int);
#define net_tcp_remote_ip_copy(pcb, ip, is_v6) do {                     \
		*is_v6 = 0;                                             \
		memcpy(&ip, net_tcp_remote_ip(pcb), sizeof(ip));        \
	} while (0)
int net_addr_cmp(int is_v6, const ip_addr_t *a, const ip_addr_t *b);
void net_addr_set_zero(int is_v6, ip_addr_t *a);

/*
 * UDP functions.
 */
struct net_udp;				/* semi-opaque structure for socket */

struct net_udp *net_udp_new(void);
enum ada_err net_udp_bind(struct net_udp *, ip_addr_t *, u16 port);
enum ada_err net_udp_connect(struct net_udp *, ip_addr_t *, u16 port);
void net_udp_recv(struct net_udp *,
		void (*recv)(void *arg, struct net_udp *, struct ada_mbuf *,
		ip_addr_t *from_ip, u16 from_port),
		void *recv_arg);
enum ada_err net_udp_send(struct net_udp *, struct ada_mbuf *);
enum ada_err net_udp_sendto_if(struct net_udp *, struct ada_mbuf *,
		ip_addr_t *to, u16 port, struct netif *);
void net_udp_remove(struct net_udp *);

enum ada_err net_igmp_joingroup(struct net_udp *, ip_addr_t *if_addr,
				ip_addr_t *group);
enum ada_err net_igmp_leavegroup(struct net_udp *,
			ip_addr_t *if_addr, ip_addr_t *group);

int net_ipv4_is_local(const ip_addr_t *ip);

int net_udp_is_v6(struct net_udp *);
void net_udp_set_v6(struct net_udp *, int);

extern void *wifi_wmi;		/* might be used by network code */

struct tcp_pcb *sock_get_pcb(int s);
struct net_tcp *net_tcp_alloc_set(int s);

#endif /* __AYLA_NET_H__ */
