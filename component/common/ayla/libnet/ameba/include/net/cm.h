/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CM_H__
#define __AYLA_CM_H__

/*
 * Connection manager.
 *
 * Monitor IP connections.
 * Run DHCP client for them.
 * Once IP address is assigned, start the client.
 * Report back successful connection to the client.
 * Handle multiple, prioritized, simultaneous connections,
 * e.g., Ethernet preferred over Wi-Fi or Wi-Fi preferred over 3G.
 *
 * The connection manager installs a link_callback and status_callback on
 * the interface.  The link status callback indicates when DHCP should start,
 * and the status_callback indicates when DHCP has obtained an IP address.
 *
 * The Wi-Fi driver may be called throught the cm_status_change callback
 * when the ADS client has either successfully connected or timed out.
 *
 * The driver (Wi-Fi or Ethernet, e.g.) sets the interface link status
 * using netif_set_link_up() or netif_set_link_down(); cm does the rest.
 */

enum cm_pri {
	CM_PRI_TEST,
	CM_PRI_ETH,
	CM_PRI_WIFI,
	CM_PRI_3G,
};

struct cm {
	/*
	 * Public fields (read-only).
	 */
	u8 enable:1;		/* zero if a higher-priority netif is used */
	u8 init_done:1;		/* client is initialized */

	/*
	 * Private fields.
	 */
	enum cm_pri pri;	/* low number is best priority */
	struct cm *next;	/* next worse priority CM */
	struct netif *netif;
	void (*status_change)(struct cm *);
	int (*signal_func)(int *);
};

/*
 * Abort all TCP PCBs on a list that use a particular interface.
 * Note this can be used for any interface, not just those managed by CM.
 * CM automatically does this when one of its interfaces goes down.
 */
void cm_tcp_abort_net(struct netif *);

/*
 * Add a connection manager instance.  Called through cm_init() only.
 */
void cm_add(struct cm *);

/*
 * Client has finished initialization (for slow devices).
 */
void cm_init_done(struct cm *);

/*
 * Initialize a connection manager instance for a network interface.
 */
static inline void cm_init(struct cm *cm, struct netif *netif, enum cm_pri pri,
		void (*status_change)(struct cm *))
{
	cm->netif = netif;
	cm->pri = pri;
	cm->status_change = status_change;
	cm_add(cm);
}

#ifdef CM_TEST_IF
void cm_test_link(int up);
#endif /* CM_TEST_IF */

#ifdef NETSTAT
void netstat_cli(int argc, char **argv);
#endif

/*
 * Set the strength of the cm being used. For example, if wifi interface
 * is being used. It'll return the RSSI value. If "strength" isn't applicable
 * for the current interface, -1 is returned.
 */
int cm_get_signal(int *value);

#endif /* __AYLA_CM_H__ */
