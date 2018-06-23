/*
 * Copyright 2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_DNSS_INTERNAL_H__
#define __AYLA_DNSS_INTERNAL_H__

#define DNSL_MAX_LOOPS	8	/* max # ptrs we follow in name */

struct dnss_state {
	struct net_udp *pcb;
	struct net_udp *mdns_disc_pcb;
	struct net_udp *mdns_pcb;
#ifdef DNSS_IPV6
	struct net_udp *mdns_pcb_v6;
#endif
	enum {
		MDNS_OFF = 0,
		MDNS_PROBE1,
		MDNS_PROBE2,
		MDNS_PROBE3,
		MDNS_ADV_FAST1,
		MDNS_ADV_FAST2,
		MDNS_ADV_STOP
	} mdns_state;
	u8 mdns_adv;
	u8 mdns_adv_bye;
	u8 mdns_hname_suf;
	u8 mdns_sname_suf;
	u16 mdns_start_time;
#if defined(MFI) || defined(HOMEKIT)
	struct timer rsp_timer;
	struct timer adv_timer;
#endif
};
extern struct dnss_state dnss_state;

void dnss_log(const char *fmt, ...) ADA_ATTRIB_FORMAT(1, 2);

u16 dnss_device_name(char *arg, u16 len);
u16 dnss_service_name(char *arg, u16 len, const char *srv_name);

struct ip_addr *dnss_my_v4addr(struct netif *nif);
struct ip6_addr *dnss_my_v6addr(struct netif *nif);

int dnss_fill_name(const u8 *start, const char *name, void *tgt_v);
int dnss_cmp_name(void *pkt_v, int off, int maxoff, const char *name);
int dnss_copy_name(void *pkt_v, int off, int maxoff, char *name,
		   const int max_name);

#endif /* __AYLA_DNSS_INTERNAL_H__ */
