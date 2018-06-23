/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ADA_DNSS_H__
#define __AYLA_ADA_DNSS_H__

/*
 * Start or stop DNS service.
 */
void dnss_up(void);
void dnss_down(void);

/*
 * Start or stop multicast DNS service for <DSN>.local.
 */
void dnss_mdns_disc_up(struct netif *);
void dnss_mdns_disc_down(void);

/*
 * Advertisement masks for mDNS.
 */
#define DNSS_ADV_MFI		0x1
#define DNSS_ADV_ALL		0xff
#define DNSS_ADV_HAP		0x2

/*
 * Start or stop mDNS advertisements for HomeKit or MFi services.
 */
void dnss_mdns_start(u8 adv_mask);
void dnss_mdns_stop(u8 adv_mask, int advertise);

#endif /* __AYLA_ADA_DNSS_H__ */
