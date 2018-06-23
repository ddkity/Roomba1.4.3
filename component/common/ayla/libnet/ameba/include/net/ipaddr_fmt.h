/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef _NET_IPADDR_FMT_H_
#define _NET_IPADDR_FMT_H_

#include <lwip/tcpip.h>
#include <lwip/ip_addr.h>

extern void ip_addr_ntop(int is_v6, const ip_addr_t *addr, char *str, int slen);
extern int ip_addr_pton(int is_v6, const char *str, ip_addr_t *addr);
#endif
