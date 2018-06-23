/*
 * Copyright 2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#define HAVE_UTYPES
#include <lwip/ip.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <net/net.h>
#include <net/ipaddr_fmt.h>

void ip_addr_ntop(int is_v6, const ip_addr_t *addr, char *str, int slen)
{
#if LWIP_IPV6
	if (is_v6) {
		ip6addr_ntoa_r(ipX_2_ip6(addr), str, slen);
	} else {
		ipaddr_ntoa_r(ipX_2_ip(addr), str, slen);
	}
#else
	ipaddr_ntoa_r(ipX_2_ip(addr), str, slen);
#endif
}

int ip_addr_pton(int is_v6, const char *str, ip_addr_t *addr)
{
	int rc;

#if LWIP_IPV6
	if (is_v6) {
		rc = ip6addr_aton(str, ipX_2_ip6(addr));
	} else {
		rc = ipaddr_aton(str, ipX_2_ip(addr));
	}
#else
	rc = ipaddr_aton(str, ipX_2_ip(addr));
#endif
	return rc;
}
