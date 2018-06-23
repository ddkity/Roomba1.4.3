/*
 * Copyright 2011-2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>

#include <ayla/dns.h>
#include <ayla/conf.h>

#include <ada/prop.h>
#include <ada/ada_conf.h>

#include <net/net.h>
#include <ada/dnss.h>
#include "dnss_internal.h"

void dnss_log(const char *fmt, ...)
{
	ADA_VA_LIST args;

	ADA_VA_START(args, fmt);
	log_put_va(MOD_LOG_DNSS, fmt, args);
	ADA_VA_END(args);
}

/*
 * DNS records contain this as the device name.
 */
u16 dnss_device_name(char *arg, u16 len)
{
	const char *name;
	u16 rc = 0;

	name = ada_conf.host_symname;
	if (*name != '\0') {
		goto ret_name;
	}

	name = conf_sys_dev_id;
	if (*name != '\0') {
		goto ret_name;
	}

	name = "Ayla device";

ret_name:
	if (dnss_state.mdns_hname_suf) {
		rc = snprintf(arg, len, "%s-%d.local.",
		    name, dnss_state.mdns_hname_suf);
	} else {
		rc = snprintf(arg, len, "%s.local.", name);
	}
	return rc;
}

/*
 * MFI/HAP DNS TXT record contains data about this 'service' name.
 */
u16 dnss_service_name(char *arg, u16 len, const char *srv_name)
{
	const char *name;
	u16 rc = 0;

#ifdef HOMEKIT
	name = hap_get_accessory_name();
#else
	name = NULL;
#endif
	if (name && *name != '0') {
		goto ret_name;
	}
	if (oem_model[0] == '\0') {
		name = "Ayla device";
	} else {
		name = oem_model;
	}

ret_name:
	if (dnss_state.mdns_sname_suf) {
		rc = snprintf(arg, len, "%s-%d.%s", name,
		    dnss_state.mdns_sname_suf, srv_name);
	} else {
		rc = snprintf(arg, len, "%s.%s", name, srv_name);
	}
	return rc;
}

struct ip_addr *dnss_my_v4addr(struct netif *nif)
{
	if (nif) {
		return &nif->ip_addr;
	} else {
		return &netif_default->ip_addr;
	}
}

#ifdef DNSS_IPV6
struct ip6_addr *dnss_my_v6addr(struct netif *nif)
{
	if (nif) {
		return &nif->ip6_addr[0];
	} else {
		return &netif_default->ip6_addr[0];
	}
}
#endif

static int dnss_find_name(const u8 *haystack, int hlen, const u8 *needle,
    int nlen)
{
	int i, end;

	end = hlen - nlen;
	for (i = 0; i < end; i++) {
		if (!memcmp(needle, &haystack[i], nlen)) {
			return i;
		}
	}
	return -1;
}

/*
 * Names of form www.apple.com. and _mfi-config._tcp.local.
 * Place it in outgoing message.
 */
int dnss_fill_name(const u8 *start, const char *name, void *tgt_v)
{
	int nlen;
	u8 *tgt = (u8 *)tgt_v;
	u8 *tlen;
	int off;

	nlen = strlen(name) + 1;
	if (!tgt) {
		return nlen;
	}
	tlen = tgt++;
	*tlen = 0;
	while (1) {
		*tgt = *name;
		if (*name == '.' || *name == '\0') {
			tlen = tgt;
			*tlen = 0;
			if (*name == '\0') {
				break;
			}
		} else {
			*tlen = *tlen + 1;
		}
		tgt++;
		name++;
	}

	/*
	 * Now compress.
	 */
	tgt = (u8 *)tgt_v;
	while (*tgt != '\0') {
		off = dnss_find_name(start, tgt - start, tgt, nlen);
		if (off >= 0) {
			tgt[0] = DNSL_PTR | ((off >> 8) & DNSL_MASK);
			tgt[1] = off;
			return tgt - (u8 *)tgt_v + 2;
		} else {
			nlen -= *tgt + 1;
			tgt += *tgt + 1;
		}
	}
	return tgt - (u8 *)tgt_v + 1;
}

/*
 * name is a straight up string, while the other is a DNS name inside pkt.
 * This means that name is broken into components and components
 * might have to be followed via offsets into pkt.
 * Returns 0 for match. > 0 if name is lexicographically later than
 * DNS name in the packet, and < 0 if it is other way around.
 */
int dnss_cmp_name(void *pkt_v, int off, int maxoff, const char *name)
{
	unsigned char *pkt = (unsigned char *)pkt_v;
	int tlen;
	unsigned char ch1, ch2;
	int loopcnt = 0;

	while (loopcnt++ < DNSL_MAX_LOOPS) {
		tlen = pkt[off++];
		/*
		 * Handle pointer.
		 */
		if (tlen > DNSL_MASK) {
			if (off + 1 > maxoff) {
				return 1;
			}
			if ((tlen & DNSL_PTR) != DNSL_PTR) {
				return 1;
			}
			off = (tlen & DNSL_MASK << 8) | pkt[off];
			continue;
		}
		if (tlen == 0) {
			if (*name != '\0') {
				return 1;
			}
			return 0;
		}
		if (off + tlen >= maxoff) {
			return 1;
		}
		while (tlen--) {
			ch1 = tolower(pkt[off++]);
			ch2 = tolower((unsigned char)*name++);
			if (ch1 != ch2) {
				return ch2 - ch1;
			}
		}
		ch2 = *name++;
		if (ch2 != '.') {
			return ch2 - '.';
		}
	}
	return 1;
}

/*
 * Copy name from incoming message, starting from offset off, to a
 * contiguous buffer.
 */
int dnss_copy_name(void *pkt_v, int off, int maxoff, char *name,
    const int max_name)
{
	unsigned char *pkt = (unsigned char *)pkt_v;
	int tlen;
	int nlen = 0;
	int loopcnt = 0;

	while (loopcnt++ < DNSL_MAX_LOOPS) {
		tlen = pkt[off++];
		/*
		 * Handle pointer.
		 */
		if (tlen > DNSL_MASK) {
			if (off + 1 > maxoff) {
				return -1;
			}
			if ((tlen & DNSL_PTR) != DNSL_PTR) {
				return -1;
			}
			off = (tlen & DNSL_MASK << 8) | pkt[off];
			continue;
		}
		if (tlen == 0) {
			return nlen;
		}
		if (off + tlen >= maxoff) {
			return -1;
		}
		if (nlen + tlen < max_name - 2) {
			memcpy(&name[nlen], &pkt[off], tlen);
			nlen += tlen;
			off += tlen;
			name[nlen++] = '.';
			name[nlen] = '\0';
		}
	}
	return -1;
}
