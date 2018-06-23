/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <ayla/utypes.h>
#include <ayla/parse.h>

/*
 * Format 48-bit MAC address into the user-supplied buffer.
 * Buffer should be at least 18 bytes long.
 * String will be NUL-terminated and truncated if necessary.
 */
char *format_mac(const u8 *mac, char *buf, size_t buf_len)
{
	snprintf(buf, buf_len, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}
