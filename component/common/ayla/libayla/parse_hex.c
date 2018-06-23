/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <ayla/utypes.h>
#include <ayla/parse.h>

/*
 * Parse arbitrarily long hex string into buffer.
 * Returns length used or negative on error.
 * Error -1 returned if input string length is not even.
 */
ssize_t parse_hex(void *buf, size_t len, const char *hex, size_t hex_len)
{
	const char *cp;
	size_t off = 0;
	u8 *dest = buf;
	u8 c;
	u8 byte;
	int i;

	for (byte = 0, i = 0, cp = hex; *cp != '\0' && hex_len--; cp++, i++) {
		c = *cp;
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (c >= 'a' && c <= 'f') {
			c += 10 - 'a';
		} else if (c >= 'A' && c <= 'F') {
			c += 10 - 'A';
		} else {
			return -1;
		}
		byte = (byte << 4) | c;
		if (i & 1) {
			if (off >= len) {
				return -1;
			}
			dest[off++] = byte;
			byte = 0;
		}
	}
	if (i & 1) {
		return -1;		/* odd length */
	}
	return off;
}
