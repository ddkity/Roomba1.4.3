/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <ayla/utypes.h>
#include <ayla/uri_code.h>

static int uri_hex_val(u8 c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	return -1;
}

/*
 * URI-decode (i.e. percent-decode) a string into a buffer.
 * Return the length of the decoded string.
 * If the buffer overflows, the return value will be -1.
 * Any invalid hex digits following a percent sign will also
 * cause an error return of -1.
 *
 * The resulting string will be NUL-terminated if there is room.
 * This is for the benefit of 32-byte SSIDs.
 */
ssize_t uri_decode_n(char *dest, size_t dest_len,
	const char *src, size_t src_len)
{
	ssize_t len = 0;
	int hi;
	int lo;
	u8 c;

	while ((c = *src++) != '\0' && src_len-- > 0) {
		if (c == '%') {
			if (src_len < 2) {
				return -1;
			}
			src_len -= 2;
			hi = uri_hex_val(*src++);
			if (hi < 0) {
				return -1;
			}
			lo = uri_hex_val(*src++);
			if (lo < 0) {
				return -1;
			}
			c = (hi << 4) | lo;
		} else if (c == '+') {
			c = ' ';
		}
		if (dest_len-- == 0) {
			return -1;
		}
		*dest++ = c;
		len++;
	}
	if (dest_len) {
		*dest++ = '\0';
	}
	return len;
}

ssize_t uri_decode(char *dest, size_t dest_len, const char *src)
{
	return uri_decode_n(dest, dest_len, src, MAX_U32);
}
