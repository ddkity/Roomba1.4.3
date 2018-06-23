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

static int nibble_to_ascii(u8 c)
{
	c &= 0xf;
	return c > 9 ? c - 10 + 'A' : c + '0';
}

/*
 * URI-encode (aka percent-encode) a string into a buffer.
 * Return the length of the encoded string.
 * If the buffer overflows, the return value will be -1.
 * The supplied bitmap has bits set for the unreserved byte values.
 */
ssize_t uri_encode(char *dest, size_t dest_len, const char *src, size_t src_len,
	const u32 *allowed_map)
{
	ssize_t len = 0;
	u8 c;

	while (src_len) {
		src_len--;
		c = *src++;

		if (allowed_map[c / 32] & BIT(c % 32)) {
			if (dest_len < 1) {
				return -1;
			}
			dest_len--;
			len++;
			*dest++ = c;
		} else {
			if (dest_len < 3) {
				return -1;
			}
			dest_len -= 3;
			len += 3;
			*dest++ = '%';
			*dest++ = nibble_to_ascii(c >> 4);
			*dest++ = nibble_to_ascii(c);
		}
	}
	if (dest_len < 1) {
		return -1;
	}
	*dest = '\0';
	return len;
}
