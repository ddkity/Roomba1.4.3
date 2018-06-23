/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <ayla/utypes.h>
#include <ayla/xml.h>

/*
 * Add c to the buffer dest if there's space
 * Return -1 if there's no space. Otherwise, return 0.
 */
static int xml_add_to_dest(char **dest, size_t *dest_len, ssize_t *len, u8 c)
{
	if (*dest == NULL) {
		(*len)++;
		return 0;
	}
	if (*dest_len < 1) {
		return -1;
	}
	(*dest_len)--;
	(*len)++;
	**dest = c;
	(*dest)++;
	return 0;
}

/*
 * XML-encode a string into a buffer, escaping reserved chars with "&#NNN;".
 * Return the length of the encoded string.
 * If the buffer overflows, the return value will be -1.
 */
ssize_t
xml_encode(char *dest, size_t dest_len, const char *src, size_t src_len,
	    size_t *consumed)
{
	ssize_t len = 0;
	char buf[8];
	size_t elen;
	const char *esc;
	u8 c;
	ssize_t read_extra = 0;

	if (consumed) {
		*consumed = 0;
	}
	while (src_len && (!dest || dest_len > 1)) {
		src_len--;
		c = *src++;
		elen = 0;
		if (read_extra > 0) {
			if (c <= 0x7f) {
				return -1;
			}
			if (xml_add_to_dest(&dest, &dest_len, &len, c)) {
				return -1;
			}
			read_extra--;
			goto cont;
		} else if (c == '&') {
			esc = "&amp;";
			elen = 5;
		} else if (c == '<') {
			esc = "&lt;";
			elen = 4;
		} else if (c == '>') {
			esc = "&gt;";
			elen = 4;
		} else if (c == '\"') {
			esc = "&quot;";
			elen = 6;
		} else if (c == '\'') {
			esc = "&apos;";
			elen = 6;
		} else if (c < 0x20) {
			elen = snprintf(buf, sizeof(buf) - 1, "&#%u;", c);
			esc = buf;
		} else if (c <= 0x7f) {
			if (xml_add_to_dest(&dest, &dest_len, &len, c)) {
				goto finish;
			}
			goto cont;
		} else {
			/* "Character in UTF-8 Format */
			if (c < 0xe0) {
				read_extra = 1;
			} else if (c < 0xf0) {
				read_extra = 2;
			} else if (c < 0xf8) {
				read_extra = 3;
			} else if (c < 0xfc) {
				read_extra = 4;
			} else {
				read_extra = 5;
			}
			if (dest && (dest_len <= read_extra + 2)) {
				goto finish;
			}
			if (xml_add_to_dest(&dest, &dest_len, &len, c)) {
				goto finish;
			}
			goto cont;
		}
		if (dest) {
			if (dest_len <= elen + 1) {
				goto finish;
			}
			memcpy(dest, esc, elen);
			dest += elen;
			dest_len -= elen;
		}
		len += elen;
cont:
		if (consumed) {
			(*consumed)++;
		}
	}
	if (read_extra > 0) {
		return -1;
	}
finish:
	if (dest) {
		if (dest_len < 1) {
			return -1;
		}
		*dest = '\0';
	}
	return len;
}
