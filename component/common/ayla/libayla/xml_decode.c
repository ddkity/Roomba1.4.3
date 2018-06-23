/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ayla/utypes.h>
#include <ayla/xml.h>

/*
 * XML-decode a string that has escaped reserved chars with "&#NNN;".
 * The source may or may not be NUL-terminated.
 * The destination buffer be the same as the source buffer.
 * Return the length of the decoded string.
 * Returns -1 on bad decode.
 *
 * Note:  See note in xml_encode().
 */
ssize_t
xml_decode(char *dest, size_t dest_len, char *src, size_t src_len,
	    char **leftover)
{
	char *esc;
	char *amp;
	unsigned long val;
	char *errptr;
	ssize_t len = 0;
	char c;

	*leftover = NULL;
	while (src_len > 0 && dest_len > 1 && (c = *src++) != '\0') {
		if (c == '&') {
			amp = src - 1;
			esc = src;		/* point to char after '&' */
			do {
				if (src_len-- <= 0) {
					*leftover = amp;
					break;
				}
				c = *src++;
				if (c == '\0') {
					*leftover = amp;
					break;
				}
			} while (c != ';');
			if (*leftover) {
				break;
			}
			src[-1] = '\0';		/* replace ';' with NUL */
			if (!strcmp(esc, "amp")) {
				c = '&';
			} else if (!strcmp(esc, "lt")) {
				c = '<';
			} else if (!strcmp(esc, "gt")) {
				c = '>';
			} else if (!strcmp(esc, "quot")) {
				c = '\"';
			} else if (!strcmp(esc, "apos")) {
				c = '\'';
			} else if (esc[0] == '#') {
				val = strtoul(esc + 1, &errptr, 10);

				if (*errptr != '\0' || val > 0x7fffffff) {
					return -2;
				}
				if (val <= 127) {
					c = (char)val;
				} else {
					/* Convert to UTF-8 Format */
					size_t extra_bytes = 1;
					if (dest_len <= 0) {
						return -2;
					}
					if (val <= 0x7ff) {
						*dest++ = 0xc0 | (val >> 6);
					} else if (val <= 0xffff) {
						*dest++ = 0xe0 | (val >> 12);
						extra_bytes = 2;
					} else if (val <= 0x1fffff) {
						*dest++ = 0xf0 | (val >> 18);
						extra_bytes = 3;
					} else if (val <= 0x3ffffff) {
						*dest++ = 0xf8 | (val >> 24);
						extra_bytes = 4;
					} else {
						*dest++ = 0xfc | (val >> 30);
						extra_bytes = 5;
					}
					if (dest_len <= extra_bytes) {
						return -2;
					}

					dest_len = dest_len - extra_bytes;
					len = len + extra_bytes;
					extra_bytes--;
					for (c = extra_bytes; c >= 1; c--) {
						*dest++ = 0x80 |
						    ((val >> (6 * c)) & 0x3f);
					}

					c = 0x80 | (val & 0x3f);
				}
			} else {
				return -2;
			}
		}
		if (dest_len <= 0) {
			return -2;
		}
		dest_len--;

		len++;
		*dest++ = c;
	}
	if (dest_len <= 0) {
		return -2;
	}
	*dest = '\0';
	return len;
}
