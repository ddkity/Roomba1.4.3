/*
 * Copyright 2013 Ayla Networks, Inc.  All rights reserved.
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
#include <ayla/utf8.h>

/*
 * decode UTF-8 to unicode.
 * returns the number of bytes consumed, or -1 if invalid UTF-8 sequence.
 * Sets *resultp to the resulting unicode value, except on error.
 */
ssize_t utf8_decode(const unsigned char *src, size_t len, u32 *resultp)
{
	u32 result;
	unsigned char c;
	size_t len_needed = 1;
	int i;

	c = *src++;
	if (c < 0x80) {
		len_needed = 1;
		result = c;
	} else if (c < 0xc2) {
		return -1;		/* invalid as first byte */
	} else if (c < 0xe0) {
		len_needed = 2;
		result = c & 0x1f;
	} else if (c < 0xf0) {
		len_needed = 3;
		result = c & 0xf;
	} else if (c < 0xf8) {
		len_needed = 4;
		result = c & 0x7;
	} else if (c < 0xfc) {		/* not strictly valid UTF-8 */
		len_needed = 5;
		result = c & 0x3;
	} else if (c < 0xfe) {		/* not strictly valid UTF-8 */
		len_needed = 6;
		result = c & 0x1;
	} else {
		return -1;
	}
	if (len_needed > len) {
		return -2;
	}
	for (i = 1; i < len_needed; i++) {
		c = *src++;
		if ((c & 0xc0) != 0x80) {
			return -3;
		}
		result = (result << 6) | (c & 0x3f);
	}
	*resultp = result;
	return len_needed;
}

/*
 * Encode a Unicode character to a UTF-8 string.
 */
ssize_t utf8_encode(unsigned char *bp, size_t len, u32 code)
{
	ssize_t len_needed;
	ssize_t i;
	u8 shift;
	u8 byte;

	if (code > MAX_UTF8) {
		return -1;
	}
	if (code < 0x80) {
		len_needed = 1;
		byte = code;
	} else if (code < (1U << (5 + 6)))  {		/* 2^11 */
		len_needed = 2;
		byte = 0xc0;
	} else if (code < (1U << (4 + 6 * 2))) {	/* 2^16 */
		len_needed = 3;
		byte = 0xe0;
	} else if (code < (1U << (3 + 6 * 3))) {	/* 2^21 */
		len_needed = 4;
		byte = 0xf0;
	} else if (code < (1U << (2 + 6 * 4))) {	/* 2^26 */
		len_needed = 5;
		byte = 0xf8;
	} else if (code < (1U << (1 + 6 * 5))) {	/* 2^31 */
		len_needed = 6;
		byte = 0xfc;
	} else {
		return -1;
	}
	if (len < len_needed) {
		return -1;
	}
	shift = (len_needed - 1) * 6;
	for (i = 0; i < len_needed; i++) {
		*bp++ = byte | ((code >> shift) & 0x3f);
		byte = 0x80;
		shift -= 6;
	}
	return len_needed;
}

/*
 * Get next UTF-8 token from a buffer.
 * Returns length, or zero if invalid UTF-8 code encountered.
 */
size_t utf8_get(u32 *result, u8 *buf, size_t len)
{
	u32 val = 0;
	size_t rlen = 0;
	u8 test[4];
	int i;
	u8 c;

	if (len == 0) {
		return 0;
	}
	c = buf[0];
	if (c < 0x80) {
		*result = c;
		return 1;
	}
	if ((c & 0xf8) == 0xf0) {
		val = c & 7;
		rlen = 4;
	} else if ((c & 0xf0) == 0xe0) {
		val = c & 0xf;
		rlen = 3;
	} else if ((c & 0xe0) == 0xc0) {
		if (c == 0xc0 || c == 0xc1) {
			return 0;
		}
		val = c & 0x1f;
		rlen = 2;
	} else if ((c & 0xc0) == 0x80) {
		return 0;
	}
	if (len < rlen) {
		return 0;
	}
	for (i = 1; i < rlen; i++) {
		c = buf[i];
		if ((c & 0xc0) != 0x80) {
			return 0;
		}
		val = (val << 6) | (c & 0x3f);
	}

	/*
	 * Check for over-long coding, which is invalid.
	 */
	if (utf8_encode(test, sizeof(test), val) != rlen) {
		return 0;
	}
	*result = val;
	return rlen;
}

/*
 * Get multiple UTF-8 wide characters from a buffer.
 * Returns the number of characters put in result, or -1 on error.
 */
int utf8_gets(u32 *result, int rcount, u8 *buf, size_t len)
{
	int tlen;
	int count;

	for (count = 0; count < rcount && len > 0; count++) {
		tlen = utf8_get(&result[count], buf, len);
		if (tlen <= 0) {
			return -1;
		}
		len -= tlen;
		buf += tlen;
	}
	if (len > 0) {
		return -1;
	}
	return count;
}
