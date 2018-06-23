/*
 * Copyright 2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_UTF8_H__
#define __AYLA_UTF8_H__

#define MAX_UTF8	0x10ffff	/* max UTF-8 code point per RFC3629 */

/*
 * Decode a UTF-8 byte string, placing result in *resultp.
 * The input string starts at src and is len bytes long.
 * Returns the number of bytes used, or -1 on invalid UTF-8 code.
 */
ssize_t utf8_decode(const unsigned char *src, size_t len, u32 *resultp);

ssize_t utf8_encode(unsigned char *src, size_t len, u32 code);

/*
 * Get next UTF-8 token from a buffer.
 * Returns length, or zero if invalid UTF-8 code encountered.
 */
size_t utf8_get(u32 *result, u8 *buf, size_t len);

/*
 * Get multiple UTF-8 wide characters from a buffer.
 * Returns the number of characters put in result, or -1 on error.
 */
int utf8_gets(u32 *result, int rcount, u8 *buf, size_t len);

#endif /* __AYLA_UTF8_H__ */
