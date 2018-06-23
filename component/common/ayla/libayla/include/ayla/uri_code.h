/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_URI_CODE_H__
#define __AYLA_URI_CODE_H__

/*
 * URI encoding / decoding.
 * See RFC 3986.
 *
 * The 256 byte values are in these categories:
 *	32 control chars: 0x00 - 0x1f
 *	18 always reserved: ! * ' ( ) ; : @ = + $ , / ? # [ ]
 *	66 unreserved: alpha / digit / "-" / "." / "_" / "~".
 *	12 sometimes reserved: SP " % < > / ^ \ { | } DEL
 *	128 non-ASCII: 0x80 - 0xff.
 */

/*
 * Bitmap for allowed characters in an URI argument
 * (after the ?, / or ? is OK).
 */
extern const u32 uri_arg_allowed_map[256 / 32];	/* unreserved chars plus some */

ssize_t uri_encode(char *dest, size_t dest_len,
		 const char *src, size_t src_len, const u32 *allowed_map);

ssize_t uri_decode(char *dest, size_t dest_len, const char *src);
ssize_t uri_decode_n(char *dest, size_t dest_len, const char *src, size_t slen);

#endif /* __AYLA_URI_CODE_H__ */
