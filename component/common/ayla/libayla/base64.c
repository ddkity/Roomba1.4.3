/*
 * Copyright 2014-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <ayla/base64.h>

int ayla_base64_encode(const void *in_buf, size_t inlen,
			void *out, size_t *outlen)
{
	unsigned long i, len2, leven;
	const unsigned char *in = in_buf;
	unsigned char *p;
	static const char *codes =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	/* valid output size ? */
	len2 = 4 * ((inlen + 2) / 3);
	if (*outlen < len2 + 1) {
		return -1;
	}
	p = out;
	leven = 3 * (inlen / 3);
	for (i = 0; i < leven; i += 3) {
		*p++ = codes[(in[0] >> 2) & 0x3F];
		*p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
		*p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
		*p++ = codes[in[2] & 0x3F];
		in += 3;
	}
	/* Pad it if necessary...  */
	if (i < inlen) {
		unsigned a = in[0];
		unsigned b = (i + 1 < inlen) ? in[1] : 0;

		*p++ = codes[(a >> 2) & 0x3F];
		*p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
		*p++ = (i + 1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
		*p++ = '=';
	}

	/* append a NULL byte */
	*p = '\0';

	/* return ok */
	*outlen = p - (unsigned char *)out;
	return 0;
}

static int ayla_base64_dec_char(unsigned char c)
{
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	switch (c) {
	case '+':
		return 62;
	case '/':
		return 63;
	case '=':
		return 64;
	default:
		return -1;
	}
}

int ayla_base64_decode(const void *inv, size_t in_len,
			void *outv, size_t *out_len)
{
	unsigned long i, leven;
	const char *in = (const char *)inv;
	unsigned char *p;
	int val1, val2, val3, val4;

	p = outv;
	leven = 4 * (in_len / 4);
	i = 0;
	while (i < leven) {
		i += 4;
		val1 = ayla_base64_dec_char(in[0]);
		val2 = ayla_base64_dec_char(in[1]);
		val3 = ayla_base64_dec_char(in[2]);
		val4 = ayla_base64_dec_char(in[3]);
		if (val1 < 0 || val1 == 64 || val2 < 0 || val2 == 64 ||
		    val3 < 0 || val4 < 0) {
			return -1;
		}
		*p++ = (val1 << 2) + (val2 >> 4);
		if (val3 == 64) {
			if (val4 != 64) {
				return -1;
			}
			break;
		} else if (val4 == 64) {
			*p++ = ((val2 & 0x0f) << 4) + (val3 >> 2);
			break;
		} else {
			*p++ = ((val2 & 0x0f) << 4) + (val3 >> 2);
			*p++ = ((val3 & 0x03) << 6) + val4;
		}
		in += 4;
	}
	if (i != in_len) {
		return -1;
	}
	*out_len = p - (unsigned char *)outv;
	return 0;
}
