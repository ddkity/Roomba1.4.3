/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_NET_BASE64_H__
#define __AYLA_NET_BASE64_H__

#include <mbedtls/base64.h>

static inline int net_base64_decode(const void *in, size_t in_len,
					void *out, size_t *out_len)
{
	int ret;
	ret = mbedtls_base64_decode((unsigned char *)out, *out_len,
		out_len, (const unsigned char *)in, in_len);
	return ret;
}

static inline int net_base64_encode(const void *in, size_t in_len,
					void *out, size_t *out_len)
{
	int ret;
	ret = mbedtls_base64_encode((unsigned char *)out, *out_len,
		out_len, (const unsigned char *)in, in_len);
	if (ret == 0)
		((unsigned char *)out)[*out_len] = 0;
	return ret;
}

#endif /* __AYLA_NET_BASE64_H__ */
