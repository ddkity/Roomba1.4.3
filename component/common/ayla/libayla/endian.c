
/*
 * Copyright 2011-2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <ayla/utypes.h>
#include <ayla/endian.h>

/*
 * Translation from little endian to big endian.
 */
int get_ua_with_len(const void *src, u8 len, u32 *dest)
{
	switch (len) {
	case 1:
		*dest = *(const u8 *)src;
		break;
	case 2:
		*dest = get_ua_be16(src);
		break;
	case 4:
		*dest = get_ua_be32(src);
		break;
	default:
		return -1;
	}
	return 0;
}

