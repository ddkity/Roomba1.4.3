/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ENDIAN_H__
#define __AYLA_ENDIAN_H__

/*
 * Initializer for byte array in big-endian order from a 32-bit value.
 */
#define U32_BYTES(v) \
		(((v) >> 24) & 0xff), \
		(((v) >> 16) & 0xff), \
		(((v) >> 8) & 0xff), \
		((v) & 0xff)

/*
 * include utypes.h first.
 * Assuming little-endian (or unknown) for now.
 */

static inline void put_ua_be32(void *dest, u32 val)
{
	u8 *byte = dest;

	byte[0] = val >> 24;
	byte[1] = val >> 16;
	byte[2] = val >> 8;
	byte[3] = val;
}

static inline void put_ua_be16(void *dest, u16 val)
{
	u8 *byte = dest;

	byte[0] = val >> 8;
	byte[1] = val;
}

static inline u32 get_ua_be32(const void *src)
{
	const u8 *byte = src;

	return ((u32)byte[0] << 24) | ((u32)byte[1] << 16) |
	    ((u32)byte[2] << 8) | byte[3];
}

static inline u16 get_ua_be16(const void *src)
{
	const u8 *byte = src;

	return ((u16)byte[0] << 8) | byte[1];
}

static inline void put_ua_le32(void *dest, u32 val)
{
	u8 *byte = dest;

	byte[3] = val >> 24;
	byte[2] = val >> 16;
	byte[1] = val >> 8;
	byte[0] = val;
}

static inline u16 get_ua_le16(const void *src)
{
	const u8 *byte = src;

	return ((u16)byte[1] << 8) | byte[0];
}

static inline void put_ua_le16(void *dest, u16 val)
{
	u8 *byte = dest;

	byte[1] = val >> 8;
	byte[0] = val;
}

static inline u32 get_ua_le32(const void *src)
{
	const u8 *byte = src;

	return ((u32)byte[3] << 24) | ((u32)byte[2] << 16) |
	    ((u32)byte[1] << 8) | byte[0];
}

static inline le32 cpu_to_le32(u32 val)
{
#ifdef BIG_ENDIAN
	le32 word;
	u8 *byte = (void *)&word;

	byte[0] = val;
	byte[1] = val >> 8;
	byte[2] = val >> 16;
	byte[3] = val >> 24;
	return val;
#else
	return (le32)val;
#endif
}

int get_ua_with_len(const void *src, u8 len, u32 *dest);

#endif /* __AYLA_ENDIAN_H__ */
