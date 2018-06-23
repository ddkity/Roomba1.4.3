/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_JSON_H__
#define __AYLA_JSON_H__

/*
 * Copy string to buffer, generating escapes needed for JSON.
 * strnlen(src, str_max_len) is used to determine len of src.
 * Returns a pointer to the buffer, or NULL on error.
 */
char *json_format_string(char *buf, size_t buf_len,
		const char *src, size_t, u8);

/*
 * Copy arbitrary bytes to buffer, generating escapes needed for JSON.
 * Returns the size of output or -1 on error;
 */
ssize_t json_format_bytes(char *buf, size_t buf_len, const char *src,
	size_t len, u32 *consumed, u8 *buflim_reached, u8);

/*
 * Copy string to buffer, generating escapes needed for JSON.
 * Returns a pointer to the buffer, or NULL on error.
 */
char *json_format_string_with_len(char *buf, size_t buf_len,
	const char *src, size_t len, u8);

#endif /* __AYLA_JSON_H__ */
