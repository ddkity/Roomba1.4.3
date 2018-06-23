/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
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
#include <ayla/json.h>
#include <ayla/utf8.h>

/*
 * Sets the ptr to val if ptr is not null
 */
static void json_set_if_not_null(u8 *ptr, u8 val)
{
	if (ptr) {
		*ptr = val;
	}
}

/*
 * JSON-escape a byte if necessary, and store it in the specified buffer.
 * The number of bytes that have been placed inside the destination is
 * returned.
 * The buf_len is decremented by the number of characters inserted.
 * Returns -1 if the buffer is not large enough to receive the escaped char.
 * Returns -2 if the character is invalid UTF-8.
 */
static ssize_t json_put_byte(char **dest, size_t *buf_len, unsigned char c,
		u8 *buflim_reached, u8 allow_unicode_escapes)
{
	ssize_t len = 0;
	ssize_t used;

	if (*dest && *buf_len <= 0) {
		json_set_if_not_null(buflim_reached, 1);
		return 0;
	}
	if (c < 0x20 || c == '\\' || c == '"' || c >= 0x80) {
		switch (c) {
		/*
		 * The Ayla service does not support \b or \f in string
		 * properties, so we don't support them here, either.
		 */
		case '\n':
			c = 'n';
			goto esc;
		case '\r':
			c = 'r';
			goto esc;
		case '\t':
			c = 't';
			goto esc;
		case '\\':
		case '"':
esc:
			len += 2;
			if (*dest == NULL) {
				break;
			}
			if (*buf_len < 2) {
				json_set_if_not_null(buflim_reached, 1);
				return 0;
			}
			(*buf_len) -= 2;
			**dest = '\\';
			(*dest)++;
			**dest = c;
			(*dest)++;
			break;
		default:
			if (!allow_unicode_escapes) {
				/* bad utf8 encoded strings are not accepted */
				return -2;
			}
			len += 6;
			if (*dest == NULL) {
				break;
			}
			if (*buf_len < 6) {
				json_set_if_not_null(buflim_reached, 1);
				return 0;
			}
			used = snprintf(*dest, *buf_len, "\\u%4.4x", c);
			(*buf_len) -= used;
			(*dest) += used;
			break;
		}
	} else if (*dest) {
		(*buf_len)--;
		**dest = c;
		(*dest)++;
		len++;
	} else {
		len++;
	}
	return len;
}

/*
 * Copy arbitrary bytes to buffer, generating escapes needed for JSON.
 * Returns the size of output or -1 on error;
 */
ssize_t json_format_bytes(char *buf, size_t buf_len, const char *src,
		size_t len, u32 *consumed, u8 *buflim_reached,
		u8 allow_unicode_escapes)
{
	char *dest = buf;
	u32 code;
	ssize_t code_len = 0;
	ssize_t outlen = 0;
	ssize_t put_len = 0;

	if (consumed) {
		*consumed = 0;
	}
	json_set_if_not_null(buflim_reached, 0);
	while (len && (!buf || buf_len)) {
		code_len = utf8_decode((const u8 *)src, len, &code);
		if (code_len <= 1) {
			code_len = 1;
			put_len = json_put_byte(&dest, &buf_len, (u32)*src,
			    buflim_reached, allow_unicode_escapes);
			if (put_len < 0) {
				return put_len;
			}
			if (buflim_reached && *buflim_reached) {
				break;
			}
			outlen += put_len;
		} else if (buf && buf_len < code_len) {
			json_set_if_not_null(buflim_reached, 1);
			break;
		} else if (buf) {
			/* escapes not needed for valid UTF-8 >= 0x80 */
			memcpy(dest, src, code_len);
			dest += code_len;
			buf_len -= code_len;
			outlen += code_len;
		} else {
			outlen += code_len;
		}
		len -= code_len;
		src += code_len;
		if (consumed) {
			(*consumed) += code_len;
		}
	}
	if (buf) {
		if (buf_len && dest) {
			*dest = '\0';
		} else {
			json_set_if_not_null(buflim_reached, 1);
		}
	}
	return outlen;
}

/*
 * Copy string to buffer, generating escapes needed for JSON.
 * Returns a pointer to the buffer, or NULL on error.
 */
char *json_format_string_with_len(char *buf, size_t buf_len,
	const char *src, size_t len, u8 allow_unicode_escapes)
{
	if (buf) {
		if (!buf_len) {
			return buf;
		}
		buf[buf_len - 1] = '\0';
	}
	if (json_format_bytes(buf, buf_len - 1,
	    src, len, NULL, NULL, allow_unicode_escapes) < 0) {
		return NULL;
	}
	return buf;
}

/*
 * Copy string to buffer, generating escapes needed for JSON.
 * strnlen(src, str_max_len) is used to determine len of src.
 * Returns a pointer to the buffer, or NULL on error.
 */
char *json_format_string(char *buf, size_t buf_len,
	const char *src, size_t str_max_len, u8 allow_unicode_escapes)
{
	return json_format_string_with_len(buf, buf_len, src,
	    strnlen(src, str_max_len), allow_unicode_escapes);
}
