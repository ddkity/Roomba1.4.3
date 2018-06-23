/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_JSMN_GET_H__
#define __AYLA_JSMN_GET_H__

/*
 * Get value object for a given name under a parent object from the parser.
 */
jsmntok_t *jsmn_get_val(jsmn_parser *, jsmntok_t *parent, const char *name);

/*
 * Parse a unsigned long integer token.
 * Returns 0 on success.
 */
int jsmn_parse_ulong(jsmn_parser *, jsmntok_t *, unsigned long *valp);

/*
 * Parse a unsigned long integer token.
 * Returns 0 on success.
 */
int jsmn_parse_long(jsmn_parser *, jsmntok_t *, long *valp);

/*
 * Parse a boolean token.
 * Returns 0 on success.
 */
int jsmn_parse_bool(jsmn_parser *, jsmntok_t *, unsigned char *valp);

/*
 * Get an unsigned long integer value object from the JSMN parser.
 * Returns 0 on success.
 */
int jsmn_get_ulong(jsmn_parser *, jsmntok_t *parent,
	 const char *name, unsigned long *valp);

/*
 * Get an integer value object from the JSMN parser.
 * Returns 0 on success.
 */
int jsmn_get_long(jsmn_parser *parser, jsmntok_t *parent,
	const char *name, long *valp);

/*
 * Get an boolean value object from the JSMN parser.
 * Returns 0 on success.
 */
int jsmn_get_bool(jsmn_parser *, jsmntok_t *parent, const char *name,
			unsigned char *valp);

/*
 * Get a string value object from the JSMN parse results.
 * Returns 0 on success.
 */
ssize_t jsmn_get_string(jsmn_parser *parser, jsmntok_t *parent,
	const char *name, char *buf, size_t len);

/*
 * Get a pointer to beginning of string object from JSMN parse results.
 * Returns length of string on success, < 0 on error.
 */
ssize_t jsmn_get_string_ptr(jsmn_parser *parser, jsmntok_t *parent,
    const char *name, char **buf);

/*
 * Iterate over array object.
 * Call the specified function for each object that is a member of the
 * specified object, which is an array.
 */
int jsmn_array_iterate(jsmn_parser *, jsmntok_t *obj,
	int (*func)(jsmn_parser *, jsmntok_t *, void *), void *arg);

#endif /* __AYLA_JSMN_GET_H__ */
