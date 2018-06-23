/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <jsmn.h>
#include <ayla/jsmn_get.h>

/*
 * Get value object inside parent object for a given name out of the parser.
 */
jsmntok_t *jsmn_get_val(jsmn_parser *parser,
	jsmntok_t *parent, const char *name)
{
	jsmntok_t *tok;
	jsmntok_t *obj = NULL;
	jsmntok_t *obj_name = NULL;
	int name_len;
	int next_start;

	if (parent) {
		obj = parent;
	} else {
		obj = parser->tokens;
	}
	if (obj->type != JSMN_OBJECT) {
		return NULL;
	}
	next_start = obj->start;

	name_len = strlen(name);
	for (tok = obj + 1; tok < parser->tokens + parser->num_tokens; tok++) {
		if (tok->start > obj->end) {
			break;
		}
		if (tok->start < next_start) {
			continue;
		}

		/*
		 * If no name yet, this must be the name.
		 */
		if (!obj_name) {
			if (tok->type != JSMN_STRING ||
			    tok->start < obj->start || tok->end > obj->end) {
				return NULL;
			}
			obj_name = tok;
			continue;
		}

		/*
		 * At an object value.  Check name.
		 */
		if (obj_name->end - obj_name->start == name_len &&
		    !memcmp(name, parser->js + obj_name->start, name_len) &&
		    tok->start >= obj->start && tok->end <= obj->end) {
			return tok;
		}

		/*
		 * If value is an object, skip past it.
		 */
		if (tok->type == JSMN_OBJECT) {
			next_start = tok->end;
		}
		obj_name = NULL;
	}
	return NULL;
}

/*
 * Get an unsigned long integer value object from the JSMN parser.
 * Returns 0 on success.
 */
int jsmn_parse_ulong(jsmn_parser *parser, jsmntok_t *obj, unsigned long *valp)
{
	unsigned long val;
	char *errptr;

	if (!obj || obj->type != JSMN_PRIMITIVE) {
		return -1;
	}
	val = strtoul(parser->js + obj->start, &errptr, 10);
	if (errptr < parser->js + obj->end) {
		return -1;
	}
	*valp = val;
	return 0;
}

/*
 * Get an unsigned long integer value object from the JSMN parser.
 * Returns 0 on success.
 */
int jsmn_get_ulong(jsmn_parser *parser, jsmntok_t *parent,
	const char *name, unsigned long *valp)
{
	return jsmn_parse_ulong(parser,
	    jsmn_get_val(parser, parent, name), valp);
}

/*
 * Parse an integer value object from the JSMN parser.
 * Returns 0 on success.
 */
int jsmn_parse_long(jsmn_parser *parser, jsmntok_t *obj, long *valp)
{
	long val;
	char *errptr;

	if (!obj || obj->type != JSMN_PRIMITIVE) {
		return -1;
	}
	val = strtol(parser->js + obj->start, &errptr, 10);
	if (errptr < parser->js + obj->end) {
		return -1;
	}
	*valp = val;
	return 0;
}

/*
 * Get an integer value object from the JSMN parser.
 * Returns 0 on success.
 */
int jsmn_get_long(jsmn_parser *parser, jsmntok_t *parent,
	const char *name, long *valp)
{
	return jsmn_parse_long(parser,
	    jsmn_get_val(parser, parent, name), valp);
}

/*
 * Get a string value object from the JSMN parser.
 * For now, this also accepts primitives which may have an
 * integer, "true", "false", or "null" as the value.
 */
ssize_t jsmn_get_string_ptr(jsmn_parser *parser, jsmntok_t *parent,
    const char *name, char **buf)
{
	jsmntok_t *obj;
	ssize_t rc;

	obj = jsmn_get_val(parser, parent, name);
	if (!obj) {
		return -1;
	}
	if (obj->type == JSMN_STRING || obj->type == JSMN_PRIMITIVE) {
		rc = obj->end - obj->start;
	} else {
		return -1;
	}
	*buf = (char *)(parser->js + obj->start);
	return rc;
}

ssize_t jsmn_get_string(jsmn_parser *parser, jsmntok_t *parent,
	const char *name, char *buf, size_t len)
{
	char *ptr;
	ssize_t rc;

	rc = jsmn_get_string_ptr(parser, parent, name, &ptr);
	if (rc < 0 || rc >= len) {
		return -1;
	}
	memcpy(buf, ptr, rc);
	buf[rc] = '\0';
	return rc;
}

int jsmn_parse_bool(jsmn_parser *parser, jsmntok_t *obj, unsigned char *vp)
{
	char *str;
	unsigned long uv;
	const char true[] = "true";
	const char false[] = "false";
	size_t len;

	if (!obj || obj->type != JSMN_PRIMITIVE) {
		return -1;
	}
	str = parser->js + obj->start;
	len = obj->end - obj->start;
	if ((len == sizeof(false) - 1) &&
	    !strncmp(str, false, (sizeof(false) - 1))) {
		uv = 0;
	} else if ((len == sizeof(true) - 1) &&
	    !strncmp(str, true, (sizeof(true) - 1))) {
		uv = 1;
	} else if (jsmn_parse_ulong(parser, obj, &uv) || uv > 1) {
		return -1;
	}
	*vp = (unsigned char)uv;
	return 0;
}

int jsmn_get_bool(jsmn_parser *parser, jsmntok_t *parent, const char *name,
		unsigned char *vp)
{
	return jsmn_parse_bool(parser, jsmn_get_val(parser, parent, name), vp);
}
