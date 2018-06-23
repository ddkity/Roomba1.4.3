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
 * Iterate over array object.
 * Call the specified function for each object that is a member of the
 * specified object, which is an array.
 */
int jsmn_array_iterate(jsmn_parser *parser, jsmntok_t *obj,
	int (*func)(jsmn_parser *, jsmntok_t *, void *), void *arg)
{
	jsmntok_t *tok;
	int next_start;
	int rc;

	if (obj->type != JSMN_ARRAY) {
		return -1;
	}
	next_start = obj->start;
	for (tok = obj + 1; tok < parser->tokens + parser->num_tokens; tok++) {
#ifdef JSMN_DEBUG
		log_put(LOG_DEBUG "jsmn_array_iterate: "
		    "token type %d %d-%d obj %p obj_name %p",
		    tok->type, tok->start, tok->end, obj, obj_name);
#endif /* JSMN_DEBUG */
		if (tok->end > obj->end) {
			break;
		}
		if (tok->start < next_start) {
			continue;
		}
		rc = func(parser, tok, arg);
		if (rc) {
			return rc;
		}
		next_start = tok->end;
	}
	return 0;
}
