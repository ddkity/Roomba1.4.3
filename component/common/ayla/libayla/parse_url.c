/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/*
 * Parse http://myhost/mypath.html into components.
 */
void parse_url(char *name, char **access, char **host, char **path)
{
	char *p;
	char *after_access = name;

	access[0] = '\0';
	host[0] = '\0';
	path[0] = '\0';

	p = strchr(name, ' ');
	if (p != NULL) {
		*p++ = '\0';
	}

	for (p = name; *p; p++) {
		/*
		 * Look for whitespaces. This is very bad for pipelining as it
		 * makes the request invalid
		 */
		if (isspace((int)*p)) {
			char *orig = p, *dest = p + 1;

			while ((*orig++ = *dest++)) {
				;
			}
			p = p - 1;
		}
		if (*p == '/' || *p == '#' || *p == '?') {
			break;
		}
		if (*p == ':') {
			*p = '\0';
			*access = after_access; /* Scheme has been specified */

			after_access = p + 1;

			if (!strcasecmp("URL", *access)) {
				/* Ignore IETF's URL: pre-prefix */
				*access = NULL;
			} else {
				break;
			}
		}
	}

	p = after_access;
	if (*p == '/' && p[1] == '/') {
		*host = p + 2;	/* host has been specified */
		*p = '\0';	/* Terminate access */

		/* look for end of host name if any */
		p = strchr(*host, '/');
		if (p) {
			*p = '\0';	/* Terminate host */
			/* Root has been found */
			*path = p + 1;
		}
	}
}

