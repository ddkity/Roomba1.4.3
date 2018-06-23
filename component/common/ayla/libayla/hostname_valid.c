/*
 * Copyright 2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <ctype.h>
#include <ayla/utypes.h>
#include <ayla/parse.h>

/*
 * Return non-zero if the string contains only valid DNS host characters.
 * Empty strings also return non-zero values.
 */
int hostname_valid(char *src)
{
	int c;

	if (*src == '-') {
		return 0;
	}
	while ((c = (unsigned)*src++) != '\0') {
		if (!isalnum(c) && c != '-') {
			return 0;
		}
	}
	return 1;
}
