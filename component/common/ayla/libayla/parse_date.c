/*
 * Copyright 2016 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/parse.h>
#include <ayla/clock.h>

/*
 * Parse the HTTP Date header from individual arguments.
 * The Date header is specified by IETF RFC 7231 section 7.1.1.1.
 * The day of the week is not verified.
 * Returns 0 on success.
 *
 * 0123456789 123456789 12345678
 * Sun, 06 Nov 1994 08:49:37 GMT
 * arg0 1  2   3    4        5
 */
int parse_http_date(u32 *timep, int argc, char **argv)
{
	char *errptr;
	unsigned long day;
	unsigned long month;
	unsigned long year;
	unsigned long hms[3];	/* integers, h, m, s */
	static const char *months[] = {
	    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
	    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	const char *in;
	int i;

	*timep = 0;
	if (argc != 6 || strcmp(argv[5], "GMT")) {
		return -1;
	}
	if (strlen(argv[0]) != 4 || argv[0][3] != ',') {
		return -1;
	}

	/*
	 * Parse day of month.
	 * Note that the numeric range checks are done in parse_date_calc(),
	 * so don't replicate them here.
	 */
	day = strtoul(argv[1], &errptr, 10);
	if (*errptr != '\0') {
		return -1;
	}

	/*
	 * Parse month.
	 */
	for (month = 1; month < 13; month++) {
		if (!strcmp(argv[2], months[month - 1])) {
			break;
		}
	}

	/*
	 * Parse year.
	 */
	year = strtoul(argv[3], &errptr, 10);
	if (*errptr != '\0') {
		return -1;
	}

	/*
	 * Parse hour, minute, and second
	 * Range checks are done in parse_date_calc().
	 */
	in = argv[4];
	for (i = 0; i < 3; i++) {
		hms[i] = strtoul(in + 3 * i, &errptr, 10);
		if (errptr != in + 3 * i + 2) {
			return -1;
		}
		if (i < 2 && *errptr != ':') {
			return -1;
		}
	}
	if (*errptr) {
		return -1;
	}
	return clock_ints_to_time(timep, year, month, day,
	    hms[0], hms[1], hms[2]);
}
