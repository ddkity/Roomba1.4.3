/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifdef WMSDK
#include <wmtime.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ayla/clock.h>

/*
 * convert time to RFC 3339 / ISO 8601 "YYYY-MM-DDThh:mm:ss" format
 */
void clock_fmt(char *buf, size_t len, u32 time)
{
	struct clock_info clk;

	clock_fill_details(&clk, time);
	snprintf(buf, len, "%4.4lu-%2.2u-%2.2uT%2.2u:%2.2u:%2.2u",
	    clk.year, clk.month, clk.days, clk.hour, clk.min, clk.sec);
}

/*
 * convert time from RFC 3339 (subset) to seconds since 1970.
 * UTC time is read from string like "YYYY-MM-DDThh:mm:ss"
 * Returns 0 on error.
 */
u32 clock_parse(const char *in)
{
	char *errptr;
	u32 t;
	unsigned int i;
	unsigned long year, month, day, hour, min, sec;
	int is_leap;
	static u8 mdays[] = {
		31, 28, 31, 30, 31, 30,
		31, 31, 30, 31, 30, 31
	};

	year = strtoul(in, &errptr, 10);
	if (errptr[0] != '-' || errptr != in + 4 || year < CLOCK_EPOCH) {
		return 0;
	}

	month = strtoul(errptr + 1, &errptr, 10);
	if (errptr[0] != '-' || errptr != in + 7 || month < 1 || month > 12) {
		return 0;
	}

	day = strtoul(errptr + 1, &errptr, 10);
	if (errptr[0] != 'T' || errptr != in + 10 || day < 1) {
		return 0;
	}

	hour = strtoul(errptr + 1, &errptr, 10);
	if (errptr[0] != ':' || errptr != in + 13 || hour >= 24) {
		return 0;
	}

	min = strtoul(errptr + 1, &errptr, 10);
	if (errptr[0] != ':' || errptr != in + 16 || min >= 60) {
		return 0;
	}

	sec = strtoul(errptr + 1, &errptr, 10);
	if (errptr[0] || errptr != in + 19 || sec >= 60) {
		return 0;
	}

	t = year - CLOCK_EPOCH;
	t = t * 365;

	/*
	 * Add leap days.  This calculation is deceptively delicate.
	 * The EPOCH, 1970, was not a leap year
	 * This assumes the intervening century years were, but only 2000 was.
	 * The leap day for the year itself will be added later for months
	 * after Februrary.
	 * For 1973 thru 1976, add 1 leap day, etc.
	 * Add the number of leap days before the current year,
	 * and subtract the number of leap days before the epoch year.
	 */
	t += (year - 1) / 4 - (CLOCK_EPOCH - 1) / 4;

	is_leap = clock_is_leap(year);
	if (is_leap && month > 2) {
		t++;
	}
	for (i = 1; i < month; i++) {
		t += mdays[i - 1];
	}
	if (day > ((month == 2 && is_leap) ? 29 : mdays[month - 1])) {
		return 0;
	}
	t += day - 1;
	t *= 24;
	t += hour;
	t *= 60;
	t += min;
	t *= 60;
	t += sec;
	return t;
}
