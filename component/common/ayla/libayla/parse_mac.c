/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <ayla/utypes.h>
#include <ayla/parse.h>

/*
 * Parse 48-bit MAC address.
 * Address may have colon separators.
 * Reject input of more than 6 bytes, even with leading zeros.
 * The MAC address output buffer is guaranteed unchanged on errors.
 * Handle %3A or %3a as an escape for ':', seen in HTTP posts.
 */
int parse_mac(u8 *mac, const char *arg)
{
	unsigned long long addr;
	unsigned long long byte;
	char *cp;
	char *endptr;
	int i;
	u8 *mp;

	addr = strtoull(arg, &endptr, 16);
	if (endptr > arg + 12) {
		return -1;
	}
	if ((*endptr == ':' || *endptr == '%') && addr <= 0xff) {
		byte = addr;
		for (i = 1; i < 6; i++) {
			cp = endptr + 1;
			if (endptr[0] == '%' && endptr[1] == '3' &&
			    (endptr[2] == 'A' || endptr[2] == 'a')) {
				cp += 2;
			} else if (*endptr != ':') {
				return -1;
			}
			byte = strtoull(cp, &endptr, 16);
			if (byte > 0xff || endptr > cp + 2) {
				return -1;
			}
			addr = (addr << 8) | byte;
		}
	}
	if (*endptr != '\0' || addr > (1ULL << 48)) {
		return -1;
	}
	for (mp = &mac[5]; mp >= mac; mp--) {
		*mp = (u8)addr;
		addr >>= 8;
	}
	return 0;
}

#ifdef TEST_PARSE_MAC

#include <stdio.h>

struct test {
	const char *in;
	int rc;
	u8 mac[6];
};

struct test test_cases[] = {
	{.in = "" },
	{.in = "0" },
	{.in = "-0" },
	{.in = "0123", .mac = { 0, 0, 0, 0, 0x01, 0x23 } },
	{.in = "010203040506", .mac = {1, 2, 3, 4, 5, 6 } },
	{.in = "01:02:03:04:05:06", .mac = {1, 2, 3, 4, 5, 6 } },
	{.in = "01%3A02%3A03%3A04%3A05%3A06", .mac = {1, 2, 3, 4, 5, 6 } },
	{.in = "000080000000", .mac = {0, 0, 0x80, 0, 0, 0 } },
	{.in = "00:00:80:00:00:00", .mac = {0, 0, 0x80, 0, 0, 0 } },
	{.in = "00%3A00%3A80%3A00%3A00%3a00", .mac = {0, 0, 0x80, 0, 0, 0 } },
	{.in = "f10203040506", .mac = {0xf1, 2, 3, 4, 5, 6 } },
	{.in = "ffffffffffff", .mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	{.in = "a1:b2:c3:d4:e5:f6",
	    .mac = {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 } },
	{.in = "A1:B2:C3:D4:E5:F6",
	    .mac = {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 } },
	{.in = "a1:b2:c3:D4:E5:F6",
	    .mac = {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 } },
	{.in = "-1", .rc = -1 },
	{.in = "-aa", .rc = -1 },
	{.in = "0a1:b2:c3:d4:e5:0f6", .rc = -1 },
	{.in = "a1:b2:c3:0d4:e5:f6", .rc = -1 },
	{.in = "a1:b2:c3:d4:e5:0f6", .rc = -1 },
	{.in = "1a1:b2:c3:d4:e5:f6", .rc = -1 },
	{.in = "101:02:03:04:05:06", .rc = -1 },
	{.in = "1a1:b2:c3:d4:e5:f6", .rc = -1 },
	{.in = "1010203040506", .rc = -1 },
	{.in = "0102030405061", .rc = -1 },
	{.in = "100:200:300:04:06", .rc = -1 },
	{.in = "01:02:03:04:05:06:", .rc = -1 },
	{.in = "01:02:03:04:05:106", .rc = -1 },
	{.in = NULL }
};

int main(int argc, char **argv)
{
	struct test *test;
	u8 mac[6];
	int rc;
	char *msg;
	int errs = 0;

	for (test = test_cases; test->in; test++) {
		memset(mac, 0xa5, sizeof(mac));
		rc = parse_mac(mac, test->in);
		if (rc != test->rc) {
			msg = "FAIL";
			errs++;
		} else if (rc == 0 && memcmp(mac, test->mac, 6)) {
			msg = "FAIL";
			errs++;
		} else {
			msg = "pass";
			continue;	/* don't print passing cases */
		}
		if (rc) {
			printf("%s: test %s rc %d\n", msg, test->in, rc);
		} else {
			printf("%s: test %s "
			    "mac %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
			    msg, test->in,
			    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		}
	}
	printf("errs %d\n", errs);
	return errs != 0;
}
#endif /* TEST_PARSE_ARGV */
