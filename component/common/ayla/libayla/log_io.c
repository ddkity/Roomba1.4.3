/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>	/* for snprintf */

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/parse.h>

static void log_bytes_va(u8 mod, enum log_sev sev, const void *buf, size_t len,
			const char *fmt, va_list args)
{
	size_t rem = len;
	size_t chunk;
	const char *bp = buf;
	char msg[40];
	char tmpbuf[48 + 1];

	if (!log_mod_sev_is_enabled(mod, sev)) {
		return;
	}

	vsnprintf(msg, sizeof(msg), fmt, args);

	for (bp = buf, rem = len; rem; bp += chunk, rem -= chunk) {
		chunk = rem;
		if (chunk > sizeof(tmpbuf) - 1) {
			chunk = sizeof(tmpbuf) - 1;
		}
		log_put_mod_sev(mod, sev, "%s %u \"%s\"",
		    msg, (unsigned int)len,
		    format_string(tmpbuf, sizeof(tmpbuf), bp, chunk));
	}
}

void log_bytes(u8 mod, enum log_sev sev,
		const void *buf, size_t len, const char *fmt, ...)
{
	ADA_VA_LIST args;

	ADA_VA_START(args, fmt);
	log_bytes_va(mod, sev, buf, len, fmt, args);
	ADA_VA_END(args);
}

void log_io(const void *buf, size_t len, const char *fmt, ...)
{
	ADA_VA_LIST args;

	ADA_VA_START(args, fmt);
	log_bytes_va(MOD_LOG_IO, LOG_SEV_DEBUG, buf, len, fmt, args);
	ADA_VA_END(args);
}
