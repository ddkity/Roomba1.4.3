/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_MOD_LOG_H__
#define __AYLA_MOD_LOG_H__

/*
 * Module log numbers.
 * These index the log_mod table.
 * These must not change, since they are stored in flash for crash logs.
 */
PREPACKED_ENUM enum mod_log_id {
	MOD_LOG_MOD = LOG_MOD_DEFAULT,
	MOD_LOG_CLIENT = LOG_MOD_APP_BASE,
	MOD_LOG_CONF,
	MOD_LOG_DNSS,
	MOD_LOG_NETSIM,		/* obsolete but used by service */
	MOD_LOG_NOTIFY,
	MOD_LOG_SERVER,
	MOD_LOG_WIFI,
	MOD_LOG_SSL,
	MOD_LOG_LOGGER,
	MOD_LOG_IO,
	MOD_LOG_SCHED,
	MOD_LOG_ETHERNET,
	MOD_LOG_TEST,
	__MOD_LOG_LIMIT		/* for assert below only, must be last */
} PACKED_ENUM;
ASSERT_SIZE(enum, mod_log_id, 1);
ASSERT_COMPILE(mod_log_ct, (int)__MOD_LOG_LIMIT - 1 <= (int)LOG_MOD_APP_MAX);

#define MOD_LOG_NAMES {				\
	[MOD_LOG_CLIENT] = "client",		\
	[MOD_LOG_CONF] = "conf",		\
	[MOD_LOG_DNSS] = "dnss",		\
	[MOD_LOG_MOD] = "mod",			\
	[MOD_LOG_NETSIM] = "netsim",		\
	[MOD_LOG_NOTIFY] = "notify",		\
	[MOD_LOG_SERVER] = "server",		\
	[MOD_LOG_SSL] = "ssl",			\
	[MOD_LOG_WIFI] = "wifi",		\
	[MOD_LOG_LOGGER] = "log-client",        \
	[MOD_LOG_IO] = "io",			\
	[MOD_LOG_SCHED] = "sched",		\
	[MOD_LOG_ETHERNET] = "eth",		\
	[MOD_LOG_TEST] = "test",		\
}

#endif /* __AYLA_MOD_LOG_H__ */
