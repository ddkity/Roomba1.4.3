/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/tlv.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/clock.h>
#include <ayla/log.h>
#include <ayla/parse.h>
#include <ayla/mod_log.h>
#ifdef AYLA_BC
#include <ayla/gpio.h>
#endif
#include <ada/client.h>
#include <ada/ada_conf.h>

void log_conf_load(void)
{
	enum conf_token tk[4] = {CT_log, CT_mod, 0x0, CT_mask};
	struct ada_conf_item item;
	char buf[30];
	u32 uint;
	int i;

	item.name = buf;
	item.type = ATLV_UINT;
	item.val = &uint;
	item.len = sizeof(uint);

	for (i = LOG_MOD_DEFAULT; i < __MOD_LOG_LIMIT; i++) {
		tk[2] = i;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		if (ada_conf_get_item(&item) > 0)
			log_mods[i].mask = uint;
	}
}

void log_conf_factory_reset(void)
{
	enum conf_token tk[4] = {CT_log, CT_mod, 0x0, CT_mask};
	struct ada_conf_item item;
	char buf[30];
	int i;

	item.name = buf;
	for (i = LOG_MOD_DEFAULT; i < __MOD_LOG_LIMIT; i++) {
		tk[2] = i;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		adap_conf_reset_factory(item.name);
	}
}


