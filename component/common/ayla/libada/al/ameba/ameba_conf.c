/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <ayla/utypes.h>
#include <ayla/conf_token.h>
#include <ayla/log.h>
#include <ayla/tlv.h>
#include <ayla/conf.h>
#include <ayla/nameval.h>
#include <ada/err.h>
#include <ada/ada_conf.h>
#include <ada/ada_lan_conf.h>
#include <ada/server_req.h>
#include <ada/client_ota.h>
#include <ayla/malloc.h>

int adap_conf_oem_key_get(void *buf, size_t len)
{
	if (oem_key_len > len) {
		return -1;
	}
	memcpy(buf, oem_key, oem_key_len);
	return (int)oem_key_len;
}


