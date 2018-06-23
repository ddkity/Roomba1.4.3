/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ayla/xml.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/tlv.h>

#include <ada/err.h>
#include <ada/ada_wifi.h>

#ifndef AYLA_WIFI_SUPPORT
int adap_wifi_in_ap_mode(void)
{
	return 0;
}

int adap_wifi_get_ssid(void *buf, size_t len)
{
	return -1;
}

int adap_net_get_signal(int *signal)
{
	return -1;
}

enum ada_wifi_features adap_wifi_features_get(void)
{
	enum ada_wifi_features features = 0;
	return features;
}

void adap_wifi_stayup(void)
{
}

#endif
