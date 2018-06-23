/*
 * Copyright 2016 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ADA_WIFI_H__
#define __AYLA_ADA_WIFI_H__

/*
 * Wi-Fi features from platform.
 */
enum ada_wifi_features {
	AWF_SIMUL_AP_STA = BIT(0),
	AWF_WPS = BIT(1),
	AWF_WPS_APREG = BIT(2),
};

/*
 * Get platform Wi-Fi features.
 */
enum ada_wifi_features adap_wifi_features_get(void);

/*
 * Indicate if AP mode is active.
 */
int adap_wifi_in_ap_mode(void);

/*
 * Get platform SSID into the provided buffer.
 * The size of the buffer is given.
 * Returns length of SSID or -1 or 0 if not connected to a wireless network.
 */
int adap_wifi_get_ssid(void *buf, size_t len);

/*
 * Indicates to platform that the AP mode should stay up a while longer.
 */
void adap_wifi_stayup(void);

/*
 * Show wifi connection history on console or to log if possible.
 */
void adap_wifi_show_hist(int to_log);

#endif /* __AYLA_ADA_WIFI_H__ */
