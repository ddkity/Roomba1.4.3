/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */
#ifndef __AYLA_DEMO_CONF_WIFI_H__
#define __AYLA_DEMO_CONF_WIFI_H__

/*
 * App name for iOS redirects during Wi-Fi setup in AP mode.
 */
#define OEM_IOS_APP "AylaControl"		/* Ayla Control App */

/*
 * Wi-Fi AP-mode SSID prefix.  Name will have - an MAC address appended.
 */
//#define OEM_AP_SSID_PREFIX "Ayla"
#define OEM_AP_SSID_PREFIX "ILIFE"

void demo_wifi_init(void);

#endif
