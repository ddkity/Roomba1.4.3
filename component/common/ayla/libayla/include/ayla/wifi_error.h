/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_WIFI_ERROR_H__
#define __AYLA_WIFI_ERROR_H__

/*
 * Wi-Fi connection error codes.
 * These codes are shared with the mobile Apps, so must not change.
 * See the "Module JSON Interface" document on Google Drive.
 */
PREPACKED_ENUM enum wifi_error {
	WIFI_ERR_NONE = 0,
	WIFI_ERR_MEM = 1,	/* resource problem, possibly temporary */
	WIFI_ERR_TIME = 2,	/* connection timed out */
	WIFI_ERR_INV_KEY = 3,	/* invalid key */
	WIFI_ERR_NOT_FOUND = 4,	/* SSID not found */
	WIFI_ERR_NOT_AUTH = 5,	/* not authenticated */
	WIFI_ERR_WRONG_KEY = 6,	/* incorrect key */
	WIFI_ERR_NO_IP = 7,	/* failed to get IP address from DHCP */
	WIFI_ERR_NO_ROUTE = 8,	/* failed to get default gateway from DHCP */
	WIFI_ERR_NO_DNS = 9,	/* failed to get DNS server from DHCP */
	WIFI_ERR_AP_DISC = 10,	/* AP disconnected the module */
	WIFI_ERR_LOS = 11,	/* Loss of signal / beacon miss */
	WIFI_ERR_CLIENT_DNS = 12, /* ADS not reached due to DNS */
	WIFI_ERR_CLIENT_REDIR = 13, /* failed to reach ADS due to redirect */
	WIFI_ERR_CLIENT_TIME = 14, /* failed to reach ADS - timeout */
	WIFI_ERR_NO_PROF = 15,	/* no empty profile slots */
	WIFI_ERR_SEC_UNSUP = 16, /* security method not supported */
	WIFI_ERR_NET_UNSUP = 17, /* network type (e.g. ad-hoc) not supported */
	WIFI_ERR_PROTOCOL = 18, /* server incompatible.  May be a hotspot. */
	WIFI_ERR_CLIENT_AUTH = 19, /* failed to authenticate to service */
	WIFI_ERR_IN_PROGRESS = 20, /* attempt still in progress */
} PACKED_ENUM;

ASSERT_SIZE(enum, wifi_error, 1);

#define WIFI_ERRORS { \
	[WIFI_ERR_NONE] =	"none", \
	[WIFI_ERR_MEM] =	"resource problem", \
	[WIFI_ERR_TIME] =	"connection timed out", \
	[WIFI_ERR_INV_KEY] =	"invalid key", \
	[WIFI_ERR_NOT_FOUND] =	"SSID not found", \
	[WIFI_ERR_NOT_AUTH] =	"not authenticated", \
	[WIFI_ERR_WRONG_KEY] =	"incorrect key", \
	[WIFI_ERR_NO_IP] =	"failed to get IP address from DHCP", \
	[WIFI_ERR_NO_ROUTE] =	"failed to get default gateway from DHCP", \
	[WIFI_ERR_NO_DNS] =	"failed to get DNS server from DHCP", \
	[WIFI_ERR_AP_DISC] =	"disconnected by AP", \
	[WIFI_ERR_LOS] =	"loss of signal / beacon miss", \
	[WIFI_ERR_CLIENT_DNS] =	"device service host name lookup failed",\
	[WIFI_ERR_CLIENT_REDIR] = "device service GET redirected",\
	[WIFI_ERR_CLIENT_TIME] = "device service connection timed out", \
	[WIFI_ERR_NO_PROF] =	 "no empty profile slots", \
	[WIFI_ERR_SEC_UNSUP] =	 "security method not supported", \
	[WIFI_ERR_NET_UNSUP] =	 "network type not supported", \
	[WIFI_ERR_CLIENT_AUTH] = "failed to authenticate to service", \
	[WIFI_ERR_IN_PROGRESS] = "attempt in progress", \
}
#endif /* __AYLA_WIFI_ERROR_H__ */
