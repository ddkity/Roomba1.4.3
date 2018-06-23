/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <stdint.h>
#include "wifi_constants.h"
#include "wifi_structures.h"
#include <wifi/wifi_conf.h>
#include "wifi_ameba.h"

rtw_result_t adw_wmi_scan_result_handler(rtw_scan_handler_result_t *result)
{
	u8 bss_type;
	u32 security;

	if (result->scan_complete) {
		adw_wmi_set_scan_result(NULL, 0, NULL, 0, 0, 0, 0);
	} else {

		rtw_scan_result_t *record = &result->ap_details;
		/* Ensure the SSID is null terminated */
		record->SSID.val[record->SSID.len] = 0;

		if (record->security > RTW_SECURITY_OPEN &&
		    record->security < RTW_SECURITY_WPS_OPEN) {
			security = record->security;
		} else {
			security = RTW_SECURITY_OPEN;
		}

		if (record->bss_type == RTW_BSS_TYPE_ADHOC) {
			bss_type = 2; /*BT_AD_HOC*/
		} else {
			bss_type = 1; /*BT_INFRASTRUCTURE*/
		}

		adw_wmi_set_scan_result(record->SSID.val, record->SSID.len,
		    record->BSSID.octet, record->channel, bss_type,
		    record->signal_strength, security);
	}
	return RTW_SUCCESS;
}
