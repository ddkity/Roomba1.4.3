/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __ADW_AMEBA_H__
#define __ADW_AMEBA_H__

rtw_result_t adw_wmi_scan_result_handler(rtw_scan_handler_result_t *result);

void adw_wmi_set_scan_result(const char *ssid, u8 ssid_len, u8 *bssid,
	u8 channel, u8 bss_type, s16 rssi, u32 security);

#endif
