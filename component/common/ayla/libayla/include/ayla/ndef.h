/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_NDEF_H__
#define __AYLA_NDEF_H__

struct wifi_ssid {
	u8 len;
	u8 id[32];
};

#define WIFI_MAX_KEY_LEN 64

enum ndef_err {
	NDEF_ERR_NONE,
	NDEF_ERR_INCOMPLETE,
	NDEF_ERR_MEM = -1,
	NDEF_ERR_BAD_HDR_FLAGS = -2,
	NDEF_ERR_CHUNK_LEN_SET = -3,
	NDEF_ERR_UNSUPPORTED_TNF = -4,
	NDEF_ERR_UNSUPPORTED_MIME = -5,
	NDEF_ERR_INCOMPLETE_REC = -6,
	NDEF_ERR_BAD_WIFI_TLV_LEN = -7,
	NDEF_ERR_BAD_WIFI_SSID_LEN = -8,
	NDEF_ERR_BAD_WIFI_KEY_LEN = -9,
};

struct wifi_conn_info {
	struct wifi_ssid ssid;
	u8 key[WIFI_MAX_KEY_LEN];
	u8 key_len;
};

void ndef_parse_init(void);
void ndef_parse_deinit(void);
enum ndef_err ndef_parse_record(u8 *buf, size_t length);
struct wifi_conn_info *ndef_get_wifi_info(void);

#endif /* __AYLA_NDEF_H_ */
