/*
 * Copyright 2011-2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>

#ifdef AYLA_BC
#include <lwip/dhcp.h>
#endif

#include <ayla/utypes.h>
#include <ayla/endian.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/log.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <net/net.h>
#include <net/ipaddr_fmt.h>
#include <ayla/tlv.h>
#include <ayla/parse.h>
#include <ayla/clock.h>
#include <ayla/wifi_error.h>
#include <net/cm.h>
#include <ayla/mod_log.h>
#include <adw/wifi.h>
#include <ada/ada_conf.h>
#include <adw/wifi_conf.h>
#include "wifi_int.h"
#ifdef AIRKISS
#include <ayla/parse.h>
#include "wifi_airkiss.h"
#endif

static u8 mfg_profile;
static u8 adw_wifi_scan_snapshot;

void adw_conf_load(void)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;
	struct ada_conf_item item;
	enum conf_token tk[4] = {CT_wifi, CT_profile, 0x0, CT_ssid};
	char buf[30];
	char utf8[WIFI_MAX_KEY_LEN];
	u32 uint;
	int i;

	/*
	 * Try to get SSID first, if non-NULL then proceed
	 * to get the other tokens from flash
	 */
	for (i = 0; i < ADW_WIFI_PROF_CT; i++) {
		prof = &wifi->profile[i];
		tk[2] = i;
		tk[3] = CT_ssid;

		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		memset(utf8, 0x0, sizeof(utf8));
		item.name = buf;
		item.type = ATLV_UTF8;
		item.val = utf8;
		item.len = sizeof(utf8);

		ada_conf_get_item(&item);

		if (!utf8[0]) {
			/*
			 * profile not present
			 */
			continue;
		}
		prof->ssid.len = strlen(utf8);
		memcpy(prof->ssid.id, utf8, prof->ssid.len);

		/*
		 * Get the key
		 */
		tk[3] = CT_key;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		memset(utf8, 0x0, sizeof(utf8));
		item.type = ATLV_BIN;

		ada_conf_get_item(&item);
		prof->key_len = strlen(utf8);
		memcpy(prof->key, utf8, prof->key_len);

		/*
		 * Get the security
		 */
		tk[3] = CT_security;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		uint = 0;
		item.type = ATLV_UINT;
		item.val = &uint;
		item.len = sizeof(uint);

		ada_conf_get_item(&item);
		prof->sec = uint;

		/*
		 * Get enable/hidden
		 */
		tk[3] = CT_enable;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		uint = 0;

		ada_conf_get_item(&item);
		if (uint & ~0x1) {
			/*
			 * enable is a bit flag
			 */
			continue;
		}
		prof->enable = uint;

		tk[3] = CT_hidden;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		uint = 0;

		ada_conf_get_item(&item);
		if (uint & ~0x1) {
			/*
			 * hidden is a bit flag
			 */
			continue;
		}
		prof->hidden = uint;
		if (prof->hidden) {
			prof->spec_scan_done = 1;
		}
	}

#ifdef AYLA_WMSDK_SUPPORT
	tk[1] = CT_ap_mode;
	tk[2] = CT_chan;
	conf_tokens_to_str(tk, 3, buf, sizeof(buf));

	item.name = buf;
	item.type = ATLV_UINT;
	item.val = &wifi->ap_mode_chan;
	item.len = sizeof(wifi->ap_mode_chan);

	ada_conf_get_item(&item);
#endif
}

void adw_conf_factory_reset(void)
{
	struct ada_conf_item item;
	enum conf_token tk[4] = {CT_wifi, CT_profile, 0x0, CT_ssid};
	char buf[30];
	int i;

	/*
	 * Try to get SSID first, if non-NULL then proceed
	 * to get the other tokens from flash
	 */
	for (i = 0; i < ADW_WIFI_PROF_CT; i++) {
		tk[2] = i;
		tk[3] = CT_ssid;

		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		item.name = buf;
		adap_conf_reset_factory(item.name);

		tk[3] = CT_key;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		adap_conf_reset_factory(item.name);

		tk[3] = CT_security;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		adap_conf_reset_factory(item.name);

		tk[3] = CT_enable;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		adap_conf_reset_factory(item.name);

		tk[3] = CT_hidden;
		conf_tokens_to_str(tk, sizeof(tk), buf, sizeof(buf));
		adap_conf_reset_factory(item.name);
	}
}

static void adw_profile_delete(enum conf_token tk)
{
#ifdef WMSDK
	conf_cd_table(tk);
	conf_delete(CT_ssid);
	conf_delete(CT_key);
	conf_delete(CT_security);
	conf_delete(CT_enable);
	conf_delete(CT_hidden);
	conf_cd_parent();
#else
	conf_delete(tk);
#endif
}

#ifdef AYLA_WMSDK_SUPPORT
static void adw_wifi_export_ap_chan(void *arg)
{
	struct adw_state *wifi = arg;

	conf_cd(CT_ap_mode);
	conf_factory_start();
	conf_put_u32_nz(CT_chan, wifi->ap_mode_chan);
	conf_factory_stop();
	conf_cd_parent();
}

void adw_wifi_persist_ap_chan(void)
{
	conf_persist(CT_wifi, adw_wifi_export_ap_chan, &adw_state);
}
#endif /* AYLA_WMSDK_SUPPORT */

static void adw_wifi_export(void)
{
	struct adw_state *wifi = &adw_state;

	adw_lock();

	if (wifi->send_ant) {
		conf_put_u32(CT_ant, wifi->ant);
	}
	if (wifi->tx_power) {
		conf_put_u32(CT_power, wifi->tx_power);
	} else {
		conf_delete(CT_power);
	}
	conf_put(CT_mac_addr, ATLV_BIN, &wifi->mac, sizeof(wifi->mac));
	conf_put_u32(CT_enable, wifi->enable);	/* new location */
	conf_put_str(CT_setup_ios_app, adw_wifi_ios_app);
#ifdef AIRKISS
	conf_cd(CT_setup_mode);
	conf_put_u32(CT_enable, wifi->setup_mode);
	conf_put(CT_key, ATLV_BIN, (char *)wifi->aes_key, AKS_AES_KEY_LEN);
	conf_cd_parent();
#endif
#ifdef AYLA_WMSDK_SUPPORT
	adw_wifi_export_ap_chan(wifi);
#endif
	conf_cd(CT_ap_mode);
	if (wifi->conditional_ap) {
		conf_put_u32(CT_enable, wifi->conditional_ap);
	} else {
		conf_delete(CT_enable);
	}
	conf_cd_parent();

	conf_cd(CT_listen);
	if (wifi->listen_itvl) {
		conf_put_s32(CT_interval, wifi->listen_itvl);
	} else {
		conf_delete(CT_interval);
	}

	conf_cd_in_parent(CT_scan);
	conf_put_u32(CT_save_on_ap_connect, wifi->save_on_ap_connect);
	conf_put_u32(CT_save_on_server_connect, wifi->save_on_server_connect);
	adw_unlock();

	conf_cd_parent();
	adw_wifi_export_profiles(wifi);
}

/*
 * Persist configured Wifi profiles.
 */
void adw_wifi_export_profiles(void *arg)
{
	struct adw_state *wifi = arg;
	struct adw_profile *prof;
	int i;

	adw_lock();
	conf_cd(CT_profile);
	for (prof = wifi->profile, i = 0; i < ADW_WIFI_PROF_CT; i++, prof++) {
		if (!prof->ssid.len) {
			adw_profile_delete(i);
			continue;
		}
		conf_cd_table(i);
		conf_put(CT_ssid, ATLV_UTF8, prof->ssid.id, prof->ssid.len);
		conf_put_u32(CT_security, prof->sec);
		conf_put(CT_key, ATLV_BIN, prof->key, prof->key_len);
		if (prof->hidden) {
			conf_put_u32(CT_hidden, 1);
		} else {
			conf_delete(CT_hidden);
		}
		conf_put_u32(CT_enable, prof->enable);
		if (prof->mfi) {
			conf_put_u32(CT_mfi, prof->mfi);
		} else {
			conf_delete(CT_mfi);
		}
		conf_cd_parent();
	}
	conf_cd_parent();
	adw_wifi_export_cur_prof(wifi);
	adw_unlock();
}

/*
 * Persist scan results for currently joined profile.
 */
void adw_wifi_export_cur_prof(void *arg)
{
	struct adw_state *wifi = arg;
	struct adw_profile *prof;
	struct adw_wifi_scan_persist wsp;
	struct adw_scan *scan;

	conf_cd(CT_scan);
	conf_delete(CT_enable);		/* remove old config item */

	prof = &wifi->profile[wifi->curr_profile];
	scan = prof->scan;
	if (!scan || wifi->state != WS_UP) {
		conf_delete(CT_profile);
		return;
	}
	memset(&wsp, 0, sizeof(wsp));
	wsp.wsp_version = WSP_VERSION;
	wsp.wsp_channel = scan->channel;
	wsp.wsp_ssid = scan->ssid;
	memcpy(wsp.wsp_bssid, scan->bssid, sizeof(wsp.wsp_bssid));
	wsp.wsp_wmi_security = scan->wmi_sec;
	if (wifi->saved_key_len <= sizeof(wsp.wsp_key) &&
	    wifi->saved_key_prof == wifi->curr_profile) {
		wsp.wsp_key_len = wifi->saved_key_len;
		memcpy(wsp.wsp_key, wifi->saved_key, wsp.wsp_key_len);
	} else {
		wsp.wsp_key_len = 0;
	}
	conf_put(CT_profile, ATLV_BIN, &wsp, sizeof(wsp));
}

/*
 * Handle incoming configuration change.
 * The path will be relative to CT_wifi.
 * token: array of configuration tokens (names, indices)
 * len: the number of configuration tokens (will be >= 1).
 * tlv: the value TLV.
 */
static enum conf_error
adw_wifi_set(int src, enum conf_token *token, size_t len, struct ayla_tlv *tlv)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;
	enum conf_error error = CONF_ERR_PATH;
	struct adw_ssid ssid;
	s32 val;
	struct adw_wifi_scan_persist wsp_buf;
	struct adw_wifi_scan_persist *wsp;
	struct adw_scan *scan;
	char *cp;

	if (token[0] == CT_setup_ios_app) {
		if (conf_access(CONF_OP_SS_SETUP_APP | CONF_OP_WRITE | src)) {
			return CONF_ERR_PERM;
		}
	} else {
		if (conf_access(CONF_OP_SS_WIFI | CONF_OP_WRITE | src)) {
			return CONF_ERR_PERM;
		}
	}
	ADW_SIZE_CHECK;
	adw_lock();
	switch (token[0]) {
	case CT_enable:
		wifi->enable = conf_get_bit(tlv);
		break;
	case CT_ant:
		val = conf_get_int32(tlv);
#ifndef NO_WIFI_ANT_SELECTION
		if (val != WIFI_ANT0 && val != WIFI_ANT1 &&
		    val != WIFI_ANT_DIV) {
			error = CONF_ERR_RANGE;
			goto err;
		}
		wifi->send_ant = 1;
#else
		if (val != WIFI_ANT0) {
			error = CONF_ERR_RANGE;
			goto err;
		}
#endif
		wifi->ant = val;
		break;
	case CT_mac_addr:
		if (tlv->len != sizeof(wifi->mac)) {
			error = CONF_ERR_LEN;
			goto err;
		}
		conf_get(tlv, ATLV_BIN, &wifi->mac, sizeof(wifi->mac));
		break;
	case CT_listen:
		if (token[1] != CT_interval) {
			goto err;
		}
		val = conf_get_int32(tlv);
		if (val < 0 || val > CHAR_MAX) {
			error = CONF_ERR_RANGE;
			goto err;
		}
		wifi->listen_itvl = val;
		break;
	case CT_scan:
		if (len < 2) {
			goto err;
		}
		switch (token[1]) {
		case CT_enable:
			wifi->enable = conf_get_bit(tlv); /* old location */
			break;
		case CT_save_on_ap_connect:
			wifi->save_on_ap_connect = conf_get_bit(tlv);
			break;
		case CT_save_on_server_connect:
			wifi->save_on_server_connect = conf_get_bit(tlv);
			break;
		case CT_profile:
			wsp = (struct adw_wifi_scan_persist *)(tlv + 1);
			if (tlv->type != ATLV_BIN) {
				break;
			}
			if (wsp->wsp_version != WSP_VERSION ||
			    tlv->len != sizeof(*wsp)) {
				break;
			}
			scan = wifi->scan;
			if (scan->ssid.len) {
				break;
			}

			/*
			 * Copy buffer onto stack to get an aligned copy.
			 */
			memcpy(&wsp_buf, wsp, sizeof(wsp_buf));
			wsp = &wsp_buf;

			wifi->saved_key_len = wsp->wsp_key_len;

			prof = adw_wifi_prof_lookup(wifi, &wsp->wsp_ssid);
			if (!prof ||
			    wifi->saved_key_len > sizeof(wifi->saved_key)) {
				wifi->saved_key_len = 0;
			} else {
				memcpy(wifi->saved_key, wsp->wsp_key,
				    wifi->saved_key_len);
				wifi->saved_key_len = wsp->wsp_key_len;
				wifi->saved_key_prof = prof - wifi->profile;
			}
			scan->channel = wsp->wsp_channel;
			scan->ssid = wsp->wsp_ssid;
			memcpy(scan->bssid, wsp->wsp_bssid,
			    sizeof(scan->bssid));
			scan->wmi_sec = wsp->wsp_wmi_security;
			scan->rssi = WIFI_MIN_SIG;
			break;
		case CT_start:
			adw_unlock();
			adw_wifi_start_scan(WIFI_SCAN_MIN_LIMIT);
			adw_lock();
			break;
		default:
			goto err;
		}
		break;
	case CT_profile:
		if (len == 2 && token[1] == CT_start) {
			val = conf_get_int32(tlv);
			if (val >= ADW_WIFI_PROF_CT ||
			    !wifi->profile[val].ssid.len) {
				error = CONF_ERR_RANGE;
				goto err;
			}
			wifi->pref_profile = val + 1;
			wifi->profile[val].join_errs = 0;
			adw_wifi_rejoin(wifi);
			break;
		}
		if (len < 3 || token[1] >= ADW_WIFI_PROF_CT) {
			goto err;
		}
		prof = &wifi->profile[token[1]];
		switch (token[2]) {
		case CT_ssid:
			memset(&ssid, 0, sizeof(ssid));
			ssid.len = conf_get(tlv, ATLV_UTF8,
				ssid.id, sizeof(ssid.id));
			/*
			 * The AP SSID must be a string for the API
			 * so limit the length to get NUL termination.
			 */
			if ((ssid.len == 0 || ssid.len > sizeof(ssid.id)) &&
			    token[1] == ADW_WIFI_PROF_AP) {
				error = CONF_ERR_RANGE;
				goto err;
			}
			prof->ssid = ssid;
			goto clear_saved_key;
		case CT_security:
			val = conf_get_int32(tlv);
			if (val != 0 && val != CT_none &&
			    val != CT_WEP && val != CT_WPA &&
			    val != CT_WPA2_Personal) {
				error = CONF_ERR_RANGE;
				goto err;
			}
			prof->sec = val;
			goto clear_saved_key;
		case CT_key:
			prof->key_len = conf_get(tlv, ATLV_BIN,
			    prof->key, sizeof(prof->key));
clear_saved_key:
			if (src != CONF_OP_SRC_FILE &&
			    wifi->saved_key_prof == prof - wifi->profile) {
				wifi->saved_key_len = 0;
			}
			break;
		case CT_enable:
			val = conf_get_bit(tlv);
			if (!val && token[1] == ADW_WIFI_PROF_AP) {
				error = CONF_ERR_RANGE;
				goto err;
			}
			prof->enable = val;
			break;
		case CT_hidden:
			prof->hidden = conf_get_bit(tlv);
			if (prof->hidden) {
				prof->spec_scan_done = 1;
			}
			break;
		case CT_mfi:
			if (src != CONF_OP_SRC_FILE) {
				error = CONF_ERR_PERM;
				goto err;
			}
			val = conf_get_bit(tlv);
			if (!val) {
				goto err;
			}
			prof->mfi = val;
			break;
		default:
			goto err;
		}
		break;
	case CT_setup_ios_app:
		if (tlv->len >= sizeof(adw_wifi_ios_app)) {
			error = CONF_ERR_LEN;
			goto err;
		}
		conf_get(tlv, ATLV_UTF8,
		    adw_wifi_ios_app, sizeof(adw_wifi_ios_app));
		adw_wifi_ios_app[tlv->len] = '\0';

		/*
		 * Some modules in the field have been misconfigured with
		 * underscores, which are illegal in the URL scheme.
		 * Change these to dashes.
		 */
		for (cp = adw_wifi_ios_app;;)  {
			cp = strchr(cp, '_');
			if (!cp) {
				break;
			}
			*cp++ = '-';
		}
		break;
#ifdef AIRKISS
	case CT_setup_mode:
		if (len < 2) {
			goto err;
		}
		switch (token[1]) {
		case CT_enable:
			val = conf_get_int32(tlv);
			wifi->setup_mode = val;
			if (wifi->setup_mode & WIFI_AIRKISS) {
				adw_unlock();
				adw_wifi_start_aks_ext(NULL);
				adw_lock();
			} else {
				adw_unlock();
				adw_wifi_stop_aks_ext(NULL);
				adw_lock();
			}
			break;
		case CT_key:
			if (tlv->len != AKS_AES_KEY_LEN) {
				goto err;
			}
			conf_get(tlv, ATLV_BIN, wifi->aes_key,
			    AKS_AES_KEY_LEN);
			break;
		default:
			goto err;
		}
		break;
#endif
	case CT_WPS:
		adw_unlock();
		val = adw_wifi_start_wps();
		adw_lock();
		if (val) {
			error = CONF_ERR_PERM;
			goto err;
		}
		break;
	case CT_power:
		val = conf_get_u8(tlv);
		/* XXX Range check? */
		wifi->tx_power = val;
		break;
	case CT_ap_mode:
		if (len < 2) {
			goto err;
		}
		switch (token[1]) {
		case CT_enable:
			wifi->conditional_ap = conf_get_bit(tlv);
			break;
#ifdef AYLA_WMSDK_SUPPORT
		case CT_chan:
			wifi->ap_mode_chan = conf_get_u8(tlv);
			break;
#endif
		default:
			goto err;
		}
		break;
	default:
		goto err;
	}
	adw_unlock();
	return CONF_ERR_NONE;

err:
	adw_unlock();
	return error;
}

void adw_wifi_scan_snapshot_reset(void)
{
	adw_wifi_scan_snapshot = 0;
}

/*
 * Handle read of config setting.
 * The path will be relative to CT_wifi.
 * token: array of configuration tokens (names, indices)
 * len: the number of configuration tokens (will be >= 1).
 */
static enum conf_error
adw_wifi_get(int src, enum conf_token *token, size_t len)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;
	struct adw_scan *scan;
	struct adw_wifi_history *hist;
	enum conf_token sec;
	enum conf_error rc = CONF_ERR_PATH;
	s32 val;
	u8 val_str[2];

	if (conf_access(CONF_OP_SS_WIFI | CONF_OP_READ | src)) {
		return CONF_ERR_PERM;
	}
	adw_lock();
	switch (token[0]) {
	case CT_ant:
		conf_resp_s32(wifi->ant);
		break;
	case CT_mac_addr:
		conf_resp(ATLV_BIN, &wifi->mac, sizeof(wifi->mac));
		break;
	case CT_enable:
		conf_resp_bool(wifi->enable);
		break;
	case CT_listen:
		if (token[1] != CT_interval) {
			goto err;
		}
		conf_resp(ATLV_INT, &wifi->listen_itvl,
		    sizeof(wifi->listen_itvl));
		break;
	case CT_scan:
		if (len < 2) {
			goto err;
		}
		switch (token[1]) {
		case CT_save_on_ap_connect:
			conf_resp_bool(wifi->save_on_ap_connect);
			break;
		case CT_save_on_server_connect:
			conf_resp_bool(wifi->save_on_server_connect);
			break;
		case CT_ready:
			if (wifi->scan_state != SS_SCAN &&
			    wifi->scan_time) {
				/*
				 * Scan is not currently in progress, and
				 * has been started at least once.
				 */
				val = 1;
			} else {
				val = 0;
			}
			conf_resp_bool(val);
			break;
		case CT_n:
			if (len == 2) {
				/*
				 * Mark scan result snapshot.
				 */
				if (wifi->scan_state == SS_SCAN) {
					rc = CONF_ERR_PERM;
					goto err;
				}
				for (val = 0;
				     wifi->scan[val].ssid.len != 0 &&
					 val < ADW_WIFI_SCAN_CT;
				     val++)
					;
				adw_wifi_scan_snapshot = val + 1;
				conf_resp_s32(val);
				break;
			}
			/*
			 * If snapshot has been taken, we'll serve this data.
			 */
			if (!adw_wifi_scan_snapshot) {
				rc = CONF_ERR_PERM;
				goto err;
			}
			if (token[2] >= adw_wifi_scan_snapshot - 1) {
				rc = CONF_ERR_RANGE;
				goto err;
			}
			scan = &wifi->scan[token[2]];
			switch (token[3]) {
			case CT_ssid:
				conf_resp(ATLV_UTF8,
				    scan->ssid.id, scan->ssid.len);
				break;
			case CT_bssid:
				conf_resp(ATLV_BIN,
				    &scan->bssid, sizeof(scan->bssid));
				break;
			case CT_rssi:
				conf_resp_s32(scan->rssi);
				break;
			case CT_bars:
				conf_resp_s32(adw_wifi_bars(scan->rssi));
				break;
			case CT_security:
				sec = adw_wmi_sec_import(scan->wmi_sec);
				conf_resp_s32(sec);
				break;
			case CT_chan:
				conf_resp_s32(scan->channel);
				break;
			default:
				goto err;
			}
			break;
		default:
			goto err;
		}
		break;
	case CT_status:
		if (len < 2) {
			goto err;
		}
		switch (token[1]) {
		case CT_profile:
			if (wifi->state >= WS_JOIN && wifi->state <= WS_UP) {
				val = wifi->curr_profile;
			} else if (wifi->state == WS_START_AP ||
			    wifi->state == WS_UP_AP) {
				val = ADW_WIFI_PROF_AP;
			} else {
				val = -1;
			}
			conf_resp_s32(val);
			break;
		case CT_rssi:
			if (wifi->state >= WS_DHCP && wifi->state <= WS_UP) {
				val = adw_wifi_avg_rssi();
			} else {
				val = MIN_S8;
			}
			conf_resp_s32(val);
			break;
		case CT_bars:
			if (wifi->state >= WS_DHCP && wifi->state <= WS_UP) {
				val = adw_wifi_bars(adw_wifi_avg_rssi());
			} else {
				val = 0;
			}
			conf_resp_s32(val);
			break;
		case CT_bssid:
			if (wifi->state >= WS_JOIN && wifi->state <= WS_UP) {
				scan = wifi->profile[wifi->curr_profile].scan;
				if (scan) {
					/* should always get result */
					conf_resp(ATLV_BIN,
					    &scan->bssid, sizeof(scan->bssid));
					break;
				}
			}
			/*
			 * Not connected to a AP.
			 */
			conf_resp(ATLV_BIN, NULL, 0);
			break;
		default:
			goto err;
		}
		break;
	case CT_profile:
		if (len < 3 || token[1] >= ADW_WIFI_PROF_CT) {
			goto err;
		}
		prof = &wifi->profile[token[1]];
		switch (token[2]) {
		case CT_ssid:
			conf_resp(ATLV_UTF8, prof->ssid.id, prof->ssid.len);
			break;
		case CT_security:
			conf_resp_s32(prof->sec);
			break;
		case CT_key:
			conf_resp(ATLV_BIN, prof->key, prof->key_len);
			break;
		case CT_enable:
			conf_resp_bool(prof->enable);
			break;
		case CT_hidden:
			conf_resp_bool(prof->hidden);
		case CT_mfi:
			conf_resp_bool(prof->mfi);
			break;
		default:
			goto err;
		}
		break;
	case CT_hist:
		if (len < 4 || token[2] >= WIFI_HIST_CT) {
			goto err;
		}
		val = token[2];
		hist = &wifi->hist[(wifi->hist_curr - val) % WIFI_HIST_CT];
		switch (token[3]) {
		case CT_ssid:
			val = hist->ssid_len;
			if (val > sizeof(hist->ssid_info)) {
				val = sizeof(hist->ssid_info);
			}
			conf_resp(ATLV_BIN, hist->ssid_info, val);
			break;
		case CT_bssid:
			val_str[0] = hist->bssid[4];
			val_str[1] = hist->bssid[5];
			conf_resp(ATLV_BIN, val_str, 2);
			break;
		case CT_dns:
			if (len < 6 || token[4] >= WIFI_HIST_DNS_SERVERS) {
				goto err;
			}
			conf_resp(ATLV_INT, &hist->dns_servers[token[4]].addr,
			    4);
			break;
		case CT_error:
			conf_resp_s32(hist->error);
			break;
		case CT_time:
			conf_resp_s32(hist->time);
			break;
		case CT_addr:
			conf_resp(ATLV_INT, &hist->ip_addr.addr, 4);
			break;
		case CT_mask:
			conf_resp(ATLV_INT, &hist->netmask.addr, 4);
			break;
		case CT_gw:
			conf_resp(ATLV_INT, &hist->def_route.addr, 4);
			break;
		default:
			goto err;
		}
		break;
#ifdef AIRKISS
	case CT_setup_mode:
		conf_resp_s32(wifi->setup_mode);
		break;
#endif
	case CT_setup_ios_app:
		conf_resp_str(adw_wifi_ios_app);
		break;
	case CT_WPS:
		conf_resp_bool(wifi->state == WS_WPS);
		break;
	case CT_power:
		conf_resp_u32(wifi->tx_power);
		break;
	case CT_ap_mode:
		if (len < 2) {
			goto err;
		}
		switch (token[1]) {
		case CT_enable:
			conf_resp_bool(wifi->conditional_ap);
			break;
#ifdef AYLA_WMSDK_SUPPORT
		case CT_chan:
			conf_resp_u32(wifi->ap_mode_chan);
			break;
#endif
		default:
			goto err;
		}
		break;
	default:
		goto err;
	}
	adw_unlock();
	return CONF_ERR_NONE;

err:
	adw_unlock();
	return rc;
}

const struct conf_entry adw_wifi_conf_entry = {
	.token = CT_wifi,
	.export = adw_wifi_export,
	.set = adw_wifi_set,
	.get = adw_wifi_get,
	.commit = adw_wifi_commit,
};

/*
 * Handle read of IP status variables.
 * The path will be relative to CT_ip.
 * token: array of configuration tokens (names, indices)
 * len: the number of configuration tokens (will be >= 1).
 */
static enum conf_error
adw_wifi_ip_get(int src, enum conf_token *token, size_t len)
{
	struct adw_state *wifi = &adw_state;
	ip_addr_t val;

	if (conf_access(CONF_OP_SS_IP | CONF_OP_READ | src)) {
		return CONF_ERR_PERM;
	}
	adw_lock();
	if (!wifi->nif) {
		adw_unlock();
		return CONF_ERR_PATH;
	}
	switch (token[0]) {
	case CT_n:
		if (len != 3 || token[1] != 0) {
			goto err;
		}
		switch (token[2]) {
		case CT_addr:
			conf_resp(ATLV_INT, &wifi->nif->ip_addr.addr, 4);
			break;
		case CT_mask:
			conf_resp(ATLV_INT, &wifi->nif->netmask.addr, 4);
			break;
		default:
			goto err;
		}
		break;
	case CT_dns:
		if (len != 3 || token[1] != CT_n) {
			goto err;
		}
		val = net_dns_getserver(token[2]);
		if (val.addr != IPADDR_ANY) {
			conf_resp(ATLV_INT, &val.addr, 4);
		} else {
			goto err;
		}
		break;
	case CT_dhcp:
		if (len != 2 || token[1] != CT_enable) {
			goto err;
		}
		conf_resp_bool(1); /* Always on for now */
		break;
	case CT_gw:
		if (len != 1) {
			goto err;
		}
		conf_resp(ATLV_INT, &wifi->nif->gw.addr, 4);
		break;
	default:
		goto err;
	}
	adw_unlock();
	return CONF_ERR_NONE;

err:
	adw_unlock();
	return CONF_ERR_PATH;
}

const struct conf_entry adw_wifi_ip_conf_entry = {
	.token = CT_ip,
	.get = adw_wifi_ip_get,
};

/*
 * Join specified profile for CLI.
 */
static void adw_wifi_cli_join(void)
{
	struct adw_state *wifi = &adw_state;
	struct adw_ssid *ssid;
	struct adw_profile *prof;
	char ssid_buf[33];

	prof = &wifi->profile[mfg_profile];
	ssid = &prof->ssid;
	if (prof >= &wifi->profile[ADW_WIFI_PROF_AP] || ssid->id[0] == '\0') {
		printcli("invalid profile for join");
		return;
	}

	adw_log(LOG_INFO "CLI starting join to %s",
	    adw_format_ssid(&prof->ssid, ssid_buf, sizeof(ssid_buf)));

	adw_lock();
	prof->scan = NULL;
	prof->join_errs = 0;
	wifi->pref_profile = (prof - wifi->profile) + 1;
	wifi->err_msg = NULL;
	adw_wifi_hist_clr_curr(wifi);
	adw_wifi_rejoin(wifi);
	adw_unlock();
}

static void adw_wifi_profiles_erase(unsigned int from, unsigned int to)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;
	unsigned int index;

	adw_lock();

	index = wifi->curr_profile;
	if (index >= from && index <= to && wifi->profile[index].enable) {
		wifi->rejoin = 1;
	}

	index = wifi->pref_profile + 1;
	if (index >= from && index <= to) {
		wifi->pref_profile = 0;
		wifi->rejoin = 1;
	}

	memset(&wifi->profile[from], 0, (to + 1 - from) * sizeof(*prof));
	if (wifi->saved_key_prof >= from && wifi->saved_key_prof <= to) {
		wifi->saved_key_len = 0;
	}

	adw_unlock();
	adw_wifi_commit(0);
}

int adw_wifi_profile_erase(unsigned int index)
{
	if (index >= ADW_WIFI_PROF_CT) {
		return -1;
	}
	adw_wifi_profiles_erase(index, index);
	return 0;
}

void adw_wifi_profile_sta_erase(void)
{
	adw_wifi_profiles_erase(0, ADW_WIFI_PROF_AP - 1);
}

void adw_wifi_profile_ap_erase(void)
{
	adw_wifi_profiles_erase(ADW_WIFI_PROF_AP, ADW_WIFI_PROF_AP);
}

void adw_wifi_cli_scan(const char *net)
{
	struct adw_ssid scan4;
	const char *msg;
	size_t len;
	enum ada_err rc;

	memset(&scan4, 0, sizeof(scan4));
	if (net) {
		len = strlen(net);
		if (len > sizeof(scan4.id)) {
			printcli("ssid too long");
			return;
		}
		scan4.len = len;
		memcpy(scan4.id, net, len);
	}
	adw_lock();
	rc = adw_wifi_start_scan4(0, &scan4);
	adw_unlock();
	switch (rc) {
	case AE_OK:
		msg = NULL;
		break;
	case AE_NOTCONN:
		msg = "connection in progress";
		break;
	case AE_INVAL_STATE:
		msg = "wifi down";
		break;
	case AE_IN_PROGRESS:
		msg = "scan in progress";
		break;
	case AE_BUSY:			/* too soon, should not occur */
	default:
		msg = "error";
		break;
	}
	if (msg) {
		printcli("%s - scan not started", msg);
	}
}

/*
 * wifi command.
 */
void adw_wifi_cli(int argc, char **argv)
{
	enum conf_token token[3];
	enum conf_token tk;
	int ntokens;
	unsigned long val;
	char *errptr;
	const struct conf_entry *entry;
	const char *name;
	const char *value;
	int rc;
	struct {
		struct ayla_tlv tlv;
		union {
			u8 mac[6];
			u8 val;
			u8 ssid[65];	/* also used for key, ios_app name */
		};
	} buf;
	char ssid_buf[65];
	u8 *mac;
#ifdef AYLA_BC
	struct netif *netif;
	struct ip_addr ipaddr, netmask, gw;
#endif
	u8 show_usage = 1;

	entry = &adw_wifi_conf_entry;
	argc--;
	argv++;
	while (argc--) {
		show_usage = 0;
		name = *argv++;

		if (!strcmp(name, "commit")) {
			entry->commit(1);
			continue;
		}
		if (!strcmp(name, "scan")) {
			if (argc) {
				adw_wifi_cli_scan(*argv);
			} else {
				adw_wifi_cli_scan(NULL);
			}
			return;
		}
		if (!strcmp(name, "join") && !argc) {
			adw_wifi_cli_join();
			return;
		}
		if (!strcmp(name, "enable") && !argc) {
			adw_wifi_enable();
			break;
		}
		if (!strcmp(name, "wps")) {
			adw_wifi_start_wps();
			break;
		}
		if (!strcmp(name, "disable")) {
			adw_wifi_disable();
			break;
		}
		if (!argc) {
			show_usage = 1;
			break;
		}
		argc--;
		value = *argv++;
		val = strtoul(value, &errptr, 10); /* speculative conversion */

		if (!strcmp(name, "ssid-mac") &&
		    mfg_profile == ADW_WIFI_PROF_AP) {
			mac = conf_sys_mac_addr;
			snprintf(ssid_buf, sizeof(ssid_buf) - 1,
			    "%s%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x", value,
			    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			value = ssid_buf;
			tk = CT_ssid;
		} else {
			tk = conf_token_parse(name);
		}
		token[0] = tk;
		token[1] = mfg_profile;		/* not always used */
		ntokens = 1;
		switch (tk) {
		case CT_ant:
			if (*errptr != '\0' || val > 255) {
				goto invalid;
			}
			if (val != WIFI_ANT0 && val != WIFI_ANT1 &&
			    val != WIFI_ANT_DIV) {
				goto invalid;
			}
			buf.tlv.type = ATLV_UINT;
			buf.tlv.len = 1;
			buf.val = val;
			break;
		case CT_mac_addr:
			rc = parse_mac(buf.mac, value);
			if (rc < 0 || (buf.mac[0] & 1)) {
				goto invalid;
			}
			buf.tlv.len = sizeof(buf.mac);
			buf.tlv.type = ATLV_BIN;
			break;
		case CT_security:
			tk = conf_token_parse(value);
			if (tk != CT_WPA && tk != CT_WEP
			    && tk != CT_WPA2_Personal && tk != CT_none) {
				goto invalid;
			}
			buf.tlv.type = ATLV_UINT;
			buf.tlv.len = 1;
			buf.val = tk;
			goto profile_val;
		case CT_key:
			buf.tlv.type = ATLV_BIN;
			goto profile_string;
		case CT_listen:
			if (val > CHAR_MAX) {
				goto invalid;
			}
			token[1] = CT_interval;
			ntokens = 2;
			buf.tlv.type = ATLV_INT;
			buf.tlv.len = 1;
			buf.val = val;
			break;
		case CT_hidden:
			if (*errptr != '\0' || val > 1) {
				goto invalid;
			}
			buf.tlv.type = ATLV_BOOL;
			buf.tlv.len = 1;
			buf.val = val;
			goto profile_val;
		case CT_ssid:
			buf.tlv.type = ATLV_UTF8;
profile_string:
			rc = strlen(value);
			if (rc > sizeof(buf.ssid) - 1) {
				goto invalid;
			}
			buf.tlv.len = rc;
			memcpy(buf.ssid, value, rc);
			buf.ssid[rc] = '\0';
profile_val:
			token[2] = token[0];
			token[0] = CT_profile;
			ntokens = 3;
			break;
		case CT_profile:
			if (!strcmp(value, "disable")) {
				buf.val = 0;
				goto profile_enable;
			}
			if (!strcmp(value, "enable")) {
				buf.val = 1;
profile_enable:
				token[2] = CT_enable;
				buf.tlv.type = ATLV_UINT;
				buf.tlv.len = 1;
				ntokens = 3;
				break;
			}
			if (!strcmp(value, "erase")) {
				adw_wifi_profile_erase(mfg_profile);
				return;
			}
			if (!strcmp(value, "ap")) {
				mfg_profile = ADW_WIFI_PROF_AP;
				continue;
			}
			if (*errptr != '\0' || val >= ADW_WIFI_PROF_AP) {
				goto invalid;
			}
			mfg_profile = val;
			continue;
		case CT_save_on_ap_connect:
		case CT_save_on_server_connect:
			token[0] = CT_scan;
			token[1] = tk;
			ntokens = 2;
			/* fall through */
		case CT_enable:
			if (*errptr != '\0') {
				goto invalid;
			}
			buf.val = val;
			buf.tlv.len = sizeof(buf.val);
			buf.tlv.type = ATLV_UINT;
			break;
		case CT_setup_ios_app:
			buf.tlv.type = ATLV_UTF8;
			rc = strlen(value);
			if (rc > sizeof(buf.ssid) - 1) {
				goto invalid;
			}
			buf.tlv.len = rc;
			memcpy(buf.ssid, value, rc);
			buf.ssid[rc] = '\0';
			break;
#ifdef AYLA_BC
		case CT_ip:
			/* Assign IP address temporarily */
			if (argc < 1) {
				goto invalid;
			}
			if (adw_state.state < WS_DHCP ||
			    adw_state.state >= WS_START_AP) {
				goto invalid;
			}
			netif = adw_wifi_sta_netif();
			if (netif->flags & NETIF_FLAG_DHCP) {
				dhcp_release(netif);
				dhcp_stop(netif);
			}

			/*
			 * This used to set WS_UP.
			 * netif_set_up should take care of that
			 */
			ip_addr_pton(0, (char *)value, ip_2_ipX(&ipaddr));
			ip_addr_pton(0, (char *)argv[0], ip_2_ipX(&netmask));
			argv++;
			memset(&gw, 0, sizeof(gw));

			netif_set_addr(netif, &ipaddr, &netmask, &gw);
			netif_set_up(netif);
			printcli("Assigned temporary address");
			return;
#endif /* AYLA_BC */
#ifdef AIRKISS
		/* Reuse setup_mode token for airkiss */
		case CT_setup_mode:
			if (strcmp(value, "airkiss")) {
				goto invalid;
			}
			ntokens = 2;
			if (!argc) {
				goto invalid;
			}
			value = *argv++;
			argc--;
			if (!strcmp(value, "key")) {
				if (!mfg_or_setup_mode_ok()) {
					return;
				}

				token[1] = CT_key;
				if (!argc) {
					goto invalid;
				}

				/* CLI input of AES Key is in hex */
				buf.tlv.type = ATLV_BIN;
				rc = parse_hex(buf.ssid,
				    AKS_AES_KEY_LEN,
				    (const char *)*argv, strlen(*argv));
				if (rc < 0) {
					goto invalid;
				}
				buf.tlv.len = rc;
				if (buf.tlv.len != AKS_AES_KEY_LEN) {
					printcli("Invalid AES key len");
					return;
				}
				value = *argv++;
				argc--;
			} else {
				buf.tlv.type = ATLV_INT;
				buf.tlv.len = sizeof(buf.val);
				if (!strcmp(value, "enable")) {
					token[1] = CT_enable;
					buf.val = adw_state.setup_mode |
					    WIFI_AIRKISS;
				} else if (!strcmp(value, "disable")) {
					token[1] = CT_enable;
					adw_wifi_stop_aks(NULL);
					buf.val = adw_state.setup_mode &
					    ~WIFI_AIRKISS;
				} else {
					goto invalid;
				}
			}
			break;
#endif /* AIRKISS */
		case CT_power:
			if (*errptr != '\0' || val > 255) {
				goto invalid;
			}
			buf.tlv.type = ATLV_UINT;
			buf.tlv.len = 1;
			buf.val = val;
			break;
		case CT_ap_mode:
			if (!strcmp(value, "conditional")) {
				if (!argc) {
					goto invalid;
				}
				value = *argv++;
				argc--;
				token[1] = CT_enable;
				ntokens = 2;
				val = strtoul(value, &errptr, 10);
				if (*errptr != '\0' || val > 1 ||
				    errptr == value) {
					goto invalid;
				}
				buf.val = val;
				buf.tlv.type = ATLV_BOOL;
				buf.tlv.len = 1;
			} else {
				goto invalid;
			}
			break;
		default:
			printcli("setting %s not supported", name);
			return;
		}

		rc = conf_set_tlv(entry, token, ntokens, &buf.tlv);
		if (rc == CONF_ERR_RANGE) {
			goto invalid;
		}
		if (rc != CONF_ERR_NONE) {
			printcli("conf err %d", rc);
			break;
		}
	}
	if (show_usage) {
		printcli("usage: wifi <name> <value>");
		printcli("supported names are: "
		    "ant, mac_addr, security, ssid, ssid-mac, "
		    "key, profile, enable, listen, tx_power, ap_mode"
#ifdef AIRKISS
		    ", setup_mode"
#endif
		    "");
	}
	return;

invalid:
	printcli("invalid value");
}

/*
 * Wifi join command from MCU. Get arguments out of the message, and tell
 * wifi subsystem to try this network.
 */
int adw_wifi_join_rx(void *buf, int len)
{
	struct adw_state *wifi;
	struct ayla_cmd *cmd;
	struct ayla_tlv *tlv;
	u8 err = 0;
	enum wifi_error wifi_error;
	int rlen;
	struct adw_ssid ssid;
	u8 *name = NULL;
	int nlen = 0;
	char *key = NULL;
	int klen = 0;
	s32 sec_token = -1;
	struct adw_wifi_history *hist;
	char ssid_buf[33];

	wifi = &adw_state;
	cmd = (struct ayla_cmd *)buf;
	tlv = (struct ayla_tlv *)(cmd + 1);
	rlen = len - sizeof(*cmd);

	/*
	 * Arguments come in specific order.
	 * - SSID as ATLV_UTF8
	 * - security type as ATLV_INT
	 * - key as ATLV_BIN
	 */
	while (rlen > 0) {
		if (rlen < sizeof(*tlv)) {
			err = AERR_LEN_ERR;
			goto error;
		}
		rlen -= sizeof(*tlv);

		if (rlen < tlv->len) {
			err = AERR_LEN_ERR;
			goto error;
		}

		switch (tlv->type) {
		case ATLV_UTF8:
			if (name) {
				err = AERR_INVAL_TLV;
				goto error;
			}
			nlen = tlv->len;
			name = (u8 *)(tlv + 1);
			break;
		case ATLV_INT:
			if (!name || sec_token != -1) {
				err = AERR_INVAL_TLV;
				goto error;
			}
			if (tlv->len != sizeof(u8)) {
				err = AERR_LEN_ERR;
				goto error;
			}
			sec_token = *(u8 *)(tlv + 1);
			break;
		case ATLV_BIN:
			if (sec_token == -1 || key) {
				err = AERR_INVAL_TLV;
				goto error;
			}
			klen = tlv->len;
			key = (char *)(tlv + 1);
			break;
		default:
			err = AERR_UNK_TYPE;
			goto error;
		}
		rlen -= tlv->len;
		tlv = (struct ayla_tlv *)((u8 *)tlv + sizeof(*tlv) + tlv->len);
	}
	if (!name || !key || sec_token == -1) {
		err = AERR_INVAL_REQ;
		goto error;
	}
	if (nlen > sizeof(ssid.id)) {
		err = AERR_LEN_ERR;
		goto error;
	}
	memcpy(&ssid.id, name, nlen);
	ssid.len = nlen;

	adw_lock();
	wifi_error = adw_wifi_add_prof(wifi, &ssid, key, klen, sec_token, 0, 0);
	switch (wifi_error) {
	case WIFI_ERR_NONE:
		err = 0;
		adw_wifi_rejoin(wifi);
		break;
	case WIFI_ERR_INV_KEY:
		err = AERR_INVAL_TLV;
		break;
	case WIFI_ERR_NO_PROF:
	default:
		/* XXX not good */
		err = AERR_INVAL_REQ;
		break;
	}
	adw_unlock();

	if (wifi->err_msg) {
		adw_log(LOG_ERR "MCU wifi join %s: %s",
		    adw_format_ssid(&ssid, ssid_buf, sizeof(ssid_buf)),
		    wifi->err_msg);
		hist = adw_wifi_hist_new(wifi, &ssid, NULL);
		hist->error = wifi_error;
	} else if (err) {
error:
		adw_log(LOG_ERR "MCU wifi join: %d", err);
	}
	return err;
}

/*
 * Wifi delete command from MCU. Get arguments out of the message, and tell
 * wifi subsystem to leave and forget this network.
 */
int adw_wifi_delete_rx(void *buf, int len)
{
	struct adw_state *wifi;
	struct ayla_cmd *cmd;
	struct ayla_tlv *tlv;
	struct adw_ssid ssid;
	u8 err = 0;
	int rc;

	wifi = &adw_state;
	cmd = (struct ayla_cmd *)buf;
	tlv = (struct ayla_tlv *)(cmd + 1);

	len -= sizeof(*cmd);

	if (len < sizeof(*tlv) || len < sizeof(*tlv) + tlv->len) {
		err = AERR_LEN_ERR;
		goto error;
	}
	if (tlv->type != ATLV_UTF8 || tlv->len == 0) {
		err = AERR_INVAL_TLV;
		goto error;
	}
	if (tlv->len > sizeof(ssid.id)) {
		err = AERR_INVAL_TLV;
		goto error;
	}
	ssid.len = tlv->len;
	memcpy(ssid.id, tlv + 1, tlv->len);

	rc = adw_wifi_del_prof(wifi, &ssid);
	if (rc > 0) {
		adw_wifi_rejoin(wifi);
	} else if (rc < 0) {
		err = AERR_UNK_VAR;
	}
	if (err) {
error:
		adw_log(LOG_ERR "MCU wifi del: %d", err);
	}
	return err;
}

/*
 * Set save on AP connect and save on server connect defaults.
 */
void adw_wifi_save_policy_set(int ap_connect, int serv_connect)
{
	struct adw_state *wifi = &adw_state;

	wifi->save_on_ap_connect = ap_connect;
	wifi->save_on_server_connect = serv_connect;
}

/*
 * Set conditional AP mode (default is unconditional).
 */
void adw_wifi_ap_conditional_set(int conditional)
{
	struct adw_state *wifi = &adw_state;

	wifi->conditional_ap = conditional;
}

/*
 * Set default AP profile name.
 * Assumes no security for AP mode.
 */
void adw_wifi_ap_ssid_set(const char *ssid)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof = &wifi->profile[ADW_WIFI_PROF_AP];
	size_t len;

	len = strlen(ssid);
	if (len > sizeof(prof->ssid.id)) {
		return;
	}
	memset(prof->ssid.id, 0, sizeof(prof->ssid.id));
	memcpy(prof->ssid.id, ssid, len);
	prof->ssid.len = len;
	prof->enable = 1;
	prof->sec = CT_none;
}

void adw_wifi_ios_setup_app_set(const char *app)
{
	snprintf(adw_wifi_ios_app, sizeof(adw_wifi_ios_app), "%s", app);
}
