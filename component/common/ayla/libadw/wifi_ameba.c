/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#define HAVE_UTYPES
#include <sys/types.h>
#include <stdint.h>
#include <main.h>

#include <lwip/tcpip.h>
#include <lwip/dns.h>
#include <netif/etharp.h>

#include <FreeRTOS.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/log.h>
#include <ayla/timer.h>
#include <ayla/conf.h>
#include <ayla/conf_token.h>
#include <ayla/parse.h>
#include <ayla/nameval.h>
#include <ayla/tlv.h>
#include <ayla/mod_log.h>
#include <net/net.h>
#include <adw/wifi.h>
#include <adw/wifi_conf.h>

#undef LIST_HEAD
#include "wifi_constants.h"
#include "wifi_structures.h"
#include "wireless.h"
#include "wifi_int.h"
#include "wifi_timer.h"
#include "wifi_ameba.h"

#ifndef min
#define min(a, b) ((a < b) ? (a) : (b))
#endif

PREPACKED struct adw_wmi_ssid_scan_result{
	u8 len;
	u8 bssid[6];
	s32 rssi;
	u8 sec;
	u8 wps_pass_id;
	u8 channel;
	char ssid[1];
} PACKED;

struct adw_wmi_state {
	rtw_mode_t wifi_mode;
	void (*scan_cb)(struct adw_scan *);
};

static struct adw_wmi_state adw_wmi_state;
static QueueHandle_t adw_sema;
u8 adw_locked;

void adw_lock(void)
{
	xSemaphoreTake(adw_sema, portMAX_DELAY);
	AYLA_ASSERT(!adw_locked);
	adw_locked = 1;
}

void adw_unlock(void)
{
	AYLA_ASSERT(adw_locked);
	adw_locked = 0;
	xSemaphoreGive(adw_sema);
}

static const char *adw_wmi_err_str(int err_code)
{
	switch (err_code) {
	case RTW_SUCCESS:
		return "none";
	case RTW_BADARG:
		return "param";
	case RTW_NOMEM:
		return "nomem";
	case RTW_NOTAP:
		return "not AP";
	case RTW_NOTSTA:
		return "not station";
	case RTW_BADCHAN:
		return "Bad channnel";
	case RTW_UNSUPPORTED:
		return "unsupported";
	case RTW_NOTREADY:
		return "not_ready";
	}
	return "";
}

static void adw_wmi_log_err(const char *msg, int rc)
{
	char *sign = "";

	if (rc < 0) {
		sign = "-";
		rc = -rc;
	}
	adw_log(LOG_ERR "wmi: %s failed rc %s0x%x %s",
	    msg, sign, rc, adw_wmi_err_str(rc));
}

/*wifi security import*/
enum conf_token adw_wmi_sec_import(u32 wmi_sec)
{
	switch (wmi_sec) {
	case RTW_SECURITY_WEP_SHARED:
	case RTW_SECURITY_WEP_PSK:
		return CT_WEP;
	case RTW_SECURITY_WPA_TKIP_PSK:
	case RTW_SECURITY_WPA_AES_PSK:
		return CT_WPA;
	case RTW_SECURITY_WPA2_AES_PSK:
	case RTW_SECURITY_WPA2_TKIP_PSK:
	case RTW_SECURITY_WPA2_MIXED_PSK:
	case RTW_SECURITY_WPA_WPA2_MIXED:
		return CT_WPA2_Personal;
	default:
	case RTW_SECURITY_OPEN:
		return CT_none;
	}
}

u32 adw_wmi_sec_export(enum conf_token sec)
{
	switch (sec) {
	case CT_WEP:
		return RTW_SECURITY_WEP_PSK;
	case CT_WPA:
		return RTW_SECURITY_WPA_AES_PSK;
	case CT_WPA2_Personal:
		return RTW_SECURITY_WPA2_AES_PSK;
	case CT_none:
	default:
		break;
	}
	return RTW_SECURITY_OPEN;
}

const char *adw_wmi_sec_string(u32 wmi_sec)
{
	rtw_security_t wlan_sec;
	wlan_sec = wmi_sec;
	const char *sec;

	switch (wlan_sec) {
	case RTW_SECURITY_OPEN:
		sec = "None";
		break;
	case RTW_SECURITY_WEP_SHARED:
		sec = "WEP Shared";
		break;
	case RTW_SECURITY_WEP_PSK:
		sec = "WEP";
		break;
	case RTW_SECURITY_WPA_TKIP_PSK:
	case RTW_SECURITY_WPA_AES_PSK:
		sec = "WPA";
		break;
	case RTW_SECURITY_WPA2_AES_PSK:
	case RTW_SECURITY_WPA2_TKIP_PSK:
		sec = "WPA2 Personal";
		break;
	case RTW_SECURITY_WPA_WPA2_MIXED:
	case RTW_SECURITY_WPA2_MIXED_PSK:
		sec = "WPA2 Personal Mixed";
		break;
	default:
		sec = "Unknown";
		break;
	}
	return sec;
}

void adw_wmi_powersave_set(enum adw_wifi_powersave_mode mode)
{
}

int adw_wmi_get_rssi(int *rssip)
{
	int rssi;

	wifi_get_rssi(&rssi);
	*rssip = rssi;
	return 0;
}

int adw_wmi_sel_ant(int ant)
{
	if (ant == 0) {
		return 0;
	}
	return -1;
}

int adw_wmi_get_txant(int *antp)
{
	*antp = 0;
	return 0;
}

int adw_wmi_get_rxant(int *antp)
{
	*antp = 0;
	return 0;
}

int adw_wmi_set_tx_power(u8 tx_power)
{
	return 0;
}

int adw_wmi_get_tx_power(u8 *tx_powerp)
{
	*tx_powerp = 0;
	return 0;
}

void adw_wmi_set_scan_result(const char *ssid, u8 ssid_len, u8 *bssid,
	u8 channel, u8 bss_type, s16 rssi, u32 security)
{
	struct adw_wmi_state *wmi = &adw_wmi_state;
	struct adw_scan scan;

	if (ssid == NULL) {
		wmi->scan_cb(NULL);
		return;
	}

	if (ssid_len == 0) {
		return;
	}

	memset(&scan, 0, sizeof(scan));
	ASSERT(ssid_len <= sizeof(scan.ssid.id));
	memcpy(scan.ssid.id, ssid, ssid_len);
	scan.ssid.len = ssid_len;
	memcpy(scan.bssid, bssid, sizeof(scan.bssid));
	scan.channel = channel;
	scan.type = bss_type;
	scan.rssi = rssi;
	scan.wmi_sec = security;
	wmi->scan_cb(&scan);
}

int adw_wmi_scan_with_ssid_handler(char *buf, int buflen,
	char *ssid, void *user_data)
{
	struct adw_wmi_ssid_scan_result *result;
	int len = 0;
	u32 security;

	while (len < buflen && buf[len]) {
		result = (struct adw_wmi_ssid_scan_result *)(buf + len);
		len += result->len;
		if (len > buflen) {
			break;
		}
		switch (result->sec) {
		case IW_ENCODE_ALG_WEP:
			security = RTW_SECURITY_WEP_PSK;
			break;
		case IW_ENCODE_ALG_CCMP:
			security = RTW_SECURITY_WPA2_AES_PSK;
			break;
		case IW_ENCODE_ALG_NONE:
		default:
			security = RTW_SECURITY_OPEN;
			break;
		}
		adw_wmi_set_scan_result(result->ssid, buf + len - result->ssid,
		    result->bssid, result->channel, BT_INFRASTRUCTURE,
		    result->rssi, security);
	}
	adw_wmi_set_scan_result(NULL, 0, NULL, 0, 0, 0, 0);
	return 0;
}

int adw_wmi_scan(struct adw_ssid *spec_ssid,
		void (*callback)(struct adw_scan *))
{
	struct adw_wmi_state *wmi = &adw_wmi_state;
	int rc;
	char ssid_buf[33];

	wmi->scan_cb = callback;
	if (spec_ssid) {
		adw_log(LOG_DEBUG "Scan ssid %s",
		    adw_format_ssid(spec_ssid, ssid_buf, sizeof(ssid_buf)));
		rc = wifi_scan_networks_with_ssid(
		    adw_wmi_scan_with_ssid_handler,
		    NULL, 512, ssid_buf, spec_ssid->len);
	} else {
		rc = wifi_scan_networks(adw_wmi_scan_result_handler, NULL);
	}
	if (rc != RTW_SUCCESS) {
		adw_wmi_log_err("Wifi scan", rc);
		return WIFI_ERR_MEM;
	}
	return WIFI_ERR_NONE;
}

enum wifi_error adw_wmi_join(struct adw_state *wifi, struct adw_profile *prof)
{
	int rc;
	struct adw_scan *scan = prof->scan;
	struct adw_wmi_state *wmi = &adw_wmi_state;

	AYLA_ASSERT(scan);

	if (scan->wmi_sec == RTW_SECURITY_WEP_PSK
	    || scan->wmi_sec == RTW_SECURITY_WEP_SHARED) {
		return WIFI_ERR_SEC_UNSUP;
	}

	if (wmi->wifi_mode == RTW_MODE_AP) {
		dhcps_deinit();
	}
	if (wmi->wifi_mode != RTW_MODE_STA) {
		wifi_off();
		vTaskDelay(100);
		rc = wifi_on(RTW_MODE_STA);
		if (rc < 0) {
			printf("\n");
			adw_wmi_log_err("Wifi on", rc);
			return WIFI_ERR_MEM;
		}
	}
	netif_set_up(wifi->nif_sta);
	netif_set_default(wifi->nif_sta);

	/* Connect to AP  */
	rc = wifi_connect((char *)(prof->ssid.id),
	    (rtw_security_t)scan->wmi_sec,
	    (char *)(prof->key), prof->ssid.len, prof->key_len, -1, NULL);
	printf("\n");
	if (rc != RTW_SUCCESS) {
		adw_wmi_log_err("Wifi join", rc);
		return WIFI_ERR_MEM;	/* XXX maybe not accurate */
	}
	return WIFI_ERR_NONE;
}

int adw_wmi_leave(struct adw_state *wifi)
{
	struct adw_wmi_state *wmi = &adw_wmi_state;
	int rc;

	rc = wifi_is_connected_to_ap();
	if (rc != RTW_SUCCESS) {
		return WIFI_ERR_NONE;
	}

	rc = wifi_disconnect();
	printf("\n");
	if (rc != RTW_SUCCESS) {
		adw_wmi_log_err("Wifi disconnect", rc);
		return WIFI_ERR_MEM;
	}

	return WIFI_ERR_NONE;
}

enum wifi_error adw_wmi_conn_status(int ap_mode)
{
	struct adw_state *wifi = &adw_state;
	struct adw_wmi_state *wmi = &adw_wmi_state;
	enum wifi_error err = WIFI_ERR_NONE;
	int sta_state;

	if (ap_mode) {
		if (RTW_SUCCESS == wifi_is_up(RTW_AP_INTERFACE)) {
			if (!(wifi->nif_ap->flags & NETIF_FLAG_LINK_UP)) {
				adw_log(LOG_DEBUG
				    "wmi_conn_status: AP link up");
			}
			netif_set_link_up(wifi->nif_ap);
		} else {
			if (wifi->nif_ap->flags & NETIF_FLAG_LINK_UP) {
				adw_log(LOG_DEBUG
				    "wmi_conn_status: AP link down");
			}
			netif_set_link_down(wifi->nif_ap);
			err = WIFI_ERR_MEM;	/* XXX what's right? */
		}
	} else {
		if (RTW_SUCCESS == wifi_is_connected_to_ap()) {
			if (!(wifi->nif_sta->flags & NETIF_FLAG_LINK_UP)) {
				adw_log(LOG_DEBUG
				    "wmi_conn_status: sta link up");
			}
			netif_set_link_up(wifi->nif_sta);
		} else {
			if (wifi->nif_sta->flags & NETIF_FLAG_LINK_UP) {
				adw_log(LOG_DEBUG
				    "wmi_conn_status: sta state %u", sta_state);
				adw_log(LOG_DEBUG
				    "wmi_conn_status: sta link down");
			}
			netif_set_link_down(wifi->nif_sta);
			if (err == WIFI_ERR_NONE) {
				err = WIFI_ERR_IN_PROGRESS;
			}
		}
	}
	return err;
}

/*
 * Start DHCP client on station interface.
 */
void adw_wmi_ipconfig(struct adw_state *wifi)
{
	LwIP_DHCP(0, 0);
}

int adw_wmi_dhcp_poll(struct adw_state *wifi, struct adw_wifi_history *hist)
{
	int i;

	if (!netif_is_up(wifi->nif_sta)) {
		return -1;
	}
	hist->ip_addr = wifi->nif_sta->ip_addr;
	hist->netmask = wifi->nif_sta->netmask;
	hist->def_route = wifi->nif_sta->gw;

	for (i = 0; i < min(DNS_MAX_SERVERS, WIFI_HIST_DNS_SERVERS); i++) {
		hist->dns_servers[i] = dns_getserver(i);
	}
	return 0;
}

/*
 * Start AP mode.
 * Only handles open AP mode for now - no Wi-Fi security.
 */
int adw_wmi_start_ap(struct adw_profile *prof, int chan)
{
	struct adw_wmi_state *wmi = &adw_wmi_state;
	struct adw_state *wifi = &adw_state;
	int rc;

	if (wmi->wifi_mode != RTW_MODE_AP) {
		wmi->wifi_mode = RTW_MODE_AP;
		wifi_off();
		vTaskDelay(20);
		rc = wifi_on(RTW_MODE_AP);
		if (rc != RTW_SUCCESS) {
			printf("\n");
			adw_wmi_log_err("Wifi on failed!", rc);
			return WIFI_ERR_MEM; /* Hardware driver fail */
		}
		wifi_disable_powersave();

		rc = wifi_start_ap((char *)(prof->ssid.id), RTW_SECURITY_OPEN,
		    NULL, prof->ssid.len, 0, chan);
		if (rc != RTW_SUCCESS) {
			printf("\n");
			adw_wmi_log_err("Wifi start AP", rc);
			return WIFI_ERR_MEM; /* Hardware driver fail */
		}

		netif_set_addr(wifi->nif_ap, &wifi->ap_mode_addr,
		    &wifi->ap_mode_netmask, &wifi->ap_mode_addr);
		dhcps_init(wifi->nif_ap);
		printf("\n");
	}

	return WIFI_ERR_NONE;
}

void adw_wmi_stop_ap(void)
{
	int rc;
	struct adw_wmi_state *wmi = &adw_wmi_state;

	if (wmi->wifi_mode == RTW_MODE_AP) {
		wmi->wifi_mode = RTW_MODE_STA;
		dhcps_deinit();
		rc = wifi_off();
		if (rc) {
			printf("\n");
			adw_wmi_log_err("Wifi stop AP", rc);
		}
		vTaskDelay(100);
		rc = wifi_on(RTW_MODE_STA);
		printf("\n");
		if (rc) {
			adw_wmi_log_err("Wifi stop AP", rc);
		}
	}
}

int adw_wmi_get_mac_addr(int ap, u8 *mac)
{
	struct adw_state *wifi = &adw_state;

	memcpy(mac, LwIP_GetMAC(ap ? wifi->nif_ap : wifi->nif_sta), 6);
	return 0;
}

/*
 * Allocate station and AP mode interfaces after first Wi-Fi start.
 */
static void adw_wmi_init_if(void)
{
	struct adw_state *wifi = &adw_state;

	if (wifi->init_if_done) {
		return;
	}
	wifi->init_if_done = 1;

	wifi->ap_mode_addr.addr = htonl(ADW_WIFI_AP_IP);
	wifi->ap_mode_netmask.addr = htonl(ADW_WIFI_AP_NETMASK);
	memcpy(conf_sys_mac_addr, LwIP_GetMAC(wifi->nif_sta),
	    sizeof(conf_sys_mac_addr));
}

int adw_wmi_on(void)
{
	struct adw_wmi_state *wmi = &adw_wmi_state;
	struct adw_state *wifi = &adw_state;
	int rc;

	wifi->nif_sta = &xnetif[0];
	wifi->nif_ap = &xnetif[0];
	adw_wmi_init_if();
	if (wmi->wifi_mode != RTW_MODE_STA) {
		wmi->wifi_mode = RTW_MODE_STA;
		wifi_off();
		vTaskDelay(100);
		rc = wifi_on(RTW_MODE_STA);
		printf("\n");
		if (rc) {
			adw_wmi_log_err("Wifi on", rc);
		}
	}

	return 0;
}

void adw_wmi_off(void)
{
	struct adw_wmi_state *wmi = &adw_wmi_state;

	if (wmi->wifi_mode != RTW_MODE_NONE) {
		wmi->wifi_mode = RTW_MODE_NONE;
		wifi_off();
		printf("\n");
	}
}

void adw_wmi_init(void)
{
	struct adw_wmi_state *wmi = &adw_wmi_state;

	adw_sema = xSemaphoreCreateMutex();

	wmi->wifi_mode = RTW_MODE_STA;
}
