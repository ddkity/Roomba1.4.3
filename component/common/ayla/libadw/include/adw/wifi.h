/*
 * Copyright 2011-2016 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ADW_WIFI_H__
#define __AYLA_ADW_WIFI_H__

#define ADW_WIFI_PROF_CT	11	/* number of profiles */
#define ADW_WIFI_PROF_AP	(ADW_WIFI_PROF_CT - 1) /* profile for AP mode */
#define ADW_WIFI_SCAN_CT	20	/* number of scan results kept */

#define WIFI_IOS_APP_LEN	16

enum adw_wifi_powersave_mode {
	ADW_WIFI_PS_OFF,		/* Power savings off */
	ADW_WIFI_PS_ON,			/* Power save on */
	ADW_WIFI_PS_ON_LESS_BEACONS,	/* Savings on, beacon itvl adjusted */
};

enum adw_wifi_event_id {
	ADW_EVID_ENABLE,
	ADW_EVID_DISABLE,
	ADW_EVID_ASSOCIATING,
	ADW_EVID_SETUP_START,
	ADW_EVID_SETUP_STOP,
	ADW_EVID_STA_DOWN,
	ADW_EVID_STA_UP,
	ADW_EVID_STA_DHCP_UP,
	ADW_EVID_AP_START,
	ADW_EVID_AP_DOWN,
	ADW_EVID_AP_UP,
	ADW_EVID_RESTART_FAILED,
};

#ifdef AYLA_WIFI_SUPPORT

extern struct net_callback adw_wifi_cbmsg_delayed;
extern char adw_wifi_ios_app[WIFI_IOS_APP_LEN];

void adw_wifi_init(void);
void adw_wifi_show_rssi(int argc, char **argv);
void adw_wifi_show(void);
int adw_wifi_fw_open(u16 conf_inode, u32 index);
void adw_wifi_powersave(enum adw_wifi_powersave_mode);
int adw_wifi_configured(void);
int adw_wifi_configured_nolock(void);
void adw_wifi_start_scan(u32 min_interval);
int adw_wifi_scan_result_count(void);
void adw_wifi_cli(int argc, char **argv);
int adw_wifi_join_rx(void *buf, int len);
int adw_wifi_delete_rx(void *buf, int len);
int adw_wifi_in_ap_mode(void);
void adw_wifi_stop(void);
int adw_wifi_start_wps(void);
int adw_wifi_start_aks_ext(void *arg);
void adw_wifi_stop_aks_ext(void *arg);
void adw_wifi_stayup(void);
void adw_wifi_show_hist(int to_log);

struct server_req;
void adw_wifi_http_ios_get(struct server_req *);

void adw_wifi_event_register(void (*fn)(enum adw_wifi_event_id, void *arg),
				void *arg);

/*
 * Wi-Fi synchronization interfaces.
 */
void adw_lock(void);
void adw_unlock(void);

extern u8 adw_locked;			/* for ASSERTs only */

#else /* no AYLA_WIFI_SUPPORT */

static inline void adw_wifi_init(void) {}
static inline void adw_wifi_powersave(enum adw_wifi_powersave_mode mode) {}
static inline int adw_wifi_configured(void) { return 0; }
static inline void adw_wifi_show_hist(int to_log) {}
static inline void adw_wifi_event_register(void (*fn)(enum adw_wifi_event_id,
			void *arg), void *arg) {}

#endif /* AYLA_WIFI_SUPPORT */

/*
 * Return non-zero if the current Wi-Fi connection was setup by MFi.
 */
int adw_wifi_was_setup_by_mfi(void);

/*
 * Network interfaces.
 */
struct netif *adw_wifi_ap_netif(void);
struct netif *adw_wifi_sta_netif(void);
struct netif *adw_wifi_netif(void);

/*
 * Server interfaces.
 */
void adw_wifi_page_init(int enable_redirect);

#endif /* __AYLA_ADW_WIFI_H__ */
