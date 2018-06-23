/*
 * Copyright 2011-2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <ayla/utypes.h>
#include <ayla/endian.h>
#include <ayla/assert.h>
#include <ayla/clock.h>
#include <ayla/log.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <ayla/parse.h>
#include <ayla/tlv.h>
#include <ayla/wifi_status.h>
#include <ada/err.h>
#include <net/net.h>
#include <ayla/mod_log.h>
#include <adw/wifi.h>
#include <adw/wifi_conf.h>
#include <ayla/timer.h>
#include "wifi_int.h"
#include "wifi_timer.h"
#include <ada/client.h>
#include <ada/dnss.h>
#include <ada/ada_wifi.h>
#include <ayla/malloc.h>

#ifdef AIRKISS
#include "wifi_airkiss.h"
static u8 adw_aks_send_fin;
#endif

#ifdef NFC_WIFI_SETUP
#include "nfc.h"
#endif

static char ssid_hostname[33];
const char * const adw_wifi_errors[] = WIFI_ERRORS;

struct adw_state adw_state;
ADW_SIZE_INIT				/* for ADW_SIZE_DEBUG */

static struct net_callback adw_wifi_cbmsg_join;
static struct net_callback adw_wifi_cbmsg_step;
struct net_callback adw_wifi_cbmsg_delayed;

static int adw_wifi_start(void);
static void adw_wifi_step_cb(void *);
static void adw_wifi_stop_ap(void *arg);
static void adw_wifi_scan2prof(struct adw_state *wifi, u8 scan_prof);

struct adw_wifi_event_handler {
	void (*handler)(enum adw_wifi_event_id, void *);
	void *arg;
};
static struct adw_wifi_event_handler adw_wifi_event_handler;

struct adw_wifi_event {
	struct adw_wifi_event *next;
	enum adw_wifi_event_id id;
};
static struct adw_wifi_event *adw_wifi_event_queue;
static struct net_callback adw_wifi_cbmsg_event;

static struct timer adw_wifi_rssi_timer;
static struct timer adw_wifi_scan_timer;
static struct timer adw_wifi_step_timer;
static struct timer adw_wifi_join_timer;
static struct timer adw_wifi_client_timer;
static struct timer adw_wifi_ap_mode_timer;
#ifdef WIFI_WPS
static struct timer adw_wifi_wps_timer;
#endif
#ifdef AIRKISS
static struct timer adw_wifi_aks_timer;
#endif
#ifdef NFC_WIFI_SETUP
static struct timer adw_wifi_nfc_timer;
#endif

/*
 * Register for event callback.
 * Currently limited to one callback to the platform code.  More later?
 * Callback is in the Wi-Fi thread.  Callee must handle any softcalls needed.
 */
void adw_wifi_event_register(void (*handler)(enum adw_wifi_event_id, void *),
				void *arg)
{
	struct adw_wifi_event_handler *hp = &adw_wifi_event_handler;

	ASSERT(!hp->handler);
	hp->handler = handler;
	hp->arg = arg;
}

/*
 * Handle all queued events.
 * The adw_lock is dropped during the event handler.
 */
void adw_wifi_event_cb(void *wifi_arg)
{
	struct adw_wifi_event_handler *hp;
	struct adw_wifi_event *ev;
	enum adw_wifi_event_id id;
	void (*handler)(enum adw_wifi_event_id, void *);
	void *arg;

	adw_lock();
	while ((ev = adw_wifi_event_queue) != NULL) {
		adw_wifi_event_queue = ev->next;
		id = ev->id;

		hp = &adw_wifi_event_handler;
		handler = hp->handler;
		arg = hp->arg;
		adw_unlock();
		free(ev);

		if (handler) {
			handler(id, arg);
		}

		adw_lock();
	}
	adw_unlock();
}

/*
 * Post an event callback.
 */
void adw_wifi_event_post(enum adw_wifi_event_id id)
{
	struct adw_wifi_event *ev;

	ev = calloc(1, sizeof(*ev));
	if (!ev) {
		adw_log(LOG_ERR "malloc failed for event");
		return;
	}
	ev->id = id;
	ev->next = adw_wifi_event_queue;
	adw_wifi_event_queue = ev;
	adw_wmi_callback_pend(&adw_wifi_cbmsg_event);
}

void adw_log(const char *fmt, ...)
{
	ADA_VA_LIST args;

	ADA_VA_START(args, fmt);
	log_put_va(MOD_LOG_WIFI, fmt, args);
	ADA_VA_END(args);
}

static inline int ether_addr_non_zero(u8 *mac)
{
	return (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) != 0;
}

/*
 * Get new connection history entry.
 * Called with lock held.
 */
struct adw_wifi_history *adw_wifi_hist_new(struct adw_state *wifi,
    struct adw_ssid *ssid, struct adw_scan *scan)
{
	struct adw_wifi_history *hist;

	if (++wifi->hist_curr >= WIFI_HIST_CT) {
		wifi->hist_curr = 0;
	}
	hist = &wifi->hist[wifi->hist_curr];
	memset(hist, 0, sizeof(*hist));
	hist->time = clock_ms();
	hist->ssid_info[0] = ssid->id[0];
	hist->ssid_info[1] = ssid->len < 2 ? '\0' : ssid->id[ssid->len - 1];
	hist->ssid_len = ssid->len;
	if (scan) {
		memcpy(hist->bssid, scan->bssid, sizeof(hist->bssid));
	}
	if (wifi->pref_profile) {
		adw_wifi_hist_clr_curr(wifi);
		hist->curr = 1;
	}
	return hist;
}

void adw_wifi_hist_clr_curr(struct adw_state *wifi)
{
	struct adw_wifi_history *old;

	for (old = wifi->hist; old < &wifi->hist[WIFI_HIST_CT]; old++) {
		old->curr = 0;
	}
}

/*
 * Convert received signal strength to bar-graph intensity.
 * Any signal should give at least one bar.  Max signal is 5 bars.
 * Lean towards giving 5 bars for a wide range of usable signals.
 */
u8 adw_wifi_bars(int signal)
{
	if (signal == WIFI_MIN_SIG) {
		return 0;
	}
	if (signal < -70) {
		return 1;
	}
	if (signal < -60) {
		return 2;
	}
	if (signal < -50) {
		return 3;
	}
	if (signal < -40) {
		return 4;
	}
	return 5;
}

/*
 * Return non-hyphenated security token string.
 */
const char *adw_wifi_conf_string(enum conf_token token)
{
	if (token == CT_WPA2_Personal) {
		return "WPA2 Personal";
	}
	return conf_string(token);
}

static int adw_profile_cnt(struct adw_state *wifi)
{
	struct adw_profile *prof;
	int enabled_entries = 0;

	for (prof = wifi->profile;
	     prof < &wifi->profile[ADW_WIFI_PROF_AP]; prof++) {
		if (prof->ssid.len && prof->enable) {
			enabled_entries++;
		}
	}
	return enabled_entries;
}

static void adw_wifi_step_cb_pend(struct adw_state *wifi)
{
	adw_wmi_callback_pend(&adw_wifi_cbmsg_step);
}

static void adw_wifi_step_timeout(struct timer *timer)
{
	adw_wifi_step_cb_pend(&adw_state);
}

static void adw_wifi_step_arm_timer(void *wifi_arg)
{
	adw_lock();
	adw_wmi_timer_set(&adw_wifi_step_timer, WIFI_CMD_RSP_TMO);
	adw_unlock();
}

static void adw_wifi_commit_locked(struct adw_state *wifi)
{
	adw_wifi_scan2prof(wifi, 0);
	if (wifi->state == WS_UP && !wifi->profile[wifi->curr_profile].enable) {
		adw_wifi_rejoin(wifi);
	} else {
		adw_wifi_step_cb_pend(wifi);
	}
}

void adw_wifi_commit(int from_ui)
{
	struct adw_state *wifi = &adw_state;

	adw_lock();
	adw_wifi_commit_locked(wifi);
	adw_unlock();
}

static void adw_wifi_enable_set(int enable)
{
	struct adw_state *wifi = &adw_state;

	adw_lock();
	if (wifi->enable != enable) {
		wifi->enable = enable;
		adw_wifi_commit_locked(wifi);
	}
	adw_unlock();
}

void adw_wifi_enable(void)
{
	adw_wifi_enable_set(1);
}

void adw_wifi_disable(void)
{
	adw_wifi_enable_set(0);
}

int adw_wifi_is_enabled(void)
{
	struct adw_state *wifi = &adw_state;

	return wifi->enable;
}

void adw_wifi_force_ap_mode(void)
{
	struct adw_state *wifi = &adw_state;

	adw_lock();
	wifi->pref_profile = ADW_WIFI_PROF_AP + 1;
	wifi->profile[ADW_WIFI_PROF_AP].join_errs = 0;
	adw_wifi_rejoin(wifi);
	adw_unlock();
}

void adw_wifi_unforce_ap_mode(void)
{
	struct adw_state *wifi = &adw_state;

	adw_lock();
	if (wifi->pref_profile == ADW_WIFI_PROF_AP + 1) {
		wifi->pref_profile = 0;
	}
	adw_wifi_rejoin(wifi);
	adw_unlock();
}

static void adw_wifi_clear_pref_profile(struct adw_state *wifi)
{
	if (wifi->pref_profile - 1 != ADW_WIFI_PROF_AP) {
		/*
		 * If AP profile was selected specifically, keep using
		 * until something else is selected, or system restarts.
		 */
		wifi->pref_profile = 0;
	}
}

void adw_wifi_save_profiles(void)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;

	adw_lock();
	if (wifi->curr_profile + 1 == wifi->pref_profile) {
		prof = &wifi->profile[wifi->curr_profile];
		prof->enable = 1;
		adw_wifi_clear_pref_profile(wifi);
	}
	adw_unlock();
	conf_persist(CT_wifi, adw_wifi_export_profiles, wifi);
}

/*
 * Log failed history entry.
 */
static void adw_wifi_hist_log(struct adw_state *wifi,
				struct adw_wifi_history *hist)
{
	struct adw_profile *prof;
	char ssid_buf[33];

	if (hist->error == WIFI_ERR_NONE) {
		return;
	}
	if (!wifi->pref_profile && hist->error == WIFI_ERR_NOT_FOUND) {
		return;
	}
	prof = &wifi->profile[wifi->curr_profile];
	snprintf(wifi->err_buf, sizeof(wifi->err_buf) - 1,
	    "Wi-Fi connect to %s: %s",
	    adw_format_ssid(&prof->ssid, ssid_buf, sizeof(ssid_buf)),
	    adw_wifi_errors[hist->error]);
	wifi->err_msg = wifi->err_buf;
	adw_log(LOG_WARN "%s", wifi->err_buf);
}

/*
 * Join attempt failed. Are we giving up on this profile?
 * We only record this for preferred profiles, i.e. tentative profiles.
 */
static int adw_wifi_current_profile_done(struct adw_state *wifi,
					struct adw_wifi_history *hist)
{
	struct adw_profile *prof;

	adw_wifi_hist_log(wifi, hist);
	if (wifi->curr_profile != wifi->pref_profile - 1) {
		return 0;
	}
	prof = &wifi->profile[wifi->curr_profile];
	if (prof->join_errs >= WIFI_PREF_TRY_LIMIT) {
#ifdef MFI
		/* MFi connect attempt failed restart adv MFi service */
		dnss_mdns_start(DNSS_ADV_MFI);
#endif
		hist->last = 1;
		return 1;
	}
	return 0;
}

static void adw_wifi_service_fail(struct adw_state *wifi)
{
	struct adw_wifi_history *hist;
	struct adw_profile *prof;

	if (wifi->state == WS_DHCP || wifi->state == WS_WAIT_CLIENT) {
		hist = &wifi->hist[wifi->hist_curr];
		if (wifi->state == WS_DHCP) {
			/*
			 * TBD: Can't distinguish between no IP and no gateway.
			 */
			hist->error = WIFI_ERR_NO_IP;
		} else {
			hist->error = client_status();
		}
		switch (hist->error) {
		case WIFI_ERR_CLIENT_AUTH:
			/*
			 * Don't rejoin on authentication error.
			 */
			if (wifi->curr_profile == wifi->pref_profile - 1) {
				hist->last = 1;
				adw_wifi_hist_log(wifi, hist);
			}
			break;
		default:
			prof = &wifi->profile[wifi->curr_profile];
			if ((wifi->state == WS_WAIT_CLIENT && prof->enable &&
				client_lanmode_is_enabled()) || prof->mfi) {
				/*
				 * Don't rejoin if this is a LAN-enabled device
				 * and the profile had successfully reached the
				 * service at some point. This is to allow the
				 * device to have LAN registrations.
				 *
				 * Or if this profile was configured with MFI.
				 */
				break;
			}
			prof->join_errs++;
			adw_wifi_current_profile_done(wifi, hist);
			adw_log(LOG_WARN "timeout: timed out waiting for %s",
			    wifi->state == WS_DHCP ? "DHCP" : "ADS");
			adw_wifi_rejoin(wifi);
		}
	}
}

/*
 * Timeout waiting for DHCP or client connection to the device service.
 */
static void adw_wifi_client_timeout(struct timer *timer)
{
	struct adw_state *wifi = &adw_state;

	adw_lock();
	adw_wifi_service_fail(wifi);
	adw_unlock();
}

/*
 * Callback when client connection status changes.
 * May be called with the wifi lock held.
 */
void adw_wifi_client_event(void *arg, enum ada_err err)
{
	struct adw_state *wifi = arg;

	adw_log(LOG_DEBUG "%s: %d", __func__, err);
	wifi->client_err = err;
	adw_wifi_step_cb_pend(wifi);
}

/*
 * Return non-zero if a new security setting is a downgrade.
 */
int adw_wifi_sec_downgrade(enum conf_token new, enum conf_token old)
{
	/* these asserts are evaluated at compile time. */
	ASSERT(CT_none < CT_WEP);
	ASSERT(CT_WEP < CT_WPA);
	ASSERT(CT_WPA < CT_WPA2_Personal);

	return new < old;
}

int adw_ssids_match(const struct adw_ssid *a, const struct adw_ssid *b)
{
	return a->len == b->len && !memcmp(a->id, b->id, a->len);
}

/*
 * Lookup profile by SSID.
 * Called with lock held.
 */
struct adw_profile *
adw_wifi_prof_lookup(struct adw_state *wifi, const struct adw_ssid *ssid)
{
	struct adw_profile *prof;

	for (prof = wifi->profile;
	    prof < &wifi->profile[ADW_WIFI_PROF_AP]; prof++) {
		if (adw_ssids_match(&prof->ssid, ssid)) {
			return prof;
		}
	}
	return NULL;
}

struct adw_profile *
adw_wifi_prof_search(struct adw_state *wifi, const struct adw_ssid *ssid)
{
	struct adw_profile *prof;

	prof = adw_wifi_prof_lookup(wifi, ssid);
	if (prof) {
		return prof;
	}
	for (prof = wifi->profile;
	     prof < &wifi->profile[ADW_WIFI_PROF_AP]; prof++) {
		if (prof->ssid.len == 0) {
			return prof;
		}
	}
	return NULL;
}

void adw_wifi_rejoin(struct adw_state *wifi)
{
	wifi->rejoin = 1;
	adw_wifi_step_cb_pend(wifi);
}

static void adw_wifi_rescan(struct timer *timer)
{
	struct adw_state *wifi = &adw_state;

	adw_lock();
	if (wifi->scan_state == SS_SCAN_WAIT) {
		adw_wifi_scan(wifi);
	} else if (wifi->scan_state == SS_SCAN) {
		if (wifi->enable) {
			adw_log(LOG_WARN "scan timeout");
		}
		wifi->scan_state = SS_DONE;
		adw_wifi_scan2prof(wifi, 0);
		adw_wifi_rejoin(wifi);
	}
	adw_unlock();
}

/*
 * Update profile data items to matching scan entries.
 */
static void adw_wifi_scan2prof(struct adw_state *wifi, u8 scan_prof)
{
	struct adw_profile *prof;
	struct adw_scan *scan;
	enum conf_token sec;

	if (!scan_prof) {
		for (prof = wifi->profile;
		    prof < &wifi->profile[ADW_WIFI_PROF_AP]; prof++) {
			prof->scan = NULL;
		}
	}
	for (scan = &wifi->scan[ADW_WIFI_SCAN_CT - 1];
	    scan >= wifi->scan; scan--) {
		if (scan->ssid.len == 0) {
			continue;
		}
		prof = adw_wifi_prof_lookup(wifi, &scan->ssid);
		if (!prof) {
			continue;
		}
		sec = adw_wmi_sec_import(scan->wmi_sec);
		if ((sec == CT_none || prof->key_len) &&
		    !adw_wifi_sec_downgrade(sec, prof->sec)) {
			prof->scan = scan;
			if (!scan_prof && !prof->spec_scan_done) {
				prof->hidden = 0;
			}
		}
	}
}

#ifdef WIFI_WPS
static void adw_wifi_wps_timeout(struct timer *timer)
{
	struct adw_state *wifi = &adw_state;

	if (adw_wmi_wps_get_result()) {
		adw_wmi_timer_set(&adw_wifi_wps_timer, WIFI_WPS_POLL);
		return;
	}
	wifi->wps_done = 1;
	adw_wifi_event_post(ADW_EVID_SETUP_STOP);
	adw_wifi_step_cb_pend(wifi);
}
#endif

int adw_wifi_start_wps(void)
{
	int rc = -1;
#ifdef WIFI_WPS
	struct adw_state *wifi = &adw_state;

	adw_lock();
	if (!wifi->enable || wifi->state != WS_UP_AP) {
		adw_log(LOG_ERR "WPS: not in AP mode");
		adw_unlock();
		return -1;
	}
	adw_wifi_event_post(ADW_EVID_SETUP_START);
	adw_log(LOG_INFO "WPS started");
	wifi->wps_done = 0;
	wifi->wps_aborted = 0;
	wifi->pref_profile = 0;
	if (adw_wmi_wps_start()) {
		goto error;
	}
	wifi->state = WS_WPS;
	adw_wmi_timer_cancel(&adw_wifi_scan_timer);
	adw_wmi_timer_set(&adw_wifi_wps_timer, WIFI_WPS_POLL);
	rc = 0;
error:
	adw_unlock();
	if (rc) {
		adw_log(LOG_ERR "WPS err %d", rc);
	}
#else
	adw_log(LOG_ERR "no WPS");
#endif
	return rc;
}

/*
 * This is called in the Wi-Fi thread, which can have a shallow stack,
 * so don't do printfs here.
 */
void adw_wifi_scan_callback(struct adw_scan *rp)
{
	struct adw_state *wifi = &adw_state;
	struct adw_scan *best;
	struct adw_scan *scan;
	int i;

	/*
	 * XXX scan_status might indicate aborted scan WICED_SCAN_ABORTED
	 * seems that would also give us a NULL resultp which also indicates
	 * a terminated scan.  What should we do differently?
	 */
	adw_lock();
	if (rp == NULL) {
		wifi->scan_state = SS_DONE;
		adw_wifi_step_cb_pend(wifi);
		adw_wmi_timer_cancel(&adw_wifi_scan_timer);
		goto out;
	}

	/*
	 * Toss scan results that have empty or all-zeroes SSID.
	 */
	for (i = 0; i < rp->ssid.len; i++) {
		if (rp->ssid.id[i]) {
			break;
		}
	}
	if (i >= rp->ssid.len) {
		goto out;
	}

	if (adw_ssids_match(&rp->ssid, &wifi->scan4)) {
		/*
		 * If doing scan for specific target, make sure there's spot
		 * for it.
		 */
		best = &wifi->scan[0];
	} else {
		best = NULL;
	}

	/*
	 * Replace an entry in the scan list that is empty,
	 * has the same SSID but a weaker signal,
	 * or has a weakest signal that's also weaker than the new result.
	 * But drop the scan result if it is a known SSID but not stronger.
	 * If hearing from multiple base stations with different security or
	 * band, keep both entries.
	 */
	for (scan = wifi->scan; scan < &wifi->scan[ADW_WIFI_SCAN_CT]; scan++) {
		if (scan->ssid.len == 0) {
			if (!best) {
				best = scan;
			}
			break;
		}
		if (!best && rp->rssi > scan->rssi) {
			best = scan;
		}
		if (adw_ssids_match(&rp->ssid, &scan->ssid) &&
		    rp->wmi_sec == scan->wmi_sec) {
			break;
		}
	}
	if (best) {
		/*
		 * Move from scan to best.
		 */
		if (best != scan) {
			if (scan == &wifi->scan[ADW_WIFI_SCAN_CT]) {
				/*
				 * Last item will fall off.
				 */
				scan--;
			}
			memmove(best + 1, best, (scan - best) * sizeof(*scan));
		}
		*best = *rp;
	}

out:
	adw_unlock();
}

/*
 * Select next candidate for joining.
 * Choose the AP with the strongest signal first.
 *
 * Called with lock held.
 */
static struct adw_profile *adw_wifi_select(struct adw_state *wifi)
{
	struct adw_profile *prof;
	struct adw_profile *best = NULL;
#ifdef WIFI_DEBUG
	char ssid_buf[33];
#endif

	if (wifi->pref_profile) {
		prof = &wifi->profile[wifi->pref_profile - 1];
		if (prof->join_errs < WIFI_PREF_TRY_LIMIT) {
			return prof;
		}
		wifi->pref_profile = 0;
	}
	for (prof = wifi->profile; prof < &wifi->profile[ADW_WIFI_PROF_AP];
	    prof++) {
		if (prof->ssid.len == 0 || prof->enable == 0) {
			continue;
		}
#ifdef WIFI_DEBUG
		adw_log(LOG_DEBUG "select: consider prof %u "
		    "ssid %s sec %s signal %d errs %u",
		    prof - wifi->profile,
		    adw_format_ssid(&prof->ssid, ssid_buf, sizeof(ssid_buf)),
		    conf_string(prof->sec), prof->signal,
		    prof->join_errs);
#endif /* WIFI_DEBUG */
		if (!prof->mfi) {
			if (prof->join_errs >= WIFI_JOIN_TRY_LIMIT) {
				continue;
			}
			if (!prof->scan) {
				continue;
			}
		}
		if (!best || !best->scan || (prof->scan &&
		    prof->scan->rssi > best->scan->rssi)) {
			best = prof;
		}
	}
	return best;
}

/*
 * We will attempt to heal ourselves by resetting wifi chip if
 * a) there are configured profiles AND
 * b) we've tried all of them 3 times AND
 * c) there has not been activity with our local server recently
 *
 * We will attempt to heal ourselves by resetting whole module if
 * a) we've attempted wifi reset 3 times and that didn't work AND
 * b) there has not been activity with our local server or console recently
 */
static int adw_wifi_health_check(struct adw_state *wifi)
{
	if (conf_setup_mode || conf_mfg_mode) {
		return 0;
	}
	if (++wifi->fail_cnt < WIFI_MAX_FAILS) {
		return 0;
	}
	wifi->fail_cnt = 0;
	return 1;
}

void adw_wifi_stayup(void)
{
	struct adw_state *wifi = &adw_state;

	wifi->fail_cnt = 0;
	wifi->reset_cnt = 0;
	wifi->use_time = clock_ms();
}

void adap_wifi_stayup(void)
{
	adw_wifi_stayup();
}

/*
 * Initialize RSSI samples.
 * Call right after join.
 * Set all samples the same to start with.
 * Called with lock held.
 */
static void adw_wifi_init_rssi(struct adw_state *wifi)
{
	int rssi;

	adw_wmi_get_rssi(&rssi);
	memset(wifi->rssi_reading, rssi, WIFI_RSSI_CT);
	wifi->rssi_total = rssi * WIFI_RSSI_CT;
	wifi->rssi_index = 1;
}

/*
 * Add a periodic RSSI sample to the accumulated samples and total.
 * Called with lock held.
 */
static void adw_wifi_sample_rssi(struct adw_state *wifi)
{
	s8 *entry;
	s8 old;
	int rssi;

	if (adw_wmi_get_rssi(&rssi)) {
		return;
	}
	entry = &wifi->rssi_reading[wifi->rssi_index];
	wifi->rssi_index = (wifi->rssi_index + 1) % WIFI_RSSI_CT;
	old = *entry;
	wifi->rssi_total += rssi - old;
	*entry = rssi;
#ifdef WIFI_DEBUG
	adw_log(LOG_DEBUG "sample_rssi: RSSI %d avg %d",
	    rssi, wifi->rssi_total / WIFI_RSSI_CT);
#endif /* WIFI_DEBUG */
}

int adw_wifi_avg_rssi(void)
{
	struct adw_state *wifi = &adw_state;
	int total = 0;
	int count = 0;
	int i;

	if (wifi->state >= WS_DHCP && wifi->state <= WS_UP) {
		adw_wifi_sample_rssi(wifi);
	}
	for (i = 0; i < WIFI_RSSI_CT; i++) {
		if (wifi->rssi_reading[i]) {
			total += wifi->rssi_reading[i];
			count++;
		}
	}
	if (count) {
		return total / count;
	}
	return WIFI_MIN_SIG;
}

static void adw_wifi_send_or_get_ant(struct adw_state *wifi)
{
	int txant;

	if (wifi->send_ant) {
		adw_wmi_sel_ant(wifi->ant);
	} else {
		if (!adw_wmi_get_txant(&txant)) {
			wifi->ant = txant;
		}
	}
}

static void adw_wifi_send_or_get_tx_power(struct adw_state *wifi)
{
	u8 tx_power;

	if (wifi->tx_power) {
		adw_wmi_set_tx_power(wifi->tx_power);
	} else {
		if (!adw_wmi_get_tx_power(&tx_power)) {
			wifi->tx_power = tx_power;
		}
	}
}

static void adw_wifi_rssi_timeout(struct timer *timer)
{
	struct adw_state *wifi = &adw_state;
	int antdiv;
	u8 tx_power;

	adw_lock();
	adw_wifi_sample_rssi(wifi);
	if (wifi->rssi_index) {
		adw_wmi_timer_set(&adw_wifi_rssi_timer, WIFI_RSSI_MIN_DELAY);
	} else {
		adw_log(LOG_INFO "RSSI average %d",
		    wifi->rssi_total / WIFI_RSSI_CT);
		if (!adw_wmi_get_rxant(&antdiv)) {
			adw_log(LOG_INFO "ant_div %d", antdiv);
		}
		if (!adw_wmi_get_txant(&antdiv)) {
			adw_log(LOG_INFO "txant %d", antdiv);
		}
		if (!adw_wmi_get_tx_power(&tx_power)) {
			adw_log(LOG_INFO "tx_power %d", tx_power);
		}
	}
	adw_unlock();
}

/*
 * Show the average RSSI.
 */
void adw_wifi_show_rssi(int argc, char **argv)
{
	struct adw_state *wifi = &adw_state;

	adw_lock();
	if (wifi->started) {
		adw_wifi_init_rssi(wifi);
		adw_wmi_timer_set(&adw_wifi_rssi_timer, WIFI_RSSI_MIN_DELAY);
	}
	adw_unlock();
}

/*
 * Check for Wi-Fi Join completion.
 */
static void adw_wifi_check_join(void *arg)
{
	struct adw_state *wifi = arg;
	struct adw_wifi_history *hist;
	struct adw_profile *prof = NULL;
	enum wifi_error err;
	struct netif *ifnet;

	err = adw_wmi_conn_status(0);	/* check STA interface status */
	adw_lock();
	adw_wmi_timer_cancel(&adw_wifi_join_timer);
	hist = &wifi->hist[wifi->hist_curr];

	switch (wifi->state) {
	case WS_JOIN:
		switch (err) {
		case WIFI_ERR_WRONG_KEY:
		case WIFI_ERR_NOT_AUTH:
			goto wait;
		case WIFI_ERR_NOT_FOUND:
		case WIFI_ERR_INV_KEY:
			goto fail;
		default:
			err = WIFI_ERR_TIME;

			/*
			 * Workaround for early status.
			 * If it's been less than X seconds, continue waiting,
			 * connect may yet complete.
			 */
wait:
			if (clock_ms() - wifi->hist[wifi->hist_curr].time >=
			    WIFI_JOIN_TIMEOUT) {
fail:
				hist->error = err;
				adw_log(LOG_DEBUG
				   "join failed %d will rescan", err);
				prof = &wifi->profile[wifi->curr_profile];
				if (err == WIFI_ERR_WRONG_KEY) {
					prof->join_errs += WIFI_JOIN_KEY_ERR;
				} else {
					prof->join_errs++;
				}

				adw_wifi_current_profile_done(wifi, hist);

				adw_wmi_leave(wifi);
				wifi->state = WS_IDLE;

				/*
				 * Profile count is zero if we're trying to
				 * connect to "preferred profile". This means
				 * wifi setup is going on.
				 */
				if (adw_profile_cnt(wifi)) {
					adw_wifi_scan(wifi);
				} else {
					wifi->state = WS_SCAN_DONE;
				}
				break;
			}
#ifdef WIFI_DEBUG
			adw_log(LOG_DEBUG "join status %d - "
			    "continue waiting", err);
#endif /* WIFI_DEBUG */
			adw_wmi_timer_set(&adw_wifi_join_timer, WIFI_JOIN_POLL);
			break;
		case WIFI_ERR_NONE:
			adw_log(LOG_INFO "join succeeded");

			ifnet = wifi->nif_sta;
			wifi->nif = ifnet;
			adw_format_ssid(&wifi->profile[ADW_WIFI_PROF_AP].ssid,
			   ssid_hostname, sizeof(ssid_hostname));
			if (wifi->profile[ADW_WIFI_PROF_AP].ssid.len) {
				net_netif_set_hostname(ifnet, ssid_hostname);
			}
			wifi->state = WS_DHCP;
			adw_wmi_timer_set(&adw_wifi_client_timer,
			    WIFI_DHCP_WAIT);
			adw_wmi_timer_set(&adw_wifi_join_timer, 1000);
			adw_wmi_ipconfig(wifi);
			net_netif_set_link_up(ifnet);
			adw_wifi_event_post(ADW_EVID_STA_UP);
			break;
		}
		adw_wifi_step_cb_pend(wifi);
		break;
	case WS_DHCP:
		adw_wifi_step_cb_pend(wifi);
		/* fallthrough */
	case WS_WAIT_CLIENT:
		if (err != WIFI_ERR_NONE) {
			prof = &wifi->profile[wifi->curr_profile];
			prof->join_errs++;
		}
		/* fallthrough */
	case WS_UP:
#ifdef AIRKISS
		if (adw_aks_send_fin) {
			adw_aks_send_fin = 0;
			adw_wifi_aks_send_fin();
		}
#endif
		/* fallthrough */
	case WS_UP_AP:
		if (err == WIFI_ERR_NONE) {
			adw_wifi_sample_rssi(wifi);
		}
		if (err != WIFI_ERR_NONE) {
			adw_log(LOG_WARN
			    "check_join: wifi down. status %d", err);
			wifi->rejoin = 1;
			/* TBD: can't tell between WIFI_ERR_LOS and AP_DISC */
			hist->error = WIFI_ERR_LOS;
			if (prof) {
				adw_wifi_current_profile_done(wifi, hist);
			}
			adw_wifi_step_cb_pend(wifi);
		} else {
			adw_wmi_timer_set(&adw_wifi_join_timer, WIFI_POLL);
		}
		break;
	case WS_DISABLED:
	case WS_IDLE:
	case WS_RESTART:
	case WS_SCAN_DONE:
	case WS_WPS:
	case WS_WPS_DONE:
	case WS_START_AP:
	case WS_ERROR:
		adw_log(LOG_WARN "check_join: unexpected state %x",
		    wifi->state);
		break;
	}
	adw_unlock();
}

static void adw_wifi_join_timeout(struct timer *timer)
{
	adw_wifi_check_join(&adw_state);
}

#ifdef AIRKISS

void adw_wifi_stop_aks_ext(void *arg)
{
	struct adw_state *wifi = &adw_state;

	adw_wifi_stop_aks(NULL);
	if (wifi->state == WS_UP_AP) {
		wifi->state = WS_START_AP;
		adw_wifi_rejoin(wifi);
	}
}

static void adw_wifi_aks_timeout(struct timer *timer)
{
	adw_wifi_stop_aks_ext(NULL);
}

#endif

#if defined(AIRKISS) || defined(NFC_WIFI_SETUP)
/*
 * Callback from alternative wifi setup options (airkiss/nfc).
 * Called after an AP to join has been successfully determined
 */
static int adw_wifi_alt_setup(struct adw_ssid *ssid, u8 *key, u16 key_len)
{
	struct adw_state *wifi = &adw_state;
	struct adw_scan *scan;
	enum conf_token sec_token = CT_INVALID_TOKEN;
	enum wifi_error error = WIFI_ERR_NONE;
	struct adw_wifi_history *hist;

	adw_log(LOG_DEBUG  "start wifi join profile");
	if (!ssid->len) {
		/* Return with an error */
		error = WIFI_ERR_MEM;
		goto err;
	}

	adw_lock();
	scan = adw_wifi_scan_lookup_ssid(wifi, ssid, WICED_SECURITY_UNKNOWN);
	if (!scan) {
		/* Error profile not found */
		error = WIFI_ERR_NOT_FOUND;
		goto err;
	}
	if (scan->type != BT_INFRASTRUCTURE) {
		error = WIFI_ERR_NET_UNSUP;
		goto err;
	}
	sec_token = adw_wmi_sec_import(scan->wmi_sec);
	if (sec_token != CT_none &&
#ifndef AMEBA	/*won't support WEP sec in Realtek platform*/
	    sec_token != CT_WEP &&
#endif
	    sec_token != CT_WPA && sec_token != CT_WPA2_Personal) {
		error = WIFI_ERR_SEC_UNSUP;
		goto err;
	}
	if (key_len == 0 && sec_token != CT_none) {
		error = WIFI_ERR_INV_KEY;
		goto err;
	}
	error = adw_wifi_add_prof(wifi, ssid, (char *)key, key_len, sec_token,
	    0, 0);

	adw_wifi_rejoin(wifi);
err:
	adw_wifi_hist_clr_curr(wifi);
	/* add the error code to wifi history */
	if (error > WIFI_ERR_MEM) {
		hist = adw_wifi_hist_new(wifi, ssid, scan);
		hist->curr = 1;
		hist->error = error;
	}

	if (error) {
#ifdef AIRKISS
		/* Failed to join AP. Restart Airkiss */
		adw_wifi_stop_aks(NULL);
		adw_wifi_start_aks(adw_wifi_alt_setup);
#endif
#ifdef NFC_WIFI_SETUP
		/* Failed to join AP. Restart NFC reader */
		adw_wifi_start_nfc(adw_wifi_alt_setup);
#endif
	} else {
#ifdef AIRKISS
		adw_aks_send_fin = 1;
		/* Wifi join succeeded stop Airkiss */
		adw_wmi_timer_cancel(&adw_wifi_aks_timer);
		adw_wifi_stop_aks(NULL);
#endif
#ifdef NFC_WIFI_SETUP
		/* Wifi join succeeded stop NFC reader */
		adw_wifi_stop_nfc(NULL);
#endif
	}
	adw_unlock();

	return error;
}
#endif /* AIRKISS || NFC_WIFI_SETUP */

#ifdef AIRKISS
/*
 * Wifi start Airkiss
 * Called by config change and gpio
 */
int adw_wifi_start_aks_ext(void *arg)
{
	struct adw_state *wifi = &adw_state;

	adw_lock();
	if (!wifi->enable || wifi->state != WS_UP_AP) {
		adw_unlock();
		adw_log(LOG_ERR "aks: not in AP mode");
		return -1;
	}
	adw_unlock();
	adw_wifi_stop_ap(wifi);

	adw_wifi_start_aks(adw_wifi_alt_setup);

	if (!(wifi->setup_mode & WIFI_AIRKISS)) {
		adw_wmi_timer_set(&adw_wifi_aks_timer, AKS_STOP_PBM_TMO);
	}
	return 0;
}

#endif /* AIRKISS */

/*
 * Start AP mode if enabled.
 * Called with lock held, but drops it while starting AP.
 */
static void adw_wifi_start_ap(struct adw_state *wifi)
{
	struct netif *ifnet;
	struct adw_profile *prof = &wifi->profile[ADW_WIFI_PROF_AP];
	int chan = WIFI_AP_MODE_CHAN;
	int rc;
	char ssid_buf[33];

	if (prof->enable == 0 || prof->ssid.len == 0) {
		wifi->state = WS_IDLE;
		return;
	}
	adw_wmi_timer_cancel(&adw_wifi_ap_mode_timer);

	adw_wifi_event_post(ADW_EVID_AP_START);

	if (wifi->ap_up) {
		wifi->state = WS_UP_AP;
		net_netif_set_default(wifi->nif_ap);
		net_netif_set_up(wifi->nif_ap);
		adw_wifi_clear_pref_profile(wifi);
		adw_wifi_event_post(ADW_EVID_AP_UP);
		return;
	}
	if (wifi->ap_mode_chan) {
		chan = wifi->ap_mode_chan;
	}

	adw_log(LOG_INFO "Setting AP mode SSID %s",
	    adw_format_ssid(&prof->ssid, ssid_buf, sizeof(ssid_buf)));

	/*
	 * Drop lock during adw_wmi_start_ap().
	 * Re-evaluate state after reacquiring lock.
	 */
	adw_unlock();
	rc = adw_wmi_start_ap(prof, chan);
	adw_lock();

	if (wifi->state != WS_START_AP) {
		return;		/* state changed while waiting for lock above */
	}
	if (rc) {
		wifi->state = WS_RESTART;	/* Starting AP mode failed */
		return;
	}

	/*
	 * Wiced may lose previous antenna setting when
	 * starting AP mode, because it resets the 4319.  Resend it.
	 */
	adw_wifi_send_or_get_ant(wifi);
	adw_wifi_send_or_get_tx_power(wifi);

	wifi->state = WS_UP_AP;
	wifi->ap_up = 1;
	ifnet = wifi->nif_ap;
	wifi->nif = ifnet;
	net_netif_set_default(ifnet);
	adw_format_ssid(&prof->ssid, ssid_hostname, sizeof(ssid_hostname));
	net_netif_set_hostname(ifnet, ssid_hostname);
	net_netif_set_link_up(ifnet);
	net_netif_set_up(ifnet);
	adw_wifi_clear_pref_profile(wifi);

	adw_wifi_event_post(ADW_EVID_AP_UP);
}

/*
 * Stop AP mode.
 * Called without holding adw_lock.  Since WICED calls adw_wifi_scan_callback,
 * which waits for adw_lock while holding the WICED thread, we cannot hold
 * adw_lock while calling into WICED.
 */
static void adw_wifi_stop_ap(void *arg)
{
	struct adw_state *wifi = (struct adw_state *)arg;

	if (!wifi->ap_up) {
		return;
	}
	adw_log(LOG_INFO "stopping AP mode");
	adw_wifi_event_post(ADW_EVID_AP_DOWN);
	net_netif_set_link_down(wifi->nif_ap);
	net_netif_set_down(wifi->nif_ap);
	adw_wmi_stop_ap();
	wifi->ap_up = 0;

	/*
	 * Wiced may lose previous antenna setting when
	 * stopping AP mode, because it resets the 4319.  Resend it.
	 */
	adw_wifi_send_or_get_ant(wifi);
	adw_wifi_send_or_get_tx_power(wifi);
}

static void adw_wifi_ap_mode_timeout(struct timer *timer)
{
	adw_wifi_stop_ap(&adw_state);
}

#ifdef NFC_WIFI_SETUP

static void adw_wifi_nfc_timeout(struct timer *timer)
{
	adw_wifi_stop_nfc(NULL);
}
#endif

#ifdef WIFI_CONCURRENT_AP_STA_MODE

/*
 * Timer for stopping AP mode operation.
 */
void adw_wifi_stop_ap_sched(int timo)
{
#ifdef AIRKISS
	adw_wmi_timer_set(&adw_wifi_aks_timer, timo);
#endif /* AIRKISS */
#ifdef NFC_WIFI_SETUP
	adw_wmi_timer_set(&adw_wifi_nfc_timer, timo);
#endif /* NFC_WIFI_SETUP */
	adw_wmi_timer_set(&adw_wifi_ap_mode_timer, timo);
}
#endif

/*
 * Convert key string to Wiced WEP key format.
 * Returns -1 for invalid key.
 */
int adw_wifi_wep_key_convert(const u8 *key, size_t key_len,
			struct adw_wifi_wep_key *wep)
{
	size_t len;

	/*
	 * WEP keys are 64 bits (10 hex digits - 40-bit secret)
	 * or 128 bits (26 hex digits, 104-bit secret).
	 * Wiced also supports 16-byte AES-CCM and
	 * 32-byte ALGO_TKIP keys.
	 */
	if (key_len == 13 || key_len == 5) {
		memcpy(wep->key, key, key_len);
		len = key_len;
	} else {
		len = parse_hex(wep->key, sizeof(wep->key),
		    (const char *)key, key_len);
	}
	if (len != 5 && len != 13 && len != 16 && len != 32) {
		return -1;
	}
	wep->len = len;
	return 0;
}

/*
 * Convert WPA key from printable string format to binary.
 * Returns -1 for failure.
 */
int adw_wifi_wpa_password_convert(const u8 *pwd, size_t pwd_len, u8 *key)
{
	if (pwd_len == 2 * WIFI_WPA_KEY_LEN &&
	    (parse_hex(key, WIFI_WPA_KEY_LEN, (const char *)pwd, pwd_len) ==
		WIFI_WPA_KEY_LEN)) {
		return 0;
	}
	return -1;
}

static void adw_wifi_scan_report(struct adw_state *wifi)
{
	struct adw_scan *scan;
	int results = 0;

	for (scan = wifi->scan; scan < &wifi->scan[ADW_WIFI_SCAN_CT]; scan++) {
		if (scan->rssi != WIFI_MIN_SIG) {
			results++;
		}
	}
	adw_log(LOG_DEBUG "scan done. %d networks found", results);
}

/*
 * Start join process to associate with the given profile. Returns 0
 * if process is underway.
 */
static int adw_wifi_join_profile(struct adw_state *wifi,
				struct adw_profile *prof)
{
	struct adw_wifi_history *hist;
	struct adw_scan *scan;
	enum wifi_error wifi_error;
	char ssid_buf[33];

	wifi->curr_profile = prof - wifi->profile;

	/*
	 * Create a connection history record.
	 */
	scan = prof->scan;
	hist = adw_wifi_hist_new(wifi, &prof->ssid, scan);
	if (!scan) {
		hist->error = WIFI_ERR_NOT_FOUND;
		prof->join_errs++;
		adw_wifi_hist_log(wifi, hist);
		return -1;
	}
	wifi->state = WS_IDLE;
	wifi->client_err = AE_IN_PROGRESS;

	adw_log(LOG_INFO "connecting to SSID %s sec %s signal %d",
	    adw_format_ssid(&prof->ssid, ssid_buf, sizeof(ssid_buf)),
	    conf_string(adw_wmi_sec_import(scan->wmi_sec)),
	    scan->rssi);

	adw_wmi_powersave_set(ADW_WIFI_PS_OFF);

	wifi_error = adw_wmi_join(wifi, prof);
	if (wifi_error != WIFI_ERR_NONE) {
		hist->error = wifi_error;
	} else {
		hist->error = WIFI_ERR_IN_PROGRESS;
	}
	switch (wifi_error) {
	case WIFI_ERR_NONE:
		adw_wmi_timer_cancel(&adw_wifi_scan_timer);
		wifi->scan_state = SS_IDLE;
		wifi->state = WS_JOIN;
		adw_wmi_callback_pend(&adw_wifi_cbmsg_join);
		return 0;

	case WIFI_ERR_WRONG_KEY:
	case WIFI_ERR_INV_KEY:
		prof->join_errs = WIFI_JOIN_KEY_ERR;
		/* fall through */
	case WIFI_ERR_NOT_AUTH:
		prof->join_errs++; /* double counting intentional */
		break;
	default:
		adw_log(LOG_WARN "Wi-Fi connect to %s failed - error %d",
		    ssid_buf, wifi_error);
		break;
	}
	prof->join_errs++;
	adw_wifi_current_profile_done(wifi, hist);
	adw_wmi_powersave_set(wifi->power_mode);
	return -1;
}

static int adw_wifi_straight_join(struct adw_state *wifi)
{
	struct adw_profile *prof;

	for (prof = wifi->profile; prof < &wifi->profile[ADW_WIFI_PROF_AP];
	     prof++) {
		if (prof->ssid.id[0] != '\0' && prof->enable && prof->scan) {
			break;
		}
	}
	if (prof == &wifi->profile[ADW_WIFI_PROF_AP]) {
		return -1;
	}
	return adw_wifi_join_profile(wifi, prof);
}

/*
 * Scan done.  Do adw_wifi_join if possible.
 * Find the strongest network in the scan results that has a profile
 * and try to join it.
 * If nothing found, and we've been scanning for more than
 * WIFI_SCAN_DEF_LIMIT seconds, go to AP mode, if enabled.
 *
 * Called with lock held.
 */
static void adw_wifi_scan_done(struct adw_state *wifi)
{
	struct adw_profile *prof;
	u32 delay = WIFI_SCAN_DEF_IDLE;
	int scan_prof;
	int join_errs;

	scan_prof = wifi->scan_profile;
	adw_wifi_scan2prof(wifi, scan_prof);

	/*
	 * If we just finished a specific scan, mark the profile scanned.
	 * If the profile is the (not-yet-enabled) preferred profile,
	 * mark it hidden.
	 */
	wifi->scan_profile = 0;
	if (scan_prof) {
		prof = &wifi->profile[scan_prof - 1];
		prof->spec_scan_done = 1;
		if (scan_prof == wifi->pref_profile && prof->scan &&
		    !prof->enable) {
			prof->hidden = 1;
		}
	}

	/*
	 * If there are hidden networks, setup for specific scan.
	 * wifi->scan_profile is the index + 1 of the one to do next.
	 */
	for (prof = &wifi->profile[scan_prof];
	     scan_prof++ < ADW_WIFI_PROF_AP; prof++) {
		if (((prof->enable && prof->hidden) ||
		    scan_prof == wifi->pref_profile) &&
		    !prof->spec_scan_done && !prof->scan &&
		    prof->ssid.id[0] != '\0') {
			wifi->scan_profile = scan_prof;
			break;
		}
	}
	if (wifi->scan_profile) {
		adw_wifi_scan(wifi);
		return;
	}

	prof = adw_wifi_select(wifi);
	if (!prof) {
		join_errs = 0;
		for (prof = wifi->profile;
		    prof < &wifi->profile[ADW_WIFI_PROF_AP]; prof++) {
			join_errs += prof->join_errs;
			prof->join_errs = 0;
		}
		if (join_errs && adw_wifi_health_check(wifi)) {
			wifi->state = WS_RESTART;
			return;
		} else if (wifi->state != WS_UP_AP &&
		    !(wifi->conditional_ap && adw_wifi_configured_nolock())) {
			wifi->state = WS_START_AP;
		}
		delay = WIFI_SCAN_AP_WAIT;
		goto rescan;
	}
	if (prof == &wifi->profile[ADW_WIFI_PROF_AP]) {
		/*
		 * Preferred profile is AP.
		 */
		if (wifi->state != WS_UP_AP) {
			wifi->state = WS_START_AP;
		}
		wifi->scan_state = SS_STOPPED;
		return;
	}
	if (wifi->state == WS_UP_AP) {
		wifi->rejoin = 1;
		delay = WIFI_SCAN_AP_WAIT;
		goto rescan;
	}

	if (adw_wifi_join_profile(wifi, prof) == 0) {
		return;
	}
rescan:
	wifi->scan_state = SS_SCAN_WAIT;
	adw_wmi_timer_cancel(&adw_wifi_join_timer);
	adw_wmi_timer_set(&adw_wifi_scan_timer, delay);
}

static int adw_wifi_server_is_active(struct adw_state *wifi)
{
	return wifi->use_time &&
	    TSTAMP_LT(clock_ms(), wifi->use_time + WIFI_SCAN_AP_WAIT);
}

/*
 * Start wifi scan.
 *
 * Called with lock held.
 */
void adw_wifi_scan(struct adw_state *wifi)
{
	struct adw_profile *prof;
	struct adw_scan *scan;
	int enabled_entries = 0;
	struct adw_ssid *scan4;
	enum wifi_error err;
	char ssid_buf[33];

	ASSERT(wifi->scan_state != SS_SCAN);

	if (wifi->scan_profile) {
		prof = &wifi->profile[wifi->scan_profile - 1];
		scan4 = &prof->ssid;
	} else if (wifi->scan4.len) {
		scan4 = &wifi->scan4;
	} else {
		scan4 = NULL;
	}
	if (wifi->scan_state != SS_SCAN_START) {
		enabled_entries = adw_profile_cnt(wifi);
		/*
		 * If we're in STA mode, don't do automatic periodic scan.
		 * If we're in AP mode with no profiles, don't do automatic
		 * scans.
		 */
		if ((wifi->state == WS_UP) ||
		    (wifi->state == WS_UP_AP && !enabled_entries)) {
			return;
		}
		/*
		 * If local webserver is active, and we've not explicitly
		 * been told to join a network, don't do scans.
		 */
		if (!wifi->pref_profile && adw_wifi_server_is_active(wifi)) {
			goto rescan;
		}
	}
	if (!scan4) {
		for (scan = wifi->scan; scan < &wifi->scan[ADW_WIFI_SCAN_CT];
		     scan++) {
			scan->rssi = WIFI_MIN_SIG;
			scan->ssid.len = 0;
		}
		for (prof = wifi->profile;
		     prof < &wifi->profile[ADW_WIFI_PROF_AP]; prof++) {
			prof->scan = NULL;
			prof->spec_scan_done = 0;
		}
	}
	adw_unlock();
	err = adw_wmi_scan(scan4, adw_wifi_scan_callback);
	adw_lock();
	if (!err) {
		adw_log(LOG_DEBUG "scan started %s",
		    scan4 ? adw_format_ssid(scan4, ssid_buf,
		    sizeof(ssid_buf)) : "");
		adw_wifi_scan_snapshot_reset();
		wifi->scan_report = 0;
		if (wifi->scan_state == SS_IDLE) {
			wifi->scan_time = clock_ms();
		}
		wifi->scan_state = SS_SCAN;
#ifdef AYLA_WMSDK_SUPPORT
		/*
		 * XXX can't scan until AP or STA started?
		 * and we don't normally start AP until scan is complete
		 */
	} else if (err == WIFI_ERR_MEM) {
		wifi->state = WS_START_AP;
		adw_wifi_start_ap(wifi);
		wifi->scan_state = SS_SCAN_WAIT;
#endif
	} else {
rescan:
		wifi->scan_state = SS_SCAN_WAIT;
	}
	adw_wmi_timer_set(&adw_wifi_scan_timer, WIFI_SCAN_MIN_LIMIT);
}

/*
 * Start Wi-Fi.
 * Called with lock held.
 */
static int adw_wifi_start(void)
{
	static u8 done;

	adw_log(LOG_DEBUG "wifi start");
	if (adw_wmi_on()) {
		return -1;
	}
	adw_wifi_event_post(ADW_EVID_ENABLE);

	/*
	 * Register for client callbacks.
	 * Do not do this in adw_init() before ADA is initialized.
	 */
	if (!done) {
		ada_client_event_register(adw_wifi_client_event, &adw_state);
		done = 1;
	}
	return 0;
}

/*
 * Stop Wi-Fi.  Turn off chip.
 * Called with lock held.
 */
void adw_wifi_stop(void)
{
	adw_log(LOG_DEBUG "wifi stop");
	adw_wmi_off();
	adw_wifi_event_post(ADW_EVID_DISABLE);
}

/*
 * Step to next state in mon_wifi state machine.
 *
 * Called with lock held.
 * Called only in the TCP thread.
 */
static int adw_wifi_step(struct adw_state *wifi)
{
	struct adw_profile *prof;
	struct adw_wifi_history *hist;
	enum adw_wifi_conn_state state;
	u8 rejoin;
	u8 enabled;
	int save = 0;

	do {
		if (wifi->scan_state == SS_DONE && !wifi->scan_report) {
			adw_wifi_scan_report(wifi);
			adw_unlock();
			adw_wifi_page_scan_done();
			wifi->scan4.len = 0;
			adw_lock();
			wifi->scan_report = 1;
		}
		rejoin = wifi->rejoin;
		wifi->rejoin = 0;
		enabled = wifi->enable && wifi->cm.enable && adw_wifi_fw_ok;

		state = wifi->state;
		switch (state) {
		/*
		 * Start scan if enabled and not already running or joined.
		 */
		case WS_DISABLED:
			if (enabled) {
				wifi->state = WS_IDLE;
			} else if (wifi->started) {
				wifi->started = 0;
				adw_wifi_stop();
			}
			break;

		case WS_ERROR:
			return 0;

		case WS_RESTART:
			/*
			 * Stop and start Wi-Fi.
			 * This is used in trying to recover from wedged states.
			 */
			wifi->started = 0;
#ifdef AIRKISS
			adw_wifi_stop_aks(NULL);
#endif
#ifdef NFC_WIFI_SETUP
			adw_wifi_stop_nfc(NULL);
#endif
			adw_wifi_stop_ap(wifi);
			adw_wifi_stop();
			wifi->state = WS_IDLE;
			wifi->scan_state = SS_IDLE;
			if (++wifi->reset_cnt >= WIFI_MAX_FAILS) {
				adw_wifi_event_post(ADW_EVID_RESTART_FAILED);
			} else {
				adw_log(LOG_WARN "resetting wifi");
			}
			break;

		case WS_IDLE:
			if (!wifi->started) {
				if (adw_wifi_start()) {
					wifi->state = WS_ERROR;
					return 0;
				}
				wifi->started = 1;
				if (!wifi->cm.enable) {
					wifi->state = WS_DISABLED;
					break;
				}
				if (adw_wifi_fw_ok) {
					adw_wifi_send_or_get_ant(wifi);
					adw_wifi_send_or_get_tx_power(wifi);
				}
			}
			if (!adw_wifi_fw_ok) {
				wifi->state = WS_IDLE;
				break;
			}

			if (wifi->scan_state == SS_DONE ||
			    (wifi->scan_state == SS_SCAN_WAIT && rejoin)) {
				wifi->state = WS_SCAN_DONE;
				break;
			}
			if (wifi->scan_state == SS_IDLE) {
				if (adw_wifi_straight_join(wifi) < 0) {
					adw_wifi_scan(wifi);
				} else {
					wifi->nif = wifi->nif_sta;
				}
			}
			break;

		case WS_SCAN_DONE:
			if (!enabled) {
				wifi->state = WS_DISABLED;
				wifi->scan_state = SS_IDLE;
				adw_wmi_timer_cancel(&adw_wifi_scan_timer);
				adw_wmi_timer_cancel(&adw_wifi_join_timer);
#ifdef AIRKISS
				adw_wifi_stop_aks(NULL);
#endif
#ifdef NFC_WIFI_SETUP
				adw_wifi_stop_nfc(NULL);
#endif
				adw_wifi_stop_ap(wifi);
				break;
			}
			if (wifi->scan_state != SS_SCAN) {
				adw_wifi_scan_done(wifi);
			} else {
				adw_log(LOG_DEBUG "scan not done, wait");
			}
			break;

		case WS_WPS:
#ifdef WIFI_WPS
			if ((!enabled || wifi->pref_profile) &&
			    !wifi->wps_aborted && !wifi->wps_done) {
				adw_wmi_wps_abort();
				wifi->wps_aborted = 1;
			}
			if (wifi->wps_done) {
				wifi->state = WS_WPS_DONE;
			}
#endif
			break;

		case WS_WPS_DONE:
#ifdef WIFI_WPS
			adw_log(LOG_INFO "WPS done: %s",
			    adw_wmi_wps_state_str(wifi));
			adw_wmi_timer_cancel(&adw_wifi_wps_timer);
			adw_wmi_wps_deinit();
			if (!enabled) {
				wifi->state = WS_DISABLED;
				wifi->scan_state = SS_IDLE;
				adw_wifi_stop_ap(wifi);
			} else {
				wifi->state = WS_SCAN_DONE;
				adw_wifi_scan_done(wifi);
			}
#endif
			break;

		case WS_DHCP:
			if (!enabled || rejoin) {
				goto up_state;
			}
			hist = &wifi->hist[wifi->hist_curr];
			if (adw_wmi_dhcp_poll(wifi, hist)) {
				adw_wmi_timer_set(&adw_wifi_step_timer,
				    WIFI_DHCP_POLL);
				break;
			}
			adw_wmi_timer_cancel(&adw_wifi_client_timer);

			/*
			 * The IP stack might not correctly handle two
			 * interfaces with the same link-local IPv4 address.
			 * If it does, the conflict check will return zero.
			 *
			 * See the station and AP IP addresses overlap, and
			 * if so, shut down the AP.
			 */
			if (wifi->ap_up &&
			    net_addr_conflict_check(htonl(hist->ip_addr.addr),
			    htonl(hist->netmask.addr),
			    ADW_WIFI_AP_IP, ADW_WIFI_AP_NETMASK)) {
				adw_log(LOG_WARN "STA IP and AP IP conflict");
				adw_wifi_stop_ap(wifi);
			}

			adw_wmi_powersave_set(wifi->power_mode);

			save |= wifi->save_on_ap_connect;

			adw_wifi_event_post(ADW_EVID_STA_DHCP_UP);

			switch (wifi->client_err) {
			case AE_OK:
				save |= wifi->save_on_server_connect;
				hist->error = WIFI_ERR_NONE;
				hist->last = 1;
				wifi->state = WS_UP;	/* client not enabled */
				adw_wifi_stayup();
				conf_persist(CT_wifi, adw_wifi_export_cur_prof,
				    wifi);
				break;
			case AE_IN_PROGRESS:
				adw_wmi_timer_set(&adw_wifi_client_timer,
				    CLIENT_WAIT);
				wifi->state = WS_WAIT_CLIENT;
				break;
			default:
				break;
			}
			break;

		case WS_WAIT_CLIENT:
			if (!enabled || rejoin) {
				goto up_state;
			}
			if (wifi->client_err == AE_IN_PROGRESS) {
				adw_log(LOG_DEBUG
				    "client not connected - keep waiting");
				break;
			}
			if (wifi->client_err != AE_OK) {
				adw_wifi_service_fail(wifi);
				break;
			}
#ifdef WIFI_CONCURRENT_AP_STA_MODE
			adw_wifi_stop_ap_sched(WIFI_STOP_AP_TMO);
#endif
			save |= wifi->save_on_server_connect;
			hist = &wifi->hist[wifi->hist_curr];
			hist->error = WIFI_ERR_NONE;
			hist->last = 1;
			wifi->state = WS_UP;
			adw_wifi_stayup();
			conf_persist(CT_wifi, adw_wifi_export_cur_prof, wifi);
			break;

		case WS_UP:
up_state:
			adw_wmi_timer_cancel(&adw_wifi_client_timer);
			if (!enabled || rejoin) {
				net_netif_set_link_down(wifi->nif_sta);
				adw_wifi_event_post(ADW_EVID_STA_DOWN);
			}
			if (!net_netif_is_up(wifi->nif_sta) && enabled) {
				wifi->state = WS_DHCP;
				net_netif_set_link_down(wifi->nif_sta);
				adw_wmi_timer_set(&adw_wifi_client_timer,
				    WIFI_DHCP_WAIT);
				adw_wifi_event_post(ADW_EVID_STA_DOWN);
			}
			if ((!enabled || rejoin) &&
			    wifi->scan_state != SS_SCAN) {
				adw_wmi_timer_cancel(&adw_wifi_client_timer);
				adw_wmi_leave(wifi);
				wifi->state = WS_SCAN_DONE;
			}
			break;

		case WS_START_AP:
#ifdef AIRKISS
			if (wifi->setup_mode & WIFI_AIRKISS) {
				adw_wifi_start_aks(adw_wifi_alt_setup);
				wifi->state = WS_UP_AP;
				break;
			}
#endif /* AIRKISS */
			adw_wifi_start_ap(wifi);
#ifdef NFC_WIFI_SETUP
			adw_wifi_start_nfc(adw_wifi_alt_setup);
#endif /* NFC_WIFI_SETUP */
			break;

		case WS_UP_AP:
			if (!enabled || rejoin) {
				wifi->state = WS_SCAN_DONE;
#ifndef WIFI_CONCURRENT_AP_STA_MODE
				/*
				 * Drop lock for adw_wifi_stop_ap().
				 * Re-evaluate state after reacquiring lock.
				 */
				adw_unlock();
#ifdef AIRKISS
				adw_wifi_stop_aks(NULL);
#endif /* AIRKISS */
#ifdef NFC_WIFI_SETUP
				adw_wifi_stop_nfc(NULL);
#endif /* NFC_WIFI_SETUP */
				adw_wifi_stop_ap(wifi);
				adw_lock();
#endif
				break;
			}
			if (wifi->scan_state == SS_DONE) {
				adw_wifi_scan_done(wifi);
			} else if (wifi->scan_state == SS_IDLE) {
				adw_wifi_scan(wifi);
			}
			break;

		/*
		 * If not joined, wait until called after configuration changes.
		 */
		case WS_JOIN:
			break;
		}
	} while (wifi->state != state || wifi->rejoin);

	if (save) {
		prof = &wifi->profile[wifi->curr_profile];
		prof->join_errs = 0;
		if (wifi->curr_profile + 1 == wifi->pref_profile) {
			prof->enable = 1;
			wifi->pref_profile = 0;
		}
	}
	return save;
}

/*
 * Advance the state machine.
 * Called only in the TCP thread.
 */
static void adw_wifi_step_cb(void *wifi_arg)
{
	struct adw_state *wifi = wifi_arg;
	int save;

	adw_lock();
	save = adw_wifi_step(wifi);
	adw_unlock();
	if (save) {
		adw_log(LOG_DEBUG "step_cb: saving Wi-Fi profiles");
		conf_persist(CT_wifi, adw_wifi_export_profiles, wifi);
	}
}

/*
 * initialize mon_wifi.
 * Called before conf_init, so wifi isn't enabled yet.
 * Initialize lock.
 * Set defaults.  May be overridden by config.
 */
void adw_wifi_init(void)
{
	struct adw_state *wifi = &adw_state;
	static u8 done;

	if (done) {
		return;
	}
	done = 1;

	net_init();
	timer_init(&adw_wifi_rssi_timer, adw_wifi_rssi_timeout);
	timer_init(&adw_wifi_scan_timer, adw_wifi_rescan);
	timer_init(&adw_wifi_step_timer, adw_wifi_step_timeout);
	timer_init(&adw_wifi_join_timer, adw_wifi_join_timeout);
	timer_init(&adw_wifi_client_timer, adw_wifi_client_timeout);
	timer_init(&adw_wifi_ap_mode_timer, adw_wifi_ap_mode_timeout);
#ifdef WIFI_WPS
	timer_init(&adw_wifi_wps_timer, adw_wifi_wps_timeout);
#endif
#ifdef AIRKISS
	timer_init(&adw_wifi_aks_timer, adw_wifi_aks_timeout);
#endif
#ifdef NFC_WIFI_SETUP
	timer_init(&adw_wifi_nfc_timer, adw_wifi_nfc_timeout);
#endif
	adw_wmi_init();
	wifi->cm.signal_func = adw_wmi_get_rssi;
	wifi->cm.enable = 1;
	wifi->save_on_server_connect = 1;
	net_callback_init(&adw_wifi_cbmsg_join, adw_wifi_check_join, wifi);
	net_callback_init(&adw_wifi_cbmsg_step, adw_wifi_step_cb, wifi);
	net_callback_init(&adw_wifi_cbmsg_delayed,
	    adw_wifi_step_arm_timer, wifi);
	net_callback_init(&adw_wifi_cbmsg_event, adw_wifi_event_cb, wifi);
#ifdef AYLA_EXT_WIFI_FW
	/* check firmware version - verify wifi_fw_ok */
	adw_wifi_fw_open(CI_WIFI_IMAGE, 0);
#endif /* AYLA_EXT_WIFI_FW */
	conf_table_entry_add(&adw_wifi_conf_entry);
	conf_table_entry_add(&adw_wifi_ip_conf_entry);
}

/*
 * Return pointer to the local MAC address in use.
 */
u8 *adw_wifi_mac(struct adw_state *wifi)
{
	u8 *mac;
	static u8 mac_buf[6];

#ifdef MAC_ADDR_SET_BY_HOST
	mac = conf_sys_mac_addr;
	if (ether_addr_non_zero(wifi->mac)) {
		mac = wifi->mac;
	}
#else
	memset(mac_buf, 0, sizeof(mac_buf));
	adw_wmi_get_mac_addr(0, mac_buf);
	mac = mac_buf;
#endif
	return mac;
}

#ifdef MAC_ADDR_SET_BY_HOST
/*
 * Called by WICED to get the MAC address to be used.
 */
void host_platform_get_mac_addr(wiced_mac_t *mac)
{
	memcpy(mac, adw_wifi_mac(&adw_state), sizeof(*mac));
}
#endif /* MAC_ADDR_SET_BY_HOST */

/*
 * Set power savings mode for wifi chip. If we're far enough in bringup,
 * set the mode immediatelly.
 */
void adw_wifi_powersave(enum adw_wifi_powersave_mode new_mode)
{
	struct adw_state *wifi = &adw_state;

	if (new_mode > ADW_WIFI_PS_ON_LESS_BEACONS) {
		ASSERT(0);
		return;
	}
	adw_lock();
	wifi->power_mode = new_mode;
	if (wifi->state >= WS_WAIT_CLIENT) {
		/*
		 * Apply change immediately.
		 */
		adw_wmi_powersave_set(new_mode);
	}
	adw_unlock();
}

/*
 * Returns 1 if there is a configured WIFI profile (not AP config).
 */
int adw_wifi_configured_nolock(void)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;
	int rc;

	rc = wifi->pref_profile != 0;
	for (prof = wifi->profile; prof < &wifi->profile[ADW_WIFI_PROF_AP];
	     prof++) {
		if (prof->enable == 1) {
			rc = 1;
			break;
		}
	}
	return rc;
}

int adw_wifi_configured(void)
{
	int rc;

	adw_lock();
	rc = adw_wifi_configured_nolock();
	adw_unlock();

	return rc;
}

int adw_wifi_in_ap_mode(void)
{
	struct adw_state *wifi = &adw_state;

	return wifi->ap_up;
}

int adw_wifi_scan_result_count(void)
{
	struct adw_state *wifi = &adw_state;
	struct adw_scan *scan;
	int count = 0;

	for (scan = wifi->scan; scan < &wifi->scan[ADW_WIFI_SCAN_CT]; scan++) {
		if (scan->ssid.len && scan->type == BT_INFRASTRUCTURE) {
			count++;
		}
	}
	return count;
}

struct netif *adw_wifi_ap_netif(void)
{
	return adw_state.nif_ap;
}

struct netif *adw_wifi_sta_netif(void)
{
	return adw_state.nif_sta;
}

struct netif *adw_wifi_netif(void)
{
	return adw_state.nif;
}

int adw_wifi_was_setup_by_mfi(void)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof = &wifi->profile[wifi->curr_profile];

	return prof->mfi;
}

enum ada_wifi_features adap_wifi_features_get(void)
{
	enum ada_wifi_features features = 0;

#ifdef WIFI_CONCURRENT_AP_STA_MODE
	features |= AWF_SIMUL_AP_STA;
#endif
#ifdef WIFI_WPS
	features |= AWF_WPS | AWF_WPS_APREG;
#endif
	return features;
}

int adap_wifi_in_ap_mode(void)
{
	return adw_wifi_in_ap_mode();
}

int adap_net_get_signal(int *signalp)
{
	return adw_wmi_get_rssi(signalp);
}
