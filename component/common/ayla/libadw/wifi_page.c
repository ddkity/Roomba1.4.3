/*
 * Copyright 2011-2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <ayla/utypes.h>
#include <ayla/endian.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/clock.h>
#include <ayla/json.h>
#include <ayla/log.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <ayla/parse.h>
#include <ayla/xml.h>
#include <ayla/http.h>
#include <ayla/wifi_status.h>
#include <ada/ada_conf.h>
#include <ayla/mod_log.h>
#include <net/net.h>
#include <net/ipaddr_fmt.h>
#include <adw/wifi.h>
#include "wifi_int.h"
#include <ada/client.h>
#include <ada/server_req.h>
#include <ada/linker_text.h>
#include <ayla/malloc.h>
#include "wifi_page.h"
#include "wifi_timer.h"

const char adw_http_content_type_html[] = "Content-Type: text/html";
char adw_wifi_ios_app[WIFI_IOS_APP_LEN] = "";

/*
 * Local server requests which are waiting for WIFI scan to be done
 * are queued in these data structures.
 */
struct adw_wifi_scan_wait {
	struct adw_wifi_scan_wait *wsw_next;
	struct server_req *wsw_req;
};
struct adw_wifi_scan_wait_connect {
	struct adw_wifi_scan_wait wswc_head;
	struct adw_ssid wswc_ssid;
	char wswc_key[WIFI_MAX_KEY_LEN];
	size_t wswc_key_len;
	u8 hidden;
};
static struct adw_wifi_scan_wait *wsw_head;

static void adw_wifi_scan_wait_dequeue(struct server_req *);

static struct net_callback adw_wifi_page_scan_callback;
static ipX_addr_t adw_wifi_iphone_ip;
static u8 adw_wifi_iphone_is_v6;

static const char *mobile_agents[] = {
	"iPhone",
	"iPad",
	"iPod",
	"Android",
	"Windows Phone",
	"BlackBerry"
};

static void adw_wifi_set_iphone_info(const ipX_addr_t *addr, u8 is_v6, u8 ver)
{
	ipX_addr_set(is_v6, &adw_wifi_iphone_ip, addr);
	adw_wifi_iphone_is_v6 = is_v6;
}

void adw_wifi_page_success(struct server_req *req)
{
	char hdr_msg[120];

	snprintf(hdr_msg, sizeof(hdr_msg), "%s\r\n",
	    adw_http_content_type_html);
	net_addr_set_zero(adw_wifi_iphone_is_v6, &adw_wifi_iphone_ip);
	req->put_head(req, HTTP_STATUS_OK, hdr_msg);
	server_put_pure(req, "<HTML><HEAD><TITLE>Success</TITLE>"
	    "</HEAD><BODY>Success</BODY></HTML>");
}

static int adw_wifi_do_ios_redirect(void)
{
	return adw_wifi_ios_app[0] != '\0';
}

/*
 * Following is the sequence of events which should happen
 * at wifi setup time, when mobile device connects to Ayla module.
 *
 * IOS 7                Ayla
 * GET some_ip_addr/junk by CaptiveNetwork
 *                      redir 192.168.0.1/
 * GET 192.168.0.1/
 *                      /
 * GET some_ip_addr/junk by iphone OS 7
 *                      serve script
 *  If has Ayla app:
 * GET some_ip_addr/junk by CaptiveNetwork
 *                      redir 192.168.0.1/library/test/success
 * GET library/test/success
 *                      success
 *
 *  If no Ayla app:
 * GET some_ip_addr/junk by CaptiveNetwork
 *                      redir 192.168.0.1/library/test/success
 * GET /library/test/success
 *                      success
 * GET 192.168.0.1/wifi by iphone OS 7
 *                      /
 *
 * IOS 6
 * GET www.apple.com/library/test/success by Captivenetwork
 *                      redir 192.168.0.1/
 * GET 192.168.0.1/
 *                      /
 * GET www.apple.com/library/test/success by iPad OS 6
 *                      serve script
 * GET www.apple.com/library/test/success by Captivenetwork
 *                      redir 192.168.0.1/
 * GET 192.168.0.1/
 *                      /
 *
 * Macbook
 * GET www.apple.com/library/test/success by Captivenetwork
 *			redir 192.168.0.1/
 * GET 192.168.0.1/
 */
static void adw_wifi_page_redir(struct server_req *req)
{
	const char *url;
	char redir_host[46];
	char hdr_msg[120];

	url = req->url->url ? req->url->url : "";

	if (!req->pcb) {
		return;
	}
	ip_addr_ntop(net_tcp_v6(req->pcb),
	    (ipX_addr_t *)net_tcp_local_ip(req->pcb),
	    redir_host, sizeof(redir_host));

	/*
	 * For mobile iOS platforms, redirect to special iOS setup page.
	 */
	if (adw_wifi_iphone_is_v6 == net_tcp_v6(req->pcb) &&
	    net_addr_cmp(net_tcp_v6(req->pcb), &adw_wifi_iphone_ip,
		net_tcp_remote_ip(req->pcb)) &&
	    !req->host_match && req->ios_ver > 6) {
		adw_wifi_page_success(req);
		return;
	} else if (!req->host_match && req->apple && req->mobile &&
	    req->ios_ver > 6 && adw_wifi_do_ios_redirect()) {
		adw_wifi_http_ios_get(req);
		adw_wifi_set_iphone_info(net_tcp_remote_ip(req->pcb),
		    net_tcp_v6(req->pcb), req->ios_ver);
		return;
	} else if (!strcmp(url, "/library/test/success.html") ||
	    (!req->host_match && req->apple && !strcmp(url, "/"))) {
		if (adw_wifi_iphone_is_v6 == net_tcp_v6(req->pcb) &&
		    net_addr_cmp(net_tcp_v6(req->pcb), &adw_wifi_iphone_ip,
			net_tcp_remote_ip(req->pcb))) {
			if (req->mobile) {
				if (adw_wifi_do_ios_redirect()) {
					adw_wifi_http_ios_get(req);
					return;
				} else {
					if (req->ios_ver != 5) {
						adw_wifi_set_iphone_info(
						    net_tcp_remote_ip(req->pcb),
							net_tcp_v6(req->pcb),
							req->ios_ver);
					}
					url = "";
				}
			} else {
				url = "";
			}
		} else {
			net_addr_set_zero(adw_wifi_iphone_is_v6,
			    &adw_wifi_iphone_ip);
			url = "";
		}
	}

	server_log(LOG_DEBUG "redir %s", url);

	snprintf(hdr_msg, sizeof(hdr_msg), "Location: http://%s%s\r\n"
	    "%s\r\n", redir_host, url, adw_http_content_type_html);

	req->put_head(req, HTTP_STATUS_FOUND, hdr_msg);

	if (req->method == REQ_GET_HEAD) {
		return;
	}
	server_put(req,
	    "<!doctype html>\n"
	    "<html><head><title>Redirect</title></head><body>\n"
	    "<h1>Redirect</h1>\n"
	    "<p>You are redirected to <a href=\"http://%s%s\"></a>%s%s</p>\n"
	    "</body></html>\n",
	    redir_host, url, redir_host, url);
}

/*
 * Decide whether redirection is wanted, based on User-Agent header value.
 * Return function to handle the redirect, or NULL.
 */
static void (*adw_wifi_redir_handler_get(struct server_req *req,
		 const char *user_agent))(struct server_req *)
{
	const char *cp = user_agent;
	void (*handler)(struct server_req *) = NULL;
	int i;

	/*
	 * Check for Apple device.
	 */
	if (strstr(cp, "CaptiveNetworkSupport") ||
	    strstr(cp, "iPhone") ||
	    strstr(cp, "iPad") ||
	    strstr(cp, "iPod") ||
	    strstr(cp, "Macintosh")) {
		req->apple = 1;
		handler = adw_wifi_page_redir;
		if (strstr(cp, "iPhone OS 5")) {
			req->ios_ver = 5;
		} else if (strstr(cp, "iPhone OS 6") ||
		    strstr(cp, "CPU OS 6")) {
			req->ios_ver = 6;
		} else if (strstr(cp, "iPhone OS 7") ||
		    strstr(cp, "CPU OS 7")) {
			req->ios_ver = 7;
		} else if (strstr(cp, "iPhone OS 8") ||
		    strstr(cp, "CPU OS 8")) {
			req->ios_ver = 8;
		} else if (strstr(cp, "iPhone OS 9") ||
		    strstr(cp, "CPU OS 9")) {
			req->ios_ver = 9;
		} else if (strstr(cp, "iPhone OS 10") ||
		    strstr(cp, "CPU OS 10")) {
			req->ios_ver = 10;
		} else {
			req->ios_ver = 11;
		}
	}
	for (i = 0; i < ARRAY_LEN(mobile_agents); i++) {
		if (strstr(cp, mobile_agents[i])) {
			req->mobile = 1;
		}
	}
	return handler;
}

/*
 * Lookup scan result by SSID/security.
 * If there are multiple entries with the same SSID, choose the one with
 * the best security.  If all have equivalent security, choose the one with
 * the strongest signal.
 * Called with lock held.
 */
struct adw_scan *
adw_wifi_scan_lookup_ssid(struct adw_state *wifi, const struct adw_ssid *ssid,
    u32 wmi_sec)
{
	struct adw_scan *scan;
	struct adw_scan *best = NULL;

	for (scan = wifi->scan; scan < &wifi->scan[ADW_WIFI_SCAN_CT]; scan++) {
		if (!adw_ssids_match(&scan->ssid, ssid)) {
			continue;
		}
		if (wmi_sec == scan->wmi_sec) {
			return scan;
		}
		if (!best ||
		    (!adw_wifi_sec_downgrade(adw_wmi_sec_import(scan->wmi_sec),
		    adw_wmi_sec_import(best->wmi_sec)) &&
		    scan->rssi >= best->rssi)) {
			best = scan;
		}
	}
	return best;
}

struct adw_scan *adw_wifi_scan_lookup_bssid(struct adw_state *wifi,
				u8 *bssid)
{
	struct adw_scan *scan;

	for (scan = wifi->scan; scan < &wifi->scan[ADW_WIFI_SCAN_CT]; scan++) {
		if (scan->ssid.len && !memcmp(scan->bssid, bssid,
		    sizeof(scan->bssid))) {
			return scan;
		}
	}
	return NULL;
}

static void adw_wifi_scan_wait_queue(struct adw_wifi_scan_wait *wsw,
    struct server_req *req)
{
	wsw->wsw_req = req;
	wsw->wsw_next = wsw_head;
	wsw_head = wsw;
	req->close_cb = adw_wifi_scan_wait_dequeue;
}

static void adw_wifi_scan_wait_dequeue(struct server_req *req)
{
	struct adw_wifi_scan_wait *wsw, *prev = NULL;

	wsw = wsw_head;
	while (wsw) {
		if (wsw->wsw_req == req) {
			if (!prev) {
				wsw_head = wsw->wsw_next;
			} else {
				prev->wsw_next = wsw->wsw_next;
			}
			free(wsw);
			return;
		}
		prev = wsw;
		wsw = wsw->wsw_next;
	}
}

void adw_wifi_page_scan_done(void)
{
	struct server_req *req;
	char buf[SERVER_BUFLEN];

	while (wsw_head) {
		req = wsw_head->wsw_req;

		if (req->prop_abort) {
			adw_wifi_scan_wait_dequeue(req);
			server_free_aborted_req(req);
			return;
		}
		req->err = AE_OK;
		req->user_in_prog = 0;
		req->buf = buf;
		req->len = 0;
		req->puts_done = 0;
		req->put_count = 0;
		if (req->resume) {
			req->resume(req);
		}
		adw_wifi_scan_wait_dequeue(req);
		if (!req->user_in_prog && req->finish_write) {
			req->finish_write(req);
		}
	}
}

/*
 * Get iOS page for Wi-Fi setup.
 */
void adw_wifi_http_ios_get(struct server_req *req)
{
	char hdr_msg[120];

	net_tcp_remote_ip_copy(req->pcb, adw_wifi_iphone_ip,
	     &adw_wifi_iphone_is_v6);

	snprintf(hdr_msg, sizeof(hdr_msg), "%s; charset=UTF-8\r\n",
	    adw_http_content_type_html);

	req->put_head(req, HTTP_STATUS_OK, hdr_msg);
	
	//中国域
	if(_memcmp(ada_conf.region, "CN" , 2) == 0)
	{
		if (req->ios_ver > 10) {
			server_put(req,
			    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN "
			    "http://www.w3.org/TR/html4/strict.dtd\">\n"
			    "<html>\n"
			    "<head>"
			    "<meta name=viewport content=\"width=device-width\"/>"
			    "</head><body><center><b><h1>"
			    "正在APP中重定向到<p>Wi-Fi设置<p>请稍后..."
			    "</h1></b> "
			    "<br /><br /><br />"
			    "<div id=done></div>"
			    "</center><script>"
			    "function wifi_setup() {"
				"setTimeout(function() {"
				    "setTimeout(function() {"
					"document.getElementById(\"done\").innerHTML ="
					"\"如果这个页面没有自动关闭"
					"<p>请点击上方的 <b>完成</b>\""
				    "}, 1000);"
				    //"try { window.location.assign("
					//"\"%s://wifi_setup?dsn=%s\");}"
				    //"catch(err) {"
					//"window.location.assign("
					//"\"http://192.168.0.1/wifi\");"
				    //"}"
				"}, 2000);"
			    "}"
			    "window.onload=wifi_setup;\n"
			    "</script></body></html>\n",
			    adw_wifi_ios_app, conf_sys_dev_id);
		} else {
			server_put(req,
			    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN "
			    "http://www.w3.org/TR/html4/strict.dtd\">\n"
			    "<html>\n"
			    "<head>"
			    "<meta name=viewport content=\"width=device-width\"/>"
			    "</head><body><center><b><h1>"
			    "正在APP中重定向到<p>Wi-Fi设置<p>请稍后..."
			    "</h1></b></center><script>"
			    "function wifi_setup() {"
				"setTimeout(function() {"
				    "setTimeout(function() {"
					"window.location.assign("
					"\"http://192.168.0.1/wifi\");"
				    "}, 3000);"
				    "try { window.location.assign("
					"\"%s://wifi_setup?dsn=%s\");}"
				    "catch(err) {"
					"window.location.assign("
					"\"http://192.168.0.1/wifi\");"
				    "}"
				"}, 2000);"
			    "}"
			    "window.onload=wifi_setup;\n"
			    "</script></body></html>\n",
			    adw_wifi_ios_app, conf_sys_dev_id);
		}
	}
	else{
		if (req->ios_ver > 10) {
			server_put(req,
			    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN "
			    "http://www.w3.org/TR/html4/strict.dtd\">\n"
			    "<html>\n"
			    "<head>"
			    "<meta name=viewport content=\"width=device-width\"/>"
			    "</head><body><center><b><h1>"
			    "Redirecting to<p>Wi-Fi setup in app<p>Please wait…"
			    "</h1></b> "
			    "<br /><br /><br />"
			    "<div id=done></div>"
			    "</center><script>"
			    "function wifi_setup() {"
				"setTimeout(function() {"
				    "setTimeout(function() {"
					"document.getElementById(\"done\").innerHTML ="
					"\"If this page does not close automatically"
					"<p>please click the <b>Done</b> link"
					"<p>in the banner, above\""
				    "}, 1000);"
				    //"try { window.location.assign("
					//"\"%s://wifi_setup?dsn=%s\");}"
				    //"catch(err) {"
					//"window.location.assign("
					//"\"http://192.168.0.1/wifi\");"
				    //"}"
				"}, 2000);"
			    "}"
			    "window.onload=wifi_setup;\n"
			    "</script></body></html>\n",
			    adw_wifi_ios_app, conf_sys_dev_id);
		} else {
			server_put(req,
			    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN "
			    "http://www.w3.org/TR/html4/strict.dtd\">\n"
			    "<html>\n"
			    "<head>"
			    "<meta name=viewport content=\"width=device-width\"/>"
			    "</head><body><center><b><h1>"
			    "Redirecting to<p>Wi-Fi setup in app<p>Please wait…"
			    "</h1></b></center><script>"
			    "function wifi_setup() {"
				"setTimeout(function() {"
				    "setTimeout(function() {"
					"window.location.assign("
					"\"http://192.168.0.1/wifi\");"
				    "}, 3000);"
				    "try { window.location.assign("
					"\"%s://wifi_setup?dsn=%s\");}"
				    "catch(err) {"
					"window.location.assign("
					"\"http://192.168.0.1/wifi\");"
				    "}"
				"}, 2000);"
			    "}"
			    "window.onload=wifi_setup;\n"
			    "</script></body></html>\n",
			    adw_wifi_ios_app, conf_sys_dev_id);
		}
	}
}

/*
 * start scan if still UP.
 * Doing this in a callback so not too many buffers are occupied.
 */
static void adw_wifi_page_scan_get_cb(void *arg)
{
	struct adw_state *wifi = arg;

	adw_lock();
	if (wifi->scan_state == SS_SCAN_START) {
		adw_wifi_scan(wifi);
	}
	adw_unlock();

}

enum ada_err adw_wifi_start_scan4(u32 min_interval, struct adw_ssid *ssid)
{
	struct adw_state *wifi = &adw_state;
	u32 now;
	enum ada_err rc;

	AYLA_ASSERT(adw_locked);
	if (wifi->scan_state == SS_SCAN) {
		rc = AE_IN_PROGRESS;	/* scanning already */
	} else if (wifi->state >= WS_JOIN && wifi->state < WS_UP) {
		rc = AE_NOTCONN;	/* connecting to service */
	} else if (wifi->state == WS_UP_AP || wifi->state == WS_UP) {
		now = clock_ms();
		if (now - wifi->scan_time >= min_interval ||
		    !wifi->scan_time) {
			wifi->scan_state = SS_SCAN_START;
			wifi->scan_time = now;
			if (ssid) {
				wifi->scan4 = *ssid;
			} else {
				wifi->scan4.len = 0;
			}
			adw_wmi_callback_pend(&adw_wifi_page_scan_callback);
			rc = AE_OK;
		} else {
			rc = AE_BUSY;	/* too soon after previous scan */
		}
	} else {
		rc = AE_INVAL_STATE;	/* wifi isn't up */
	}
	return rc;
}

void adw_wifi_start_scan(u32 min_interval)
{
	adw_lock();
	adw_wifi_start_scan4(min_interval, NULL);
	adw_unlock();
}

void adw_wifi_setup_callback(struct adw_state *wifi, struct server_req *req)
{
	wifi->rejoin = 1;
	req->tcpip_cb = &adw_wifi_cbmsg_delayed;
}

/*
 * Add or update a Wi-Fi profile.
 * Called while holding lock.
 */
enum wifi_error
adw_wifi_add_prof(struct adw_state *wifi, const struct adw_ssid *ssid,
	const char *key, size_t key_len, enum conf_token sec_token, u8 mfi,
	u8 hidden)
{
	struct adw_profile *prof;
	struct adw_wifi_wep_key wep_buf;
	char ssid_buf[33];

	prof = adw_wifi_prof_search(wifi, ssid);
	if (!prof) {
		/*
		 * If no free slots, override next to last one.
		 */
		prof = &wifi->profile[ADW_WIFI_PROF_AP - 1];
		if (wifi->curr_profile == ADW_WIFI_PROF_AP - 1) {
			prof--;
		}
	} else {
		hidden |= prof->hidden;
	}

	if (sec_token == CT_none) {
		key_len = 0;
#ifndef AMEBA	/*won't support WEP sec in Realtek platform*/
	} else if (sec_token == CT_WEP) {
		if (adw_wifi_wep_key_convert((u8 *)key, key_len, &wep_buf)) {
			wifi->err_msg = "A WEP key may be 5 or 13 characters "
			    "long, or may contain only numbers and "
			    "letters a thru f, (case insensitive), "
			    "and be 10, 16, 26, or 32 characters long.";
			return WIFI_ERR_INV_KEY;
		}
#endif
	} else if (key_len < WIFI_MIN_KEY_LEN) {
		snprintf(wifi->err_buf, sizeof(wifi->err_buf) - 1,
		    "Key too short.  %d characters or more required.",
		    WIFI_MIN_KEY_LEN);
		return WIFI_ERR_INV_KEY;
	}

	memset(prof, 0, sizeof(*prof));	/* clear prof->enable and prof->scan */
	prof->ssid = *ssid;
	prof->sec = sec_token;
	memcpy(prof->key, key, key_len);
	prof->key_len = key_len;
	wifi->saved_key_len = 0;
	prof->mfi = mfi;
	prof->hidden = hidden;
	if (hidden) {
		prof->spec_scan_done = 1;
	}
	wifi->pref_profile = (prof - wifi->profile) + 1;
	wifi->err_msg = NULL;

	adw_log(LOG_DEBUG "add_prof ssid %s sec %u %s%s",
	    adw_format_ssid(ssid, ssid_buf, sizeof(ssid_buf)),
	    sec_token, mfi ? "mfi " : "", hidden ? "hidden " : "");

	return WIFI_ERR_NONE;
}

/*
 * Handle request ssid arg and lookup profile.
 * Called with lock held.
 */
static struct adw_profile *
adw_wifi_get_prof(struct server_req *req, struct adw_ssid *ssid)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;
	char *arg;
	char ssid_buf[33];

	ssid->len = 0;
	arg = server_get_arg_by_name(req, "ssid", ssid_buf, sizeof(ssid_buf));
	if (!arg) {
		adw_log(LOG_WARN "get_prof: no ssid arg");
		/* XXX TBD show error on web page */
		return NULL;
	}
	memset(ssid, 0, sizeof(*ssid));
	ssid->len = strlen(arg);
	if (ssid->len > sizeof(ssid->id)) {
		adw_log(LOG_WARN "SSID is too long");
		return NULL;
	}
	memcpy(ssid->id, arg, ssid->len);

	prof = adw_wifi_prof_lookup(wifi, ssid);
	if (prof == NULL) {
		adw_log(LOG_WARN "get_prof: no profile ssid '%s'",
		    ssid_buf);
	}
	return prof;
}

/*
 * Delete a profile / disconnect if connected.
 * Returns:  1 if the connected profile is being deleted.
 *	0 otherwise on success.
 *	-1 if profile not found.
 */
int adw_wifi_del_prof(struct adw_state *wifi, const struct adw_ssid *ssid)
{
	struct adw_profile *prof;
	int rc = 0;

	adw_lock();
	prof = adw_wifi_prof_lookup(wifi, ssid);
	if (prof == NULL) {
		adw_unlock();
		return -1;
	}
	memset(prof, 0, sizeof(*prof));
	if (prof == &wifi->profile[wifi->pref_profile - 1]) {
		wifi->pref_profile = 0;
	}
	if (wifi->state >= WS_JOIN &&
	    prof == &wifi->profile[wifi->curr_profile]) {
		rc = 1;
	}
	adw_unlock();
	conf_persist(CT_wifi, adw_wifi_export_profiles, wifi);

	return rc;
}

/*
 * Delete profile for web page.
 * Returns non-zero if profile not found.
 */
static int adw_wifi_delete(struct server_req *req)
{
	struct adw_ssid ssid;
	struct adw_state *wifi = &adw_state;
	int rc;

	if (!adw_wifi_get_prof(req, &ssid)) {
		return -1;
	}
	rc = adw_wifi_del_prof(wifi, &ssid);
	if (rc > 0) {
		adw_wifi_setup_callback(wifi, req);
		rc = 0;
	}
	return rc;
}

/*
 * Get JSON Wifi Scan results
 */
static void adw_wifi_json_scan_get(struct server_req *req)
{
	struct adw_state *wifi = &adw_state;
	struct adw_scan *scan;
	u8 *bp;
	char ssid_buf[32 * 6 + 1];	/* room for SSID with escapes */
	char sep;
	const char *end_token;
	struct adw_wifi_scan_wait *wsw;
	int nossid;

	if (wifi->scan[0].rssi == WIFI_MIN_SIG) {
		adw_wifi_start_scan(WIFI_SCAN_MIN_LIMIT);
	}
	adw_lock();
	if (wifi->scan_state == SS_SCAN || wifi->scan_state == SS_SCAN_START) {
		/*
		 * Wait for scan to finish before reporting results.
		 */
		wsw = malloc(sizeof(*wsw));
		if (wsw) {
			req->user_in_prog = 1;
			req->err = AE_IN_PROGRESS;
			adw_wifi_scan_wait_queue(wsw, req);
			adw_unlock();
			return;
		} else {
			/*
			 * If we cannot alloc mem to wait for completion
			 * of currently ongoing scan, then just report
			 * scan data collected so far.
			 */
		}
	}

	nossid = server_get_bool_arg_by_name(req, "nossid");

	server_json_header(req);
	server_put(req, "{\"wifi_scan\":{\"mtime\":%lu,\"results\":",
	    wifi->scan_time);
	sep = '[';
	end_token = "null}}";
	for (scan = wifi->scan; scan < &wifi->scan[ADW_WIFI_SCAN_CT]; scan++) {
		if (scan->ssid.len == 0) {
			continue;
		}
		if (!json_format_string_with_len(ssid_buf, sizeof(ssid_buf),
		    (char *)scan->ssid.id, scan->ssid.len, 1)) {
			continue;
		}
		bp = scan->bssid;

		server_put(req, "%c{"
		    "%s%s%s"
		    "\"type\":\"%s\","
		    "\"chan\":%u,"
		    "\"signal\":%d,"
		    "\"bars\":%u,"
		    "\"security\":\"%s\","
		    "\"bssid\":\"%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x\"}",
		    sep,
		    nossid ? "" : "\"ssid\":\"",
		    nossid ? "" : ssid_buf,
		    nossid ? "" : "\",",
		    scan->type == BT_INFRASTRUCTURE ? "AP" :
		    scan->type == BT_AD_HOC ?  "Ad hoc" : "Unknown",
		    scan->channel, scan->rssi,
		    adw_wifi_bars(scan->rssi),
		    adw_wmi_sec_string(scan->wmi_sec),
		    bp[0], bp[1], bp[2], bp[3], bp[4], bp[5]);
		sep = ',';
		end_token = "]}}";
	}
	adw_unlock();
	server_put_pure(req, end_token);
}

/*
 * JSON get profiles.
 */
static void adw_wifi_json_prof_get(struct server_req *req)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;
	char ssid_buf[32 * 6 + 1];	/* room for SSID with escapes */
	int indx;
	char sep;
	const char *end_token;

	server_json_header(req);
	server_put_pure(req, "{\"wifi_profiles\":");

	adw_lock();
	sep = '[';
	end_token = "null}";
	for (indx = 0, prof = wifi->profile;
	    indx < ADW_WIFI_PROF_AP; prof++, indx++) {
		if (prof->ssid.len == 0 ||
		    (!prof->enable && indx + 1 != wifi->pref_profile)) {
			continue;
		}
		if (!json_format_string_with_len(ssid_buf, sizeof(ssid_buf),
		    (char *)prof->ssid.id, prof->ssid.len, 1)) {
			continue;
		}

		server_put(req,
		    "%c{\"ssid\":\"%s\","
		    "\"security\":\"%s\"}",
		    sep, ssid_buf, adw_wifi_conf_string(prof->sec));
		sep = ',';
		end_token = "]}";
	}
	adw_unlock();
	server_put_pure(req, end_token);
}

static char *adw_format_ip(ip_addr_t *ip, char *buf, size_t len)
{
	u8 *bp = (u8 *)ip;

	len = snprintf(buf, len - 1, "%u.%u.%u.%u", bp[0], bp[1], bp[2], bp[3]);
	buf[len] = '\0';
	return buf;
}

const char *adw_format_ssid(struct adw_ssid *ssid, char *buf, size_t len)
{
	static char ssid_buf[33];
	int half_len;

	if (buf == NULL) {
		buf = ssid_buf;
		len = sizeof(ssid_buf);
	}

	if (ssid->len < len) {
		memcpy(buf, ssid->id, ssid->len);
		buf[ssid->len] = '\0';
	} else {
		ASSERT(len > 16);
		half_len = len / 2 - 3;
		memcpy(buf, ssid->id, half_len);
		memcpy(buf + half_len, " ... ", 5);
		memcpy(buf + half_len + 5, ssid->id + ssid->len - half_len,
		    half_len);
		buf[2 * half_len + 5] = '\0';
	}
	return buf;
}

/*
 * JSON get status.
 */
static void adw_wifi_json_stat_get(struct server_req *req)
{
	struct adw_state *wifi = &adw_state;
	struct adw_wifi_history *hist;
	struct adw_profile *prof;
	u8 *mac;
	char buf[18];
	char ssid[sizeof(prof->ssid.id) * 6 + 1]; /* JSON-encoded */
	char symname_buf[CLIENT_CONF_SYMNAME_LEN * 6 + 1]; /* JSON-encoded */
	char bssid_buf[20];
	u8 bssid[6];
	size_t bssid_len = 0;
	const char *symname;
	int rssi;
	char sep;
	const char *end_token;
	char *arg;
	int i;

	arg = server_get_arg_by_name(req, "bssid",
	     bssid_buf, sizeof(bssid_buf));
	if (arg) {
		bssid_len = parse_hex(bssid, sizeof(bssid),
		    arg, sizeof(bssid_buf));
	}

	server_json_header(req);
	adw_lock();
	rssi = adw_wifi_avg_rssi();

	server_put(req, "{\"wifi_status\":{\"connect_history\":");
	sep = '[';
	end_token = "null";
	hist = &wifi->hist[wifi->hist_curr];
	for (i = 0; i < WIFI_HIST_CT; i++) {
		if (hist->ssid_len &&
		    (bssid_len == 0 || (hist->curr &&
		    !memcmp(bssid, hist->bssid, sizeof(hist->bssid))))) {
			buf[0] = hist->ssid_info[0];
			buf[1] = hist->ssid_info[1];
			buf[2] = '\0';
			server_put(req, "%c{"
			    "\"ssid_info\": \"%s\",\"ssid_len\":%u,"
			    "\"bssid\":\"%2.2x%2.2x\","
			    "\"error\":%d,"
			    "\"msg\":\"%s\","
			    "\"mtime\":%lu,"
			    "\"last\":%u,",
			    sep, buf, hist->ssid_len,
			    hist->bssid[4], hist->bssid[5], hist->error,
			    adw_wifi_errors[hist->error],
			    hist->time, hist->last ? 1 : 0);
			server_put(req, "\"ip_addr\":\"%s\",",
			    adw_format_ip(&hist->ip_addr,
			    buf, sizeof(buf)));
			server_put(req, "\"netmask\":\"%s\",",
			    adw_format_ip(&hist->netmask,
			    buf, sizeof(buf)));
			server_put(req, "\"default_route\":\"%s\",",
			    adw_format_ip(&hist->def_route,
			    buf, sizeof(buf)));
			server_put(req, "\"dns_servers\":[\"%s\",",
			    adw_format_ip(&hist->dns_servers[0],
			    buf, sizeof(buf)));
			server_put(req, "\"%s\"]}",
			    adw_format_ip(&hist->dns_servers[1],
			    buf, sizeof(buf)));
			sep = ',';
			end_token = "]";
		}
		if (--hist < wifi->hist) {
			hist += WIFI_HIST_CT;
		}
	}

	ssid[0] = '\0';
	if (wifi->state == WS_UP || wifi->state == WS_WAIT_CLIENT) {
		prof = &wifi->profile[wifi->curr_profile];
		json_format_string_with_len(ssid, sizeof(ssid),
		    (const char *)prof->ssid.id, prof->ssid.len, 1);
	}

	symname = json_format_string(symname_buf, sizeof(symname_buf),
	    ada_conf.host_symname, sizeof(ada_conf.host_symname), 1);

	mac = adw_wifi_mac(wifi);
	server_put(req, "%s,\"dsn\":\"%s\","
	    "\"device_service\":\"%s\","
	    "\"log_service\":\"%s\","
	    "\"mac\":\"%s\","
	    "\"mtime\":%lu,"
	    "\"host_symname\":\"%s\","
	    "\"connected_ssid\":\"%s\","
	    "\"ant\":%u,"
#ifdef WIFI_WPS
	    "\"wps\":\"%s\","
#endif
	    "\"rssi\":%d,"
	    "\"bars\":%u"
	    "}}",
	    end_token,
	    conf_sys_dev_id, client_host(),
#ifdef QCA4010 /* XXX */
	    "",
#else
	    log_client_host(),
#endif
	    format_mac(mac, buf, sizeof(buf)),
	    clock_ms(), symname, ssid, wifi->ant,
#ifdef WIFI_WPS
	    adw_wmi_wps_state_str(wifi),
#endif
	    rssi, adw_wifi_bars(rssi));
	adw_unlock();
}

/*
 * JSON interface to add or update a Wi-Fi profile.
 * Called without holding lock.
 *
 * Generates empty JSON response to server request.
 * Arguments are ssid, key, setup_token, and optional "hidden" flag.
 * The SSID must match an SSID in the scan list, and the security type
 * is taken from the scan list, not from an argument.
 */
static void adw_wifi_json_connect_post(struct server_req *req)
{
	struct adw_state *wifi = &adw_state;
	struct adw_wifi_history *hist;
	enum conf_token sec_token = CT_INVALID_TOKEN;
	enum wifi_error error;
	struct adw_scan *scan;
	struct adw_ssid ssid;
	char key[WIFI_MAX_KEY_LEN];
	char bssid_buf[20];
	char setup_buf[20];
	u8 bssid[6];
	size_t key_len = 0;
	size_t len;
	ssize_t bssid_len = 0;
	char ssid_buf[3 * sizeof(ssid.id) + 1];	/* for all escaped chars */
	char *arg;
	char *location;
	struct adw_wifi_scan_wait_connect *wswc;
	u8 hidden = 0;

	wifi->err_msg = wifi->err_buf;
	client_set_setup_token("");

	if (req->user_priv) {
		wswc = (struct adw_wifi_scan_wait_connect *)req->user_priv;
		ssid = wswc->wswc_ssid;
		key_len = wswc->wswc_key_len;
		memcpy(key, wswc->wswc_key, key_len);
		hidden = wswc->hidden;
	} else {
		memset(&ssid, 0, sizeof(ssid));
		arg = server_get_arg_by_name(req, "ssid",
		    ssid_buf, sizeof(ssid_buf));
		if (arg) {
			len = strlen(arg);
			if (len > sizeof(ssid.id)) {
				goto invalid;
			}
			memcpy(ssid.id, arg, len);
			ssid.len = len;
		}

		arg = server_get_arg_by_name(req, "bssid",
		    bssid_buf, sizeof(bssid_buf));
		if (arg) {
			bssid_len = parse_hex(bssid, sizeof(bssid),
			    arg, sizeof(bssid_buf));
			if (bssid_len <= 0) {
				goto invalid;
			}
		}

		arg = server_get_arg_by_name(req, "key", key, sizeof(key));
		if (arg) {
			key_len = strlen(arg);
		}

		arg = server_get_arg_by_name(req, "setup_token",
		    setup_buf, sizeof(setup_buf));
		if (arg) {
			client_set_setup_token(arg);
		}
		location = server_get_dup_arg_by_name(req, "location");
		client_set_setup_location(location);

		if (!ssid.len && !bssid_len) {
			snprintf(wifi->err_buf, sizeof(wifi->err_buf) - 1,
			    "Missing SSID");
invalid:
			server_put_status(req, HTTP_STATUS_BAD_REQ);
			return;
		}
	}
	/*
	 * Find SSID in scan list.
	 */
	adw_lock();
	if (ssid.len)  {
		scan = adw_wifi_scan_lookup_ssid(wifi, &ssid, 0);
	} else {
		scan = adw_wifi_scan_lookup_bssid(wifi, bssid);
		if (scan) {
			ssid = scan->ssid;
		}
	}
	if (!scan) {
		if (!req->user_priv || wifi->scan_state == SS_SCAN) {
			wswc = malloc(sizeof(*wswc));
			if (wswc) {
				req->user_in_prog = 1;
				req->err = AE_IN_PROGRESS;
				req->user_priv = (void *)wswc;
				adw_wifi_start_scan4(0, &ssid);
				wswc->wswc_ssid = ssid;
				wswc->wswc_key_len = key_len;
				memcpy(wswc->wswc_key, key, key_len);
				wswc->hidden = 1;
				adw_wifi_scan_wait_queue(&wswc->wswc_head, req);
				adw_unlock();
				return;
			} else {
				/*
				 * Fail by failing the join early.
				 */
			}
		}
		adw_log(LOG_DEBUG "not finding it");
		snprintf(wifi->err_buf, sizeof(wifi->err_buf) - 1,
		    "%s not found in scan",
		    adw_format_ssid(&ssid, ssid_buf, sizeof(ssid_buf)));
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
		snprintf(wifi->err_buf, sizeof(wifi->err_buf) - 1,
		    "Unsupported security type \"%s\"",
		    adw_wmi_sec_string(scan->wmi_sec));
		error = WIFI_ERR_SEC_UNSUP;
		goto err;
	}

	if (key_len == 0 && sec_token != CT_none) {
		snprintf(wifi->err_buf, sizeof(wifi->err_buf) - 1,
		    "Missing key");
		error = WIFI_ERR_INV_KEY;
		goto err;
	}
	error = adw_wifi_add_prof(wifi, &ssid, key, key_len,
	    sec_token, 0, hidden);
err:
	adw_wifi_hist_clr_curr(wifi);
	if (error) {
		hist = adw_wifi_hist_new(wifi, &ssid, scan);
		hist->curr = 1;
		hist->error = error;

		/*
		 * HTTP status 400 for 'Bad Request'.
		 */
		req->http_status = HTTP_STATUS_BAD_REQ;
		server_json_header(req);
		server_put(req, "{\"error\":%d,\"msg\":\"%s\"}",
		    error, adw_wifi_errors[error]);
	} else {
		adw_wifi_setup_callback(wifi, req);
		server_put_status(req, HTTP_STATUS_NO_CONTENT);
	}
	adw_unlock();
}

static void adw_wifi_json_stop_ap_put(struct server_req *req)
{
#ifdef WIFI_CONCURRENT_AP_STA_MODE
	struct adw_state *state = &adw_state;

	if (state->state == WS_UP) {
		adw_lock();
		adw_wifi_stop_ap_sched(WIFI_CMD_RSP_TMO);
		adw_unlock();
		server_put_status(req, HTTP_STATUS_NO_CONTENT);
	} else {
		server_put_status(req, HTTP_STATUS_FORBID);
	}
#else
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
#endif
}

/*
 * Handle DELETE on /wifi_profile.json.
 */
static void adw_wifi_json_prof_delete(struct server_req *req)
{
	if (adw_wifi_delete(req) == -1) {
		server_put_status(req, HTTP_STATUS_NOT_FOUND);
		return;
	}
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
}

/*
 * Start new scan.
 */
static void adw_wifi_json_scan_post(struct server_req *req)
{
	adw_wifi_start_scan(WIFI_SCAN_MIN_LIMIT);
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
}

#ifdef WIFI_WPS
/*
 * WPS virtual button press
 */
static void adw_wifi_json_wps_post(struct server_req *req)
{
	char tok[CLIENT_SETUP_TOK_LEN];
	char *cp;

	if (!adw_wifi_in_ap_mode() || adw_wifi_start_wps()) {
		server_put_status(req, HTTP_STATUS_FORBID);
		return;
	}

	/*
	 * Get setup token using local buffer, restricting length.
	 */
	cp = server_get_arg_by_name(req, "setup_token", tok, sizeof(tok));
	if (cp) {
		client_set_setup_token(cp);
	}

	/*
	 * Get location, allocating a buffer to pass to set function.
	 */
	cp = server_get_dup_arg_by_name(req, "location");
	if (cp) {
		client_set_setup_location(cp);
		/* do not free cp, as client_set_setup_location() keeps it */
	}

	server_put_status(req, HTTP_STATUS_NO_CONTENT);
}

/*
 * AP Mode registration token
 */
void adw_wifi_json_apreg_post(struct server_req *req)
{
	char tok[CLIENT_SETUP_TOK_LEN];
	char *cp;

	if (!adw_wifi_in_ap_mode()) {
		server_put_status(req, HTTP_STATUS_FORBID);
		return;
	}

	/*
	 * Get setup token using local buffer, restricting length.
	 */
	cp = server_get_arg_by_name(req, "setup_token", tok, sizeof(tok));
	if (cp) {
		client_set_setup_token(cp);
	}

	/*
	 * Get location, allocating a buffer to pass to set function.
	 */
	cp = server_get_dup_arg_by_name(req, "location");
	if (cp) {
		client_set_setup_location(cp);
		/* do not free cp, as client_set_setup_location() keeps it */
	}

	server_put_status(req, HTTP_STATUS_NO_CONTENT);
}
#endif /* WIFI_WPS */

/*
 * Log function for adw_wifi_show_hist.
 */
int adw_wifi_show_hist_log(void *arg, const char *msg)
{
	adw_log(LOG_INFO "%s", msg);
	return 0;
}

void adap_wifi_show_hist(int to_log)
{
	adw_wifi_show_hist(to_log);
}

/*
 * Show Wi-Fi history.
 * If to_log is non-zero, send to logging server.
 */
void adw_wifi_show_hist(int to_log)
{
	struct adw_state *wifi = &adw_state;
	struct adw_wifi_history *hist;
	const char *label = "    ";
	char ip[46];
	char mask[18];
	char gw[18];
	char dns0[18];
#if WIFI_HIST_DNS_SERVERS > 1
	char dns1[18];
#endif /* WIFI_HIST_DNS_SERVERS */
	char timestamp[CLOCK_FMT_LEN];
	char anon_ssid[4];
	int indx;
	char *cp;

	if (to_log) {
		print_remote_set(adw_wifi_show_hist_log, NULL);
		label = "hist ";
	}
	indx = wifi->hist_curr;
	do {
		indx++;
		if (indx >= WIFI_HIST_CT) {
			indx = 0;
		}
		hist = &wifi->hist[indx];
		if (!hist->ssid_len) {
			continue;
		}
		if (to_log) {
			if (hist->logged) {
				continue;
			}
			hist->logged = 1;
		}
		cp = anon_ssid;
		*cp++ = hist->ssid_info[0];
		if (hist->ssid_len > 1) {
			if (hist->ssid_len > 2) {
				*cp++ = '*';
			}
			*cp++ = hist->ssid_info[1];
		}
		*cp++ = '\0';

		clock_fmt(timestamp, sizeof(timestamp),
		    boot_rel_time.ct_sec +
		    (boot_rel_time.ct_usec / 1000 + hist->time) / 1000);

		printcli("%s%sZ anon ssid %s bssid %2.2x%2.2x status%s %u %s",
		    label, timestamp, anon_ssid, hist->bssid[4], hist->bssid[5],
		    hist->last ? " (final)" : "", hist->error,
		    adw_wifi_errors[hist->error]);

		printcli("%s  IP %s mask %s default route %s",
		    label,
		    adw_format_ip(&hist->ip_addr, ip, sizeof(ip)),
		    adw_format_ip(&hist->netmask, mask, sizeof(mask)),
		    adw_format_ip(&hist->def_route, gw, sizeof(gw)));

#if WIFI_HIST_DNS_SERVERS > 1
		printcli("%s  DNS %s, %s",
		    label,
		    adw_format_ip(&hist->dns_servers[0], dns0, sizeof(dns0)),
		    adw_format_ip(&hist->dns_servers[1], dns1, sizeof(dns1)));
#else
		printcli("%s  DNS %s",
		    label,
		    adw_format_ip(&hist->dns_servers[0], dns0, sizeof(dns0)));
#endif /* WIFI_HIST_DNS_SERVERS */

	} while (indx != wifi->hist_curr);

	if (to_log) {
		print_remote_set(NULL, NULL);
	}
}

#ifndef AYLA_NO_CLI

static void adw_wifi_show_if(const char *name, struct netif *ifnet)
{
	struct adw_state *wifi = &adw_state;
	ip_addr_t addr;
	const u8 *mac;
	u8 mac_buf[6];
	char buf[46];
	int indx;
	int ap;

	if (!ifnet) {
		return;
	}

	ap = (ifnet == wifi->nif_ap);

#ifdef MAC_ADDR_SET_BY_HOST
	mac = adw_wifi_mac(wifi);
#else
	adw_wmi_get_mac_addr(ap, mac_buf);
	mac = mac_buf;
#endif
	printcli("\n%s MAC address %s",
	    name, format_mac(mac, buf, sizeof(buf)));

	if (net_netif_is_up(ifnet) && net_netif_is_link_up(ifnet)) {
		printcli("IP       %s",
		    adw_format_ip(&ifnet->ip_addr, buf, sizeof(buf)));
		printcli("netmask  %s",
		    adw_format_ip(&ifnet->netmask, buf, sizeof(buf)));
#ifdef NET_IPV6
		for (indx = 0; indx < LWIP_IPV6_NUM_ADDRESSES; indx++) {
			if (ip6_addr_isvalid(netif_ip6_addr_state(ifnet,
				    indx))) {
				ip_addr_ntop(1,
				    ip6_2_ipX(netif_ip6_addr(ifnet, indx)),
				    buf, sizeof(buf));
				printcli("IP6 %s", buf);
			}
		}
#endif
		if (!ap) {
			for (indx = 0;; indx++) {
				addr = net_dns_getserver(indx);
				if (!addr.addr) {
					break;
				}
				printcli("DNS      %s",
				    adw_format_ip(&addr, buf, sizeof(buf)));
			}
		}
	} else {
		printcli("Net %s, Link %s",
		    net_netif_is_up(ifnet) ? "Up" : "Down",
		    net_netif_is_link_up(ifnet) ? "Up" : "Down");
	}
}

void adw_wifi_show(void)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;
	struct adw_scan *scan;
	char *cp;
	char *hid;
	const char *sec;
	int indx;
	u8 tx_power;
	char ssid_buf[33];

	adw_lock();
	prof = &wifi->profile[wifi->curr_profile];

	switch (wifi->state) {
	case WS_DISABLED:
		if (!wifi->cm.enable) {
			printcli("Wi-Fi disabled in favor of other network");
		} else {
			printcli("Wi-Fi disabled");
		}
		break;
	case WS_ERROR:
		printcli("Wi-Fi failed");
		break;
	case WS_IDLE:
		printcli("Wi-Fi idle %sscanning",
		    wifi->scan_state == SS_IDLE ? "not " : "");
		break;
	case WS_RESTART:
	case WS_SCAN_DONE:
		printcli("Wi-Fi idle");
		break;
	case WS_WPS:
	case WS_WPS_DONE:
		printcli("WPS scanning");
		break;
	case WS_JOIN:
		printcli("Wi-Fi associating with SSID %s",
		    adw_format_ssid(&prof->ssid, ssid_buf, sizeof(ssid_buf)));
		break;
	case WS_DHCP:
	case WS_WAIT_CLIENT:
	case WS_UP:
		printcli("Wi-Fi associated with SSID %s",
		    adw_format_ssid(&prof->ssid, ssid_buf, sizeof(ssid_buf)));
		switch (wifi->state) {
		case WS_DHCP:
			printcli("Wi-Fi waiting for DHCP");
			break;
		case WS_WAIT_CLIENT:
			printcli("Wi-Fi waiting for ADS");
			break;
		default:
			break;
		}
		printcli("RSSI %d antenna %d", adw_wifi_avg_rssi(), wifi->ant);
		if (!adw_wmi_get_tx_power(&tx_power) && (tx_power)) {
			printcli("tx_power %d", tx_power);
		}
		if (wifi->listen_itvl) {
			printcli("listen interval %d", wifi->listen_itvl);
		}
		break;
	case WS_START_AP:
	case WS_UP_AP:
#ifdef AIRKISS
		if (wifi->setup_mode & WIFI_AIRKISS) {
			printcli("Wi-Fi Airkiss mode: Listening...");
			break;
		}
#endif
		printcli("Wi-Fi AP mode ssid %s",
		    adw_format_ssid(&wifi->profile[ADW_WIFI_PROF_AP].ssid,
		    ssid_buf, sizeof(ssid_buf)));
		printcli("RSSI %d antenna %d", adw_wifi_avg_rssi(), wifi->ant);
		if (!adw_wmi_get_tx_power(&tx_power) && (tx_power)) {
			printcli("tx_power %d", tx_power);
		}
		break;
	}

	adw_wifi_show_if("STA", wifi->nif_sta);
	adw_wifi_show_if("AP", wifi->nif_ap);

	if (!wifi->save_on_server_connect) {
		printcli("\nsave_on_server_connect off");
	}
	if (wifi->save_on_ap_connect) {
		printcli("\nsave_on_ap_connect on");
	}

	printcli("\nprofiles:\n%5s %20s  %15s",
	    "Index", "Network", "Security");
	for (indx = 0, prof = wifi->profile;
	    indx <= ADW_WIFI_PROF_AP; prof++, indx++) {
		if (prof->ssid.len == 0) {
			continue;
		}
		hid = prof->hidden ? "hidden " : "";
		cp = prof->enable ? "" : "disabled";
		sec = conf_string(prof->sec);
		if (!sec) {
			sec = "Unknown";
		}
		if (indx == ADW_WIFI_PROF_AP) {
			printcli("   AP %20s  %15s %s",
			    adw_format_ssid(&prof->ssid, ssid_buf,
			    sizeof(ssid_buf)), sec, cp);
		} else {
			printcli("%5d %20s  %15s %s%s",
			    indx, adw_format_ssid(&prof->ssid, ssid_buf,
			    sizeof(ssid_buf)), sec, hid, cp);
		}
	}

	printcli("\nscan results:\n%32s %8s %4s %6s %20s",
	    "Network", "Type", "Chan", "Signal", "Security");
	for (scan = wifi->scan; scan < &wifi->scan[ADW_WIFI_SCAN_CT]; scan++) {
		if (scan->ssid.len == 0) {
			continue;
		}

		/*
		 * If the SSID contains unprintable characters, show it in hex.
		 */
		cp = (char *)scan->ssid.id;
		for (indx = 0; indx < scan->ssid.len; indx++) {
			if (scan->ssid.id[indx] < 0x20) {
				printcli_s("Hex SSID: ");
				for (indx = 0; indx < scan->ssid.len; indx++) {
					printcli_s("%2.2x ",
					    scan->ssid.id[indx]);
				}
				printcli("\n");
				cp = "";
				break;
			}
		}
		printcli("%32s %8s %4u %6d %20s",
		    cp[0] ? adw_format_ssid(&scan->ssid, ssid_buf,
		    sizeof(ssid_buf)) : cp,
		    scan->type == BT_INFRASTRUCTURE ? "AP" :
		    scan->type == BT_AD_HOC ? "Ad hoc" :
		    "Unknown",
		    scan->channel, scan->rssi,
		    adw_wmi_sec_string(scan->wmi_sec));
	}

	printcli("\nconnection history:");
	adw_wifi_show_hist(0);

	adw_unlock();
}
#endif /* AYLA_NO_CLI */

/*
 * Fill in the buffer with the currently-connected network SSID.
 * Returns the length, or 0 or negative number if no SSID.
 */
int adap_wifi_get_ssid(void *buf, size_t len)
{
	struct adw_state *wifi = &adw_state;
	struct adw_profile *prof;
	int rc = 0;

	memset(buf, 0, len);
	adw_lock();
	switch (wifi->state) {
	case WS_JOIN:
	case WS_DHCP:
	case WS_WAIT_CLIENT:
	case WS_UP:
		prof = &wifi->profile[wifi->curr_profile];
		if (len > prof->ssid.len) {
			len = prof->ssid.len;
		}
		memcpy(buf, prof->ssid.id, len);
		rc = len;
	default:
		break;
	}
	adw_unlock();
	return rc;
}

static const struct server_buf adw_server_lock_buf =
	SERVER_BUF_INIT(lock_gif_txt, "lock.gif", "image/gif");

static const struct server_buf adw_server_refresh_buf =
	SERVER_BUF_INIT(refresh_gif_txt, "refresh.gif", "image/gif");

static const struct server_buf adw_server_wifi_html_buf =
	SERVER_BUF_INIT(wifi_html_txt, "wifi.html.txt", "text/html");

static const struct server_buf adw_server_wifi_js_buf =
	SERVER_BUF_INIT(wifi_js_txt, "wifi.js", "application/javascript");

static const struct url_list adw_wifi_url_list[] = {
	URL_GET_ARG("/", server_send_static,
	    REQ_KEEPOPEN | REQ_SOFT_AP, &adw_server_wifi_html_buf),
	URL_GET_ARG("/index.html", server_send_static,
	    REQ_KEEPOPEN | REQ_SOFT_AP, &adw_server_wifi_html_buf),
	URL_GET("/library/test/success.html", adw_wifi_page_success,
	    REQ_SOFT_AP),
	URL_GET_ARG("/lock.gif", server_send_static,
	    REQ_KEEPOPEN | REQ_SOFT_AP, &adw_server_lock_buf),
	URL_GET_ARG("/refresh.gif", server_send_static,
	    REQ_KEEPOPEN | REQ_SOFT_AP, &adw_server_refresh_buf),
	URL_GET_ARG("/wifi", server_send_static,
	    REQ_KEEPOPEN | REQ_SOFT_AP, &adw_server_wifi_html_buf),
	URL_GET_ARG("/wifi.js", server_send_static,
	    REQ_KEEPOPEN | REQ_SOFT_AP, &adw_server_wifi_js_buf),
	URL_GET("/wifi_ios", adw_wifi_http_ios_get, REQ_SOFT_AP),
	URL_GET("/wifi_profiles.json", adw_wifi_json_prof_get,
	    REQ_SOFT_AP | APP_ADS_REQS),
	URL_GET("/wifi_scan_results.json", adw_wifi_json_scan_get,
	    REQ_SOFT_AP | APP_ADS_REQS),
	URL_GET("/wifi_status.json", adw_wifi_json_stat_get,
	    APP_ADS_REQS | REQ_SOFT_AP),
	URL_POST("/wifi_connect.json", adw_wifi_json_connect_post,
	    APP_ADS_REQS | REQ_SOFT_AP),
	URL_POST("/wifi_scan.json", adw_wifi_json_scan_post,
	    APP_ADS_REQS | REQ_SOFT_AP),
#ifdef WIFI_WPS
	URL_POST("/wps_pbc.json", adw_wifi_json_wps_post, REQ_SOFT_AP),
#endif /* WIFI_WPS */
	URL_PUT("/wifi_stop_ap.json", adw_wifi_json_stop_ap_put,
	    REQ_SOFT_AP | APP_REQ),
	URL_DELETE("/wifi_profile.json", adw_wifi_json_prof_delete,
	    APP_ADS_REQS),
	{ 0 }
};

void adw_wifi_page_init(int enable_redirect)
{
	if (enable_redirect) {
		server_redir_handler_get = adw_wifi_redir_handler_get;
	}
	server_add_urls(adw_wifi_url_list);
	net_callback_init(&adw_wifi_page_scan_callback,
	    adw_wifi_page_scan_get_cb, &adw_state);
}
