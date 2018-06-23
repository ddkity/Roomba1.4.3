/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#include <ayla/utypes.h>
#include <ada/libada.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/log.h>
#include <ada/dnss.h>
#include <net/net.h>
#include <ada/server_req.h>
#include <adw/wifi.h>
#include <adw/wifi_conf.h>
#include <httpd/httpd.h>

#include "conf_wifi.h"
#include "demo.h"

unsigned char ILITE_NetConnetFlag = 0;	//网络连接标志，1表示连接上了路由，0表示没有连接到路由

/*
 * Event handler.
 * This is called by the Wi-Fi subsystem on connects and disconnects
 * and similar events.
 * This allows the application to start or stop services on those events,
 * and to implement status LEDs, for example.
 */
static void demo_wifi_event_handler(enum adw_wifi_event_id id, void *arg)
{
	static u8 is_cloud_started;

	switch (id) {
	case ADW_EVID_AP_START:
		ILITE_NetConnetFlag = 0;	/* 断开路由 */
		break;

	case ADW_EVID_AP_UP:
		server_up();
		dnss_up();
		ILITE_NetConnetFlag = 0;	/* 断开路由 */
		break;

	case ADW_EVID_AP_DOWN:
		dnss_down();
		ILITE_NetConnetFlag = 0;	/* 断开路由 */
		break;

	case ADW_EVID_STA_UP:
		log_put(LOG_DEBUG "Wifi associated with a AP!");
		ILITE_NetConnetFlag = 0;	/* 断开路由 */
		break;

	case ADW_EVID_STA_DHCP_UP:
		ada_client_up();
		server_up();
		if (!is_cloud_started) {
			if (xTaskCreate(demo_idle_enter, "A_LedEvb",
			    DEMO_APP_STACKSZ, NULL, DEMO_APP_PRIO,
			    NULL) != pdPASS) {
				AYLA_ASSERT_NOTREACHED();
			}
			is_cloud_started = 1;
		}
		ILITE_NetConnetFlag = 1;	/* 连接到路由 */
		break;

	case ADW_EVID_STA_DOWN:
		ada_client_down();
		ILITE_NetConnetFlag = 0;	/* 断开路由 */
		break;

	case ADW_EVID_SETUP_START:
	case ADW_EVID_SETUP_STOP:
	case ADW_EVID_ENABLE:
	case ADW_EVID_DISABLE:
		ILITE_NetConnetFlag = 0;	/* 断开路由 */
		break;

	case ADW_EVID_RESTART_FAILED:
		log_put(LOG_WARN "resetting due to Wi-Fi failure");
		/* sys_msleep(400);
		arch_reboot(); */
		ILITE_NetConnetFlag = 0;	/* 断开路由 */
		break;

	default:
		ILITE_NetConnetFlag = 0;	/* 断开路由 */
		break;
	}
}

void demo_wifi_enable(void)
{
	char *argv[] = { "wifi", "enable" };

	adw_wifi_cli(2, argv);
}

void demo_wifi_init(void)
{
	struct ada_conf *cf = &ada_conf;
	int enable_redirect = 1;
	char ssid[32];

	adw_wifi_event_register(demo_wifi_event_handler, NULL);
	adw_wifi_init();
	adw_wifi_page_init(enable_redirect);

	/*
	 * Set the network name for AP mode, for use during Wi-Fi setup.
	 */
	cf->mac_addr = LwIP_GetMAC(&xnetif[0]);
	snprintf(ssid, sizeof(ssid),
	    OEM_AP_SSID_PREFIX "-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x",
	    cf->mac_addr[0], cf->mac_addr[1], cf->mac_addr[2],
	    cf->mac_addr[3], cf->mac_addr[4], cf->mac_addr[5]);
	adw_wifi_ap_ssid_set(ssid);
	adw_wifi_ios_setup_app_set(OEM_IOS_APP);

}
