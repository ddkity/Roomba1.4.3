/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */
#define HAVE_UTYPES
#include "lwip/ip_addr.h"
#include <wifi_constants.h>

#include <FreeRTOS.h>
#include <task.h>
#include <httpd/httpd.h>

#include <ayla/utypes.h>
#include <sys/types.h>
#include <ada/libada.h>
#include <ada/sched.h>
#include <ayla/nameval.h>
#include <ayla/log.h>
#ifdef AYLA_WIFI_SUPPORT
#include <adw/wifi.h>
#endif
#include "conf.h"
#include "conf_wifi.h"
#include "demo.h"

/*
 * CLI command to reset the module, optionally to the factory configuration.
 */
void demo_reset_cmd(int argc, char **argv)
{

	if (argc == 2 && !strcmp(argv[1], "factory")) {
		ada_conf_reset(1);
	}
	adap_conf_reset(0);
}

/*
 * setup_mode command.
 * setup_mode enable|disable|show [<key>]
 */
void demo_setup_mode_cmd(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "show")) {
		printcli("setup_mode %sabled", conf_setup_mode ? "en" : "dis");
		return;
	}
#ifdef DEMO_SETUP_ENABLE_KEY
	if (argc == 3 && !strcmp(argv[1], "enable")) {
		if (strcmp(argv[2], DEMO_SETUP_ENABLE_KEY)) {
			printcli("wrong key");
			return;
		}
		ada_conf_setup_mode(1); /* saves if not in setup mode */
		return;
	}
#endif /* SETUP_ENABLE_KEY */
	if (argc == 2 && !strcmp(argv[1], "disable")) {
		ada_conf_setup_mode(0);	/* saves if clearing setup mode */
		return;
	}
	printcli("usage error");
}

void demo_time_cmd(int argc, char **argv)
{
	char buf[40];
	unsigned long sec;
	unsigned long usec;
	u32 t;

	if (argc == 1) {
		clock_fmt(buf, sizeof(buf), clock_utc());
		printcli("%s  %lu ms since boot", buf, clock_ms());
		return;
	}
	if (argc != 2) {
usage:
		printcli("usage: time YYYY-MM-DDTHH:MM:SS");
		return;
	}
	t = clock_parse(argv[1]);
	if (!t || t < CLOCK_START) {
		printcli("time setting invalid");
		goto usage;
	}
	if (clock_set(t, CS_LOCAL)) {
		printcli("time setting failed");
		return;
	}
	printcli("time set\n");
	printcli("time cmd disabled\n");
	return;
}

void demo_client_cmd(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "test")) {
		ada_conf.test_connect = 1;
		return;
	} else if (argc == 4 && strcmp(argv[1], "server") == 0 &&
	    strcmp(argv[2], "region") == 0) {
		if (!mfg_or_setup_mode_ok()) {
			return;
		}
		if (client_set_region(argv[3])) {
			printcli("unknown region code %s\n", argv[3]);
		} else {
			conf_save_config();
			return;
		}
	}
	/* other usage is reserved and should match ADA client_cli() */
	printcli("usage: client <test>|server region <CN|US>");
	return;
}


void demo_save_cmd(int argc, char **argv)
{
	char *args[] = { "conf", "save", NULL};

	conf_cli(2, args);
}

void demo_show_cmd(int argc, char **argv)
{
	char *args[] = { "conf", "show", NULL};

	if (argc != 2) {
		goto usage;
	}

	if (!strcmp(argv[1], "conf")) {
		conf_cli(2, args);
		return;
	}
	if (!strcmp(argv[1], "version")) {
		printcli("%s\n", adap_conf_sw_version());
		return;
	}
#ifdef AYLA_WIFI_SUPPORT
	if (!strcmp(argv[1], "wifi")) {
		adw_wifi_show();
		return;
	}
#endif

usage:
	printcli("usage: show [conf|version|wifi]");
	return;
}

void demo_fact_log_cmd(int argc, char **argv)
{
	struct ada_conf *cf = &ada_conf;
	u32 now;
	struct clock_info ci;
	const u8 *mac = cf->mac_addr;
	const int conf_connected = 0;

	if (argc != 1) {
		printcli("factory-log: invalid usage");
		return;
	}
	if (clock_source() <= CS_DEF) {
		printcli("factory-log: clock not set");
		return;
	}
	now = clock_utc();
	clock_fill_details(&ci, now);
	printcli("factory-log line:\r\n");
	printcli("3,%lu,%2.2lu/%2.2u/%2.2u %2.2u:%2.2u:%2.2u UTC,label,0,"
	    "%s,%s,%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x,%s,"
	    "%s,%s,,%s,%s,%u,%s\r\n",
	    now, ci.year, ci.month, ci.days, ci.hour, ci.min, ci.sec,
	    conf_sys_model, conf_sys_dev_id,
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
	    conf_sys_mfg_model,
	    conf_sys_mfg_serial, cf->hw_id, oem, oem_model, conf_connected,
	    ODM_NAME/*,
	    demo_version*/);
}

void ayla_demo_init(void)
{
	int rc;

	demo_init();

#ifdef AYLA_WIFI_SUPPORT
	demo_wifi_init();
#endif
	/*
	 * Read configuration.
	 */
	client_conf_init();

	/*
	 * Init libada.
	 */
#ifdef AYLA_DEMO_TEST
	rc = ada_api_call(ADA_CLIENT_INIT);
#else
	rc = ada_init();
#endif
	if (rc) {
		log_put(LOG_ERR "ADA init failed");
		return;
	}

	demo_ota_init();

#ifdef AYLA_WIFI_SUPPORT
	demo_wifi_enable();
#endif
}

void demo_idle_enter(void *arg)
{

	demo_idle();
	AYLA_ASSERT_NOTREACHED();
}

#ifndef AYLA_WIFI_SUPPORT
static void rtl_dhcp_bound_handler(int interface, ip_addr_t *ip)
{
	static u8 is_cloud_started;
	char ipbuf[30];

	log_put(LOG_DEBUG "Interface %d got IP %s!",
		interface, ipaddr_ntoa_r(ip, ipbuf, sizeof(ipbuf)));

	/* Interface 0 is  Realtek STA network interface */
	if (interface != 0)
		return;

	ada_client_up();
	server_up();

	if (!is_cloud_started) {
		if (xTaskCreate(demo_idle_enter, "A_LedEvb",
		    DEMO_APP_STACKSZ, NULL, DEMO_APP_PRIO, NULL) != pdPASS) {
			AYLA_ASSERT_NOTREACHED();
		}
		is_cloud_started = 1;
	}
}

static void rtl_wifi_disconnected_handler(char *buf,
	int buf_len, int flags, void *handler_user_data)
{
	log_put(LOG_DEBUG "Wifi disassociated from a AP!");
	ada_client_down();
}

static int(*old_init_wifi_handler)(void);

/* This function is called in the Wifi driver task and will be called when
  * driver is initialized
  */
static int rtl_wifi_drive_ready_handle(void)
{
	wifi_reg_event_handler(WIFI_EVENT_DISCONNECT,
	    rtl_wifi_disconnected_handler, NULL);

	dhcp_set_bound_handler(rtl_dhcp_bound_handler);

	if (old_init_wifi_handler) {
		/* Fast wifi connect by the credit that is set by
		    ATW0, ATW1 and ATWC */
		old_init_wifi_handler();
	}

	return 0;
}
#endif /* AYLA_WIFI_SUPPORT */

void ayla_wlan_init(void)
{
#ifndef AYLA_WIFI_SUPPORT
	old_init_wifi_handler = p_wlan_init_done_callback;
	p_wlan_init_done_callback = rtl_wifi_drive_ready_handle;
#endif
}
