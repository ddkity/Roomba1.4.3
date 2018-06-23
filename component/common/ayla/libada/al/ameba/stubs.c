/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/xml.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/tlv.h>
#include <ayla/clock.h>
#include <ayla/conf.h>
#include <ayla/http.h>
#include <ayla/nameval.h>
#include <ayla/timer.h>
#include <ayla/patch_state.h>

#include <net/stream.h>
#include <net/net.h>
#include <net/http_client.h>
#include <net/net_crypto.h>

#include <ada/err.h>
#include <ada/ada_conf.h>
#include <ada/ada_lan_conf.h>
#include <ada/client.h>
#include <ada/prop.h>
#include <ada/prop_mgr.h>
#include <ada/metric.h>
#include <ada/server_req.h>
#include <ada/client_ota.h>
#include <ayla/malloc.h>

#include "notify_int.h"
#include "client_int.h"

#define AYLA_MODEL "AY008RTK1"		/* Ayla "module" part number */

char conf_sys_model[CONF_MODEL_MAX] = AYLA_MODEL;

u8 log_snap_saved;

void __assert_f(const char *file, int line)
{
	log_put(LOG_ERR "ASSERT failed at %s:%d", file, line);
	vTaskDelay(5000);
	sys_reset();
}

const char *prop_dp_put_get_loc(void)
{
	ASSERT_NOTREACHED();
}

enum ada_err prop_dp_put_close(enum prop_cb_status stat, void *arg)
{
	ASSERT_NOTREACHED();
}

enum ada_err prop_dp_put(enum prop_cb_status stat, void *arg)
{
	ASSERT_NOTREACHED();
}

enum ada_err prop_dp_req(enum prop_cb_status stat, void *arg)
{
	ASSERT_NOTREACHED();
}

void log_client_init(void)
{
}

int log_client_enable(int enable)
{
	return -1;
}

const char *log_client_host(void)
{
	return "";
}

void log_client_set(const char *host, char *uri, const char *protocol)
{
}

void log_client_reset(void)
{
}

void *client_lan_buf_alloc(void)
{
	return malloc(CLIENT_LAN_BUF_LEN);
}

void client_lan_buf_free(void *buf)
{
	free(buf);
}

int mfg_or_setup_mode_ok(void)
{
	if (conf_mfg_mode | conf_setup_mode) {
		return 1;
	}
	printcli("not in mfg or setup mode");
	return 0;
}

int mfg_mode_ok(void)
{
	if (conf_mfg_mode) {
		return 1;
	}
	printcli("not in mfg mode");
	return 0;
}

int client_conf_server_change_en(void)
{
	return 1;
}

void random_fill(void *buf, size_t len)
{
	static struct adc_rng rng;

	adc_rng_init(&rng);		/* inits only if not already done */
	if (adc_rng_random_fill(&rng, buf, len)) {
		ASSERT_NOTREACHED();
	}
}

void log_print(const char *str)
{
	printf("[ada] %s", str); /* caller supplies '\n' */
}

int print(const char *str)
{
	printf("%s", str); /* caller supplies '\n' */
	return 0;
}

void metric_log_http_reqs(u8 mod_nr, struct http_metrics *metrics, u8 fce)
{
}

void metric_log_ssl_reqs(u8 mod_nr, struct ssl_metrics *metrics, u8 fce)
{
}

void metric_log_tcp_reqs(u8 mod_nr, struct tcp_metrics *metrics, u8 fce)
{
}

struct https_metrics *client_metric_get(void)
{
	return NULL;
}

struct netif *ada_mbuf_netif(struct ada_mbuf *am)
{
	return NULL;
}

int adap_server_file_get(struct server_req *req)
{
	return -1;
}

unsigned long long xTaskGetTotalTickCount(void)
{
	static u64 high_tick;
	static u32 old_tick;
	u32 tick;

	tick = xTaskGetTickCount();
	if (old_tick > tick) {
		high_tick += 0x100000000ull;
	}
	old_tick = tick;

	return high_tick | tick;
}
