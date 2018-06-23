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
#include <string.h>
#include <stdio.h>

#include <FreeRTOS.h>
#include <task.h>
#include <mDNS/mDNS.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ada/task_label.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/timer.h>
#include <ayla/http.h>
#include <ayla/notify_proto.h>
#include <ayla/xml.h>
#include <ayla/tlv.h>
#include <ayla/conf.h>
#include <ayla/nameval.h>

#include <net/net.h>
#include <net/net_crypto.h>
#include <net/stream.h>
#include <net/http_client.h>

#include <ayla/malloc.h>
#include <ada/libada.h>
#include <ada/metric.h>
#include <ada/client.h>
#include <ada/client_ota.h>
#include <ada/server_req.h>
#include <ada/ada_lan_conf.h>

#include "client_req.h"
#include "notify_int.h"
#include "client_int.h"
#include "client_lock.h"
#include "client_timer.h"

#define CLIENT_TASK_STACKSZ	((7 * 1024 + 512) / sizeof(portSTACK_TYPE))
#define CLIENT_TASK_PRIO	(tskIDLE_PRIORITY+1)
#define CLIENT_Q_LEN	8

static struct net_callback_queue *client_task_queue;
static struct timer_head client_timers;
static struct net_callback client_timer_callback;

static QueueHandle_t client_mutex;
static const char *client_mutex_func;
static int client_mutex_line;
static void *client_mutex_owner;
u8 client_locked;			/* for debug only */

struct log_mod log_mods[LOG_MOD_CT];
const char * const log_mod_names[LOG_MOD_CT] = MOD_LOG_NAMES;

const char *log_mod_get_name(u8 mod_nr)
{
	mod_nr &= LOG_MOD_MASK;
	if (mod_nr >= LOG_MOD_CT) {
		return NULL;
	}
	return log_mod_names[mod_nr];
}

static void *client_lock_curthread(void)
{
	return xTaskGetCurrentTaskHandle();
}

static volatile u8 client_sync_req;

void client_lock_stamp(const char *func, int line)
{
	ASSERT(client_locked);
	client_mutex_func = func;
	client_mutex_line = line;
}

void client_lock_int(const char *func, int line)
{
	int rc;
	void *thread = client_lock_curthread();

	ASSERT(client_mutex_owner != thread);
	xSemaphoreTake(client_mutex, portMAX_DELAY);
	client_mutex_owner = thread;
	ASSERT(!client_locked);
	client_locked = 1;
	client_mutex_func = func;
	client_mutex_line = line;
}

void client_unlock_int(const char *func, int line)
{
	int rc;

	client_mutex_func = func;
	client_mutex_line = line;
	ASSERT(client_mutex_owner == client_lock_curthread());
	client_mutex_owner = NULL;
	client_locked = 0;
	xSemaphoreGive(client_mutex);
}

/*
 * Block in server thread, waiting for client thread to be idle.
 */
void client_lan_sync_wait(void)
{
	ASSERT(client_locked);
	client_sync_req++;
	ASSERT(client_sync_req);	/* guard against overflow */
	client_wakeup();
	client_unlock();
	client_lock();
}

/*
 * Allow client to continue after it allowed server to run.
 */
void client_lan_sync_release(void)
{
	ASSERT(client_locked);
	ASSERT(client_sync_req);
	client_sync_req--;
}

/*
 * Allow server thread, waiting in client_lan_sync_wait(), to proceed.
 */
void client_lan_sync_post(void)
{
	ASSERT(client_locked);

	while (client_sync_req) {
		/*
		 * Allow the server (requester) to run.
		 * We need to guarantee that we don't loop forever here.
		 * The other thread should run before we take back the lock.
		 * Make sure sync has changed before we keep the sync mutex.
		 */
		client_unlock();

		/*
		 * Allow server to run, but it isn't guaranteed, we could be
		 * the first to get the lock again, so yield.
		 */
		client_lock();
	}
	ASSERT(client_locked);
}

static void client_timer_cb(void *arg)
{
}

void client_timer_set(struct timer *timer, unsigned long ms)
{
	ASSERT(client_locked);
	timer_set(&client_timers, timer, ms);
	client_callback_pend(&client_timer_callback);	/* wakeup client task */
}

void client_timer_cancel(struct timer *timer)
{
	ASSERT(client_locked);
	timer_cancel(&client_timers, timer);
}

/*
 * This SDK needs .html extensions on files like client.html,
 * but the service expects /client without an extension.
 * Redirect /client to client.html.
 */
static void client_redir_client_html(struct server_req *req)
{
	char ip[30];
	char loc[60];

	snprintf(loc, sizeof(loc), "Location: http://%s/client.html\r\n",
	    ipaddr_ntoa_r(&netif_default->ip_addr, ip, sizeof(ip)));

	req->put_head(req, HTTP_STATUS_REDIR_PERM, loc);
}

static const struct url_list client_redir_urls[] = {
	URL_GET("/client", client_redir_client_html, ALL_REQS),
	{ 0 }
};

/*
 * Client thread main idle loop.
 */
static void client_idle(void *arg)
{
	struct net_callback *ac;
	int max_wait;

	/*
	 * Initialize here as we need the RSA parsing for authentication
	 * before first TLS connection is made.
	 */
	log_thread_id_set(TASK_LABEL_CLIENT);
	taskstat_dbg_start();

	server_add_urls(client_redir_urls);

	client_lock();

	while (1) {
		max_wait = timer_advance(&client_timers);
		client_unlock();
		ac = net_callback_wait(client_task_queue, max_wait);
		client_lock();
		if (ac) {
			ASSERT(ac->pending);
			ac->pending = 0;
			ac->func(ac->arg);
		}
	}
}

/*
 * Pend a callback for the client thread to handle.
 * This may be called from any thread, and doesn't need to hold client_lock.
 */
void client_callback_pend(struct net_callback *cb)
{
	if (!cb) {
		return;
	}
	if (net_callback_enqueue(client_task_queue, cb)) {
		ASSERT_NOTREACHED();
	}
}

static void client_mdns_init(void)
{
	static DNSServiceRef mdns_service;

	if (mdns_service || mDNSResponderInit()) {
		return;
	}
	mdns_service = mDNSRegisterService(conf_sys_dev_id,
	    "_Ayla_Device._tcp", "local", 80, NULL);
	if (!mdns_service) {
		mDNSResponderDeinit();
	}
}

int ada_init(void)
{
	const struct conf_entry * const *tp;

	log_init();
	log_mask_init_min(BIT(LOG_SEV_INFO), LOG_DEFAULT);

	log_thread_id_set(TASK_LABEL_MAIN);

	net_callback_init(&client_timer_callback, client_timer_cb, NULL);

	/* RTLTODO: Set wifi retry times */

	client_mutex = xSemaphoreCreateMutex();
	ASSERT(client_mutex);

	/* Set memory management function for mbedtls library */
	mbedtls_platform_set_calloc_free(ayla_calloc, ayla_free);

	/* RTLTODO: remove WMSDK
	 * WMSDK has no ID file so start with STARTUP config
	 */
	conf_state.conf_cur = CI_STARTUP;

	client_task_queue = net_callback_queue_new(CLIENT_Q_LEN);
	ASSERT(client_task_queue);
	if (!client_task_queue) {
		return -1;
	}

	ada_conf_init();
	net_init();
	stream_init();
	client_init();
	conf_load_config();
	clock_init();
	log_page_mods_init();

	if (xTaskCreate(client_idle, "A_Client", CLIENT_TASK_STACKSZ,
	    NULL, CLIENT_TASK_PRIO, NULL) != pdPASS) {
		AYLA_ASSERT_NOTREACHED();
	}
	client_mdns_init();
	return 0;
}
