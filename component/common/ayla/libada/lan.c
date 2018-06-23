/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/base64.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/http.h>
#include <ayla/xml.h>
#include <ayla/tlv.h>
#include <ayla/ayla_proto_mcu.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <ayla/clock.h>
#include <ayla/uri_code.h>
#include <ayla/nameval.h>
#include <ayla/parse.h>
#include <ayla/json.h>
#include <ayla/patch.h>
#include <ayla/random.h>
#include <ayla/timer.h>
#include <jsmn.h>

#include <net/net.h>
#include <net/base64.h>
#include <net/net_crypto.h>
#include <ayla/wifi_error.h>
#include <ayla/wifi_status.h>
#include <ayla/jsmn_get.h>
#include <ada/prop.h>
#include <ada/server_req.h>
#include <net/stream.h>
#include <ada/ada_conf.h>
#include <ada/ada_lan_conf.h>
#include <ada/client.h>
#include "client_req.h"
#include <net/http_client.h>
#include <ayla/malloc.h>
#include <ada/metric.h>
#include <net/cm.h>
#include <ada/client_ota.h>
#include <ada/prop_mgr.h>
#include <ada/ada_wifi.h>
#include "notify_int.h"
#include "client_int.h"
#include "client_lock.h"
#include "client_timer.h"
#include "lan_int.h"

struct client_lan_reg client_lan_reg[CLIENT_LAN_REGS];

static struct adc_rng client_lan_rng;	/* random number generator */

static const char lan_enc_tag[] = "{\"enc\":\""; /* start of JSON string */

static int client_lan_send_key_exch(struct client_lan_reg *);
static int client_lan_send_cmd(struct client_lan_reg *);
static int client_lan_send_echo(struct client_lan_reg *);
static int client_lan_send_prop(struct client_lan_reg *);
static int client_lan_send_get(struct client_lan_reg *);
static enum ada_err client_lan_send_buf_resp(struct client_lan_reg *);
static enum ada_err client_parse_lan_json(struct client_state *,
				struct client_lan_reg *);
static void client_lan_clear_cmd_flags(struct client_state *,
				struct client_lan_reg *);
static void client_lan_refresh(struct client_lan_reg *, u8 notify);
static void client_lan_clearout(struct client_lan_reg *);

/*
 * Free lan recv recv_buf if needed.
 * Note, it may be pointing to lan->buf which we wouldn't want to free.
 */
static void client_lan_buf_free_int(struct client_lan_reg *lan)
{
	if (lan->recv_buf && lan->recv_buf != lan->buf) {
		client_lan_buf_free(lan->recv_buf);
	}
	lan->recv_buf = NULL;
	lan->recv_buf_len = 0;
}

/*
 * Determine if the LAN client is allow to do a GET operation
 */
static int client_lan_can_get(struct client_state *state,
			struct client_lan_reg *lan)
{
	struct prop_recvd *prop = &prop_recvd;

	return lan->pending && !state->lan_cmd_pending &&
	    !state->get_echo_inprog && !state->cmd_pending &&
	    !state->cmd_rsp_pending && !state->http_client.prop_callback &&
	    !lan->http_client.prop_callback &&
	    !prop->is_file;
}

/*
 * Call from client_next_step.  Start a LAN request if needed.
 * Returns 0 if any request started.
 */
static int client_lan_next_step(struct client_lan_reg *lan)
{
	struct client_state *state = &client_state;
	struct http_client *hc = &lan->http_client;
	u8 cur_parent_mask = 1 << lan->id;
	u8 can_get;

	if (lan->uri[0] == '\0' || lan->conn_state != CS_WAIT_EVENT) {
		return -1;
	}
	if (state->wait_for_file_put) {
		/*
		 * don't do any ops when waiting for HOST MCU to do a file put
		 */
		return -1;
	}

	can_get = client_lan_can_get(state, lan);
	if (!lan->valid_key) {
		return client_lan_send_key_exch(lan);
	}
	if (state->prop_send_cb && hc->prop_callback) {
		/* if we're already in the middle of a prop_send_cb, continue */
		goto post;
	}
	if (lan->cmd_pending && !state->prop_send_cb &&
	    !state->cmd_rsp_pending) {
		return client_lan_send_cmd(lan);
	}
	if (state->echo_dest_mask & cur_parent_mask) {
		if (!client_lan_send_echo(lan)) {
			return 0;
		}
	}
	if (can_get && lan->prefer_get) {
		return client_lan_send_get(lan);
	}
	if (state->prop_send_cb && (state->dest_mask & cur_parent_mask)) {
post:
		return client_lan_send_prop(lan);
	}
	if (can_get) {
		return client_lan_send_get(lan);
	}
	return -1;
}

/*
 * Cycle through LAN clients and call next_step_cb on eligible clients.
 * Skip destinations that haven't been configured or if they equal exception.
 * As a next_step callback, this returns 0 if it starts a request, -1 otherwise.
 */
int client_lan_cycle(struct client_state *state)
{
	struct client_lan_reg *lan;
	int rc = -1;

	ASSERT(client_locked);

	for (lan = client_lan_reg;
	    lan < &client_lan_reg[CLIENT_LAN_REGS]; lan++) {
		if (!client_lan_next_step(lan)) {
			rc = 0;
		}
	}
	return rc;
}

/*
 * Schedule a timeout for an HTTP request to the mobile LAN client.
 * This must be set BEFORE, the request is issued, in case of a
 * synchronous http_client implementation.
 */
static void client_lan_wait(struct client_lan_reg *lan)
{
	CLIENT_LOGF(LOG_DEBUG2, "wait %u ms", CLIENT_LOCAL_WAIT);
	client_timer_set(&lan->timer, CLIENT_LOCAL_WAIT);
}

/*
 * Common completion handling for client LAN send callbacks.
 * Called after any LAN send callback is finished.
 */
static void client_lan_send_next(struct http_client *hc, enum ada_err err)
{
	struct client_lan_reg *lan = hc->parent;
	struct client_state *state = &client_state;
	u8 cur_parent_mask = 1 << lan->id;

	if (hc->user_in_prog) {
		/*
		 * Waiting for MCU to respond back to prop_send request.
		 * Abort because the mcu could've sent us a property update
		 * in the meantime. So we need to POST the update to the app
		 * before the mcu can respond back to our request.
		 */
		hc->user_in_prog = 0;
		lan->cmd_rsp_pending = 1;
		state->cmd_rsp_pending = 1;
		lan->conn_state = CS_WAIT_EVENT;
		http_client_abort(hc);
		return;
	}
	if (err == AE_OK) {
		if (http_client_is_sending(hc)) {
			http_client_send_complete(hc);
		}
	} else if (err != AE_BUF) {
		client_timer_cancel(&lan->timer);
		http_client_abort(hc);
		if (state->conn_state == CS_WAIT_POST) {
			client_prop_send_done(state, 0, NULL,
			    cur_parent_mask, hc);
		}
	}
}

/*
 * Received LAN data that is not expected.
 */
static enum ada_err client_lan_recv_err(struct http_client *hc,
					void *buf, size_t len)
{
	CLIENT_LOGF(LOG_DEBUG, "recved unexpected payload len %u",
	    (unsigned int)len);
	return AE_OK;
}

/*
 * Receive payload into LAN buffer.
 */
static enum ada_err client_lan_recv_buf(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_lan_reg *lan = hc->parent;

	ASSERT(lan->recv_buf);
	if (lan->recved_len + len > lan->recv_buf_len) {
		return client_lan_recv_err(hc, buf, len);
	}
	memcpy(lan->recv_buf + lan->recved_len, buf, len);
	lan->recved_len += len;
	return AE_OK;
}

/*
 * Handle completion of receive portion of a LAN request.
 */
static void client_lan_tcp_recv_done(struct http_client *hc)
{
	struct client_lan_reg *lan = hc->parent;

	client_timer_cancel(&lan->timer);
	client_lan_buf_free_int(lan);
	lan->connect_time = clock_ms();
	lan->conn_state = CS_WAIT_EVENT;
	client_wakeup();
}

static enum ada_err client_lan_recv_post(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = hc->parent;
	enum ada_err err = AE_OK;

	if (buf) {
		return client_lan_recv_err(hc, buf, len);
	}
	client_timer_cancel(&lan->timer);
	err = client_prop_send_done(state, 1,
	    state->prop_send_cb_arg, 1 << lan->id, hc);
	if (err == AE_BUF) {
		return err;
	}
	lan->send_seq_no++;
	lan->prefer_get = 1;
	client_lan_tcp_recv_done(hc);
	return err;
}

/*
 * Use pSha256 KDF function for key gen
 */
static void client_lan_key_gen(struct client_state *state,
	struct client_lan_reg *lan, u8 *secret, int sec_len,
	u8 *dest_buf, char *root, char *suffix)
{
	struct adc_hmac_ctx ctx;
	char seed[CLIENT_LAN_SEED_SIZE];
	size_t seed_len;

	seed_len = snprintf(seed, sizeof(seed), "%s%s", root, suffix);
	ASSERT(seed_len < sizeof(seed));

	/*
	 * key = PRF(secret, seed) = SHA256(secret, A(1) + seed).
	 *      A(0) = seed, A(i) = SHA256(secret, A(i - 1))
	 * so, key = SHA256(secret, SHA256(secret, seed) + seed);
	 * See RFC 2104.
	 */
	adc_hmac_sha256_init(&ctx, secret, sec_len);
	adc_hmac_sha256_update(&ctx, seed, seed_len);
	adc_hmac_sha256_final(&ctx, dest_buf);

	adc_hmac_sha256_init(&ctx, secret, sec_len);
	adc_hmac_sha256_update(&ctx, dest_buf, CLIENT_LAN_KEY_LEN);
	adc_hmac_sha256_update(&ctx, seed, seed_len);
	adc_hmac_sha256_final(&ctx, dest_buf);
}

static int client_lan_gen_keys(struct client_state *state,
    struct client_lan_reg *lan, u8 *secret, int sec_len,
    char *random_two, char *time_two)
{
	char mod_root[4 * CLIENT_LAN_RAND_SIZE + 1];
	char app_root[4 * CLIENT_LAN_RAND_SIZE + 1];
	u8 iv_tmp_dest[ADC_SHA256_HASH_SIZE];
#if !AES_GET_IV_SUPPORT
	u8 key[CLIENT_LAN_ENC_SIZE];
	int rc;
#endif /* AES_GET_IV_SUPPORT */
	int len;

	/* Run the KDF Functions to generate the keys */
	len = snprintf(mod_root, sizeof(mod_root) - 1,
	    "%s%s%s%s", random_two, lan->random_one, time_two, lan->time_one);
	mod_root[len] = '\0';
	len = snprintf(app_root, sizeof(app_root) - 1,
	    "%s%s%s%s", lan->random_one, random_two, lan->time_one, time_two);
	app_root[len] = '\0';

	client_lan_key_gen(state, lan, secret, sec_len, lan->mod_sign_key,
	    mod_root, "0");
	client_lan_key_gen(state, lan, secret, sec_len, lan->app_sign_key,
	    app_root, "0");
	client_lan_key_gen(state, lan, secret, sec_len, iv_tmp_dest,
	    mod_root, "2");
#if AES_GET_IV_SUPPORT
	client_lan_key_gen(state, lan, secret, sec_len, lan->mod_enc_key,
	    mod_root, "1");
	memcpy(lan->mod_iv_seed, iv_tmp_dest, sizeof(lan->mod_iv_seed));
#else
	client_lan_key_gen(state, lan, secret, sec_len, key,
	    mod_root, "1");
	rc = adc_aes_cbc_key_set(state->aes_dev, &lan->aes_tx,
	    key, sizeof(key), iv_tmp_dest, 0);
	if (rc) {
		CLIENT_LOGF(LOG_WARN, "AES init err %d", rc);
		return -1;
	}
#endif /* AES_GET_IV_SUPPORT */

	client_lan_key_gen(state, lan, secret, sec_len, iv_tmp_dest,
	    app_root, "2");

#if AES_GET_IV_SUPPORT
	client_lan_key_gen(state, lan, secret, sec_len, lan->app_enc_key,
	    app_root, "1");
	memcpy(lan->app_iv_seed, iv_tmp_dest, sizeof(lan->app_iv_seed));
#else
	client_lan_key_gen(state, lan, secret, sec_len, key,
	    app_root, "1");
	rc = adc_aes_cbc_key_set(state->aes_dev, &lan->aes_rx,
	    key, sizeof(key), iv_tmp_dest, 1);
	if (rc) {
		CLIENT_LOGF(LOG_WARN, "AES init err %d", rc);
		return -1;
	}
#endif /* AES_GET_IV_SUPPORT */

	lan->valid_key = 1;
	return 0;
}

static void client_lan_free_pubkey(struct adc_rsa_key **keyp)
{
	struct adc_rsa_key *key = *keyp;

	if (key) {
		adc_rsa_key_clear(key);
		free(key);
		*keyp = NULL;
	}
}

/*
 * Parse the JSON key exchange response from lan client.
 */
static void client_parse_lan_key(struct client_state *state,
			    struct client_lan_reg *lan)
{
	struct ada_lan_conf *lcf = &ada_lan_conf;
	jsmn_parser parser;
	jsmntok_t tokens[CLIENT_LAN_JSON];
	jsmnerr_t err;
	char random_two[CLIENT_LAN_RAND_SIZE + 1];
	char time_two[CLIENT_LAN_RAND_SIZE + 1];
	int rc;

	jsmn_init_parser(&parser, lan->recv_buf, tokens, CLIENT_LAN_JSON);
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		CLIENT_LOGF(LOG_WARN, "jsmn err %d", err);
		goto bad_key;
	}
	if (jsmn_get_string(&parser, NULL, "random_2",
	    random_two, sizeof(random_two)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad random_2");
		goto bad_key;
	}
	if (jsmn_get_string(&parser, NULL, "time_2",
	    time_two, sizeof(time_two)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad time_2");
		goto bad_key;
	}
	if (!lan->rsa_ke) {
		rc = client_lan_gen_keys(state, lan,
		    (u8 *)lcf->lanip_key,
		    strlen(lcf->lanip_key), random_two, time_two);
	} else {
		rc = client_lan_gen_keys(state, lan,
		    (u8 *)state->lanip.lanip_random_key,
		    sizeof(state->lanip.lanip_random_key), random_two,
			time_two);
	}
	if (rc) {
		CLIENT_LOGF(LOG_WARN, "can't gen keys");
bad_key:
		client_lan_clearout(lan);
		return;
	}
	/*
	 * Key exchange is done, we should not need public key anymore.
	 */
	client_lan_free_pubkey(&lan->pubkey);
}

static enum ada_err client_lan_recv_check(struct client_lan_reg *lan)
{
	if (!lan->recv_decrypted) {
		lan->recv_buf[lan->recved_len] = '\0';
		log_bytes(MOD_LOG_CLIENT, LOG_SEV_DEBUG2,
		    lan->recv_buf, lan->recved_len, "lan recvd");
	}
	return AE_OK;
}

static enum ada_err client_lan_recv_empty(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_lan_reg *lan = hc->parent;

	client_timer_cancel(&lan->timer);
	if (buf) {
		return client_lan_recv_err(hc, buf, len);
	}
	client_lan_tcp_recv_done(hc);
	return AE_OK;
}

static enum ada_err client_lan_recv_resp(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = hc->parent;

	if (!buf) {
		client_lan_clear_cmd_flags(state, lan);
	}
	return client_lan_recv_empty(hc, buf, len);
}

/*
 * Start HTTP request to LAN client's server.
 * This must be called before starting the http_client request.
 * Returns the HTTP client.  Always succeeds.
 */
static struct http_client *client_lan_req_new(struct client_lan_reg *lan)
{
	struct http_client *hc = &lan->http_client;
	struct client_state *state = &client_state;

	state->http_lan = lan;
	if (hc->state != HCS_IDLE) {
		http_client_abort(hc);
	}

	hc->sending_chunked = 0;
	hc->prop_callback = 0;
	hc->user_in_prog = 0;
	hc->content_len = 0;
	hc->body_len = 0;
	hc->sent_len = 0;
	hc->body_buf_len = 0;
	hc->client_tcp_recv_cb = client_lan_recv_empty;
	hc->client_send_data_cb = NULL;
	hc->req_len = 0;
	hc->req_part = 0;

	lan->recved_len = 0;
	lan->recv_decrypted = 0;
	lan->mtime = clock_ms();

	return hc;
}

static enum ada_err client_lan_recv_echo(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = hc->parent;
	u8 dest_mask = 1 << lan->id;

	if (buf) {
		return client_lan_recv_err(hc, buf, len);
	}
	client_timer_cancel(&lan->timer);
	lan->send_seq_no++;
	client_finish_echo(state, dest_mask);
	client_lan_tcp_recv_done(hc);
	return AE_OK;
}

static int client_lan_send_echo(struct client_lan_reg *lan)
{
	struct client_state *state = &client_state;
	struct prop_recvd *echo_prop = state->echo_prop;
	struct prop *prop;
	enum ada_err err;

	ASSERT(echo_prop);

	prop = &echo_prop->prop;
	prop->name = echo_prop->name;
	prop->val = echo_prop->val;
	prop->len = echo_prop->prop.len;
	prop->type = echo_prop->type;
	prop->echo = 1;

	if (prop->name[0] == '\0') {
		client_finish_echo(state, 1 << lan->id);
		return -1;
	}

	err = client_send_lan_data(lan, prop, 1);
	if (err) {
		client_finish_echo(state, 1 << lan->id);
		return -1;
	}
	return 0;
}

static void client_lan_send_prop_cb(struct http_client *hc)
{
	struct client_state *state = &client_state;
	enum ada_err err;

	err = state->prop_send_cb(PROP_CB_BEGIN, NULL);
	client_lan_send_next(hc, err);
}

static int client_lan_send_prop(struct client_lan_reg *lan)
{
	struct http_client *hc;

	lan->conn_state = CS_WAIT_POST;
	hc = client_lan_req_new(lan);
	hc->client_tcp_recv_cb = client_lan_recv_post;
	hc->client_send_data_cb = client_lan_send_prop_cb;
	hc->prop_callback = 1;
	client_lan_send_prop_cb(hc);
	return 0;
}

static enum ada_err client_lan_recv_get(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = hc->parent;
	u8 cur_parent_mask = 1 << lan->id;
	enum ada_err err = AE_OK;

	if (buf) {
		return client_lan_recv_buf(hc, buf, len);
	}
	client_lan_recv_check(lan);

	lan->prefer_get = 0;
	state->get_echo_inprog = 0;

	err = client_parse_lan_json(state, lan);
	if (err != AE_OK) {
		if (err == AE_BUF) {
			state->get_echo_inprog = 1;
		}
		return err;
	}
	if (lan->uri[0] == '\0') {
		goto recv_complete;
	}
	if (!(state->valid_dest_mask & cur_parent_mask) && !lan->rsa_ke) {
		/* don't send prop updates to LAN using RSA */
		state->valid_dest_mask |= cur_parent_mask;
		client_connectivity_update();
	}
	if (hc->http_status == HTTP_STATUS_PAR_CONTENT) {
		lan->pending = 1;
	}
recv_complete:
	client_lan_tcp_recv_done(hc);
	return err;
}

/*
 * Request data from server.
 */
static int client_lan_send_get(struct client_lan_reg *lan)
{
	struct client_state *state = &client_state;
	struct http_client *hc;

	lan->recv_buf = client_lan_buf_alloc();
	if (!lan->recv_buf) {
		client_log(LOG_ERR "lan_send_get: buf alloc failed");
		return -1;
	}
	lan->recv_buf_len = CLIENT_LAN_BUF_LEN;
	lan->pending = 0;

	lan->conn_state = CS_WAIT_GET;
	hc = client_lan_req_new(lan);
	hc->client_tcp_recv_cb = client_lan_recv_get;

	state->get_echo_inprog = 1;
	state->cmd.data = NULL;
	state->cmd.resource = NULL;

	memset(&prop_recvd, 0, sizeof(prop_recvd));

	snprintf(lan->buf, sizeof(lan->buf), "%s/commands.json", lan->uri);

	client_lan_wait(lan);
	client_req_start(hc, HTTP_REQ_GET, lan->buf, NULL);
	return 0;
}

/*
 * Create randomness for lan client, used during key exchange.
 */
static int client_lan_gen_random(struct client_lan_reg *lan)
{
	/* Min Size for base64 output (look in base64_encode for func) */

	u8 random_data[(CLIENT_LAN_RAND_SIZE * 6) / 8];
	char random_one[(4 * ((sizeof(random_data) + 2) / 3))
		+ 4 /* Add 4 for padding */];
	size_t enc_fill_size = sizeof(random_one);
	int rc;

	random_fill(random_data, sizeof(random_data));
	rc = net_base64_encode(random_data, sizeof(random_data),
	    random_one, &enc_fill_size);
	if (rc < 0) {
		CLIENT_LOGF(LOG_WARN, "enc fail rc %d", rc);
		client_lan_clearout(lan);
		return AE_INVAL_VAL;
	}

	memcpy(lan->random_one, random_one, CLIENT_LAN_RAND_SIZE);
	snprintf(lan->time_one, sizeof(lan->time_one) - 1,
	    "%lu%lu", clock_ms(), clock_utc());
	return 0;
}

/*
 * Request key exchange from mobile app.
 */
static void client_lan_key_exchange(struct client_lan_reg *lan,
			    struct http_client *hc)
{
	struct client_state *state = &client_state;
	struct ada_lan_conf *lcf = &ada_lan_conf;
	char uri[CLIENT_LAN_URI_LEN + 20];
	size_t xml_len;
	int rc;
	u8 tmp_str[CLIENT_RSA_KEY_MAXLEN];
	size_t tmp_len;

	rc = client_lan_gen_random(lan);
	ASSERT(!rc);

	xml_len = snprintf(state->xml_buf,
	    sizeof(state->xml_buf) - 1, "{\"key_exchange\":{\"ver\":%u,"
	    "\"random_1\":\"%s\",\"time_1\":%s,\"proto\":%u,",
	    CLIENT_LAN_EXCH_VER, lan->random_one, lan->time_one,
	    CLIENT_LAN_PROTO_NUM);
	if (!lan->pubkey) {
		xml_len += snprintf(state->xml_buf + xml_len,
		    sizeof(state->xml_buf) - 1 - xml_len,
		    "\"key_id\":%u}}",
		    lcf->lanip_key_id);
	} else {
		xml_len += snprintf(state->xml_buf + xml_len,
		    sizeof(state->xml_buf) - 1 - xml_len,
		    "\"sec\":\"");

		adc_rng_init(&client_lan_rng);

		rc = adc_rsa_encrypt_pub(lan->pubkey,
		    state->lanip.lanip_random_key,
		    sizeof(state->lanip.lanip_random_key),
		    tmp_str, sizeof(tmp_str), &client_lan_rng);

		tmp_len = sizeof(state->xml_buf) - xml_len - 1;
		net_base64_encode(tmp_str, rc,
		    state->xml_buf + xml_len, &tmp_len);
		xml_len += tmp_len;
		xml_len += snprintf(state->xml_buf + xml_len,
		    sizeof(state->xml_buf) - 1 - xml_len,
		    "\"}}");
	}
	hc->body_buf = state->xml_buf;
	hc->body_buf_len = xml_len;
	hc->body_len = xml_len;

	snprintf(uri, sizeof(uri), "%s/key_exchange.json", lan->uri);
	client_lan_wait(lan);
	client_req_start(hc, HTTP_REQ_POST, uri, &http_hdr_content_json);
}

static enum ada_err client_lan_recv_key(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = hc->parent;
	enum ada_err err = AE_OK;

	if (buf) {
		return client_lan_recv_buf(hc, buf, len);
	}
	client_lan_recv_check(lan);
	client_parse_lan_key(state, lan);
	client_lan_tcp_recv_done(hc);
	return err;
}

static int client_lan_send_key_exch(struct client_lan_reg *lan)
{
	struct http_client *hc;

	hc = client_lan_req_new(lan);
	lan->conn_state = CS_WAIT_LANIP_GET;
	hc->client_tcp_recv_cb = client_lan_recv_key;
	lan->recv_buf = lan->buf;
	lan->recv_buf_len = sizeof(lan->buf);
	client_lan_key_exchange(lan, hc);
	return 0;
}

/*
 * Calculate the size of the prop info that needs to be sent
 * after all the json encoding.
 */
static ssize_t client_lan_prop_data_size(const char *name,
	const char *value, enum ayla_tlv_type type, size_t value_len)
{
	ssize_t len = 0;
	ssize_t json_val_len;
	const char name_tag[] = "name";
	const char value_tag[] = "value";

	json_val_len = json_format_bytes(NULL, 0, name, strlen(name),
	    NULL, NULL, 0);
	if (json_val_len < 0 || json_val_len > PROP_NAME_LEN) {
		return -1;
	}
	len = json_val_len + 2;		/* add 2 for the quotes */

	if (prop_type_is_str(type)) {
		json_val_len = json_format_bytes(NULL, 0, value, value_len,
		    NULL, NULL, 0);
		if (json_val_len < 0 || json_val_len > TLV_MAX_STR_LEN) {
			return -1;
		}
		len += json_val_len + 2;	/* add 2 for the quotes */
	} else {
		len += value_len;
	}

	/* add 4 for quotes around the tags and 2 for the curly braces */
	/* add 2 for colons, and 1 for comma */
	len += sizeof(name_tag) - 1 + sizeof(value_tag) - 1 + 4 + 2 + 2 + 1;

	return len;
}

/*
 * Prepare the cleartext prop data to be encrypted and signed
 * Return is non-zero on success, AE_BUF if buffer length is exceeded.
 * The result buffer buf will not necessarily be NUL-terminated.
 */
static enum ada_err client_lan_get_prop_data(char *buf, u32 buf_len,
	const char *name, const char *value, enum ayla_tlv_type type,
	size_t value_len, u32 *consumed, size_t send_offset)
{
	char tmpbuf[CLIENT_LAN_BLK_SIZE + 1];
	ssize_t len = 0;
	ssize_t totlen = 0;
	u32 processed;
	char *tmpbuf_ptr = tmpbuf;
	u8 buflim_reached = 0;

	if (consumed) {
		*consumed = 0;
	}
	if (!buf_len) {
		return AE_INVAL_VAL;
	}
	totlen = snprintf(tmpbuf, sizeof(tmpbuf), "{\"name\":\"");
	if (send_offset < totlen) {
		/* check if buf can hold the initial part of the tag */
		len = snprintf(buf, buf_len, "%s", tmpbuf_ptr + send_offset);
		if (len >= buf_len) {
			return AE_BUF;
		}
		if (consumed) {
			(*consumed) += len;
		}
		buf += len;
		buf_len -= len;
		send_offset += len;
	}
	send_offset -= totlen;

	ASSERT(name);
	totlen = strlen(name);
	if (send_offset < totlen) {
		/* check if buf can hold the name */
		len = json_format_bytes(buf, buf_len, name + send_offset,
		    strlen(name) - send_offset, &processed,
		    &buflim_reached, 0);
		if (len < 0) {
			CLIENT_LOGF(LOG_ERR, "json fmt err");
			return AE_INVAL_VAL;
		}
		if (consumed) {
			(*consumed) += processed;
		}
		buf += len;
		buf_len -= len;
		send_offset += processed;
		if (buf_len <= 1 || buflim_reached) {
			return AE_BUF;
		}
	}
	send_offset -= totlen;

	/* check if buf can hold the middle part of the tag */
	totlen = snprintf(tmpbuf, sizeof(tmpbuf), "\",\"value\":%s",
	    prop_type_is_str(type) ? "\"" : "");
	if (totlen >= sizeof(tmpbuf)) {
		totlen = sizeof(tmpbuf) - 1;
	}
	if (send_offset < totlen) {
		len = snprintf(buf, buf_len, "%s", tmpbuf_ptr + send_offset);
		if (len >= buf_len) {
			len = buf_len - 1;
		}
		if (consumed) {
			(*consumed) += len;
		}
		buf += len;
		buf_len -= len;
		send_offset += len;
		if (buf_len <= 1 || buflim_reached) {
			return AE_BUF;
		}
	}
	send_offset -= totlen;

	if (send_offset < value_len) {
		if (prop_type_is_str(type)) {
			len = json_format_bytes(buf, buf_len,
			    value + send_offset, value_len - send_offset,
			    &processed, &buflim_reached, 0);
			if (len < 0) {
				CLIENT_LOGF(LOG_ERR, "json fmt err");
				return AE_INVAL_VAL;
			}
			if (len < buf_len) {
				buf[len] = '\0';
			}
			if (consumed) {
				(*consumed) += processed;
			}
			send_offset += processed;
		} else {
			len = snprintf(buf, buf_len, "%s", value + send_offset);
			if (len >= buf_len) {
				return AE_BUF;
			}
			if (consumed) {
				(*consumed) += len;
			}
			send_offset += len;
		}
		buf += len;
		buf_len -= len;
		if (buf_len <= 1 || buflim_reached) {
			return AE_BUF;
		}
	}
	send_offset -= value_len;

	/* check if buf can hold the last part of the tag */
	totlen = snprintf(tmpbuf, sizeof(tmpbuf), "%s}",
	    prop_type_is_str(type) ? "\"" : "");
	if (send_offset < totlen) {
		len = snprintf(buf, buf_len, "%s", tmpbuf_ptr + send_offset);
		if (len >= buf_len) {
			if (consumed && buf_len) {
				(*consumed) += buf_len - 1;
			}
			/* we didn't copy all of tmpbuf into buf */
			return AE_BUF;
		}
		if (consumed) {
			(*consumed) += len;
		}
	}
	return AE_OK;
}

/*
 * Given the size of the data thats going to be encrypted, this will return
 * what the LAN payload size will be. This is used to determine the
 * Content-Length.
 */
static u32 client_lan_determine_payload_size(u16 seq_no, ssize_t data_len)
{
	ssize_t size_of_encrypt;
	ssize_t payload_len = 0;
	char buf[50];

	/* start by determining the size of the tags which will be encrypted */
	size_of_encrypt = data_len + snprintf(buf, sizeof(buf),
	    "{\"seq_no\":%d,\"data\":}", seq_no);
	/*
	 * determine the length of the encrypted block after base64 encoding.
	 * before base64 encoding, the size of the encrypted block equals
	 * the size of the plain block rounded up to a multiple of
	 * CLIENT_LAN_IV_SIZE
	 */
	size_of_encrypt += -size_of_encrypt & (CLIENT_LAN_IV_SIZE - 1);
	payload_len += BASE64_LEN_EXPAND(size_of_encrypt);

	/* add the length of the base64 signature */
	payload_len += BASE64_LEN_EXPAND(ADC_SHA256_HASH_SIZE);

	/* finally add the cost of the final enclosure for sending */
	payload_len += snprintf(buf, sizeof(buf),
	    "{\"enc\":\"\",\"sign\":\"\"}");

	return payload_len;
}

/*
 * Prepare lan buf for sending to lan clients
 */
static enum ada_err client_lan_encr_send(struct client_state *state,
	struct client_lan_reg *lan, struct http_client *hc, char *buf,
	ssize_t pkt_size)
{
#if AES_GET_IV_SUPPORT
	struct adc_aes ctx;
#endif
	int padding;
	int rc;
	u8 base64_out[BASE64_LEN_EXPAND(CLIENT_LAN_BLK_SIZE) + 5];
	size_t base64_len = sizeof(base64_out);
	enum ada_err err;

	ASSERT(pkt_size <= sizeof(lan->buf));
	memcpy(lan->buf, buf, pkt_size);

	log_bytes(MOD_LOG_CLIENT, LOG_SEV_DEBUG2,
	    lan->buf, pkt_size, "lan_clr_tx");

	padding = -pkt_size & (CLIENT_LAN_IV_SIZE - 1);
	memset(lan->buf + pkt_size, 0, padding);
	pkt_size += padding;
	ASSERT(pkt_size <= sizeof(lan->buf));

#if AES_GET_IV_SUPPORT
	rc = adc_aes_cbc_key_set(state->aes_dev, &ctx,
	    lan->mod_enc_key, sizeof(lan->mod_enc_key), lan->mod_int_seed, 0);
	if (rc) {
		CLIENT_LOGF(LOG_WARN, "AES init err %d", rc);
		return AE_INVAL_VAL;
	}
	rc = adc_aes_cbc_encrypt(state->aes_dev, &ctx, lan->buf, pkt_size);
#else
	rc = adc_aes_cbc_encrypt(state->aes_dev,
	    &lan->aes_tx, lan->buf, pkt_size);
#endif
	if (rc < 0) {
		CLIENT_LOGF(LOG_WARN, "encr err %d", rc);
		return AE_INVAL_VAL;
	}

	rc = net_base64_encode((u8 *)lan->buf, pkt_size,
	    base64_out, &base64_len);
	ASSERT_DEBUG(!rc);
	if (rc < 0) {
		CLIENT_LOGF(LOG_WARN, "encode err");
		return AE_INVAL_VAL;
	}

	err = http_client_send(hc, base64_out, base64_len);
#if AES_GET_IV_SUPPORT
	if (err == AE_OK) {
		adc_aes_iv_get(&ctx,
		    lan->mod_int_seed, sizeof(lan->mod_int_seed));
	}
#endif
	return err;
}

/*
 * Send the PUT header + data for a LAN command response
 */
static void client_lan_cmd_put_rsp(struct client_state *state, int status)
{
	struct client_lan_reg *lan = state->lan_cmd_responder;
	struct http_client *hc = &lan->http_client;

	snprintf(lan->buf, sizeof(lan->buf),
	    "%s?cmd_id=%lu&status=%d",
	    state->cmd.uri, state->cmd.id, status);
	client_lan_wait(lan);
	client_req_start(hc, HTTP_REQ_POST, lan->buf, &http_hdr_content_json);
}

/*
 * Send the "enc" tag
 */
static enum ada_err client_lan_send_enc_str(struct http_client *hc,
				struct client_lan_reg *lan)
{
	enum ada_err err;

	err = http_client_send(hc, lan_enc_tag, sizeof(lan_enc_tag) - 1);
	if (err != AE_OK) {
		return err;
	}
#if AES_GET_IV_SUPPORT
	memcpy(lan->mod_int_seed, lan->mod_iv_seed,
	    sizeof(lan->mod_iv_seed));
#endif
	adc_hmac_sha256_init(&lan->sign_ctx, lan->mod_sign_key,
	    sizeof(lan->mod_sign_key));
	return AE_OK;
}

/*
 * Send the signature
 */
static enum ada_err client_lan_send_signature(struct client_state *state,
		struct client_lan_reg *lan, struct http_client *hc)
{
	u8 sign[ADC_SHA256_HASH_SIZE];
	u8 base64_sign[BASE64_LEN_EXPAND(ADC_SHA256_HASH_SIZE) + 1];
	size_t base64_len = sizeof(base64_sign);
	ssize_t len;
	enum ada_err err;

	adc_hmac_sha256_final(&lan->sign_ctx, sign);
	if (net_base64_encode(sign, ADC_SHA256_HASH_SIZE,
	    base64_sign, &base64_len)) {
		CLIENT_LOGF(LOG_WARN, "enc fail");
		return AE_INVAL_VAL;
	}
	len = snprintf(lan->buf, sizeof(lan->buf) - 1,
	    "\",\"sign\":\"%s\"}", base64_sign);
	err = http_client_send(hc, lan->buf, len);
	if (err != AE_OK) {
		return err;
	}
#if AES_GET_IV_SUPPORT
	memcpy(lan->mod_iv_seed, lan->mod_int_seed, sizeof(lan->mod_int_seed));
#endif
	return err;
}

static void client_lan_send_resp_body(struct http_client *hc)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = hc->parent;
	ssize_t len;
	ssize_t xlen;
	enum ada_err err = AE_OK;
	int pkt_size;
	char sendbuf[CLIENT_LAN_BLK_SIZE + 1];
	char *sendptr;

	CLIENT_LOGF(LOG_DEBUG2, "part %d state %d", hc->req_part, hc->state);
	if (hc->req_part == 0) {
		err = client_lan_send_enc_str(hc, lan);
		if (err != AE_OK) {
			goto write_err;
		}
		hc->req_part++;
	}
	if (hc->req_part == 1) {
		/* put } at the end of recv buffer to match the {"seq_no".. */
		xlen = strlen(lan->recv_buf);
		lan->recv_buf[xlen++] = '}';
		lan->recv_buf[xlen] = '\0';

		len = snprintf(sendbuf, sizeof(sendbuf) - 1,
		    "{\"seq_no\":%d,\"data\":", lan->send_seq_no);
		if (len > sizeof(sendbuf) - 1) {
			len = sizeof(sendbuf) - 1;
		}
		sendptr = sendbuf + len;
		if (xlen > sizeof(sendbuf) - 1 - len) {
			xlen = sizeof(sendbuf) - 1 - len;
		}
		memcpy(sendptr, lan->recv_buf, xlen);
		lan->send_val_offset = xlen;
		sendbuf[len + xlen] = '\0';
		err = client_lan_encr_send(state, lan, hc,
		    sendbuf, len + xlen);
		if (err != AE_OK) {
			goto write_err;
		}
		adc_hmac_sha256_update(&lan->sign_ctx, sendbuf, len + xlen);
		hc->req_part++;
	}
	if (hc->req_part == 2) {
		len = strlen(lan->recv_buf);
		while (lan->send_val_offset < len) {
			pkt_size = len - lan->send_val_offset;
			if (pkt_size > CLIENT_LAN_BLK_SIZE) {
				pkt_size = CLIENT_LAN_BLK_SIZE;
			}
			sendptr = lan->recv_buf + lan->send_val_offset;
			err = client_lan_encr_send(state, lan, hc,
			    sendptr, pkt_size);
			if (err != AE_OK) {
				goto write_err;
			}
			lan->send_val_offset += pkt_size;
			adc_hmac_sha256_update(&lan->sign_ctx, sendptr,
			    pkt_size);
		}
		hc->req_part++;
	}
	if (hc->req_part == 3) {
		err = client_lan_send_signature(state, lan, hc);
		if (err != AE_OK) {
			goto write_err;
		}
		hc->req_part++;
		http_client_send_complete(hc);
	}
	return;

write_err:
	CLIENT_LOGF(LOG_DEBUG, "write err %d\n", err);
}

static enum ada_err client_lan_send_buf_nop(struct server_req *req)
{
	return AE_OK;
}

/*
 * Send whatever is in lan->buf as a response to the command
 */
static enum ada_err client_lan_send_buf_resp(struct client_lan_reg *lan)
{
	struct http_client *hc = &lan->http_client;
	struct client_state *state = &client_state;
	struct server_req *cmd_req = &state->cmd_req;

	if (lan->recv_buf[0] == '\0') {
		snprintf(lan->recv_buf, lan->recv_buf_len, "{}");
		state->cmd.output_len = 2;
	}
	hc->body_len = client_lan_determine_payload_size(lan->send_seq_no,
	    state->cmd.output_len);
	hc->client_send_data_cb = client_lan_send_resp_body;
	hc->client_tcp_recv_cb = client_lan_recv_resp;
	client_lan_cmd_put_rsp(state, cmd_req->http_status ?
	    cmd_req->http_status : HTTP_STATUS_OK);

	/*
	 * HTTP client request started, make sure this isn't repeated.
	 */
	cmd_req->finish_write = client_lan_send_buf_nop;

	return AE_OK;
}

/*
 * Send body for POST of datapoint.
 * The body is encrypted a block at a time.
 */
static void client_lan_send_data_cb(struct http_client *hc)
{
	struct client_lan_reg *lan = hc->parent;
	struct client_state *state = &client_state;
	ssize_t len;
	enum ada_err err = AE_OK;
	char fmt_val[BASE64_LEN_EXPAND(PROP_VAL_LEN) + 1];
	char *value;
	size_t value_len;
	char sendbuf[CLIENT_LAN_BLK_SIZE + 8];
	u32 consumed;
	char tmpstr[30];
	char *leftover;
	size_t leftover_len;
	struct prop *prop = lan->send_prop;
	u8 next_part;

	ASSERT(prop);

	value_len = prop_fmt(fmt_val, sizeof(fmt_val), prop->type,
	    prop->val, prop->len, &value);

	if (hc->req_part == 0) {
		/* copy the initial part to be encrypted to a char buffer */
		leftover = tmpstr;
		leftover_len = snprintf(tmpstr, sizeof(tmpstr),
		    "{\"seq_no\":%d,\"data\":", lan->send_seq_no);
		ASSERT(leftover_len < sizeof(tmpstr));
	} else {
		leftover = lan->leftover;
		leftover_len = strlen(leftover);
	}
	while (hc->req_part <= 1) {
		len = leftover_len;
		ASSERT(len < sizeof(sendbuf));
		memcpy(sendbuf, leftover, len);
		memset(sendbuf + len, 0, sizeof(sendbuf) - len);

		err = client_lan_get_prop_data(sendbuf + len,
		    sizeof(sendbuf) - len - 1,	/* save room for curly */
		    prop->name, value, prop->type, value_len,
		    &consumed, lan->send_val_offset);
		if (err && err != AE_BUF) {
			goto write_err;
		}

		len += consumed;
		ASSERT(len < sizeof(sendbuf));
		next_part = 1;

		/*
		 * Even if all of the data made it into the buffer,
		 * there may be more than the encryption block size.
		 * Prepare to copy to the leftover buffer if the send works.
		 * Do not NUL-terminate sendbuf at the leftover start.
		 */
		if (len > CLIENT_LAN_BLK_SIZE) {
			leftover_len = len - CLIENT_LAN_BLK_SIZE;
			len = CLIENT_LAN_BLK_SIZE;
		} else {
			leftover_len = 0;
			if (!err && len < CLIENT_LAN_BLK_SIZE) {
				sendbuf[len++] = '}';
				next_part = 2;
			}
		}
		err = client_lan_encr_send(state, lan, hc, sendbuf, len);
		if (err) {
			goto write_err;
		}
		hc->req_part = next_part;
		lan->send_val_offset += consumed;

		ASSERT(leftover_len < sizeof(lan->leftover));
		memcpy(lan->leftover, sendbuf + len, leftover_len);
		lan->leftover[leftover_len] = '\0';
		leftover = lan->leftover;

		adc_hmac_sha256_update(&lan->sign_ctx, sendbuf, len);
	}
	if (hc->req_part == 2) {
		err = client_lan_send_signature(state, lan, hc);
		if (err) {
			goto write_err;
		}
		hc->req_part = 3;
		ASSERT(hc->body_len == hc->sent_len);	/* verify estimates */
	}
	hc->hc_error = 0;
	hc->client_send_data_cb = NULL;
	http_client_send_complete(hc);
	return;

write_err:
	CLIENT_LOGF(LOG_DEBUG, "write err %d\n", err);
	hc->hc_error = HC_ERR_SEND;
	if (err == AE_BUF) {
		hc->hc_error = HC_ERR_MEM;
	}
}

/*
 * Send changed data to LAN App
 * The agent_echo flag indicates this is an echo by the agent, as opposed to by
 * the property manager or host app.
 */
enum ada_err client_send_lan_data(struct client_lan_reg *lan, struct prop *prop,
				int agent_echo)
{
	struct client_state *state = &client_state;
	struct http_client *hc;
	struct server_req *req = &state->cmd_req;
	ssize_t len;
	char uri[CLIENT_LAN_URI_LEN + 50];
	char fmt_val[BASE64_LEN_EXPAND(PROP_VAL_LEN) + 1];
	char *value;
	size_t value_len;

	lan->send_prop = prop;

	hc = &lan->http_client;		/* see if we're already using hc */

	ASSERT(prop);
	ASSERT(prop->name);
	CLIENT_LOGF(LOG_DEBUG2, "lan %u prop \"%s\" part %d state %d echo %d",
	    lan->id, prop->name, hc->req_part, hc->state, agent_echo);

	if (prop->name[0] == '\0') {
		return AE_INVAL_NAME;
	}

	value_len = prop_fmt(fmt_val, sizeof(fmt_val), prop->type,
	    prop->val, prop->len, &value);

	/* determine the content length */
	len = client_lan_prop_data_size(prop->name, value,
	     prop->type, value_len);
	if (len < 0) {
		if (state->conn_state == CS_WAIT_PROP_RESP) {
			req->http_status = HTTP_STATUS_INTERNAL_ERR;
			client_lan_send_buf_resp(lan);
			return AE_OK;
		}
		return AE_INVAL_VAL;
	}
	len = client_lan_determine_payload_size(lan->send_seq_no, len);
	if (state->conn_state == CS_WAIT_PROP_RESP) {
		client_lan_cmd_put_rsp(state, HTTP_STATUS_OK);
		return AE_OK;
	}

	hc = client_lan_req_new(lan);
	hc->body_len = len;

	snprintf(uri, sizeof(uri), "%s/property/datapoint.json%s",
	    lan->uri, prop->echo ? "?echo=true" : "");

	lan->send_val_offset = 0;
	CLIENT_DEBUG(LOG_DEBUG,
	    "name=\"%s\" val=\"%s\" type=%s",
	    prop->name, value, lookup_by_val(prop_types, prop->type));

	hc->body_buf = lan_enc_tag;
	hc->body_buf_len = sizeof(lan_enc_tag) - 1;

	hc->client_send_data_cb = client_lan_send_data_cb;
	if (agent_echo) {
		lan->conn_state = CS_WAIT_ECHO;
		hc->client_tcp_recv_cb = client_lan_recv_echo;
	} else {
		hc->client_tcp_recv_cb = client_lan_recv_post;
	}

#if AES_GET_IV_SUPPORT
	memcpy(lan->mod_int_seed, lan->mod_iv_seed,
	    sizeof(lan->mod_iv_seed));
#endif
	adc_hmac_sha256_init(&lan->sign_ctx, lan->mod_sign_key,
	    sizeof(lan->mod_sign_key));

	client_lan_wait(lan);
	client_req_start(hc, HTTP_REQ_POST, uri, &http_hdr_content_json);
	return AE_OK;
}

/*
 * Iterator to handle the properties sub-object.
 */
static int client_parse_lan_prop(jsmn_parser *parser,
	jsmntok_t *obj, void *client_lan)
{
	struct client_state *state = &client_state;
	struct ada_lan_conf *lcf = &ada_lan_conf;
	struct client_lan_reg *lan = (struct client_lan_reg *)client_lan;
	struct prop_recvd *prop = &prop_recvd;
	char type[20];
	jsmntok_t *prop_t;
	enum ada_err err;
	u8 cur_parent_mask = 1 << lan->id;

	if (lan->recv_decrypted) {
		/*
		 * if we've already decr that means the prop information
		 * is already in the prop_recvd structure.
		 */
		goto continue_sending;
	}
	if (prop->is_file) {
		/*
		 * the prop structure is locked with file information
		 * we shouldn't have started this request in the first place.
		 * this is a very rare occurence and almost never should happen.
		 * it can only happen if a file op and a mobile app GET happen
		 * at exactly the same time and a race condition occurs.
		 * for now, just drop the property update. the app will have
		 * to resend it
		 */
		 return AE_OK;
	}
	prop_t = jsmn_get_val(parser, obj, "property");
	if (!prop_t) {
		CLIENT_LOGF(LOG_WARN, "no prop");
		return AE_INVAL_VAL;
	}

	if (jsmn_get_string(parser, prop_t, "name",
	    prop->name, sizeof(prop->name)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad prop name");
		return AE_INVAL_VAL;
	}
	if (jsmn_get_string(parser, prop_t, "value",
	    prop->val, sizeof(prop->val)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad prop val");
		return AE_INVAL_VAL;
	}
	if (jsmn_get_string(parser, prop_t, "base_type",
	    type, sizeof(type)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad prop type");
		return AE_INVAL_VAL;
	}
	prop->type = lookup_by_name(prop_types, type);

	client_log(LOG_DEBUG
	    "%s: name=\"%s\" val=\"%s\" type=%s",
	    __func__, prop->name, prop->val, type);

	lan->recv_decrypted = 1;
continue_sending:
	if (state->mcu_overflow) {
		CLIENT_LOGF(LOG_WARN, "%s dropped due to mcu overflow",
		    prop->name);
		return AE_OK;
	}
	prop->arg = NULL;
	prop->src = cur_parent_mask;

	/* offset now is the point where prop.val needs to be sent from */
	err = client_prop_set(prop);
	if (err != AE_OK || !lcf->auto_echo) {
		return err;
	}
	state->echo_dest_mask = state->valid_dest_mask & ~cur_parent_mask;
	if (!state->echo_dest_mask) {
		/* echo not needed, only one valid dest */
		return AE_OK;
	}
	state->echo_prop = prop;
	state->get_echo_inprog = 1;

	return AE_OK;
}

static void client_lan_clearout(struct client_lan_reg *lan)
{
	struct client_state *state = &client_state;
	u8 cur_parent_mask = 1 << lan->id;

	ASSERT(client_locked);
	client_log(LOG_INFO "deleting lan %u", lan->id);
	http_client_abort(&lan->http_client);
	client_timer_cancel(&lan->timer);
	client_lan_buf_free_int(lan);
	lan->uri[0] = '\0';
	client_lan_free_pubkey(&lan->pubkey);
	if (state->valid_dest_mask & cur_parent_mask) {
		state->valid_dest_mask &= ~cur_parent_mask;
		client_connectivity_update();
	}
}

/*
 * Iterator to handle the cmds sub-object.
 */
static int client_parse_lan_cmd(jsmn_parser *parser,
	jsmntok_t *obj, void *client_lan)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = (struct client_lan_reg *)client_lan;
	jsmntok_t *cmd;
	ssize_t len;

	if (state->cmd_delayed || state->ota.in_prog != COS_NONE) {
		/*
		 * there is an OTA response pending. we need the client->cmd
		 * structure for the URI of the OTA response.
		 * drop this command, the mobile app will resend
		 */
		return AE_OK;
	}
	if (lan->cmd_pending) {
		/* only process one cmd at a time */
		return AE_OK;
	}

	cmd = jsmn_get_val(parser, obj, "cmd");
	if (!cmd) {
		CLIENT_LOGF(LOG_WARN, "no cmd");
		return AE_INVAL_VAL;
	}

	memset(&state->cmd, 0, sizeof(state->cmd));
	if (jsmn_get_string(parser, cmd, "method",
	    state->cmd.method, sizeof(state->cmd.method)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad method");
		return AE_INVAL_VAL;
	}

	len = jsmn_get_string(parser, cmd, "resource",
	    state->cmd.res_data + 1, sizeof(state->cmd.res_data));
	if (len < 0) {
		CLIENT_LOGF(LOG_WARN, "bad resource");
		return AE_INVAL_VAL;
	}
	state->cmd.res_data[0] = '/';
	state->cmd.resource = state->cmd.res_data;

	if (!strcmp(state->cmd.method, "DELETE") &&
	    !strcmp(state->cmd.resource, "/local_reg.json")) {
		client_lan_clearout(lan);
		return AE_INVAL_VAL;
	}

	state->cmd.data = state->cmd.res_data + len + 2;
	if (jsmn_get_string(parser, cmd, "data",
	    state->cmd.data, sizeof(state->cmd.res_data) - len - 2) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad data");
		return AE_INVAL_VAL;
	}

	if (jsmn_get_ulong(parser, cmd, "cmd_id",
	    &state->cmd.id)) {
		CLIENT_LOGF(LOG_WARN, "bad cmd_id");
		return AE_INVAL_VAL;
	}
	if (jsmn_get_string(parser, cmd, "uri",
	    state->cmd.uri, sizeof(state->cmd.uri)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad cmd uri");
		return AE_INVAL_VAL;
	}
	lan->cmd_pending = 1;
	state->lan_cmd_pending = 1;

	CLIENT_LOGF(LOG_DEBUG2, "lan cmd: %s %s",
	    state->cmd.method, state->cmd.resource);
	CLIENT_LOGF(LOG_DEBUG2, "lan cmd id %lu reply to uri \"%s\"",
	    state->cmd.id, state->cmd.uri);

	return AE_OK;
}

/*
 * Parse the JSON property response from lan client.
 */
static enum ada_err client_parse_lan_json(struct client_state *state,
	struct client_lan_reg *lan)
{
	jsmn_parser parser;
	jsmntok_t tokens[CLIENT_LAN_JSON];
	size_t recv_buf_len = lan->recv_buf_len;
	u8 dec_sign[CLIENT_LAN_SIGN_SIZE + 1];	/* + 1 for CYA base-64 decode */
	u8 packet_sign[CLIENT_LAN_SIGN_SIZE];
	size_t sign_len;
	jsmntok_t *props;
	jsmntok_t *cmds;
	jsmntok_t *json_data;
	jsmnerr_t err;
	ssize_t rc;
#if AES_GET_IV_SUPPORT
	struct adc_aes ctx;
#endif
	struct adc_hmac_ctx hmac_ctx;
	enum ada_err parse_err = AE_OK;
	int len;
	char *enc_ptr;

	/*
	 * If called again due to an AE_BUF or AE_IN_PROG
	 * from the prop_mgr or rev-REST cmd, skip top-level parsing and
	 * decryption if it's already been done.
	 */
	if (lan->recv_decrypted) {
		if (lan->recv_cmds) {
			parse_err = client_parse_lan_cmd(NULL, NULL, lan);
		} else {
			parse_err = client_parse_lan_prop(NULL, NULL, lan);
		}
		if (parse_err != AE_OK && parse_err != AE_BUF) {
iterate_failed:
			CLIENT_LOGF(LOG_WARN, "itr failed");
			goto remove_client;
		}
		return parse_err;
	}
	jsmn_init_parser(&parser, lan->recv_buf, tokens, CLIENT_LAN_JSON);
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		CLIENT_LOGF(LOG_WARN, "jsmn err");
		goto remove_client;
	}
	if (jsmn_get_string(&parser, NULL, "sign",
	    lan->buf, sizeof(lan->buf)) < 0) {
		CLIENT_LOGF(LOG_WARN, "bad sign");
		goto remove_client;
	}
	sign_len = sizeof(dec_sign);
	if (net_base64_decode(lan->buf, strlen(lan->buf),
	    dec_sign, &sign_len)) {
decode_failure:
		CLIENT_LOGF(LOG_WARN, "decode failed");
		goto remove_client;
	}
	rc = jsmn_get_string_ptr(&parser, NULL, "enc", &enc_ptr);
	if (rc < 0) {
		CLIENT_LOGF(LOG_WARN, "bad enc");
		goto remove_client;
	}

	if (net_base64_decode(enc_ptr, rc, lan->recv_buf, &recv_buf_len)) {
		goto decode_failure;
	}

#if AES_GET_IV_SUPPORT
	rc = adc_aes_cbc_key_set(state->aes_dev, &ctx,
	    lan->app_enc_key, sizeof(lan->app_enc_key), lan->app_iv_seed, 1);
	if (rc) {
		CLIENT_LOGF(LOG_WARN, "AES key init err %d", rc);
		goto remove_client;
	}
	rc = adc_aes_cbc_decrypt(state->aes_dev, &ctx,
	    lan->recv_buf, recv_buf_len);
#else
	rc = adc_aes_cbc_decrypt(state->aes_dev, &lan->aes_rx,
	    lan->recv_buf, recv_buf_len);
#endif
	if (rc < 0) {
		CLIENT_LOGF(LOG_WARN, "decrypt err %d", rc);
		goto remove_client;
	}
	lan->recv_buf[recv_buf_len] = '\0';
	len = strlen(lan->recv_buf);

	adc_hmac_sha256_init(&hmac_ctx,
	    lan->app_sign_key, sizeof(lan->app_sign_key));
	adc_hmac_sha256_update(&hmac_ctx, lan->recv_buf, len);
	adc_hmac_sha256_final(&hmac_ctx, packet_sign);

	log_bytes(MOD_LOG_CLIENT, LOG_SEV_DEBUG2,
	    lan->recv_buf, len, "lan_dec_rx");

	if (memcmp(packet_sign, dec_sign, ADC_SHA256_HASH_SIZE)) {
		CLIENT_LOGF(LOG_WARN, "wrong sign");
		goto remove_client;
	}
	jsmn_init_parser(&parser, lan->recv_buf, tokens, CLIENT_LAN_JSON);
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		CLIENT_LOGF(LOG_WARN, "jsmn err");
		goto remove_client;
	}

	json_data = jsmn_get_val(&parser, NULL, "data");
	if (!json_data) {
		CLIENT_LOGF(LOG_WARN, "no data");
		goto remove_client;
	}

	lan->recv_cmds = 0;
	props = jsmn_get_val(&parser, json_data, "properties");
	if (props) {
		if (lan->rsa_ke) {
			/* don't accept prop updates from a LAN using RSA */
			goto finish;
		}
		if (props->type != JSMN_ARRAY) {
			CLIENT_LOGF(LOG_WARN, "no props");
			goto remove_client;
		}
		parse_err = jsmn_array_iterate(&parser, props,
		    client_parse_lan_prop, (void *)lan);
		if (parse_err != AE_OK && parse_err != AE_BUF) {
			goto iterate_failed;
		}
	} else {
		cmds = jsmn_get_val(&parser, json_data, "cmds");
		if (cmds) {
			if (cmds->type != JSMN_ARRAY) {
				CLIENT_LOGF(LOG_WARN, "no cmds");
				goto remove_client;
			}
			lan->recv_cmds = 1;
			parse_err = jsmn_array_iterate(&parser, cmds,
			    client_parse_lan_cmd, (void *)lan);
			if (parse_err != AE_OK && parse_err != AE_BUF) {
				goto iterate_failed;
			}
		}
	}

finish:
#if AES_GET_IV_SUPPORT
	adc_aes_iv_get(&ctx, lan->app_iv_seed, sizeof(lan->app_iv_seed));
#endif
	return parse_err;

remove_client:
	client_lan_clearout(lan);
	return AE_OK;
}

/*
 * Function to clear up state after a LAN client finishes a cmd response
 */
static void client_lan_clear_cmd_flags(struct client_state *state,
					struct client_lan_reg *lan)
{
	struct server_req *cmd_req = &state->cmd_req;

	lan->cmd_pending = 0;
	state->lan_cmd_pending = 0;
	if (lan->cmd_rsp_pending) {
		lan->cmd_rsp_pending = 0;
		state->cmd_rsp_pending = 0;
	}
	lan->send_seq_no++;
	net_callback_pend(cmd_req->tcpip_cb);
	cmd_req->tcpip_cb = NULL;
	if (cmd_req->close_cb) {
		cmd_req->close_cb(cmd_req);
	}
}

/*
 * Reset the LAN clients.
 */
void client_lan_reset(struct client_state *state)
{
	struct client_lan_reg *lan;
	struct http_client *hc;

	for (lan = client_lan_reg;
	    lan < &client_lan_reg[CLIENT_LAN_REGS]; lan++) {
		if (lan->uri[0] != '\0') {
			hc = &lan->http_client;
			hc->client_err_cb = NULL;
			http_client_abort(hc);
			client_timer_cancel(&lan->timer);
			/* perhaps do more (lan_remove()?) XXX */
		}
	}
	state->dest_mask &= NODES_ADS;
	state->failed_dest_mask |= (state->dest_mask & ~NODES_ADS);
	state->valid_dest_mask &= NODES_ADS;
	state->echo_dest_mask &= NODES_ADS;
	memset(client_lan_reg, 0, sizeof(client_lan_reg));
}

static void client_lan_remove(struct client_lan_reg *lan)
{
	struct client_state *state = &client_state;
	u8 cur_parent_mask = 1 << lan->id;
	struct server_req *req = &state->cmd_req;

	client_lan_clearout(lan);
	client_prop_send_done(state, 0, NULL, cur_parent_mask,
	    &lan->http_client);
	client_finish_echo(state, cur_parent_mask);

	net_callback_pend(req->tcpip_cb);
	req->tcpip_cb = NULL;

	if (lan->cmd_pending) {
		state->lan_cmd_pending = 0;
		lan->cmd_pending = 0;
		if (lan->cmd_rsp_pending) {
			state->cmd_rsp_pending = 0;
			lan->cmd_rsp_pending = 0;
		}
		if (lan->conn_state == CS_WAIT_CMD_PUT) {
			req->prop_abort = 1;
		} else if (lan->conn_state == CS_WAIT_PROP_RESP) {
			if (req->close_cb) {
				req->close_cb(req);
			}
		}
		goto cycle_through;
	}
	if (lan->conn_state == CS_WAIT_GET) {
		state->get_echo_inprog = 0;
cycle_through:
		client_wakeup();
	}
}

/*
 * Callback from TCP when connection fails or gets reset.
 */
static void client_err_lan_cb(struct http_client *hc)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan =
	    (struct client_lan_reg *)(hc->parent);
	u8 cur_parent_mask = 1 << lan->id;

	ASSERT(client_locked);
	client_timer_cancel(&lan->timer);
	client_log(LOG_DEBUG "http err %d, lan #%u/%u", hc->hc_error, lan->id,
	    lan->conn_state);
	if (hc->hc_error == HC_ERR_CONN_CLSD) {
		/* connection closed at the same time we were trying a req */
		/* so just try the request again */
		if (lan->conn_state == CS_WAIT_GET) {
			state->get_echo_inprog = 0;
		}
		goto next_step;
	}
	if (hc->hc_error == HC_ERR_HTTP_STATUS &&
	    hc->http_state.status == HTTP_STATUS_NOT_FOUND) {
		/*
		 * don't drop the session on 404 from LAN in case of GET, POST,
		 * CMD_PUT or ECHO. it just means the app doesn't care about
		 * this prop.
		 */
		switch (lan->conn_state) {
		case CS_WAIT_GET:
			state->get_echo_inprog = 0;
			break;
		case CS_WAIT_ECHO:
			client_finish_echo(state, cur_parent_mask);
			break;
		case CS_WAIT_POST:
			client_prop_send_done(state, 1, NULL, cur_parent_mask,
			    hc);
			lan->send_seq_no++;
			break;
		case CS_WAIT_CMD_PUT:
			client_lan_clear_cmd_flags(state, lan);
			break;
		default:
			client_lan_remove(lan);
			return;
		}
next_step:
		client_lan_buf_free_int(lan);
		lan->conn_state = CS_WAIT_EVENT;
		client_wakeup();
		return;
	}
	client_lan_remove(lan);
}

/*
 * Parse the LAN registration request.
 * lan: pointer to the result.
 * Returns NULL on success, or appropriate status otherwise.
 */
static unsigned int client_json_lan_parse(struct server_req *req,
				struct lan_parse *parse)
{
	jsmn_parser parser;
	jsmntok_t tokens[16];
	jsmntok_t *parent;
	jsmnerr_t err;
	char buf[CLIENT_LAN_URI_LEN];
#ifdef AYLA_WIFI_SUPPORT
	u8 tmp_str[CLIENT_RSA_PUBKEY_LEN];
	u8 *p;
	size_t key_len;
	struct adc_rsa_key *key;
	int len;
#endif /* AYLA_WIFI_SUPPORT */
	ip_addr_t ipaddr;
	u8 *bp;
	unsigned long port;
	unsigned long np;

	memset(parse, 0, sizeof(*parse));

	jsmn_init_parser(&parser, req->post_data, tokens, ARRAY_LEN(tokens));
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		CLIENT_LOGF(LOG_WARN, "jsmn err %d", err);
		return HTTP_STATUS_BAD_REQ;
	}
	parent = jsmn_get_val(&parser, NULL, "local_reg");
	if (!parent) {
invalid:
		CLIENT_LOGF(LOG_WARN, "invalid reg");
		return HTTP_STATUS_BAD_REQ;
	}

	if (jsmn_get_string(&parser, parent, "uri",
	    parse->uri, sizeof(parse->uri)) < 0) {
		goto invalid;
	}
	if (jsmn_get_string(&parser, parent, "ip", buf, sizeof(buf)) < 0) {
		goto invalid;
	}
	ipaddr.addr = ipaddr_addr(buf);
	if (ipaddr.addr == IPADDR_NONE || !ipaddr.addr) {
		goto invalid;
	}
	parse->host_addr = ipaddr.addr;

	if (jsmn_get_ulong(&parser, parent, "port", &port) || port > MAX_U16) {
		goto invalid;
	}
	parse->port = port;

	if (jsmn_get_ulong(&parser, parent, "notify", &np) || np) {
		parse->notify = 1;	/* default to 1 */
	}

	bp = (u8 *)&ipaddr.addr;
	CLIENT_LOGF(LOG_DEBUG2, "ip %u.%u.%u.%u port %lu notify %u",
	    bp[0], bp[1], bp[2], bp[3], port, parse->notify);

	/*
	 * Check for same network.
	 */
	if (!net_ipv4_is_local(&ipaddr)) {
		CLIENT_LOGF(LOG_WARN, "IP not local");
		return HTTP_STATUS_FORBID;
	}

#ifdef AYLA_WIFI_SUPPORT
	len = jsmn_get_string_ptr(&parser, parent, "key", (char **)&p);
	if (adap_wifi_in_ap_mode() && len >= 0) {
		key = calloc(1, sizeof(*key));
		if (!key) {
			return HTTP_STATUS_INTERNAL_ERR;
		}
		key_len = sizeof(tmp_str);
		if (net_base64_decode(p, len, tmp_str, &key_len)) {
			free(key);
			goto invalid;
		}
		p = tmp_str;
		if (adc_rsa_key_set(key, tmp_str, key_len) <
		    CLIENT_RSA_KEY_MINLEN) {
			CLIENT_LOGF(LOG_WARN, "Invalid pub key");
			free(key);
			goto invalid;
		}
		parse->pubkey = key;
	}
#endif /* AYLA_WIFI_SUPPORT */

	return 0;
}

void client_lan_reg_timeout(struct timer *timer)
{
	struct client_state *state = &client_state;
	struct ada_lan_conf *lcf = &ada_lan_conf;
	struct client_lan_reg *lan;
	s32 max_age = -1;
	s32 age;
	u32 now;

	ASSERT(client_locked);
	client_timer_cancel(&state->lan_reg_timer);
	now = clock_ms();
	for (lan = client_lan_reg;
	    lan < &client_lan_reg[CLIENT_LAN_REGS]; lan++) {
		if (lan->uri[0] != '\0') {
			age = now - lan->mtime;
			if (age > (lcf->keep_alive * 1000 +
			    CLIENT_LAN_KEEPALIVE_GRACE * 1000)) {
				client_log(LOG_DEBUG "expire, lan #%u",
				    lan->id);
				client_lan_remove(lan);
			} else if (age > max_age) {
				max_age = age;
			}
		}
	}
	if (max_age >= 0) {
		client_timer_set(&state->lan_reg_timer,
		    lcf->keep_alive * 1000 - max_age);
	}
}

/*
 * Find LAN or best one to replace.
 * Prefer the first one without a URI, or the oldest one.
 */
static struct client_lan_reg *client_lan_lookup(struct lan_parse *parse)
{
	struct client_lan_reg *best;
	struct client_lan_reg *reg;

	best = client_lan_reg;
	for (reg = client_lan_reg;
	    reg < &client_lan_reg[CLIENT_LAN_REGS]; reg++) {
		if (best->uri[0] != '\0' && (reg->uri[0] == '\0' ||
		    clock_gt(best->connect_time, reg->connect_time))) {
			best = reg;
		}
		if (reg->http_client.host_addr.addr == parse->host_addr &&
		    reg->http_client.host_port == parse->port &&
		    !strncmp(reg->uri, parse->uri, sizeof(reg->uri))) {
			return reg;
		}
	}
	return best;
}

/*
 * Check preconditions for LAN client registration or refresh.
 */
static unsigned int client_lan_check_precon(struct client_state *state)
{
	struct ada_lan_conf *lcf = &ada_lan_conf;
	struct ada_conf *cf = &ada_conf;

	if (!CLIENT_LAN_REGS) {
		return HTTP_STATUS_NOT_FOUND;
#ifdef AYLA_WIFI_SUPPORT
	} else if (adap_wifi_in_ap_mode()) {
		return 0;
#endif /* AYLA_WIFI_SUPPORT */
	} else if (!lcf->enable || cf->lan_disable) {
		return HTTP_STATUS_NOT_FOUND;
	} else if (!CLIENT_LANIP_HAS_KEY(lcf)) {
		return HTTP_STATUS_PRECOND_FAIL;
	} else if (state->conn_state == CS_DOWN ||
	    state->conn_state == CS_DISABLED) {
		return HTTP_STATUS_SERV_UNAV;
	}
	return 0;
}

/*
 * TCP timeout on LAN request.
 */
static void client_lan_timeout(struct timer *timer)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan =
	    CONTAINER_OF(struct client_lan_reg, timer, timer);
	struct http_client *hc = &lan->http_client;

	if (hc->state == HCS_COMPLETE) {
		return;
	}
	client_log(LOG_DEBUG "timeout, lan #%u state %d",
	    lan->id, lan->conn_state);
	http_client_abort(hc);
	client_lan_buf_free_int(lan);
	switch (lan->conn_state) {
	case CS_WAIT_GET:
		state->get_echo_inprog = 0;
		lan->pending = 1;
		break;
	case CS_WAIT_ECHO:
	case CS_WAIT_POST:
	default:
		break;
	}
	client_lan_remove(lan);
	client_wakeup();
}

/*
 * Callback after HTTP request complete.
 */
static void client_lan_http_done(struct http_client *hc)
{
	client_wakeup();
}

static void client_lan_add(struct client_state *state,
	struct client_lan_reg *lan, struct lan_parse *parse)
{
	struct http_client *hc;
	u8 *bp;

	ASSERT(client_locked);
	ASSERT(!lan->uri[0]);
	client_timer_cancel(&lan->timer);

	memcpy(lan->uri, parse->uri, sizeof(lan->uri));

	timer_init(&lan->timer, client_lan_timeout);
	lan->id = (lan - client_lan_reg) + 1;	/* id 0 is for ADS */

	lan->valid_key = 0;
	lan->conn_state = CS_WAIT_EVENT;
	lan->pending |= 1;
	lan->rsa_ke = 0;

#ifdef AYLA_WIFI_SUPPORT
	client_lan_free_pubkey(&lan->pubkey);
	if (parse->pubkey) {
		lan->pubkey = parse->pubkey;
		parse->pubkey = NULL;
		lan->rsa_ke = 1;
	}
#endif
	if (lan->rsa_ke) {
		/*
		 * Need new secret for every new connection.
		 */
		random_fill(state->lanip.lanip_random_key,
		    sizeof(state->lanip.lanip_random_key));
	}
	lan->mtime = clock_ms();
	client_lan_reg_timeout(&state->lan_reg_timer);
	client_log(LOG_INFO "add, lan %u%s",
	    lan->id, lan->rsa_ke ? " rsa" : "");
	hc = &lan->http_client;
	http_client_reset(hc, MOD_LOG_CLIENT, NULL);
	hc->parent = lan;
	hc->host_addr.addr = parse->host_addr;
	hc->host_port = parse->port;

	bp = (u8 *)&hc->host_addr;
	snprintf(hc->host, sizeof(hc->host), "%u.%u.%u.%u",
	    bp[0], bp[1], bp[2], bp[3]);

	hc->client_send_data_cb = NULL;
	hc->client_err_cb = client_err_lan_cb;
	hc->client_tcp_recv_cb = client_lan_recv_err;
	hc->client_next_step_cb = client_lan_http_done;

	http_client_set_retry_limit(hc, CLIENT_LAN_RETRY_LIMIT);
	http_client_set_retry_wait(hc, CLIENT_LAN_RETRY_WAIT);
	http_client_set_conn_wait(hc, CLIENT_LAN_CONN_WAIT);

	client_wakeup();
}

/*
 * Create LAN registration session. POST local_reg
 * Kills an existing LAN connection to the same ip address.
 * Does a new key exchange.
 * Does a GET command.
 *
 * Note:  On platforms with an httpd thread, this will be called in that thread.
 * Be aware that a client thread may be blocked waiting for a lock, perhaps
 * on a pending callback for this LAN session.
 */
static void client_json_lan_post(struct server_req *req)
{
	struct client_state *state = &client_state;
	struct ada_lan_conf *lcf = &ada_lan_conf;
	struct lan_parse parse;
	struct client_lan_reg *lan;
	unsigned int status;

	client_lock();
	parse.pubkey = NULL;
	status = client_lan_check_precon(state);
	if (status) {
		goto put_bad_status;
	}
	status = client_json_lan_parse(req, &parse);
	if (status) {
		goto put_bad_status;
	}
	if (!parse.pubkey && !CLIENT_LANIP_HAS_KEY(lcf)) {
		/*
		 * Either we're doing key exchange with RSA, or we have
		 * to have server set shared secret.
		 */
		status = HTTP_STATUS_PRECOND_FAIL;
		goto put_bad_status;
	}
	lan = client_lan_lookup(&parse);
	if (!lan) {
		/* Could assert that this does not happen */
		status = HTTP_STATUS_SERV_UNAV;
		goto put_bad_status;
	}
	if (lan->uri[0] != '\0') {
		client_lan_clearout(lan);
	}
	client_lan_add(state, lan, &parse);
	status = HTTP_STATUS_ACCEPTED;
out:
	server_put_status(req, status);
	client_unlock();
	return;

put_bad_status:
	if (parse.pubkey) {
		adc_rsa_key_clear(parse.pubkey);
		free(parse.pubkey);
	}
	goto out;
}

/*
 * LAN client refresh. PUT local_reg.
 * Does a GET command if notify == 1 or if this is the nth refresh.
 *
 * Note:  On platforms with an httpd thread, this will be called in that thread.
 * Be aware that a client thread may be blocked waiting for a lock, perhaps
 * on a pending callback for this LAN session.
 */
static void client_json_lan_put(struct server_req *req)
{
	struct client_state *state = &client_state;
	struct lan_parse parse;
	struct ada_lan_conf *lcf = &ada_lan_conf;
	struct client_lan_reg *lan;
	unsigned int status = 0;

	client_lock();
	parse.pubkey = NULL;
	status = client_lan_check_precon(state);
	if (status) {
		goto put_status;
	}
	status = client_json_lan_parse(req, &parse);
	if (status) {
		goto put_status;
	}
	lan = client_lan_lookup(&parse);
	if (!lan) {
		status = HTTP_STATUS_SERV_UNAV;
		goto put_status;
	}
	if (lan->uri[0] == '\0') {
		if (!parse.pubkey && !CLIENT_LANIP_HAS_KEY(lcf)) {
			/*
			 * Either we're doing key exchange with RSA, or we have
			 * to have server set shared secret.
			 */
			status = HTTP_STATUS_PRECOND_FAIL;
			goto put_status;
		}
		client_lan_add(state, lan, &parse);
	} else {
		client_lan_refresh(lan, parse.notify);
	}
	status = HTTP_STATUS_ACCEPTED;
put_status:
	client_lan_free_pubkey(&parse.pubkey);
	server_put_status(req, status);
	client_unlock();
}

static void client_lan_refresh(struct client_lan_reg *lan, u8 notify)
{
	struct client_state *state = &client_state;

	client_log(LOG_DEBUG "refresh, lan #%u", lan->id);
	lan->refresh_count++;
	if (notify && (state->wait_for_file_put || state->wait_for_file_get)) {
		/*
		 * tell the host mcu that there's a pending update
		 * so he can abort the file operation if he wants
		 */
		prop_mgr_event(PME_NOTIFY, NULL);
	}
	if (lan->refresh_count >= CLIENT_LAN_REFRESH_LIM) {
		notify = 1;
	}
	lan->pending |= notify;
	if (lan->pending) {
		lan->refresh_count = 0;
	}
	lan->mtime = clock_ms();
	client_lan_reg_timeout(&state->lan_reg_timer);
	client_wakeup();
}

/*
 * Command to store LAN cmd response in a buffer
 */
static void client_lan_cmd_flush(struct server_req *req, const char *msg)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = state->lan_cmd_responder;

	CLIENT_LOGF(LOG_DEBUG, "msg \"%s\"", msg);
	if (req->suppress_out || req->len == 0 || req->err != AE_OK) {
		return;
	}

	if ((req->len + state->cmd.output_len) > lan->recv_buf_len - 1) {
		/* response too long, chop off the response */
		req->suppress_out = 1;
		req->http_status = HTTP_STATUS_REQ_LARGE;
		return;
	}

	memcpy(lan->recv_buf + state->cmd.output_len, msg, req->len);
	state->cmd.output_len += req->len;
	req->len = 0;
}

/*
 * Finish the command response for LAN client
 */
static enum ada_err client_lan_cmd_finish_put(struct server_req *req)
{
	struct client_state *state = &client_state;
	struct client_lan_reg *lan = state->lan_cmd_responder;
	enum ada_err rc = AE_OK;

	client_lock();
	if (lan->uri[0] && lan->cmd_pending) {
		lan->recv_buf[state->cmd.output_len] = '\0';
		rc = client_lan_send_buf_resp(lan);
	}
	client_unlock();
	return rc;
}

/*
 * Execute a reverse-REST command which will PUT back the result asynchronously.
 */
static int client_lan_send_cmd(struct client_lan_reg *lan)
{
	struct client_state *state = &client_state;
	struct server_req *cmd_req = &state->cmd_req;
	struct http_client *hc;
	u8 priv;

	lan->conn_state = CS_WAIT_CMD_PUT;
	state->lan_cmd_responder = lan;

	lan->recv_buf = client_lan_buf_alloc();
	if (!lan->recv_buf) {
		client_log(LOG_ERR "lan_send_cmd: buf alloc failed");
		return -1;
	}
	lan->recv_buf_len = CLIENT_LAN_BUF_LEN;

	server_req_init(cmd_req);
	cmd_req->put_head = client_cmd_put_head;
	cmd_req->write_cmd = client_lan_cmd_flush;
	cmd_req->finish_write = client_lan_cmd_finish_put;

	/*
	 * Determine the privilege we have for the command.
	 */
	priv = APP_REQ;
#ifdef AYLA_WIFI_SUPPORT
	if (lan->rsa_ke) {
		priv = LOC_REQ;
		if (adap_wifi_in_ap_mode()) {
			priv = REQ_SOFT_AP;
		}
	}
#endif

	/*
	 * Start reverse-REST request.
	 */
	hc = client_lan_req_new(lan);
	client_rev_rest_cmd(hc, priv);

	if (cmd_req->user_in_prog) {
		lan->cmd_rsp_pending = 1;
	}
	return 0;
}

static const struct url_list client_lan_urls[] = {
	URL_POST("/local_reg.json", client_json_lan_post,
	    LOC_REQ | APP_REQ | REQ_SOFT_AP),
	URL_PUT("/local_reg.json", client_json_lan_put,
	    LOC_REQ | APP_REQ | REQ_SOFT_AP),
	{ 0 }
};

void client_lan_init(void)
{
	server_add_urls(client_lan_urls);
}
