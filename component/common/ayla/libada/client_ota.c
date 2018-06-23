/*
 * Copyright 2015-2016 Ayla Networks, Inc.  All rights reserved.
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
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/http.h>
#include <ayla/xml.h>
#include <ayla/conf.h>
#include <ayla/tlv.h>
#include <ayla/clock.h>
#include <ayla/parse.h>
#include <ayla/json.h>
#include <ayla/patch.h>
#include <ayla/nameval.h>
#include <ayla/timer.h>
#include <ayla/crc.h>
#include <ayla/wifi_status.h>
#include <jsmn.h>

#include <net/net.h>
#include <net/net_crypto.h>
#include <ayla/jsmn_get.h>
#include <ayla/malloc.h>
#include <ada/prop.h>
#include <ada/server_req.h>
#include <net/stream.h>
#include <ada/ada_conf.h>
#include <ada/ada_lan_conf.h>
#include <ada/client.h>
#include <ada/client_ota.h>
#include "client_req.h"
#include <net/http_client.h>
#include <ada/metric.h>
#include <ada/client_ota.h>
#include <net/base64.h>
#include "notify_int.h"
#include "client_int.h"
#include "client_lock.h"
#include "lan_int.h"

#ifdef CLIENT_OTA_LAN_TEST_KEY	/* Define to use test_key only */
/*
 * Test LAN-OTA key. The associated private key is in util/lan_ota/test_key.priv
 */
static const char client_ota_test_key[] =
    "MIIBCgKCAQEAyyOanfGOiUxDTg08T2ftRnzWJ9+nD4LQPXofLEktLq5JuZ6HjcPw"
    "3XNWQwEIeVcJLnMgxwQ4aVOm97q8kw2xp4qF7oC+Nbm3kmu13axdHVtGWDztI+My"
    "MP2icHUK6bcpyyiTjDd/1NBuuPpbh/TIWBMQfZR5gmpzPC26cdy9CJJ4QDN4Ksxw"
    "EQPmnJ6+DAF3APX2PVpnYLhtHAPJaLMKA4ja0lt+yyiGxrNXYLAGse+mARVKLP1k"
    "BjnKXOF7d0bVhjBsgaRWZCvVrnSLdgIzK2w7OD1Qr444j095teRf9lyhnVN/ta8M"
    "vPaT4vgS9j4e7LbLp6eCGxCqPafCqALMgwIDAQAB";
#endif /* CLIENT_OTA_LAN_TEST_KEY */

static int client_ota_json_parse(char *post_data);

/*
 * OTA sequence notes:
 *
 * client_ota_json_put(): reverse rest command is parsed.  State COS_NOTIFIED
 *	calls notify() handler, may start or give status.
 * ada_ota_start() - in other thread, sets state to COS_IN_PROG, client_wakeup()
 * client_next_step() calls:
 *
 * client_ota_fetch_image() starts request for a section of image
 * ... hc->client_tcp_recv_cb
 * client_recv_ota_get() receives a piece of image, delivers to ops->save().
 *	when done sets cmd_status to 200.
 *
 * client_next_step() calls:
 * client_put_cmd_sts()
 * client_cmd_put_rsp()
 * ... hc->client_tcp_recv_cb
 * client_recv_sts_put()
 *	calls client_ota_save_done()
 *		ops->save_done() - may reboot
 *		calls client_ota_cleanup();
 * ota_failed status may be put here, if non-zero
 */

/*
 * Clear OTA state
 */
void client_ota_cleanup(struct client_state *state)
{
	free(state->ota.recv_buf.data);
	free(state->ota.version);
	free(state->ota.img_sign);
	memset(&state->ota, 0x0, sizeof(state->ota));
	state->ota_server.remote = 0;
	state->ota_server.lan = 0;
}

void client_ota_save_done(struct client_state *state)
{
	enum ada_ota_type type = state->ota.type;
	const struct ada_ota_ops *ops = state->ota_ops[type];
	unsigned int status;

	ASSERT(client_locked);
	status = state->ota.http_status;
	state->ota.http_status = 0;

	client_ota_cleanup(state);
	state->np_event = 1;
	client_unlock();

	if (status == HTTP_STATUS_OK) {
		ASSERT(ops);
		ASSERT(ops->save_done);
		ops->save_done();
		client_log(LOG_INFO "OTA save done");
	} else {
		client_log(LOG_INFO "OTA abandoned");
	}
	client_lock();
}

static enum patch_state client_ota_save(struct client_state *state,
					void *data, size_t len)
{
	enum ada_ota_type type = state->ota.type;
	const struct ada_ota_ops *ops = state->ota_ops[type];
	enum patch_state status;

#ifdef WDG_SUPPORT
	wdg_reload();
#endif
	ASSERT(ops->save);
	status = ops->save(state->ota.off, data, len);
	if (status) {
		if (status != PB_ERR_STALL) {
			return status;
		}
		state->ota.in_prog = COS_STALL;
		client_wait(state, CLIENT_PROP_WAIT);
	}
	state->ota.off += len;
	return status;
}

void client_ota_server(struct client_state *state)
{
	struct http_client *hc = &state->http_client;

	strncpy(hc->host, state->ota_server.host, sizeof(hc->host) - 1);
	hc->ssl_enable = state->ota_server.ssl;
	hc->accept_non_ayla = 0;
	hc->client_auth = 1;
	hc->host_port = hc->ssl_enable ? HTTP_CLIENT_SERVER_PORT_SSL :
	    state->ota_server.port;

	/* LAN OTA or S3 OTA */
	if (!hc->ssl_enable || (state->ota_server.remote &&
	    state->ota.url_fetched)) {
		hc->accept_non_ayla = 1;
		hc->client_auth = 0;
	}
}

#ifndef DISABLE_LAN_OTA
static int client_lanota_verify_img(struct client_state *state)
{
	u8 sign[SHA256_SIG_LEN];

	adc_sha256_final(&state->ota.sha_ctx, sign);

	if (memcmp(state->ota.img_sign, sign, sizeof(sign))) {
		client_log(LOG_WARN "lan ota img verification failed");
		return -1;
	}
	return 0;
}

/*
 * Process incoming data for LAN OTA
 * AES-256-CBC decryption of payload and incremental
 * SHA-256 computation for img verification
 * Returns the valid length of the buffer, or negative error number.
 */
static int client_lanota_process_data(struct client_state *state,
    void *payload, size_t payload_len)
{
	u8 *dec_buf = state->ota.recv_buf.data;
	u8 *new;
	size_t dec_len = state->ota.recv_buf.len;
	size_t prev_len = state->ota.recv_buf.consumed;
	size_t rem_sz;
	u8 pad;
	int rc;

	if (dec_buf) {
		/* avoid realloc() for some platforms */
		new = malloc(dec_len + payload_len);
		if (new) {
			memcpy(new, dec_buf + prev_len, dec_len);
		}
		free(dec_buf);
		dec_buf = new;
	} else {
		dec_buf = malloc(payload_len);
		ASSERT(!dec_len);
	}
	if (!dec_buf) {
		CLIENT_LOGF(LOG_WARN, "out of mem");
		return AE_BUF;
	}
	memcpy(dec_buf + dec_len, payload, payload_len);

	rem_sz = (dec_len + payload_len) & (AES_BLOCK_SIZE - 1);
	dec_len = (dec_len + payload_len) - rem_sz;

	rc = adc_aes_cbc_decrypt(state->aes_dev, &state->ota.aes_ctx,
	    dec_buf, dec_len);
	if (rc < 0) {
		CLIENT_LOGF(LOG_WARN, "decrypt err %d", rc);
		return AE_INVAL_VAL;
	}

	/*
	 * Update buffer state.  dec_len must be a multiple of AES_BLOCK_SIZE.
	 */
	state->ota.recv_buf.data = dec_buf;
	state->ota.recv_buf.len = rem_sz;
	state->ota.recv_buf.consumed = dec_len;

	/*
	 * If this is the last chunk remove the
	 * PKCS#7 pad at the end of the image.
	 */
	if (state->ota.off + dec_len >= state->ota.max_off) {
		pad = dec_buf[dec_len - 1];
		if (pad > AES_BLOCK_SIZE || pad > dec_len) {
			CLIENT_LOGF(LOG_WARN, "padding err %x", pad);
			return AE_INVAL_VAL;
		}
		for (new = &dec_buf[dec_len - pad]; new < &dec_buf[dec_len];
		   new++) {
			if (*new != pad) {
				CLIENT_LOGF(LOG_WARN, "padding err %x not %x",
				    *new, pad);
				return AE_INVAL_VAL;
			}
		}
		state->ota.pad = pad;
		dec_len -= pad;
	}

	/*
	 * Incrementally calculate SHA256 signature
	 */
	adc_sha256_update(&state->ota.sha_ctx, dec_buf, dec_len, NULL, 0);
	return dec_len;
}

/*
 * Check the 256B RSA-2048-signed header
 */
static int client_lanota_hdr_chk(char *inbuf, int sz)
{
	struct client_state *state = &client_state;
	struct adc_rsa_key key;
	size_t key_len;
	u8 tbuf[CLIENT_RSA_SIGN_MAX_LEN + 1];	/* allow for extra NUL */
	size_t tbuf_sz;
	char pub_key[CLIENT_CONF_PUB_KEY_LEN];
	int pub_key_len;
	jsmn_parser parser;
	jsmnerr_t err;
	jsmntok_t tokens[OTA_JSON_PUT_TOKENS];
	char dsn[CONF_DEV_ID_MAX];
	char ver[ADA_CONF_VER_LEN];
	u8 aes_key[CLIENT_LAN_ENC_SIZE];
	int rc = -1;

#ifdef CLIENT_OTA_LAN_TEST_KEY
	size_t outlen;

	outlen = sizeof(pub_key);
	if (net_base64_decode(client_ota_test_key,
	     sizeof(client_ota_test_key) - 1,
	     pub_key, &outlen) || !outlen || outlen > sizeof(pub_key)) {
		client_log(LOG_ERR "test key decode failed");
		return -1;
	}
	client_log(LOG_INFO "using test LAN OTA key len %u",
	    (unsigned int)outlen);
	pub_key_len = outlen;
#else
	pub_key_len = adap_conf_pub_key_get(pub_key, sizeof(pub_key));
	if (pub_key_len <= 0) {
		return rc;
	}
#endif /* CLIENT_OTA_LAN_TEST_KEY */

	key_len = adc_rsa_key_set(&key, pub_key, pub_key_len);
	client_log(LOG_DEBUG "test key len %u", (unsigned int)key_len);
	if (!key_len || key_len > pub_key_len) {
		adc_rsa_key_clear(&key);
		goto hdr_chk_fail;
	}

	/*
	 * Decrypt the header
	 */
	rc = adc_rsa_verify(&key, inbuf, sz, tbuf, sizeof(tbuf) - 1);
	adc_rsa_key_clear(&key);
	if (rc < 0 || rc > sizeof(tbuf)) {
		client_log(LOG_WARN "header verify failed %d", rc);
		goto hdr_chk_fail;
	}

	/*
	 * Verify the CRC on the header
	 */
	tbuf[sizeof(tbuf) - 1] = '\0';		/* guarantee NUL */
	tbuf_sz = strlen((char *)tbuf) + 3; /* JSON + 0x00 + 2B CRC */
	if (tbuf_sz >= sizeof(tbuf) - 3) {
		client_log(LOG_WARN "json too long");
		goto hdr_chk_fail;
	}
	if (crc16(tbuf, tbuf_sz, CRC16_INIT)) {
		client_log(LOG_WARN "header crc failed");
		goto hdr_chk_fail;
	}

	jsmn_init_parser(&parser, (char *)tbuf, tokens, OTA_JSON_PUT_TOKENS);
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		client_log(LOG_WARN "ota_json_put jsmn err %d", err);
		goto hdr_chk_fail;
	}

	rc = jsmn_get_string(&parser, NULL, "dsn", dsn, sizeof(dsn));
	if (rc < 0 || strcmp(conf_sys_dev_id, dsn)) {
		goto hdr_chk_fail;
	}

	rc = jsmn_get_string(&parser, NULL, "ver", ver, sizeof(ver));
	if (rc < 0) {
		goto hdr_chk_fail;
	}
	state->ota.version = calloc(strlen(ver) + 1, sizeof(char));
	if (!state->ota.version) {
		client_log(LOG_WARN "ota_json_put out of mem");
		goto hdr_chk_fail;
	}
	strcpy(state->ota.version, ver);

	/*
	 * Get the AES-128 key to decrypt the OTA image
	 */
	key_len = sizeof(aes_key);
	rc = jsmn_get_string(&parser, NULL, "key",
	    (char *)tbuf, sizeof(tbuf));
	if (rc < 0 || rc != (key_len * 2)) {
		goto hdr_chk_fail;
	}
	rc = parse_hex(aes_key, key_len, (char *)tbuf, rc);
	if (rc < 0) {
		goto hdr_chk_fail;
	}

	/*
	 * Setup the AES ctx to begin img decryption
	 */
	rc = adc_aes_cbc_key_set(state->aes_dev, &state->ota.aes_ctx,
	    aes_key, sizeof(aes_key), dsn, 1);
	if (rc) {
		CLIENT_LOGF(LOG_WARN, "AES key init err %d", rc);
		goto hdr_chk_fail;
	}

	/*
	 * Get the SHA-256 signature of the OTA image
	 */
	key_len = CLIENT_LAN_SIGN_SIZE;
	rc = jsmn_get_string(&parser, NULL, "sign",
	    (char *)tbuf, sizeof(tbuf));
	if (rc < 0 || rc != (key_len * 2)) {
		goto hdr_chk_fail;
	}
	state->ota.img_sign = malloc(key_len);
	if (!state->ota.img_sign) {
		CLIENT_LOGF(LOG_WARN, "out of mem");
		goto hdr_chk_fail;
	}
	rc = parse_hex(state->ota.img_sign, key_len, (char *)tbuf, rc);
	if (rc < 0) {
		goto hdr_chk_fail;
	}
	adc_sha256_init(&state->ota.sha_ctx);
	return 0;

hdr_chk_fail:
	free(state->ota.version);
	state->ota.version = NULL;
	free(state->ota.img_sign);
	state->ota.img_sign = NULL;
	client_log(LOG_WARN "header chk failed");
	return -1;
}

static int client_lan_ota_hdr_process(const char *header)
{
	char dec_header[CLIENT_LAN_OTA_HDR_SZ];
	size_t dec_head_len = sizeof(dec_header);

	/* Decode the header */
	if (net_base64_decode(header, strlen(header), dec_header,
	    &dec_head_len)) {
		server_log(LOG_WARN "failed to decode header");
		return -1;
	}

	/* Verify the header length */
	if (dec_head_len != CLIENT_LAN_OTA_HDR_SZ) {
		server_log(LOG_WARN "invalid header len");
		return -1;
	}

	/* Do the header check */
	return client_lanota_hdr_chk(dec_header, CLIENT_LAN_OTA_HDR_SZ);
}

/*
 *  PUT /lanota.json
 *  { "ota":
 *	{ "url": "https://<lan_ip>/<path>/bc-0.18.1.patch",
 *	  "ver": "0.18.1", "size": 12300, "type":"module"|"host_mcu",
 *	  "checksum": something, "head":"<base64_encoded_256B_Header>" }
 *  }
 *  Note that the size above is the size before encryption, which adds padding.
 */
void client_lanota_json_put(struct server_req *req)
{
	struct client_state *state = &client_state;

	client_lock();
	state->ota_server.lan = 1;

	if (!req->content_len) {
		server_log(LOG_WARN "content len %d", req->content_len);
		goto inval_lan_ota;
	}

	/*
	 * Parse the JSON to initiate the OTA
	 */
	client_ota_json_put(req);

	state->ota.max_off = (state->ota.max_off + AES_BLOCK_SIZE - 1) &
	    ~(AES_BLOCK_SIZE - 1);	/* round up for padding */

#ifdef AYLA_BC
	if (adap_wifi_in_ap_mode()) {
		ada_client_start(state);
	}
#endif
	client_wakeup();
	client_unlock();
	return;

inval_lan_ota:
	server_log(LOG_WARN "%s: request err", __func__);
	server_put_status(req, HTTP_STATUS_BAD_REQ);
	client_unlock();
}
#endif /* DISABLE_LAN_OTA */

static void client_fill_state_buf(void *payload, size_t payload_len)
{
	struct client_state *state = &client_state;

	if (state->recved_len + payload_len < sizeof(state->buf)) {
		memcpy(state->buf + state->recved_len,
		    payload, payload_len);
		state->recved_len += payload_len;
	}
}

/*
 * Receive portion of OTA image.
 */
static enum ada_err client_recv_ota_get(struct http_client *hc,
					void *buf, size_t len)
{
	struct client_state *state = &client_state;
	enum patch_state status;
#ifndef DISABLE_LAN_OTA
	int rc;
#endif

	if (buf) {
		state->ota.auth_fail = 0;
		if (state->ota_server.remote && !state->ota.url_fetched) {
			client_log(LOG_DEBUG "ota fetch remote URL");
			client_fill_state_buf(buf, len);
			return AE_OK;
		}
		client_log(LOG_DEBUG "ota recv %d+%lu/%lu",
		    len, state->ota.off, state->ota.max_off);

#ifndef DISABLE_LAN_OTA
		if (state->ota_server.lan) {
			/* XXX TBD could probably decrypt in place */
			rc = client_lanota_process_data(state, buf, len);
			if (rc < 0) {
				ada_ota_report_int(state->ota.type,
				    PB_ERR_FILE_CRC);	/* not precise */
				return AE_INVAL_VAL;
			}
			buf = state->ota.recv_buf.data;
			len = rc;
		}
#endif /* DISABLE_LAN_OTA */

		status = client_ota_save(state, buf, len);
		state->ota.data_recvd = 1;
		if (status && status != PB_ERR_STALL) {
			if (state->ota_server.uri) {
				free(state->ota_server.uri);
				state->ota_server.uri = NULL;
			}
			ada_ota_report_int(state->ota.type, status);
			return AE_INVAL_VAL;
		}
		return AE_OK;
	}

	if (state->ota_server.remote && !state->ota.url_fetched) {
		/*
		 * Parse remote OTA URL.
		 */
		state->ota.url_fetched = 1;
		state->buf[state->recved_len] = '\0';
		if (client_ota_json_parse(state->buf)) {
			client_ota_cleanup(state);
			return AE_ALLOC;
		}
	} else if (state->ota.off + state->ota.pad >= state->ota.max_off ||
	    state->ota.data_recvd == 0) {
		/*
		 * End of chunk or entire image.
		 */
		if (state->ota.data_recvd == 0) {
			ada_ota_report_int(state->ota.type, PB_ERR_GET);
			client_log(LOG_WARN "ota short read: "
			    "%lu bytes of %lu",
			    state->ota.off + state->ota.pad,
			    state->ota.max_off);
		} else {
			client_log(LOG_INFO "ota fetch done: "
			    "%lu bytes", state->ota.max_off);
#ifndef DISABLE_LAN_OTA
			/*
			 * verify the SHA-256 hash for LAN OTA
			 */
			if (state->ota_server.lan &&
			    client_lanota_verify_img(state)) {
				ada_ota_report_int(state->ota.type,
				    PB_ERR_NEW_CRC);
			}
#endif /* DISABLE_LAN_OTA */
		}
		client_ota_set_sts_rpt(state, HTTP_STATUS_OK);
	}
	client_tcp_recv_done(state);
	return AE_OK;
}

/*
 * Ask for a part of the patch.
 */
int client_ota_fetch_image(struct client_state *state)
{
	struct http_client *hc;
	char range[30];
	struct http_hdr range_hdr = {
		.name = "Range",
		.val = range
	};
	struct http_hdr *hdr;
	u32 off, cnt;

	if (state->ota.in_prog != COS_IN_PROG || !state->ota_server.host[0]) {
		return -1;
	}
	if (!CLIENT_HAS_KEY(state) && !state->ota_server.lan) {
		return -1;
	}

	state->conn_state = CS_WAIT_OTA_GET;
	state->request = CS_GET_OTA;
	state->ota.data_recvd = 0;
	off = state->ota.off;
	if (state->ota.type == OTA_HOST) {
#ifdef AMEBA
		if (state->ota_server.remote) {
			cnt = S3_OTA_GET_MCU_CHUNK_SIZE - 1;
		} else {
#endif
			cnt = OTA_GET_MCU_CHUNK_SIZE - 1;
#ifdef AMEBA
		}
#endif
	} else {
		cnt = OTA_GET_CHUNK_SIZE - 1;
	}
	if (off + cnt + state->ota.pad > state->ota.max_off) {
		cnt = state->ota.max_off - (off + state->ota.pad);
	}
	if (!cnt) {
		return -1;	/* nothing more to fetch */
	}

	if (off == state->ota.prev_off) {
		state->ota.chunk_retries++;
	} else {
		state->ota.chunk_retries = 0;
	}
	if (state->ota.chunk_retries > OTA_CHUNK_RETRIES) {
		ada_ota_report_int(state->ota.type, PB_ERR_GET);
		return -1;
	}
	state->ota.prev_off = off;

	if (state->ota_server.lan) {
		hc = client_req_new(CCT_LAN);
		/* Range not required for LAN OTA */
		client_log(LOG_DEBUG "LAN OTA get from %s",  hc->host);
		hdr = NULL;
	} else if (state->ota_server.remote && !state->ota.url_fetched) {
		state->recved_len = 0;
		hc = client_req_new(CCT_REMOTE);
		/* Range not required for URL fetch */
		client_log(LOG_DEBUG "OTA URL get from %s", hc->host);
		hdr = NULL;
	} else {
		hc = client_req_new(CCT_IMAGE_SERVER);
		client_log(LOG_DEBUG "OTA get from %s %lu-%lu", hc->host,
		    off, off + cnt);
		snprintf(range, sizeof(range), "bytes=%lu-%lu", off, off + cnt);
		hdr = &range_hdr;
	}
	ASSERT(hc);
	hc->client_tcp_recv_cb = client_recv_ota_get;

	ASSERT(state->ota_server.uri);
	client_req_start(hc, HTTP_REQ_GET, state->ota_server.uri, hdr);
	return 0;
}

/*
 * Handle response from PUT /ota_failed.json.
 */
static enum ada_err client_put_ota_recv(struct http_client *hc,
				void *payload, size_t len)
{
	struct client_state *state = &client_state;
	const struct ada_ota_ops *ops;

	if (!payload) {
		state->ota_status.status = 0;
		ops = state->ota_ops[state->ota_status.type];
		if (ops && ops->status_clear) {
			ops->status_clear();
		}
		client_tcp_recv_done(state);
	}
	return AE_OK;
}

/*
 * Put OTA failure code to the server.
 */
int client_put_ota_status(struct client_state *state)
{
	struct http_client *hc;
	char uri[CLIENT_GET_REQ_LEN];

	ASSERT(client_locked);
	if (!state->ota_status.status) {
		return -1;
	}
	hc = client_req_ads_new();
	ASSERT(hc);
	hc->client_tcp_recv_cb = client_put_ota_recv;
	state->conn_state = CS_WAIT_OTA_PUT;
	state->request = CS_PUT_OTA;

	hc->body_len = snprintf(state->xml_buf, sizeof(state->xml_buf) - 1,
	    "{\"ota-status\":{\"status\":%u,\"type\":\"%s\"}}",
	    state->ota_status.status,
	    state->ota_status.type == OTA_HOST ? "host_mcu" : "module");
	hc->body_buf = state->xml_buf;
	hc->body_buf_len = hc->body_len;

	snprintf(uri, sizeof(uri), "/devices/%s/ota_failed.json",
	    state->client_key);

	client_req_start(hc, HTTP_REQ_PUT, uri, &http_hdr_content_json);
	return 0;
}

/*
 * Handler has delivered all the data so far, ask for more.
 */
void ada_ota_continue(void)
{
	struct client_state *state = &client_state;

	client_lock();
	state->ota.in_prog = COS_IN_PROG;
	if (state->conn_state == CS_WAIT_EVENT ||
	    state->conn_state == CS_WAIT_RETRY) {
		client_wakeup();
	}
	client_unlock();
}

/*
 * Report OTA status.
 * Status will be non-zero for failure.
 */
void ada_ota_report_int(enum ada_ota_type type, enum patch_state status)
{
	struct client_state *state = &client_state;

	ASSERT(client_locked);

	if (status && state->ota_status.status) {
		return;		/* previous status pending */
	}
	state->ota_status.status = status;
	state->ota_status.type = state->ota.type;

	if (state->ota.type != type || state->ota.in_prog == COS_NONE) {
		return;		/* not applicable to the ongoing OTA */
	}

	/*
	 * If notification error, retry by allowing command to be refetched.
	 */
	if (status == PB_ERR_NOTIFY && state->ota.in_prog == COS_NOTIFIED) {
		if (state->ota.retries < 5) {
			state->ota.retries++;
			client_ota_cleanup(state);
			client_wakeup();
			return;
		}
		state->ota.retries = 0;
	}

	/*
	 * If in the midst of the download, abort it.
	 */
	if ((state->ota.in_prog == COS_IN_PROG ||
	    state->ota.in_prog == COS_STALL) &&
	    !http_client_is_ready(&state->http_client)) {
		http_client_abort(&state->http_client);
	}

	client_log(LOG_INFO "ota_report %s: status: 0x%x\n",
	    type == OTA_HOST ? "host" : "mod", status);

	client_ota_set_sts_rpt(state,
	    status ? HTTP_STATUS_INTERNAL_ERR : HTTP_STATUS_OK);
	client_wakeup();
}

/*
 * Report OTA status.
 * Status will be non-zero for failure.
 */
void ada_ota_report(enum ada_ota_type type, enum patch_state status)
{
	client_lock();
	ada_ota_report_int(type, status);
	client_unlock();
}

/*
 * Job status report for OTA.
 */
void client_ota_set_sts_rpt(struct client_state *state, u16 sts)
{
	ASSERT(client_locked);
	ASSERT(sts);

	CLIENT_LOGF(LOG_INFO, "OTA status %u", sts);

	if (state->ota.http_status) {
		return;
	}
	state->ota.http_status = sts;
	state->ota.in_prog = COS_CMD_STATUS;
}

static int client_ota_json_parse(char *post_data)
{
	struct client_state *state = &client_state;
	enum patch_state status;
	jsmn_parser parser;
	jsmnerr_t err;
	jsmntok_t tokens[OTA_JSON_PUT_TOKENS];
	char *url;
	char ver[ADA_CONF_VER_LEN];
	char type[9]; /* "host_mcu" or "module" */
	char header[4 * CLIENT_LAN_OTA_HDR_SZ / 3 + 10];
	char source[6]; /* "local" or "s3" */
	int url_len, tmp_len;
	enum ada_ota_type ota_type = OTA_MODULE;
	unsigned long image_len;
	char *protocol, *host, *path;
	jsmntok_t *parent;
	unsigned long port;
	int rc;

	jsmn_init_parser(&parser, post_data, tokens, OTA_JSON_PUT_TOKENS);
	err = jsmn_parse(&parser);
	if (err != JSMN_SUCCESS) {
		server_log(LOG_WARN "ota_json_put jsmn err %d", err);
		status = PB_ERR_REQ;
		goto report;
	}

	parent = jsmn_get_val(&parser, NULL, "ota");
	if (!parent) {
		server_log(LOG_WARN "ota_json_put no ota obj");
		status = PB_ERR_URL;
		goto report;
	}
	url_len = jsmn_get_string_ptr(&parser, parent, "url", &url);
	if (url_len <= 0) {
		status = PB_ERR_URL;
		goto report;
	}

	if (jsmn_get_ulong(&parser, parent, "size", &image_len) < 0 ||
	    !image_len) {
		server_log(LOG_WARN "ota_json_put no sz");
		status = PB_ERR_SIZE;
		goto report;
	}

	tmp_len = jsmn_get_string(&parser, parent, "type", type, sizeof(type));
	if (tmp_len <= 0 || !strcasecmp(type, "module")) {
		snprintf(type, sizeof(type), "module");
	} else if (!strcasecmp(type, "host_mcu")) {
		ota_type = OTA_HOST;
	} else {
		status = PB_ERR_TYPE;
		goto report;
	}

	tmp_len = jsmn_get_string(&parser, parent, "ver", ver, sizeof(ver));
	if (tmp_len <= 0) {
		status = PB_ERR_VER;
		goto report;
	}

	if (state->ota_server.lan) {
		/* Parse out the base64 encoded header */
		tmp_len = jsmn_get_string(&parser, parent, "head", header,
		    sizeof(header));
		if (tmp_len <= 0) {
			server_log(LOG_WARN "missing base64 hdr (LAN OTA v1)");
			return -1;
		}

		/* Decrypt and parse the header */
		rc = client_lan_ota_hdr_process(header);
		if (rc) {
			return -1;
		}

		/* Verify the version is same as in the encrypted hdr */
		if (strcmp(ver, state->ota.version)) {
			return -1;
		}

		tmp_len = jsmn_get_ulong(&parser, parent, "port", &port);
		if (tmp_len < 0 || port > MAX_U16) {
			status = PB_ERR_REQ;
			goto report;
		}
		state->ota_server.port = port;
	} else {
		tmp_len = jsmn_get_string(&parser, parent, "source",
		    source, sizeof(source));
		if (tmp_len <= 0) {
			status = PB_ERR_REQ;
			goto report;
		}
		state->ota_server.remote = strcmp(source, "local") ? 1 : 0;

		state->ota.version = calloc(strlen(ver) + 1, sizeof(char));
		if (!state->ota.version) {
			client_log(LOG_WARN "ota_json_put out of mem");
			free(state->ota.version);
			state->ota.version = NULL;
			return -1;
		}
		strcpy(state->ota.version, ver);
	}

	url[url_len] = '\0';
	parse_url(url, &protocol, &host, &path);
	if (!protocol || !host || !path) {
		status = PB_ERR_URL;
		goto report;
	}
	if (!strcmp(protocol, "https")) {
		state->ota_server.ssl = 1;
	} else if (!strcmp(protocol, "http")) {
		state->ota_server.ssl = 0;
	} else {
		status = PB_ERR_URL;
		goto report;
	}
	strncpy(state->ota_server.host, host,
	    sizeof(state->ota_server.host) - 1);
	state->ota_server.host[sizeof(state->ota_server.host) - 1] = '\0';

	if (state->ota_server.uri == NULL) {
		state->ota_server.uri = calloc(MAX_S3_URL_LEN, sizeof(char));
		ASSERT(state->ota_server.uri);
	}
	snprintf(state->ota_server.uri, MAX_S3_URL_LEN, "/%s", path);

	state->ota.off = 0;
	state->ota.max_off = image_len;
	state->ota.auth_fail = 0;
	state->ota.type = ota_type;
	state->ota.pad = 0;
	return 0;
report:
	state->ota.max_off = image_len;
	state->ota.type = ota_type;
	ada_ota_report_int(ota_type, status);
	return 0;
}

/*
 * Notify driver. It may call ada_ota_start() here or later.
 */
static void client_ota_notify(void)
{
	struct client_state *state = &client_state;
	const struct ada_ota_ops *ops;
	enum patch_state status;

	state->ota.in_prog = COS_NOTIFIED;
	state->ota.http_status = 0;
	state->ota_status.status = 0;

	ops = state->ota_ops[state->ota.type];
	if (!ops) {
		server_log(LOG_WARN "ota_json_put no handler for %s OTA update",
		    (state->ota.type == OTA_MODULE) ? "module" : "host");
		status = PB_ERR_TYPE;
		goto report;
	}

	client_unlock();
	ASSERT(ops->notify);
	status = ops->notify(state->ota.max_off, state->ota.version);
	client_lock();
	if (status) {
		server_log(LOG_WARN "ota_json_put notify status %x", status);
		goto report;
	}
	return;
report:
	ada_ota_report_int(state->ota.type, status);
	return;
}

/*
 *  PUT /ota.json
 * { "ota":
 *	{ "url": "https://<image-server>/updates/AY001MUS/bc-0.18.1.patch",
 *	  "ver": "0.18.1", "size": 12300, "type":"module"|"host_mcu",
 *	  "checksum": "0x1234567", "source":"local" }
 * }
 *
 * Note: drops client_lock() to call OTA notify op, which could trigger the
 * start of the OTA.
 */
void client_ota_json_put(struct server_req *req)
{
	struct client_state *state = &client_state;

	ASSERT(client_locked);
	if (state->ota.in_prog != COS_NONE) {
		server_log(LOG_ERR "ota_json_put OTA already in progress");
		goto inval;
	}

	if (client_ota_json_parse(req->post_data)) {
		goto inval;
	}

	client_ota_notify();
	server_put_status(req, HTTP_STATUS_NO_CONTENT);
	return;

	/*
	 * Invalid request should only occur with LAN OTA.
	 * Clean out any previous request, so we can try again.
	 */
inval:
	server_put_status(req, HTTP_STATUS_BAD_REQ);
	server_log(LOG_WARN "ota_json_put request err");
	client_ota_cleanup(state);
}

void ada_ota_start(enum ada_ota_type type)
{
	struct client_state *state = &client_state;

	client_lock();
	if (type == state->ota.type) {
		state->ota.in_prog = COS_IN_PROG;
		state->ota.off = 0;
		client_wakeup();
	}
	client_unlock();
}

void ada_ota_register(enum ada_ota_type type, const struct ada_ota_ops *ops)
{
	struct client_state *state = &client_state;

	ASSERT(type < OTA_TYPE_CT);
	state->ota_ops[type] = ops;
}
