/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/endian.h>
#include <ayla/log.h>
#include <ayla/http.h>
#include <ayla/clock.h>
#include <ayla/tlv.h>
#include <net/net.h>
#include <net/net_crypto.h>
#include <net/base64.h>
#include <ada/client.h>

static struct adc_rng client_auth_rng;

/*
 * Encrypt field signed by the private key.
 * The result will be 256 bytes if successful.
 * Returns the length of result or negative error number.
 */
int client_auth_encrypt(void *pub_key, size_t pub_key_len,
		void *buf, size_t len, const char *req)
{
	u8 tbuf[HTTP_MAX_TEXT];
	size_t tlen;
	struct adc_rsa_key key;
	int rc = -1;
	size_t key_len;

	adc_rng_init(&client_auth_rng);

	key_len = adc_rsa_key_set(&key, pub_key, pub_key_len);
	if (!key_len) {
		client_log(LOG_ERR "auth_gen failed");
		goto free_key;
	}

	/*
	 * form pseudo-header in result buffer.
	 */
	tlen = snprintf(buf, len, "%lu %s", clock_utc(), req);
	if (tlen >= len) {
		client_log(LOG_ERR "auth: pseudo-header too long");
		goto free_key;
	}

	client_log(LOG_DEBUG "auth: pseudo-header '%s'", (char *)buf);

	/*
	 * encrypt to temporary buffer.
	 */
	rc = adc_rsa_encrypt_pub(&key, buf, tlen, tbuf, key_len,
	    &client_auth_rng);
	if (rc < 0) {
		client_log(LOG_ERR "auth: encrypt fail rc %d", rc);
		goto free_key;
	}
	if (rc > len) {
		client_log(LOG_ERR "auth: dest length %u insuff need %d",
		    (unsigned int)len, rc);
		goto free_key;
	}
	memcpy(buf, tbuf, rc);

free_key:
	adc_rsa_key_clear(&key);
	return rc;
}

/*
 * Create client-auth field signed by the private key.
 * The result will be around 333 bytes long (256 bytes base-64-encoded).
 * Returns the length of result or negative error number.
 */
int client_auth_gen(void *key, size_t key_len,
		void *buf, size_t len, const char *req)
{
	u8 tbuf[HTTP_MAX_TEXT];
	size_t outlen;
	int rc;

	rc = client_auth_encrypt(key, key_len, tbuf, len, req);
	if (rc < 0) {
		return rc;
	}

	/*
	 * Base-64 encode to result buffer.
	 */
	outlen = len;
	rc = net_base64_encode(tbuf, rc, buf, &outlen);
	if (rc < 0) {
		client_log(LOG_ERR "auth: base-64 encode failed rc %d", rc);
		return rc;
	}
	return outlen;
}
