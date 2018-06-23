/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ADC_CRYPTO_H__
#define __AYLA_ADC_CRYPTO_H__

#include <stdlib.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <device_lock.h>

#define AES_BLOCK_SIZE	16

#define SHA1_SIG_LEN	20

#define AES_GET_IV_SUPPORT	1

static inline int adc_sha1(const void *buf, size_t len,
    const void *buf2, size_t len2, void *sig)
{
	mbedtls_sha1_context sha_ctx;

	mbedtls_sha1_init(&sha_ctx);
	mbedtls_sha1_starts(&sha_ctx);
	mbedtls_sha1_update(&sha_ctx, buf, len);
	if (buf2) {
		mbedtls_sha1_update(&sha_ctx, buf2, len2);
	}
	mbedtls_sha1_finish(&sha_ctx, (u8_t *)sig);
	mbedtls_sha1_free(&sha_ctx);
	return 0;
}

#define SHA256_SIG_LEN	32

struct adc_sha256 {
	mbedtls_sha256_context ctx;
};

static inline void adc_sha256_init(struct adc_sha256 *sha_ctx)
{
	mbedtls_sha256_init(&sha_ctx->ctx);
	mbedtls_sha256_starts(&sha_ctx->ctx, 0);
}

static inline void adc_sha256_update(struct adc_sha256 *sha_ctx,
    const void *buf, size_t len, const void *buf2, size_t len2)
{
	mbedtls_sha256_update(&sha_ctx->ctx, buf, len);
	if (buf2) {
		mbedtls_sha256_update(&sha_ctx->ctx, buf2, len2);
	}
}

static inline void adc_sha256_final(struct adc_sha256 *sha_ctx,
		void *sign)
{
	mbedtls_sha256_finish(&sha_ctx->ctx, sign);
	mbedtls_sha256_free(&sha_ctx->ctx);
}

struct adc_aes {
	mbedtls_aes_context ctxt;
	u8 iv[16];
};

struct adc_dev;

static inline struct adc_dev *adc_aes_open(void)
{
	return NULL;
}

static inline int adc_aes_cbc_key_set(struct adc_dev *dev, struct adc_aes *aes,
		void *key, size_t key_len, void *iv, int decrypt)
{
	mbedtls_aes_init(&aes->ctxt);
	if (decrypt) {
		mbedtls_aes_setkey_dec(&aes->ctxt, key, key_len * 8);
	} else {
		mbedtls_aes_setkey_enc(&aes->ctxt, key, key_len * 8);
	}
	memcpy(aes->iv, iv, sizeof(aes->iv));

	return 0;
}

/*
 * If possible, return the Initialization Vector (IV) from the AES key context.
 * If not possible, return -1, and leave buffer untouched.
 */
static inline int adc_aes_iv_get(struct adc_aes *aes, void *buf, size_t len)
{
	if (len > sizeof(aes->iv)) {
		len = sizeof(aes->iv);
	}
	memcpy(buf, aes->iv, len);
	return 0;
}

static inline int adc_aes_cbc_encrypt(struct adc_dev *dev, struct adc_aes *aes,
				void *buf, size_t len)
{
	mbedtls_aes_crypt_cbc(&aes->ctxt, MBEDTLS_AES_ENCRYPT,
	    len, aes->iv, buf, buf);
	return 0;
}

static inline int adc_aes_cbc_decrypt(struct adc_dev *dev, struct adc_aes *aes,
				void *buf, size_t len)
{
	mbedtls_aes_crypt_cbc(&aes->ctxt, MBEDTLS_AES_DECRYPT,
	    len, aes->iv, buf, buf);
	return 0;
}

static inline int adc_aes_entropy_add(void *random_data, size_t len)
{
	return 0;
}

/*
 * random number generator.
 */
struct adc_rng {
	u8 init;
	void *rng;
};

static inline void adc_rng_init(struct adc_rng *rng)
{
}

static inline int adc_rng_random_fill(struct adc_rng *rng,
					void *buf, size_t len)
{
	return rtw_get_random_bytes(buf, len);
}

int pk_get_rsapubkey(unsigned char **p,
	const unsigned char *end,
	mbedtls_rsa_context *rsa);

struct adc_rsa_key {
	mbedtls_pk_context key;
};

/*
 * Set key from binary ASN-1 sequence buffer.
 * Returns key size, or 0 on failure.
 * Caller must call adc_rsa_key_clear(), even on failure.
 */
static inline size_t adc_rsa_key_set(struct adc_rsa_key *key,
				void *buf, size_t keylen)
{
	unsigned char *p;
	int ret;

	ASSERT(key);
	memset(key, 0, sizeof(struct adc_rsa_key));
	ret = mbedtls_pk_setup(&key->key,
	    mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (ret) {
		goto version_1_5;
	}
	p = (unsigned char *)buf;
	ret = pk_get_rsapubkey(&p, p+keylen, mbedtls_pk_rsa(key->key));
	if (ret == 0) {
		return mbedtls_pk_rsa(key->key)->len;
	}
	mbedtls_pk_free(&key->key);

version_1_5:
	p = (unsigned char *)buf;
	if (mbedtls_pk_parse_subpubkey(&p, p+keylen, &key->key) == 0 &&
	    mbedtls_pk_can_do(&key->key, MBEDTLS_PK_RSA)) {
		return mbedtls_pk_rsa(key->key)->len;
	}
	return 0;
}

static inline void adc_rsa_key_clear(struct adc_rsa_key *key)
{
	mbedtls_pk_free(&key->key);
}

static inline int adc_rsa_encrypt_pub(struct adc_rsa_key *key,
				void *in, size_t in_len,
				void *out, size_t out_len,
				struct adc_rng *rng)
{
	mbedtls_rsa_context *rsa;
	int ret;

	rsa = mbedtls_pk_rsa(key->key);
	mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, 0);

	ret = mbedtls_rsa_pkcs1_encrypt(rsa, adc_rng_random_fill, rng,
	    MBEDTLS_RSA_PUBLIC, in_len, in, out);
	if (ret < 0)
		return ret;
	else
		return rsa->len;
}

static inline int adc_rsa_verify(struct adc_rsa_key *key,
				void *in, size_t in_len,
				void *out, size_t out_len)
{
	mbedtls_rsa_context *rsa;
	int ret;

	rsa = mbedtls_pk_rsa(key->key);
	mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, 0);

	ret = mbedtls_rsa_pkcs1_decrypt(rsa, NULL, NULL,
	    MBEDTLS_RSA_PUBLIC, &out_len, in, out, out_len);

	if (ret < 0)
		return ret;
	else
		return out_len;
}

/*
 * SHA-256 functions.
 */
#define ADC_SHA256_HASH_SIZE 32

struct adc_hmac_ctx {
	mbedtls_md_context_t ctx;
};

static inline void adc_hmac_sha256_init(struct adc_hmac_ctx *ctx,
					 const void *seed, size_t len)
{
	mbedtls_md_init(&ctx->ctx);
	mbedtls_md_setup(&ctx->ctx,
	    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&ctx->ctx, seed, len);
}

static inline void adc_hmac_sha256_update(struct adc_hmac_ctx *ctx,
					const void *buf, size_t len)
{
	mbedtls_md_hmac_update(&ctx->ctx, buf, len);
}

static inline int adc_hmac_sha256_final(struct adc_hmac_ctx *ctx, void *sign)
{
	mbedtls_md_hmac_finish(&ctx->ctx, sign);
	mbedtls_md_free(&ctx->ctx);
	return 0;
}

#endif /* __AYLA_ADC_CRYPTO_H__ */
