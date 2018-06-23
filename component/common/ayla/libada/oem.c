/*
 * Copyright 2012-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <ayla/assert.h>
#include <ayla/utypes.h>
#include <ada/err.h>
#include <ayla/tlv.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/clock.h>
#include <ayla/log.h>
#include <ayla/parse.h>
#ifdef AYLA_BC
#include <ayla/gpio.h>
#endif
#include <ada/client.h>
#include <ada/ada_conf.h>

/*
 * /oem configuration items.
 */
u8 oem_key[CONF_OEM_KEY_MAX];	/* encrypted OEM key */
u16 oem_key_len;		/* length of OEM key */

#ifdef AYLA_BC
char oem_host_version[CONF_OEM_VER_MAX + 1]; /* GPIO mode host version */
u8 oem_host_version_sent;	/* non-zero if version sent to ADS */
#endif

static const struct ada_conf_item oem_conf_items[] = {
	{ "oem", ATLV_UTF8, oem, sizeof(oem)},
	{ "oem/model", ATLV_UTF8, oem_model, sizeof(oem_model)},
	{ ADA_CONF_OEM_KEY, ATLV_FILE, oem_key, sizeof(oem_key)},
	{ NULL }
};

/*
 * Persist the OEM ID and OEM model only if they were entered on the CLI.
 * This allows a compiled in version to be set before the configuration
 * is loaded without being overwritten unless the CLI was used.
 * If an empty string is entered with the CLI, the compiled-in default,
 * if non-empty, is used.
 */
static u8 oem_persist_id;
static u8 oem_persist_model;

/*
 * Export OEM configuration items.
 */
static void oem_export(void)
{
	conf_put_str_ne(CT_oem, oem_persist_id ? oem : "");
	conf_put_str_ne(CT_model, oem_persist_model ? oem_model : "");
#ifdef AYLA_BC
	conf_put_str(CT_version, oem_host_version);
	conf_put_u32(CT_complete, oem_host_version_sent);
#endif /* AYLA_BC */
	conf_put(CT_key, ATLV_FILE, oem_key, oem_key_len);
}

static void oem_version_export(void *arg)
{
	oem_export();
}

void oem_save(void)
{
	conf_persist(CT_oem, oem_version_export, NULL);
}

/*
 * Set encrypted OEM key.
 * oem_model_for_key is used for the encrypted string.
 * If the model is "*" in the encrypted string, the plaintext
 * oem model may be changed later without re-encrypting the key.
 */
enum conf_error oem_set_key(char *key, size_t key_len, const char *model)
{
	char buf[CONF_OEM_KEY_MAX + 1];
	char pub_key[CLIENT_CONF_PUB_KEY_LEN];
	int pub_key_len;
	int rc;
	size_t len = key_len;

	if (len == '\0') {
		oem_key_len = 0;
		goto out;
	}
	if (len > sizeof(buf) - 1) {
		return CONF_ERR_RANGE;
	}
	memcpy(buf, key, len);
	len += snprintf(buf + len, sizeof(buf) - 1 - len, " %s %s", oem, model);
	buf[len] = '\0';

	pub_key_len = adap_conf_pub_key_get(pub_key, sizeof(pub_key));
	if (pub_key_len <= 0) {
		conf_log(LOG_ERR "pub key not set");
		return CONF_ERR_RANGE;
	}

	rc = client_auth_encrypt(pub_key, pub_key_len,
	    oem_key, CONF_OEM_KEY_MAX, buf);
	if (rc < 0) {
		conf_log(LOG_ERR "oem_key encryption failed.  rc %d", rc);
		return CONF_ERR_RANGE;
	}
	oem_key_len = rc;
out:
	rc = adap_conf_set(ADA_CONF_OEM_KEY, oem_key, oem_key_len);
	if (rc) {
		conf_log(LOG_ERR "oem_key save failed");
	}
	return rc;
}

/*
 * Set OEM items
 */
static enum conf_error
oem_set(int src, enum conf_token *token, size_t len, struct ayla_tlv *tlv)
{
	int op;

	if (len != 1) {
		goto err;
	}

	if (token[0] == CT_model) {
		op = CONF_OP_SS_OEM_MODEL;
	} else {
		op = CONF_OP_SS_OEM;
	}
	if (conf_access(op | CONF_OP_WRITE | src)) {
		return CONF_ERR_PERM;
	}

	switch (token[0]) {
	case CT_oem:
		conf_get(tlv, ATLV_UTF8, oem, sizeof(oem) - 1);
		oem_persist_id = 1;
		break;
	case CT_model:
		conf_get(tlv, ATLV_UTF8, oem_model, sizeof(oem_model) - 1);
		/* reset the client if set from MCU */
		if (src == CONF_OP_SRC_MCU) {
			client_server_reset();
		}
		oem_persist_model = 1;
		break;
#ifdef AYLA_BC
	case CT_version:
		conf_get(tlv, ATLV_UTF8, oem_host_version,
		    sizeof(oem_host_version) - 1);
		break;
	case CT_complete:
		oem_host_version_sent = conf_get_bit(tlv);
		break;
#endif /* AYLA_BC */
	case CT_key:
		if (tlv->type == ATLV_UTF8) {
			return oem_set_key((char *)(tlv + 1), tlv->len,
			    oem_model);
		}
		oem_key_len = (u16)conf_get(tlv, ATLV_FILE,
		    oem_key, sizeof(oem_key));
		break;
	default:
		goto err;
	}
	return CONF_ERR_NONE;
err:
	return CONF_ERR_PATH;
}

/*
 * Handle get of sys or id config setting.
 */
static enum conf_error oem_get(int src, enum conf_token *token, size_t len)
{
	if (len != 1) {
		goto err;
	}
	if (conf_access(CONF_OP_SS_OEM | CONF_OP_READ | src)) {
		return CONF_ERR_PERM;
	}
	switch (token[0]) {
	case CT_oem:
		conf_resp_str(oem);
		break;
	case CT_model:
		conf_resp_str(oem_model);
		break;
#ifdef AYLA_BC
	case CT_version:
		conf_resp_str(oem_host_version);
		break;
	case CT_complete:
		conf_resp_u32(oem_host_version_sent);
		break;
#endif /* AYLA_BC */
	case CT_key:
		conf_resp(ATLV_FILE, oem_key, oem_key_len);
		break;
	default:
		goto err;
	}
	return CONF_ERR_NONE;
err:
	return CONF_ERR_PATH;
}

const struct conf_entry conf_oem_entry = {
	.token = CT_oem,
	.export = oem_export,
	.set = oem_set,
	.get = oem_get,
};

void oem_conf_load(void)
{
	const struct ada_conf_item *item;
	int len;

	for (item = oem_conf_items; item->name; item++) {
		len = ada_conf_get_item(item);
		if (!strcmp(item->name, ADA_CONF_OEM_KEY) && len > 0) {
			oem_key_len = len;
		}
	}
}

void oem_conf_factory_reset(void)
{
	const struct ada_conf_item *item;

	for (item = oem_conf_items; item->name; item++) {
		adap_conf_reset_factory(item->name);
	}
}

/*
 * Set OEM or OEM model.
 * The maximum string length is CONF_OEM_MAX.
 * Returns zero on success, non-zero if invalid or too long.
 */
static int ada_conf_oem_set_string(char *dest, char *src)
{
	int len;

	/*
	 * Work-around for parser in early SDK versions, drop in ada-1.2.
	 */
	if (!strcmp(src, "\"\"")) {
		src = "";
	}
	if (!hostname_valid(src)) {
		printcli("error: invalid value");
		return -1;
	}
	len = snprintf(dest, CONF_OEM_MAX + 1, "%s", src);
	if (len > CONF_OEM_MAX) {
		printcli("error: value too long");
		return -1;
	}
	return 0;
}

/*
 * Handle OEM CLI commands.
 */
void ada_conf_oem_cli(int argc, char **argv)
{
	char *model;

	if (argc <= 1) {
		printcli("oem: \"%s\"", oem);
		printcli("oem_model: \"%s\"", oem_model);
		printcli("oem_key: (%s set)", oem_key_len ? "is" : "not");
#ifdef AYLA_BC
		if (oem_host_version[0] != '\0') {
			printcli("oem_host_version: %s", oem_host_version);
		}
#endif /* AYLA_BC */
		return;
	}
	if (!mfg_or_setup_mode_ok()) {
		return;
	}
	if (argc == 2) {
		if (ada_conf_oem_set_string(oem, argv[1])) {
			return;
		}
		oem_persist_id = 1;
		return;
	}
	if (argc == 3 && !strcmp(argv[1], "model")) {
		if (ada_conf_oem_set_string(oem_model, argv[2])) {
			return;
		}
		oem_persist_model = 1;
		return;
	}
	if ((argc == 3 || argc == 4) && !strcmp(argv[1], "key")) {
		model = argc == 4 ? argv[3] : oem_model;
		if (oem[0] == '\0' || model[0] == '\0') {
			printcli("error: oem and oem model "
			    "must be set before key");
			return;
		}
		oem_set_key(argv[2], strlen(argv[2]), model);
		return;
	}
#ifdef AYLA_BC
	if (argc == 3 && !strcmp(argv[1], "host_version")) {
		len = strlen(argv[2]);
		if (len > CONF_OEM_VER_MAX) {
			printcli("error: value too long");
			return;
		}
		snprintf(oem_host_version, CONF_OEM_VER_MAX, "%s", argv[2]);
		oem_host_version_sent = 0;
		gpio_host_ver_send();
		return;
	}
#endif /* AYLA_BC */
	printcli("usage: oem <name>");
	printcli("   or: oem model <model>");
#ifdef AYLA_BC
	printcli("   or: oem host_version <version>");
#endif /* AYLA_BC */
	printcli("   or: oem key <key> [<model>]");
}
