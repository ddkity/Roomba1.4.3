/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/timer.h>
#include <ayla/tlv.h>
#include <ayla/clock.h>
#include <ayla/conf.h>
#include <ayla/crc.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/http.h>
#include <ayla/hw_sig.h>

#include <net/base64.h>
#include <net/stream.h>
#include <ada/ada_conf.h>
#include <ada/ada_lan_conf.h>
#include <net/http_client.h>
#include <ada/client.h>

u8 conf_id_set;
static u8 client_conf_reset_at_commit;

static u8 ada_pub_key_buf[400];		/* actually public key in base-64 */
static struct mem_file *client_conf_curr_file;

struct mem_file ada_pub_key_file = {
	.buf = ada_pub_key_buf,
	.max_len = sizeof(ada_pub_key_buf),
};

char conf_sys_hw_id[32];

static const struct ada_conf_item client_conf_items[] = {
	{ ADA_PSM_ID_PUB_KEY, ATLV_UTF8, ada_pub_key_buf,
	    sizeof(ada_pub_key_buf)},
	{ NULL }
};

int adap_conf_pub_key_get(void *buf, size_t len)
{
	struct mem_file *key_file = &ada_pub_key_file;
	size_t outlen = len;

	if (net_base64_decode(key_file->buf, key_file->len, buf, &outlen)) {
		client_log(LOG_ERR "pub_key decode failed");
		return -1;
	}
	return (int)outlen;
}

const char *client_conf_pub_key_base64(void)
{
	struct mem_file *key_file = &ada_pub_key_file;

	return key_file->buf;
}

void client_conf_pub_key_set(struct ayla_tlv *tlv)
{
	struct mem_file *file = &ada_pub_key_file;

	file->len = conf_get(tlv, ATLV_FILE, file->buf, file->max_len);
}

/*
 * Conf load functions used to load initial values from flash
 * for platforms not supporting entry->get()
 */
void client_conf_load(void)
{
	struct mem_file *file = &ada_pub_key_file;
	const struct ada_conf_item *item;

	for (item = client_conf_items; item->name; item++) {
		ada_conf_get_item(item);
	}
	file->len = strlen((char *)ada_pub_key_buf);
}

void client_conf_factory_reset(void)
{
	const struct ada_conf_item *item;

	for (item = client_conf_items; item->name; item++) {
		adap_conf_reset_factory(item->name);
	}
}

/*
 * Save the LANIP information
 */
static void client_conf_lanip_config_save(void *arg)
{
	struct ada_lan_conf *lcf = &ada_lan_conf;

	conf_cd(CT_lan);
	conf_put_u32(CT_enable, lcf->enable);
	if (lcf->enable) {
		conf_put_str(CT_private_key, lcf->lanip_key);
		conf_put_u32(CT_key, lcf->lanip_key_id);
		conf_put_u32(CT_poll_interval, lcf->keep_alive);
		conf_put_u32(CT_auto, lcf->auto_echo);
	}
	conf_cd_parent();
}

void ada_conf_lanip_save(void)
{
	conf_persist(CT_client, client_conf_lanip_config_save, NULL);
}

static void client_conf_reg_save(void *arg)
{
	struct ada_conf *cf = &ada_conf;

	conf_cd(CT_reg);
	conf_put_u32_nz(CT_ready, cf->reg_user);
	conf_cd_parent();
}

void client_conf_reg_persist(void)
{
	conf_persist(CT_client, client_conf_reg_save, NULL);
}

/*
 * Export config for writing config file.
 */
static void client_conf_export(void)
{
	struct ada_conf *cf = &ada_conf;
#ifndef WMSDK
	const char *pub_key;
#endif

	client_conf_lanip_config_save(NULL);
	conf_cd(CT_server);
	conf_put_u32(CT_default, cf->conf_serv_override);
	conf_put_str(CT_region, cf->region ? cf->region : "");
	conf_cd_parent();
	conf_put_u32(CT_enable, cf->enable);
	conf_put_u32(CT_poll_interval, cf->poll_interval);
	if (client_conf_server_change_en()) {
		conf_put_str(CT_hostname, cf->conf_server);
		conf_put_u32(CT_port, cf->conf_port);
	}

#ifndef WMSDK
	conf_cd(CT_gif);
	pub_key = client_conf_pub_key_base64();
	conf_put(0, ATLV_FILE, pub_key, strlen(pub_key));
	conf_cd_parent();
#endif
	client_conf_reg_save(NULL);
}

/*
 * Get configuration item.
 */
static enum conf_error client_conf_get(int src,
					enum conf_token *token, size_t len)
{
	struct ada_conf *cf = &ada_conf;
	struct ada_lan_conf *lcf = &ada_lan_conf;
	int op;

	if (len && token[0] == CT_enable) {
		op = CONF_OP_SS_CLIENT_ENA;
	} else {
		op = CONF_OP_SS_CLIENT;
	}
	if (conf_access(op | CONF_OP_READ | src)) {
		return CONF_ERR_PERM;
	}
	if (len == 2 && token[0] == CT_ssl && token[1] == CT_enable) {
		conf_resp_bool(1);	/* for compatibility, always 1 */
		return CONF_ERR_NONE;
	}
	if (len == 2 && token[0] == CT_server) {
		switch (token[1]) {
		case CT_default:
			conf_resp_bool(cf->conf_serv_override);
			break;
		case CT_region:
			if (!cf->region) {
				conf_resp_str("");
			} else {
				conf_resp_str(cf->region);
			}
			break;
		default:
			goto err;
		}
		return CONF_ERR_NONE;
	}
	if (len == 2 && token[0] == CT_lan) {
		switch (token[1]) {
		case CT_enable:
			conf_resp_bool(lcf->enable);
			break;
		case CT_key:
			conf_resp_u32(lcf->lanip_key_id);
			break;
		case CT_poll_interval:
			conf_resp_u32(lcf->keep_alive);
			break;
		case CT_auto:
			conf_resp_u32(lcf->auto_echo);
			break;
		default:
			goto err;
		}
		return CONF_ERR_NONE;
	}
	if (len == 2 && token[0] == CT_reg && token[1] == CT_ready) {
		conf_resp_bool(cf->reg_user);
		return CONF_ERR_NONE;
	}
	if (len != 1) {
		goto err;
	}
	switch (token[0]) {
	case CT_enable:
		conf_resp_bool(cf->enable);
		break;
	case CT_poll_interval:
		conf_resp_s32(cf->poll_interval);
		break;
	case CT_hostname:
		if (!client_conf_server_change_en()) {
			goto err;
		}
		conf_resp_str(cf->conf_server);
		break;
	case CT_port:
		if (!client_conf_server_change_en()) {
			goto err;
		}
		conf_resp_u32(cf->conf_port);
		break;
	case CT_reg:
		conf_resp_str(cf->reg_token);
		break;
	default:
		goto err;
	}
	return CONF_ERR_NONE;

err:
	return CONF_ERR_PATH;
}

/*
 * Set configuration item.
 */
static enum conf_error client_conf_set(int src, enum conf_token *token,
					size_t len, struct ayla_tlv *tlv)
{
	struct ada_conf *cf = &ada_conf;
	struct ada_lan_conf *lcf = &ada_lan_conf;
	int op;
	u8 lanip_key[CLIENT_LANIP_KEY_SIZE + 1];
	char region_code[CLIENT_CONF_REGION_CODE_LEN + 1];
	s32 val;
	size_t val_len;

	if (token[0] == CT_enable) {
		op = CONF_OP_SS_CLIENT_ENA;
	} else if (token[0] == CT_reg) {
		op = CONF_OP_SS_CLIENT_REG;
	} else {
		op = CONF_OP_SS_CLIENT;
	}
	if (conf_access(op | CONF_OP_WRITE | src)) {
		return CONF_ERR_PERM;
	}

	if (len == 2 && token[0] == CT_gif && token[1] == 0) {
		client_conf_pub_key_set(tlv);
		return CONF_ERR_NONE;
	}
	if (len == 2 && token[0] == CT_ssl && token[1] == CT_enable) {
		/* for compatibility, ignore setting */
		return CONF_ERR_NONE;
	}
	if (len == 2 && token[0] == CT_server) {
		switch (token[1]) {
		case CT_default:
			if (src != CONF_OP_SRC_FILE &&
			    conf_get_bit(tlv) != cf->conf_serv_override) {
				lcf->lanip_key[0] = '\0';
			}
			cf->conf_serv_override = conf_get_bit(tlv);
			client_conf_reset_at_commit = 1;
			break;
		case CT_region:
			val_len = conf_get(tlv, ATLV_UTF8, region_code,
				sizeof(region_code) - 1);
			ASSERT(val_len < sizeof(region_code));
			region_code[val_len] = '\0';
			if (client_set_region(region_code)) {
				return CONF_ERR_RANGE;
			}
			client_conf_reset_at_commit = 1;
			break;
		default:
			goto err;
		}
		return CONF_ERR_NONE;
	}
	if (len == 2 && token[0] == CT_lan) {
		switch (token[1]) {
		case CT_enable:
			lcf->enable = conf_get_bit(tlv);
			return CONF_ERR_NONE;
		case CT_private_key:
			conf_get(tlv, ATLV_UTF8, lanip_key,
			    sizeof(lanip_key));
			snprintf(lcf->lanip_key, sizeof(lcf->lanip_key), "%s",
			    lanip_key);
			return CONF_ERR_NONE;
		case CT_key:
			lcf->lanip_key_id = conf_get_u32(tlv);
			return CONF_ERR_NONE;
		case CT_poll_interval:
			lcf->keep_alive = conf_get_u32(tlv);
			return CONF_ERR_NONE;
		case CT_auto:
			lcf->auto_echo = conf_get_u32(tlv);
			return CONF_ERR_NONE;
		default:
			goto err;
		}
	}
	if (len == 2 && token[0] == CT_user) {
		switch (token[1]) {
		case CT_reg:		/* accept for compatibility */
			return CONF_ERR_NONE;
		default:
			goto err;
		}
	}
	if (len == 2 && token[0] == CT_reg) {
		switch (token[1]) {
		case CT_start:
			if (conf_get_bit(tlv)) {
				cf->reg_token[0] = '\0';
				client_conf_reset_at_commit = 1;
			}
			break;
		case CT_interval:
			if (conf_get_bit(tlv)) {
				client_reg_window_start();
			}
			break;
		case CT_ready:
			cf->reg_user = conf_get_bit(tlv);
			break;
		default:
			goto err;
		}
		return CONF_ERR_NONE;
	}
	if (len != 1) {
		goto err;
	}
	switch (token[0]) {
	case CT_enable:
		cf->enable = conf_get_bit(tlv);
		break;
	case CT_poll_interval:
		val = conf_get_int32(tlv);
		if (val < 0 || val > 65535) {
			return CONF_ERR_RANGE;
		}
		cf->poll_interval = val;
		break;
	case CT_hostname:
		if (!client_conf_server_change_en()) {
			return CONF_ERR_PATH;
		}
		if (src != CONF_OP_SRC_FILE) {
			lcf->lanip_key[0] = '\0';
		}
		conf_get(tlv, ATLV_UTF8,
		    cf->conf_server, sizeof(cf->conf_server) - 1);
		break;
	case CT_port:
		if (!client_conf_server_change_en()) {
			return CONF_ERR_PATH;
		}
		cf->conf_port = conf_get_u16(tlv);
		break;
	default:
		goto err;
	}
	client_conf_reset_at_commit = 1;
	return CONF_ERR_NONE;

err:
	return CONF_ERR_PATH;
}

/*
 * Finish config changes - restart connection.
 */
static void client_conf_commit(int from_ui)
{
#ifdef AYLA_BC	/* platform code should do these */
	struct ada_conf *cf = &ada_conf;

	cf->get_all = gpio_mode;
	cf->mac_addr = conf_sys_mac_addr;
	cf->hw_id = conf_sys_hw_id;
	if (!conf_sys_hw_id[0]) {
		hw_sig_str(conf_sys_hw_id, sizeof(conf_sys_hw_id));
	}
#endif /* AYLA_BC */

	/*
	 * Don't reset link if only simple config changes were made.
	 */
	if (!client_conf_reset_at_commit) {
		return;
	}
	client_conf_reset_at_commit = 0;
	client_commit();
}

const struct conf_entry client_conf_entry = {
	.token = CT_client,
	.export = client_conf_export,
	.set = client_conf_set,
	.get = client_conf_get,
	.commit = client_conf_commit,
};

/*
 * "id" command.
 */
void ada_conf_id_cli(int argc, char **argv)
{
	enum conf_token tk[2];
	int rc;
	struct {
		struct ayla_tlv tlv;
		union {
			u8 str[64];	/* smaller max enforced by conf */
			u8 mac[6];
		};
	} buf;

	if (!mfg_mode_ok()) {
		return;
	}

	tk[1] = CT_INVALID_TOKEN;
	if (argc > 1) {
		tk[1] = conf_token_parse(argv[1]);
#ifndef CONF_NO_ID_FILE
		if (argc == 2 && tk[1] == CT_reset) {
			conf_id_reset();
			return;
		}
#endif /* CONF_NO_ID_FILE */
	}

	if (argc != 3) {
		printcli("usage: id <name> <value>");
		printcli("supported names are:  "
		    "dev_id, "
#ifdef AYLA_BC
		    "serial, model, "
#endif /* AYLA_BC */
		    "mfg_model, mfg_serial");
		return;
	}
#ifdef AYLA_BC
	if (!conf_mfg_test_time) {
		printcli("no record of mfg tests passing");
		return;
	}
#endif /* AYLA_BC */

	switch (tk[1]) {
#ifdef AYLA_BC
	case CT_serial:
	case CT_model:
#endif /* AYLA_BC */
	case CT_mfg_model:
	case CT_mfg_serial:
	case CT_dev_id:
		rc = strlen(argv[2]);
		if (rc == 0 || rc > sizeof(buf.str) - 1) {
			printcli("invalid value");
			return;
		}
		buf.tlv.type = ATLV_UTF8;
		buf.tlv.len = rc;
		memcpy(buf.str, argv[2], rc + 1);
		break;
#ifdef MAC_ADDR_SET_BY_HOST
	case CT_mac_addr:
		rc = parse_mac(buf.mac, argv[2]);
		if (rc < 0 || (buf.mac[0] & 1)) {
			printcli("invalid valid");
			return;
		}
		buf.tlv.len = sizeof(buf.mac);
		buf.tlv.type = ATLV_BIN;
		break;
#endif /* MAC_ADDR_SET_BY_HOST */
	default:
		printcli("setting %s not supported", argv[1]);
		return;
	}

	tk[0] = CT_sys;
	rc = conf_cli_set_tlv(tk, 2, &buf.tlv);
	if (rc == CONF_ERR_PERM) {
		printcli("id: conf not permitted");
		return;
	}
	if (rc == CONF_ERR_RANGE) {
		printcli("id: invalid value");
		return;
	}
	if (rc != CONF_ERR_NONE) {
		printcli("id: conf err %d", rc);
		return;
	}
	conf_id_set = 1;
	/* separate commit not necessary  */
	/* save/reset if service needs to restart */
}

/*
 * Set current file.
 */
static struct mem_file *ada_conf_file_set_curr(const char *name)
{
	struct mem_file *file;
	unsigned long val;
	char *errptr;

	val = strtoul(name, &errptr, 10);
	if (*errptr != '\0') {
invalid:
		printcli("invalid file number");
		return NULL;
	}
	switch (val) {
	case 0:
		file = &ada_pub_key_file;
		client_conf_curr_file = file;
		break;
	default:
		goto invalid;
	}
	return file;
}

/*
 * file loader.
 * Syntax:
 *	file start <file-number>
 *	file add <data>
 *	file crc <file-number>
 */
void ada_conf_file_cli(int argc, char **argv)
{
	struct mem_file *file = client_conf_curr_file;

	if (!mfg_mode_ok()) {
		return;
	}
	if (argc != 3) {
		printcli("usage: file <cmd> <arg>");
		return;
	}
	if (!strcmp(argv[1], "start")) {
		file = ada_conf_file_set_curr(argv[2]);
		if (file) {
			file->len = 0;
		}
	} else if (!strcmp(argv[1], "add") && file) {
		file->len += snprintf((char *)file->buf + file->len,
		    file->max_len - file->len, "%s", argv[2]);
	} else if (!strcmp(argv[1], "crc")) {
		file = ada_conf_file_set_curr(argv[2]);
		if (!file) {
			return;
		}
		printcli("file %d len %d crc %lx",
		    0, file->len, crc32(file->buf, file->len, CRC32_INIT));
	} else {
		printcli("setting %s not supported", argv[1]);
	}
}

/*
 * CLI command to reset the module, optionally to the factory configuration.
 */
void ada_conf_reset_cli(int argc, char **argv)
{
	if (argc == 1) {
		ada_conf_reset(0);
		return;		/* not reached */
	}
	if (argc == 2) {
		if (!strcmp(argv[1], "factory")) {
			ada_conf_reset(1);
			return;		/* not reached */
		}
	}
	printcli("usage: reset [factory]\n");
}
