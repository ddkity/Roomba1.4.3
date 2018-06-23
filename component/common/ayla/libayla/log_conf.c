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

#include <ayla/utypes.h>
#include <ayla/endian.h>
#include <ayla/assert.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/tlv.h>

/*
 * Save and reload log masks in config log/mod/<n>/mask
 */

static void log_export(void)
{
	int i;

	conf_cd(CT_mod);
	for (i = LOG_MOD_DEFAULT; i < __MOD_LOG_LIMIT; i++) {
		conf_cd_table(i);
		conf_put_u32(CT_mask, log_mods[i].mask);
		conf_cd_parent();
	}
	conf_cd_parent();
	conf_cd(CT_client);
	conf_put_u32(CT_enable, log_client_conf_enabled);
}

/*
 * Handle incoming configuration change.
 * The path will be relative to CT_log.
 * token: array of configuration tokens (names, indices)
 * len: the number of configuration tokens (will be >= 1).
 * tlv: the value TLV.
 */
static enum conf_error log_set(int src, enum conf_token *token,
				size_t len, struct ayla_tlv *tlv)
{
	unsigned int i;
	enum conf_error error = CONF_ERR_NONE;

	switch (token[0]) {
	case CT_mod:
		if (conf_access(CONF_OP_SS_LOG | CONF_OP_WRITE | src)) {
			return CONF_ERR_PERM;
		}
		i = token[1];
		if (len < 3 || i >= __MOD_LOG_LIMIT) {
			error = CONF_ERR_PATH;
			break;
		}
		if (tlv->type != ATLV_UINT) {
			error = CONF_ERR_TYPE;
			break;
		}
		log_mods[i].mask = conf_get_u32(tlv);
		break;
	case CT_client:
		if (conf_access(CONF_OP_SS_LOG_ENA | CONF_OP_WRITE | src)) {
			return CONF_ERR_PERM;
		}
		if (len == 2 && token[1] == CT_enable) {
			log_client_conf_enabled = conf_get_bit(tlv);
		}
		break;
	default:
		error = CONF_ERR_PATH;
		break;
	}
	return error;
}

static enum conf_error log_get(int src, enum conf_token *token, size_t len)
{
	unsigned int i;
	enum conf_error error = CONF_ERR_NONE;

	switch (token[0]) {
	case CT_mod:
		if (conf_access(CONF_OP_SS_LOG | CONF_OP_READ | src)) {
			return CONF_ERR_PERM;
		}
		i = token[1];
		if (len < 3 || i >= __MOD_LOG_LIMIT) {
			error = CONF_ERR_PATH;
			break;
		}
		conf_resp_s32(log_mods[i].mask);
		break;
	case CT_client:
		if (conf_access(CONF_OP_SS_LOG_ENA | CONF_OP_READ | src)) {
			return CONF_ERR_PERM;
		}
		if (len == 2 && token[1] == CT_enable) {
			conf_resp_bool(log_client_conf_enabled);
		}
		break;
	default:
		error = CONF_ERR_PATH;
		break;
	}
	return error;
}

const struct conf_entry log_conf_entry = {
	.token = CT_log,
	.export = log_export,
	.set = log_set,
	.get = log_get,
};
