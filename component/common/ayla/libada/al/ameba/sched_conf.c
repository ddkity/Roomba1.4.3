/*
 * Copyright 2013-2016 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 *
 * Schedule configuration.
 */
#include <stdio.h>
#include <stdlib.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/tlv.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/endian.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <ayla/bb_ops.h>
#include <ayla/clock.h>
#include <ada/err.h>
#include <ada/prop.h>
#include <ada/ada_conf.h>
#include <ayla/malloc.h>
#include <ada/sched.h>
#include <ada/prop_mgr.h>

static enum conf_error
sched_conf_get(int src, enum conf_token *token, size_t len)
{
	char *name;
	u8 sched[SCHED_TLV_LEN];
	size_t sched_len;
	enum ada_err err;

	if (token[0] != CT_n || len != 3) {
		return CONF_ERR_PATH;
	}

	sched_len = sizeof(sched);
	err = ada_sched_get_index(token[1], &name, sched, &sched_len);
	if (err) {
		if (err == AE_NOT_FOUND || !name || name[0] == '\0') {
			return CONF_ERR_PATH;
		}
		return CONF_ERR_LEN;
	}

	if (token[2] == CT_prop) {
		conf_resp_str(name);
	} else if (token[2] == CT_value) {
		conf_resp(ATLV_SCHED, sched, sched_len);
	} else {
		return CONF_ERR_PATH;
	}

	return CONF_ERR_NONE;
}

static enum conf_error sched_conf_set(int src, enum conf_token *token,
				    size_t len, struct ayla_tlv *tlv)
{
	char name[SCHED_NAME_LEN];
	u8 sched[SCHED_TLV_LEN];
	size_t sched_len;
	enum ada_err err;
	unsigned int index;

	if (token[0] != CT_n || len != 3) {
		return CONF_ERR_PATH;
	}
	index = token[1];
	if (token[2] == CT_prop) {
		name[0] = '\0';
		name[sizeof(name) - 1] = '\0';
		conf_get(tlv, ATLV_UTF8, name, sizeof(name) - 1);
		err = ada_sched_set_name(index, name);
	} else if (token[2] == CT_value) {
		sched_len = conf_get(tlv, ATLV_SCHED, sched, sizeof(sched));
		err = ada_sched_set_index(index, sched, sched_len);
	} else {
		return CONF_ERR_PATH;
	}

	if (err) {
		if (err == AE_NOT_FOUND) {
			return CONF_ERR_PATH;
		}
		return CONF_ERR_LEN;
	}
	return CONF_ERR_NONE;
}

/*
 * Save the schedule info to flash. All names and values.
 */
static void sched_conf_save(void *arg)
{
	char *name;
	u8 sched[SCHED_TLV_LEN];
	size_t sched_len;
	enum ada_err err;
	int i;

	conf_cd(CT_n);
	for (i = 0; ; i++) {
		sched_len = sizeof(sched);
		err = ada_sched_get_index(i, &name, sched, &sched_len);
		if (err == AE_INVAL_STATE) {
			break;		/* past the max index */
		}
		if (err || !name || name[0] == '\0') {
			conf_delete(i);
			continue;
		}
		conf_cd_table(i);
		conf_put_str(CT_prop, name);
		conf_put(CT_value, ATLV_SCHED, sched, sched_len);
		conf_cd_parent();
	}
}

static void sched_conf_export(void)
{
	sched_conf_save(NULL);
}

static void sched_conf_commit(int from_ui)
{
	ada_sched_enable();
}

const struct conf_entry sched_conf_entry = {
	.token = CT_sched,
	.get = sched_conf_get,
	.set = sched_conf_set,
	.commit = sched_conf_commit,
	.export = sched_conf_export,
};

/*
 * Persist schedule values as required.
 */
void adap_sched_conf_persist(void)
{
	conf_persist(CT_sched, sched_conf_save, NULL);
}
