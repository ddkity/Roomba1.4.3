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
#include <ayla/tlv.h>
#include <ayla/clock.h>
#include <ayla/log.h>
#include <ayla/timer.h>

#include <ada/err.h>
#include <ada/prop.h>
#include <ada/prop_mgr.h>
#include <ada/sprop.h>
#include <ada/client.h>
#include <net/net.h>
#include <ayla/malloc.h>
#include "client_lock.h"
#include "client_timer.h"

#include "ilifesweeper.h"

extern unsigned char  PropertySendDoneFlag[43];

struct ada_sprop_entry {
	char name[SPROP_NAME_MAX_LEN];
	struct ada_sprop *table;
	unsigned int entries;
};

static struct ada_sprop_entry ada_sprop_table[SPROP_TABLE_ENTRIES];
static struct prop_mgr ada_sprop_mgr;

u8 ada_sprop_dest_mask;

static enum ada_err sprop_send_opt(struct ada_sprop *, int echo);

static u32 ada_sprop_echos_pending;
static struct net_callback ada_sprop_ready_callback;

static struct ada_sprop *ada_sprop_lookup(const char *name)
{
	struct ada_sprop *sprop;
	int i;
	int j;

	for (i = 0; i < SPROP_TABLE_ENTRIES; i++) {
		for (j = 0; j < ada_sprop_table[i].entries; j++) {
			sprop = &ada_sprop_table[i].table[j];
			if (!strcmp(name, sprop->name)) {
				return sprop;
			}
		}
	}
	return NULL;
}

static enum ada_err ada_sprop_mgr_set(const char *name,
	enum ayla_tlv_type type, const void *val, size_t len,
	size_t *offset, u8 src, void *cb_arg)
{
	struct ada_sprop *sprop;
	enum ada_err err;

	sprop = ada_sprop_lookup(name);
	if (!sprop) {
		return AE_NOT_FOUND;
	}
	if (!sprop->set) {
		return AE_RDONLY;
	}
	err = sprop->set(sprop, val, len);
	if (!err && src == NODES_SCHED) {
		sprop_send_opt(sprop, 1);	/* echo to cloud and LAN */
	} else if (!err && !(ada_sprop_dest_mask & NODES_ADS)) {
		/* ADS is down, remember to echo when ADS is back up */
		sprop->send_req = 1;
	}
	return err;
}

static void ada_sprop_prop_free(struct prop *prop)
{
	free(prop);
}

static enum ada_err ada_sprop_mgr_get(const char *name,
	enum ada_err (*get_cb)(struct prop *, void *arg, enum ada_err),
	void *arg)
{
	struct prop *prop;
	struct ada_sprop *sprop;
	int ret;
	void *buf;
	size_t buf_len;

	sprop = ada_sprop_lookup(name);
	if (!sprop) {
		return AE_NOT_FOUND;
	}
	buf_len = sprop->val_len + sizeof(u32);
	prop = malloc(sizeof(*prop) + buf_len);
	if (!prop) {
		return -AE_ALLOC;
	}
	memset(prop, 0, sizeof(*prop));
	buf = prop + 1;

	prop->name = sprop->name;
	prop->type = sprop->type;
	prop->val = buf;
	prop->prop_mgr_done = ada_sprop_prop_free;

	ret = sprop->get(sprop, buf, buf_len);
	if (ret < 0) {
		free(prop);
		return ret;
	}
	prop->len = ret;

	ret = get_cb(prop, arg, AE_OK);
	if (ret != AE_IN_PROGRESS) {
		free(prop);
	}
	return ret;
}

/*
 * Send any pending echos if possible.
 * Return 0 if no echos are pending.
 * Currently only queues one per call.
 * More will be sent when that one finishes.
 */
static int ada_sprop_send_echo(void)
{
	struct ada_sprop *sprop;
	enum ada_err err;
	int i;
	int j;

	/*
	 * Send any required echos before enabling listen.
	 */
	for (i = 0; i < SPROP_TABLE_ENTRIES; i++) {
		for (j = 0; j < ada_sprop_table[i].entries; j++) {
			sprop = &ada_sprop_table[i].table[j];
			if (sprop->send_req) {
				sprop->send_req = 0;
				err = ada_sprop_send(sprop);
				if (err && err != AE_IN_PROGRESS) {
					sprop->send_req = 1;
					break;
				}
				break;
			}
		}
	}
	return ada_sprop_echos_pending != 0;
}

/*
 * Call prop_mgr_ready.
 * This must be done in a callback to avoid recursively locking the client lock.
 */
static void ada_sprop_ready_cb(void *arg)
{
	if (!ada_sprop_echos_pending && (ada_sprop_dest_mask & NODES_ADS)) {
		client_unlock();
		ada_prop_mgr_ready(&ada_sprop_mgr);	/* gets client_lock */
		client_lock();
	}
}

void PropertySendDoneFlagCnt(const char *name)
{ 
	//vTaskSuspendAll();
	if(strcmp(name, "f_battery") == 0){
		PropertySendDoneFlag[PP_f_battery] = PropertySendDoneFlag[PP_f_battery] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_work_mode") == 0){
		PropertySendDoneFlag[PP_t_work_mode] = PropertySendDoneFlag[PP_t_work_mode] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_error") == 0){
		PropertySendDoneFlag[PP_f_error] = PropertySendDoneFlag[PP_f_error] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_d_strength") == 0){
		PropertySendDoneFlag[PP_t_d_strength] = PropertySendDoneFlag[PP_t_d_strength] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_p_strength") == 0){
		PropertySendDoneFlag[PP_t_p_strength] = PropertySendDoneFlag[PP_t_p_strength] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_clean_record") == 0){
		PropertySendDoneFlag[PP_f_clean_record] = PropertySendDoneFlag[PP_f_clean_record] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_upload_realmap_starttime") == 0){
		PropertySendDoneFlag[PP_f_upload_realmap_starttime] = PropertySendDoneFlag[PP_f_upload_realmap_starttime] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_realtime_mapinfo") == 0){
		PropertySendDoneFlag[PP_f_realtime_mapinfo] = PropertySendDoneFlag[PP_f_realtime_mapinfo] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_factory_reset") == 0){
		PropertySendDoneFlag[PP_t_factory_reset] = PropertySendDoneFlag[PP_t_factory_reset] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_edge_brush_lifetime") == 0){
		PropertySendDoneFlag[PP_f_edge_brush_lifetime] = PropertySendDoneFlag[PP_f_edge_brush_lifetime] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_roll_brush_lifetime") == 0){
		PropertySendDoneFlag[PP_f_roll_brush_lifetime] = PropertySendDoneFlag[PP_f_roll_brush_lifetime] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_filter_lifetime") == 0){
		PropertySendDoneFlag[PP_f_filter_lifetime] = PropertySendDoneFlag[PP_f_filter_lifetime] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_duster_lifetime") == 0){
		PropertySendDoneFlag[PP_f_duster_lifetime] = PropertySendDoneFlag[PP_f_duster_lifetime] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_battery_lifetime") == 0){
		PropertySendDoneFlag[PP_f_battery_lifetime] = PropertySendDoneFlag[PP_f_battery_lifetime] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_0") == 0){
		PropertySendDoneFlag[PP_t_timer_0] = PropertySendDoneFlag[PP_t_timer_0] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_1") == 0){
		PropertySendDoneFlag[PP_t_timer_1] = PropertySendDoneFlag[PP_t_timer_1] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_2") == 0){
		PropertySendDoneFlag[PP_t_timer_2] = PropertySendDoneFlag[PP_t_timer_2] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_3") == 0){
		PropertySendDoneFlag[PP_t_timer_3] = PropertySendDoneFlag[PP_t_timer_3] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_4") == 0){
		PropertySendDoneFlag[PP_t_timer_4] = PropertySendDoneFlag[PP_t_timer_4] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_5") == 0){
		PropertySendDoneFlag[PP_t_timer_5] = PropertySendDoneFlag[PP_t_timer_5] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_6") == 0){
		PropertySendDoneFlag[PP_t_timer_6] = PropertySendDoneFlag[PP_t_timer_6] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_7") == 0){
		PropertySendDoneFlag[PP_t_timer_7] = PropertySendDoneFlag[PP_t_timer_7] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_8") == 0){
		PropertySendDoneFlag[PP_t_timer_8] = PropertySendDoneFlag[PP_t_timer_8] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_timer_9") == 0){
		PropertySendDoneFlag[PP_t_timer_9] = PropertySendDoneFlag[PP_t_timer_9] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_control") == 0){
		PropertySendDoneFlag[PP_t_control] = PropertySendDoneFlag[PP_t_control] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_search") == 0){
		PropertySendDoneFlag[PP_t_search] = PropertySendDoneFlag[PP_t_search] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_realtime_info") == 0){
		PropertySendDoneFlag[PP_t_realtime_info] = PropertySendDoneFlag[PP_t_realtime_info] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "oem_host_version") == 0){
		PropertySendDoneFlag[PP_oem_host_version] = PropertySendDoneFlag[PP_oem_host_version] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "version") == 0){
		PropertySendDoneFlag[PP_version] = PropertySendDoneFlag[PP_version] - 1;
		goto PROPOUT;
	}
//////////////////////////////////////////////////////////////////////////////////
	if(strcmp(name, "t_room_mode") == 0){
		PropertySendDoneFlag[PP_t_room_mode] = PropertySendDoneFlag[PP_t_room_mode] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_sound") == 0){
		PropertySendDoneFlag[PP_t_sound] = PropertySendDoneFlag[PP_t_sound] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_light") == 0){
		PropertySendDoneFlag[PP_t_light] = PropertySendDoneFlag[PP_t_light] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_work_time") == 0){
		PropertySendDoneFlag[PP_f_work_time] = PropertySendDoneFlag[PP_f_work_time] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_water_box_time") == 0){
		PropertySendDoneFlag[PP_f_water_box_time] = PropertySendDoneFlag[PP_f_water_box_time] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_dustbin_time") == 0){
		PropertySendDoneFlag[PP_f_dustbin_time] = PropertySendDoneFlag[PP_f_dustbin_time] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_mul_box_time") == 0){
		PropertySendDoneFlag[PP_f_mul_box_time] = PropertySendDoneFlag[PP_f_mul_box_time] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_upload_realmap_switch") == 0){
		PropertySendDoneFlag[PP_f_upload_realmap_switch] = PropertySendDoneFlag[PP_f_upload_realmap_switch] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_reset_edge_brush") == 0){
		PropertySendDoneFlag[PP_t_reset_edge_brush] = PropertySendDoneFlag[PP_t_reset_edge_brush] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_reset_roll_brush") == 0){
		PropertySendDoneFlag[PP_t_reset_roll_brush] = PropertySendDoneFlag[PP_t_reset_roll_brush] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_reset_filter") == 0){
		PropertySendDoneFlag[PP_t_reset_filter] = PropertySendDoneFlag[PP_t_reset_filter] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_reset_duster") == 0){
		PropertySendDoneFlag[PP_t_reset_duster] = PropertySendDoneFlag[PP_t_reset_duster] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "t_reset_power") == 0){
		PropertySendDoneFlag[PP_t_reset_power] = PropertySendDoneFlag[PP_t_reset_power] - 1;
		goto PROPOUT;
	}
	if(strcmp(name, "f_clean_mode") == 0){
		PropertySendDoneFlag[PP_f_clean_mode] = PropertySendDoneFlag[PP_f_clean_mode] - 1;
		goto PROPOUT;
	}

PROPOUT:
	//xTaskResumeAll();
	//client_log(LOG_DEBUG "%s: sent \"%s\"", __func__, name);
        return;
}
static void ada_sprop_mgr_send_done(enum prop_cb_status status,
	u8 fail_mask, void *cb_arg)
{
	struct prop *prop = cb_arg;
	struct ada_sprop *sprop;
	u8 dests = ada_sprop_dest_mask;

	if (status != PROP_CB_DONE) {
		client_log(LOG_ERR "%s: send of \"%s\" failed. "
		   "status %d mask %x",
		    __func__, prop->name, status, fail_mask);

		/*
		 * If we were echoing and have lost connectivity with ADS,
		 * re-pend the echo.  Otherwise, just let it fail.
		 */
		if (prop->echo && (fail_mask & NODES_ADS) &&
		    (status == PROP_CB_CONN_ERR ||
		    status == PROP_CB_CONN_ERR2)) {
			sprop = ada_sprop_lookup(prop->name);
			if (sprop) {
				sprop->send_req = 1;
			}
			dests &= ~fail_mask;
		}
	} else {
		PropertySendDoneFlagCnt(prop->name);
		client_log(LOG_DEBUG "%s: sent \"%s\"", __func__, prop->name);
	}

	if (prop->echo && ada_sprop_echos_pending) {

		/*
		 * If there are more echos to send, send them, otherwise
		 * declare sprop ready so listen is enabled.
		 */
		ada_sprop_echos_pending--;
		if ((dests & NODES_ADS) && !ada_sprop_send_echo()) {
			client_callback_pend(&ada_sprop_ready_callback);
		}
	}

	free(prop);
}

static void ada_sprop_mgr_connect_sts(u8 mask)
{
	ada_sprop_dest_mask = mask;
	if ((mask & NODES_ADS) && !ada_sprop_send_echo()) {
		ada_prop_mgr_ready(&ada_sprop_mgr);
	}
}

static void ada_sprop_mgr_event(enum prop_mgr_event event, const void *arg)
{
	struct ada_sprop *sprop;

	switch (event) {
	case PME_ECHO_FAIL:
		client_log(LOG_WARN "Failed echoing %s to ADS\n", (char *)arg);
		sprop = ada_sprop_lookup((const char *)arg);
		if (!sprop) {
			return;
		}
		sprop->send_req = 1;
		break;
	#if 1		//add by YUJUNWU default 0
	case PME_TIME:
		// add by huangjituan
		if(0 == g_TimezoneChange){
			g_TimezoneChange = 1;
			client_log(LOG_INFO " g_TimezoneChange set to 1.Time zone is update\n\n");
		}
		client_log(LOG_INFO "time is update, tell MCU\n\n");
		break;
	#endif
	
	default:
		break;
	}
}

static struct prop_mgr ada_sprop_mgr = {
	.name = "sprop",
	.prop_recv = ada_sprop_mgr_set,
	.get_val = ada_sprop_mgr_get,
	.send_done = ada_sprop_mgr_send_done,
	.connect_status = ada_sprop_mgr_connect_sts,
	.event = ada_sprop_mgr_event,
};

/*
 * Get an ATLV_INT or ATLV_CENTS type property from the
 * sprop structure.
 */
ssize_t ada_sprop_get_int(struct ada_sprop *sprop, void *buf, size_t len)
{
	if (!sprop || !buf) {
		return AE_ERR;
	}
	if (sprop->type != ATLV_INT && sprop->type != ATLV_CENTS) {
		return AE_INVAL_TYPE;
	}
	if (len < sizeof(s32)) {
		return AE_LEN;
	}

	switch (sprop->val_len) {
	case 1:
		*(s32 *)buf = *(s8 *)sprop->val;
		break;
	case 2:
		*(s32 *)buf = *(s16 *)sprop->val;
		break;
	case 4:
		*(s32 *)buf = *(s32 *)sprop->val;
		break;
	default:
		return AE_ERR;
	}

	return sizeof(s32);
}

/*
 * Get an ATLV_UINT type property from the sprop structure.
 */
ssize_t ada_sprop_get_uint(struct ada_sprop *sprop, void *buf, size_t len)
{
	if (!sprop || !buf) {
		return AE_ERR;
	}
	if (sprop->type != ATLV_UINT) {
		return AE_INVAL_TYPE;
	}
	if (len < sizeof(u32)) {
		return AE_LEN;
	}

	switch (sprop->val_len) {
	case 1:
		*(u32 *)buf = *(u8 *)sprop->val;
		break;
	case 2:
		*(u32 *)buf = *(u16 *)sprop->val;
		break;
	case 4:
		*(u32 *)buf = *(u32 *)sprop->val;
		break;
	default:
		return AE_ERR;
	}

	return sizeof(u32);
}


/*
 * Get an ATLV_BOOL type property from the sprop structure.
 */
ssize_t ada_sprop_get_bool(struct ada_sprop *sprop, void *buf, size_t len)
{
	if (!sprop || !buf) {
		return AE_ERR;
	}
	if (sprop->type != ATLV_BOOL) {
		return AE_INVAL_TYPE;
	}
	if (len < sizeof(u8)) {
		return AE_LEN;
	}

	*(u8 *)buf = (*(u8 *)sprop->val != 0);
	return sizeof(u8);
}

/*
 * Get an ATLV_UTF8 type property from the sprop structure.
 */
ssize_t ada_sprop_get_string(struct ada_sprop *sprop, void *buf, size_t len)
{
	size_t val_len;

	if (!sprop) {
		return AE_ERR;
	}

	if (sprop->type != ATLV_UTF8) {
		return AE_INVAL_TYPE;
	}

	val_len = strlen(sprop->val);
	if (val_len + 1 > len) {
		return AE_LEN;
	}
	memcpy(buf, sprop->val, val_len + 1);	/* copy includes NUL term */
	return val_len;
}

/*
 * Set an ATLV_INT or ATLV_CENTS property value to the
 * value in *buf.
 */
enum ada_err ada_sprop_set_int(struct ada_sprop *sprop,
				const void *buf, size_t len)
{
	s32 val;

	if (!sprop || !buf) {
		return AE_ERR;
	}
	if (len != sizeof(s32)) {
		return AE_LEN;
	}
	if (sprop->type != ATLV_INT && sprop->type != ATLV_CENTS) {
		return AE_INVAL_TYPE;
	}

	val = *(s32 *)buf;

	switch (sprop->val_len) {
	case 1:
		if (val < MIN_S8 || val > MAX_S8) {
			return AE_INVAL_VAL;
		}
		*(s8 *)sprop->val = val;
		break;
	case 2:
		if (val < MIN_S16 || val > MAX_S16) {
			return AE_INVAL_VAL;
		}
		*(s16 *)sprop->val = val;
		break;
	case 4:
		*(s32 *)sprop->val = *(s32 *)buf;
		break;
	default:
		return AE_LEN;
	}
	return AE_OK;
}

/*
 * Set an ATLV_UINT property value to the value in *buf.
 */
enum ada_err ada_sprop_set_uint(struct ada_sprop *sprop,
				const void *buf, size_t len)
{
	u32 val;

	if (!sprop || !buf) {
		return AE_ERR;
	}
	if (sprop->type != ATLV_UINT) {
		return AE_INVAL_TYPE;
	}
	if (len != sizeof(u32)) {
		return AE_LEN;
	}
	val = *(u32 *)buf;

	switch (len) {
	case 1:
		if (val > MAX_U8) {
			return AE_INVAL_VAL;
		}
		*(u8 *)sprop->val = val;
		break;
	case 2:
		if (val > MAX_U16) {
			return AE_INVAL_VAL;
		}
		*(u16 *)sprop->val = val;
		break;
	case 4:
		*(u32 *)sprop->val = val;
		break;
	default:
		return AE_LEN;
	}
	return AE_OK;
}


/*
 * Set an ATLV_BOOL property value to the value in *buf.
 */
enum ada_err ada_sprop_set_bool(struct ada_sprop *sprop,
				const void *buf, size_t len)
{
	u32 val;

	if (!sprop || !buf) {
		return AE_ERR;
	}
	if (sprop->type != ATLV_BOOL) {
		return AE_INVAL_TYPE;
	}
	if (len != sizeof(u32)) {
		return AE_LEN;
	}
	val = *(u32 *)buf;
	if (val > 1) {
		return AE_INVAL_VAL;
	}
	if (sprop->val_len != sizeof(u8)) {
		return AE_LEN;
	}
	*(u8 *)sprop->val = val;
	return AE_OK;
}

/*
 * Set an ATLV_UTF8 property value to the value in *buf.
 */
enum ada_err ada_sprop_set_string(struct ada_sprop *sprop,
				const void *buf, size_t len)
{
	size_t val_len;

	if (!sprop || !buf) {
		return AE_ERR;
	}
	if (sprop->type != ATLV_UTF8) {
		return AE_INVAL_TYPE;
	}
	val_len = strnlen(buf, len);
	if (val_len + 1 > sprop->val_len || val_len > TLV_MAX_STR_LEN) {
		return AE_LEN;
	}
	memcpy(sprop->val, buf, val_len);
	((char *)sprop->val)[val_len] = '\0';
	return AE_OK;
}

/*
 * Send property update, possibly for echo.
 */
static enum ada_err sprop_send_opt(struct ada_sprop *sprop, int echo)
{
	struct prop *prop;
	size_t len;
	ssize_t ret;
	u8 dest = ada_sprop_dest_mask;

	if (!sprop) {
		return AE_INVAL_STATE;
	}

	/*
	 * Properties with a set handler should be to-device properties.
	 * Set the echo flag for them.
	 */
	if (sprop->set) {
		echo = 1;
	}

	/*
	 * If sending an echo to ADS, but ADS is not connected, set the
	 * send_req flag.  We'll send the echo when we connect, and not
	 * queue the current value.
	 */
	if (echo && !(dest & NODES_ADS)) {
		sprop->send_req = 1;

		if (!dest) {
			return AE_IN_PROGRESS;
		}
	}
	dest |= NODES_ADS;

	len = sprop->val_len + sizeof(u32);
	prop = malloc(sizeof(*prop) + len);
	if (!prop) {
		return AE_ALLOC;
	}
	memset(prop, 0, sizeof(*prop));
	prop->name = sprop->name;
	prop->type = sprop->type;
	prop->val = prop + 1;
	prop->echo = echo;
	prop->prop_mgr_done = ada_sprop_prop_free;

	ret = sprop->get(sprop, prop->val, len);
	if (ret < 0) {
		free(prop);
		return ret;
	}
	ASSERT(ret <= len);
	prop->len = ret;

	ret = ada_prop_mgr_send(&ada_sprop_mgr, prop, dest, prop);
	if (!ret || ret == AE_IN_PROGRESS) {
		if (echo) {
			ada_sprop_echos_pending++;
		}
		ret = 0;
	} else {
		free(prop);
	}
	return ret;
}

enum ada_err ada_sprop_send(struct ada_sprop *sprop)
{
	return sprop_send_opt(sprop, 0);
}

enum ada_err ada_sprop_send_by_name(const char *name)
{
	struct ada_sprop *sprop;

	sprop = ada_sprop_lookup(name);
	if (!sprop) {
		return AE_NOT_FOUND;
	}
	return ada_sprop_send(sprop);
}

/*
 * Register a table of properties to the sprop prop_mgr.
 */
enum ada_err ada_sprop_mgr_register(char *name, struct ada_sprop *table,
		unsigned int entries)
{
	static int i;

	if (!name || !table) {
		return AE_ERR;
	}

	if (i >= SPROP_TABLE_ENTRIES) {
		client_log(LOG_ERR "sprop table limit reached");
		return AE_ERR;
	}

	if (i == 0) {
		net_callback_init(&ada_sprop_ready_callback,
		    ada_sprop_ready_cb, NULL);
		ada_prop_mgr_register(&ada_sprop_mgr);
	}

	strncpy(ada_sprop_table[i].name, name, SPROP_NAME_MAX_LEN);
	ada_sprop_table[i].table = table;
	ada_sprop_table[i].entries = entries;
	i++;

	return AE_OK;
}
