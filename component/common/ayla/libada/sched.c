/*
 * Copyright 2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 *
 * Schedule analyzer and interpreter. Can be converted into a
 * user program by defining SCHED_TEST and using the makefile
 * in ayla_lib dir/test/sched_usrprog.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/tlv.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/endian.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <ayla/clock.h>
#include <ayla/timer.h>
#include <ada/err.h>
#include <ada/prop.h>
#include <ada/ada_conf.h>
#include <ayla/malloc.h>
#include <ada/sched.h>
#include <ada/prop_mgr.h>
#include "client_timer.h"
#include "client_lock.h"
#include "schedeval.h"

#ifndef SCHED_TEST
/*
 * Action to be performed after all schedules evaluated up to the current time.
 * This element is used only during the call to sched_evaluate.
 */
struct sched_action {
	struct ayla_tlv *atlv;		/* TLV containing prop and value */
};

/*
 * State for schedule subsystem.
 */
struct sched_state {
	struct sched_prop *mod_scheds;
	u32 nsched;          /* length of mod_scheds array */
	struct sched_action *actions;
	u32 action_table_ct; /* number of actions in table */
	u32 action_pend_ct;  /* number of actions pending */
	u32 action_en_ct;    /* number of actions in enabled schedules */
	u32 run_time;	     /* virtual run time */
	u32 next_event_time; /* time of next scheduled event */
	u8 next_fire_sched;  /* index of schedule we expect to fire */
	u8 save_needed:1;    /* persist schedule values */
	u8 enabled:1;
	struct timer timer;
};

static struct sched_state sched_state;

static void sched_timeout(struct timer *);

/*
 * Logging for sched
 */
void sched_log(const char *fmt, ...)
{
	ADA_VA_LIST args;

	ADA_VA_START(args, fmt);
	log_put_va(MOD_LOG_SCHED, fmt, args);
	ADA_VA_END(args);
}

static struct sched_prop *sched_prop_by_index(unsigned int index)
{
	struct sched_state *st = &sched_state;

	if (index < st->nsched) {
		return &st->mod_scheds[index];
	}
	return NULL;
}

static struct sched_prop *sched_prop_lookup(const char *name)
{
	struct sched_state *st = &sched_state;
	struct sched_prop *sched;
	int i;

	sched = st->mod_scheds;
	if (!sched) {
		return NULL;
	}
	for (i = 0; i < st->nsched; i++, sched++) {
		if (!strcmp(name, sched->name)) {
			return sched;
		}
	}
	return NULL;
}

/*
 * Count the number of actions in a schedule.
 */
static u32 sched_action_count(struct sched_prop *sched)
{
	struct ayla_tlv *tlv = (struct ayla_tlv *)sched->tlvs;
	size_t len = sched->len;
	int count = 0;

	while (len) {
		if (len < sizeof(*tlv) || len < sizeof(*tlv) + tlv->len) {
			return count;
		}
		switch (tlv->type) {
		case ATLV_SETPROP:
			count++;
			break;
		case ATLV_DISABLE:
			count = 0;
			break;
		default:
			break;
		}
		len -= sizeof(*tlv) + tlv->len;
		tlv = (struct ayla_tlv *)((char *)(tlv + 1) + tlv->len);
	}
	return count;
}

/*
 * Reset all pending actions.
 */
static void sched_actions_reset(struct sched_state *st)
{
	struct sched_action *new;

	st->action_pend_ct = 0;
	if (st->action_table_ct < st->action_en_ct) {
		new = malloc(sizeof(*new) * st->action_en_ct);
		if (!new) {
			SCHED_LOGF(LOG_ERR, "%s: alloc failed");
			return;
		}
		free(st->actions);
		st->actions = new;
		st->action_table_ct = st->action_en_ct;
	}
	if (st->actions) {
		memset(st->actions, 0,
		    sizeof(*st->actions) * st->action_table_ct);
	}
}

/*
 * Pend an action.
 * If already pending, move it to the end, so the actions are chronological.
 */
void sched_action_pend(struct ayla_tlv *atlv)
{
	struct sched_state *st = &sched_state;
	int i;

	sched_log(LOG_DEBUG "sched action pend %p", atlv);
	for (i = 0; i < st->action_pend_ct; i++) {
		if (st->actions[i].atlv == atlv) {
			memcpy(&st->actions[i], &st->actions[i + 1],
			    (st->action_pend_ct - (i + 1)) *
			    sizeof(*st->actions));
			i = st->action_pend_ct - 1;
			break;
		}
	}
	if (i < st->action_table_ct) {
		st->actions[i].atlv = atlv;
		st->action_pend_ct = i + 1;
	}
}

/*
 * Act on all pending actions and then clear them.
 */
static void sched_actions_run(struct sched_state *st)
{
	struct ayla_tlv *atlv;
	int i;

	for (i = 0; i < st->action_pend_ct; i++) {
		atlv = st->actions[i].atlv;
		sched_log(LOG_DEBUG "sched action fire %p", atlv);
		sched_set_prop(atlv + 1, atlv->len);
	}
	st->action_pend_ct = 0;
}

/*
 * Set schedule from configuration.
 */
static enum ada_err sched_set(struct sched_prop *sched,
				const void *tlvs, size_t len)
{
	struct sched_state *st = &sched_state;
	u32 actions;

	if (len > sizeof(sched->tlvs)) {
		return AE_LEN;
	}

	actions = sched_action_count(sched);
	ASSERT(actions <= st->action_en_ct);
	st->action_en_ct -= actions;

	memcpy(sched->tlvs, tlvs, len);
	sched->len = len;

	actions = sched_action_count(sched);
	st->action_en_ct += actions;
	return 0;
}

/*
 * Handle a schedule property from service using the module library.
 */
static enum ada_err sched_prop_set_int(const char *name, const void *val_ptr,
				size_t val_len)
{
	struct sched_prop *sched;

	sched = sched_prop_lookup(name);
	if (!sched) {
		return AE_NOT_FOUND;
	}
	return sched_set(sched, val_ptr, val_len);
}

/*
 * Handle a schedule property from service using the module library.
 */
int sched_prop_set(const char *name, const void *val_ptr, size_t val_len)
{
	if (sched_prop_set_int(name, val_ptr, val_len)) {
		return -1;
	}
	return 0;
}

/*
 * Set a timeout to re-evaluate all schedules after one is set
 * or after a possible time change.
 */
static void sched_time_update(void)
{
	struct sched_state *st = &sched_state;

	client_timer_set(&st->timer, 0);
}

static enum ada_err sched_prop_recv(const char *name, enum ayla_tlv_type type,
			const void *val, size_t val_len, size_t *off,
			u8 src, void *req_arg)
{
	struct sched_state *state = &sched_state;
	enum ada_err err;

	err = sched_prop_set_int(name, val, val_len);
	if (err) {
		return err;
	}
	state->save_needed = 1;
	sched_time_update();
	return AE_OK;
}

static void sched_prop_send_done(enum prop_cb_status status,
			u8 fail_mask, void *req_arg)
{
}

static enum ada_err sched_prop_get_val(const char *name,
		enum ada_err (*send_cb)(struct prop *, void *arg, enum ada_err),
		void *arg)
{
	if (!sched_prop_lookup(name)) {
		return AE_NOT_FOUND;
	}
	return AE_INVAL_VAL;
}

static void sched_prop_event(enum prop_mgr_event event, const void *arg)
{
	if (event == PME_TIME) {
		sched_time_update();
	}
}

static const struct prop_mgr sched_prop_mgr = {
	.name = "sched",
	.prop_recv = sched_prop_recv,
	.send_done = sched_prop_send_done,
	.get_val = sched_prop_get_val,
	.event = sched_prop_event,
};

enum ada_err ada_sched_enable(void)
{
	struct sched_state *st = &sched_state;

	if (!st->enabled) {
		st->enabled = 1;
		ada_prop_mgr_register(&sched_prop_mgr);
		ada_prop_mgr_ready(&sched_prop_mgr);
		sched_log(LOG_DEBUG "schedules enabled. count %u", st->nsched);
		client_lock();
		sched_time_update();
		client_unlock();
	}
	return 0;
}

/*
 * Initialize and allocate storage for schedules.
 */
enum ada_err ada_sched_init(unsigned int count)
{
	struct sched_state *st = &sched_state;

	if (st->mod_scheds) {
		return AE_BUSY;
	}
	st->mod_scheds = calloc(count, sizeof(*st->mod_scheds));
	if (!st->mod_scheds) {
		return AE_ALLOC;
	}
	st->nsched = count;
	timer_init(&st->timer, sched_timeout);
	return 0;
}

/*
 * Set name for schedule.
 * The passed-in name is not referenced after this function returns.
 */
enum ada_err ada_sched_set_name(unsigned int index, const char *name)
{
	struct sched_state *st = &sched_state;
	struct sched_prop *sched;

	if (index >= st->nsched) {
		return AE_INVAL_STATE;
	}
	sched = &st->mod_scheds[index];
	strncpy(sched->name, name, sizeof(sched->name) - 1);
	return 0;
}

/*
 * Get name and value for schedule.
 * Fills in the name pointer, the value to be persisted, and its length.
 */
enum ada_err ada_sched_get_index(unsigned int index, char **name,
				void *tlvs, size_t *lenp)
{
	struct sched_state *st = &sched_state;
	struct sched_prop *sched;

	if (index >= st->nsched) {
		return AE_INVAL_STATE;
	}
	sched = &st->mod_scheds[index];
	*name = sched->name;
	if (*lenp < sched->len) {
		return AE_LEN;
	}
	memcpy(tlvs, sched->tlvs, sched->len);
	*lenp = sched->len;
	return 0;
}

/*
 * Set the value for a schedule by index.
 * This sets the value of the schedule, e.g., after reloaded from flash.
 */
enum ada_err ada_sched_set_index(unsigned int index,
				const void *tlvs, size_t len)
{
	struct sched_state *st = &sched_state;
	struct sched_prop *sched;

	if (index >= st->nsched) {
		return AE_NOT_FOUND;
	}
	sched = &st->mod_scheds[index];
	return sched_set(sched, tlvs, len);
}

enum ada_err ada_sched_set(const char *name, const void *tlvs, size_t len)
{
	struct sched_prop *sched;

	sched = sched_prop_lookup(name);
	if (!sched) {
		return AE_NOT_FOUND;
	}
	return sched_set(sched, tlvs, len);
}
#endif /* SCHED_TEST */

/*
 * Converts from network byte order to host byte order
 */
int sched_int_get(struct ayla_tlv *atlv, long *value)
{
#ifndef SCHED_TEST
	return get_ua_with_len(atlv + 1, atlv->len, (u32 *)value);
#else
	switch (atlv->len) {
	case 1:
		*value = *(u8 *)(atlv + 1);
		break;
	case 2:
		*value = get_ua_be16(atlv + 1);
		break;
	case 4:
		*value = get_ua_be32(atlv + 1);
		break;
	default:
		SCHED_LOGF(LOG_WARN, "len/val err");
		return -1;
	}
	return 0;
#endif
}

/*
 * Reads the schedule action and fires it.
 */
void sched_set_prop(struct ayla_tlv *atlv, u8 tot_len)
{
	struct prop_recvd recvd;
	struct ayla_tlv *prop;
	enum ayla_tlv_type type;
	long val;
	int cur_len;

	memset(&recvd, 0, sizeof(recvd));
	prop = (struct ayla_tlv *)(atlv);
	if (prop->type != ATLV_NAME) {
		SCHED_LOGF(LOG_WARN, "missing name");
		return;
	}
	if (prop->len >= sizeof(recvd.name)) {
		SCHED_LOGF(LOG_WARN, "invalid prop name");
		return;
	}
	memcpy(recvd.name, prop + 1, prop->len);
	recvd.name[prop->len] = '\0';
	cur_len = prop->len;

	prop = (struct ayla_tlv *)((u8 *)prop + prop->len +
	    sizeof(struct ayla_tlv));
	type = prop->type;

	if (cur_len + prop->len != tot_len - 2 * sizeof(struct ayla_tlv) ||
	    sched_int_get(prop, &val)) {
		SCHED_LOGF(LOG_WARN, "len/val err");
		return;
	}
#ifdef SCHED_TEST
	sched_prop_set(recvd.name, &val, type, 1);
#else
	ada_prop_mgr_set(recvd.name, type, &val, sizeof(val),
	    &recvd.offset, NODES_SCHED, NULL);
#endif

	/*
	 * Perhaps this function should echo the datapoint to ADS and LAN.
	 * For now, we rely on each property manager to perform the echo.
	 */
}

#ifndef SCHED_TEST

static void sched_show_all(void)
{
	struct sched_state *st = &sched_state;
	int i;

	printcli("schedules %sabled", st->nsched ? "en" : "dis");
	for (i = 0; i < st->nsched; i++) {
		printcli("%d : %s", i,
		    st->mod_scheds[i].name);
	}
}

/*
 * CLI Interfaced for sched
 */
void sched_cli(int argc, char **argv)
{
	struct sched_prop *sched;
	unsigned long i;
	char *n;
	char *errptr;

	if (argc == 1) {
		sched_show_all();
		return;
	}
	if (!mfg_or_setup_mode_ok()) {
		return;
	}
	if (argc != 4) {
		goto usage;
	}
	argv++;
	n = *argv++;
	argc -= 2;
	i = strtoul(n, &errptr, 10);
	if (*errptr != '\0') {
		printcli("bad sched # \"%s\"", n);
		return;
	}
	sched = sched_prop_by_index(i);
	if (!sched) {
		printcli("bad sched # \"%s\"", n);
		return;
	}
	if (strcmp(*argv++, "name")) {
		goto usage;
	}
	if (!prop_name_valid(*argv)) {
		printcli("bad sched name");
		return;
	}
	strncpy(sched->name, *argv, sizeof(sched->name) - 1);
	return;

usage:
	printcli("usage:");
	printcli("sched <schedule #> name <schedule name>");
}

/*
 * A scheduled event is due to fire.
 */
static void sched_timeout(struct timer *arg)
{
	struct sched_state *state = &sched_state;

	if (state->save_needed) {
		state->save_needed = 0;
		adap_sched_conf_persist();	/* persist all changes */
	}
	sched_state.run_time = sched_state.next_event_time;
	sched_run_all();
}

/*
 * Run through all schedules. Fire events as time progresses
 * to current utc time. Determine the next future event and
 * setup a timer to re-run at that time.
 */
void sched_run_all(void)
{
	struct sched_state *st = &sched_state;
	u32 utc_time = clock_utc();
	u32 next_event;
	u32 earliest_event = MAX_U32;
	u32 bb_run_time = adap_sched_run_time_read();
	u8 start;
	int i;

	/* Determine if time has been set. If not, then don't run schedules */
	client_timer_cancel(&st->timer);
	if (!st->enabled || !st->mod_scheds || clock_source() <= CS_DEF) {
		return;
	}
	sched_actions_reset(st);
	if (!bb_run_time || bb_run_time > utc_time ||
	    bb_run_time < CLOCK_START) {
		/* the stored bb_run_time can't be trusted */
		/* start from the current utc time */
		bb_run_time = utc_time;
		sched_state.next_fire_sched = 0;
	}
	sched_state.run_time = bb_run_time;
	if (sched_state.next_fire_sched >= st->nsched) {
		sched_state.next_fire_sched = 0;
	}
run_schedules:
	start = sched_state.next_fire_sched;
	i = start;
	do {
		ASSERT(i < st->nsched);
		if (sched_state.mod_scheds[i].name[0] == '\0' ||
		    !sched_state.mod_scheds[i].len) {
			goto move_on;
		}
		SCHED_LOGF(LOG_DEBUG2, "looking at sched %s",
		    sched_state.mod_scheds[i].name);
		next_event = sched_evaluate(&sched_state.mod_scheds[i],
		    sched_state.run_time);
		SCHED_LOGF(LOG_DEBUG2, "next event %lu", next_event);
		if (!next_event || next_event == MAX_U32) {
			/* no more events to fire for this schedule */
			goto move_on;
		}
		if (next_event < earliest_event) {
			sched_state.next_fire_sched = i;
			earliest_event = next_event;
		}
move_on:
		i++;
		if (i >= st->nsched) {
			i = 0;
		}
	} while (i != start);

	SCHED_LOGF(LOG_DEBUG2, "earliest event %lu", earliest_event);
	if (!earliest_event || earliest_event == MAX_U32) {
		/* no events left for any of the schedules */
		goto finish;
	}

	if (earliest_event <= utc_time) {
		sched_state.run_time = earliest_event;
		earliest_event = MAX_U32;
		goto run_schedules;
	}

	sched_state.next_event_time = earliest_event;
	sched_state.run_time = utc_time + 1;

	SCHED_LOGF(LOG_DEBUG, "scheduling timeout for %lu",
	    earliest_event - utc_time);
	client_timer_set(&st->timer, (earliest_event - utc_time) * 1000);

finish:
	adap_sched_run_time_write(sched_state.run_time);
	sched_actions_run(st);
}

#endif
