/*
 * Copyright 2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_SCHED_H__
#define __AYLA_SCHED_H__

#define SCHED_NAME_LEN	28		/* max name length including NUL */
#define SCHED_TLV_LEN	255		/* max length of schedule value */

/*
 * Macro to make logging easier
 */
#define SCHED_LOGF(_level, _format, ...) \
	sched_log(_level "%s: " _format, __func__, ##__VA_ARGS__)

/*
 * Run through all schedules. Fire events as time progresses
 * to current utc time. Determine the next future event and
 * setup a timer to re-run at that time.
 */
void sched_run_all(void);

#ifdef SCHED_TEST
/*
 * Handle a set_prop action inside a schedule
 */
#define sched_log printf

int sched_prop_set(const char *name, const void *val_ptr,
		enum ayla_tlv_type type, u8 src);
#else
/*
 * Handle a schedule property from service using the module library.
 */
int sched_prop_set(const char *name, const void *val_ptr, size_t val_len);

/*
 * Logging for sched
 */
void sched_log(const char *fmt, ...);

#endif /* SCHED_TEST */

/*
 * Initialize schedules and allocate space.
 */
enum ada_err ada_sched_init(unsigned int count);

/*
 * Turn on schedule handling.
 */
enum ada_err ada_sched_enable(void);

/*
 * Set name of schedule.
 * The passed-in name is not referenced after this function returns.
 */
enum ada_err ada_sched_set_name(unsigned int index, const char *name);

/*
 * Get name and value for schedule.
 * Fills in the name pointer, the value to be persisted, and its length.
 */
enum ada_err ada_sched_get_index(unsigned int idx, char **name,
				void *tlvs, size_t *tlv_len);

/*
 * Set the value for a schedule by index.
 * This sets the value of the schedule, e.g., after reloaded from flash.
 */
enum ada_err ada_sched_set_index(unsigned int idx, const void *buf, size_t len);

/*
 * Set the value for a schedule by name.
 */
enum ada_err ada_sched_set(const char *name, const void *buf, size_t len);

/*
 * Persist schedule values as required.
 * Supplied by platform.
 * The schedule values can be fetched with ada_sched_get_index();
 */
void adap_sched_conf_persist(void);

/*
 * Save last run time to NVRAM.
 * Supplied by platform.
 * This allows the schedules to be more efficient if power has not been lost.
 * Use RAM if no NVRAM is provided.
 */
void adap_sched_run_time_write(u32);

/*
 * Read last run time for schedules from NVRAM.
 * Supplied by platform.
 * Use RAM if no NVRAM is provided.  Return 0 if the value hasn't been saved.
 */
u32 adap_sched_run_time_read(void);

/*
 * CLI Interfaced for sched
 */
void sched_cli(int argc, char **argv);

/*
 * Converts from network byte order to host byte order
 */
int sched_int_get(struct ayla_tlv *atlv, long *value);

/*
 * Reads the schedule action and fires it.
 */
void sched_set_prop(struct ayla_tlv *atlv, u8 tot_len);

#ifdef SERVER_DEV_PAGES
/*
 * Run through sched1 and generate a debug string to send to service.
 * See Google Doc on Schedule Property Testing.
 */
void sched_generate_debug(long start_time);

/*
 * Send the debug string to service.
 */
void sched_send_debug(void);

#endif /* SERVER_DEV_PAGES */

#endif /* __AYLA_SCHED_H__ */
