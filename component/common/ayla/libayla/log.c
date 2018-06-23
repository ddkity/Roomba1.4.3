/*
 * Copyright 2011-2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>	/* for snprintf */

#ifdef AMEBA
#define HAVE_UTYPES
#endif

#ifdef AYLA_FreeRTOS
#include <FreeRTOS.h>
#include <task.h>
#include <semphr.h>
#endif

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/log.h>
#include <ayla/timer.h>
#include <ayla/tty.h>
#include <ayla/clock.h>
#include <ayla/nameval.h>

/*
 * Optionally protect the log lines with locks if desired for debugging.
 * One thing to watch out for: fatal traps taken during logging could hang
 * trying to get this lock.  So, don't use for production yet.
 */
#ifdef LOG_LOCK
xSemaphoreHandle log_lock;	/* protects log_line and serializes log */
#endif /* LOG_LOCK */

enum log_mask log_mask_minimum;
static char log_line[LOG_LINE];
const char *log_prefix = "";
static u8 log_enabled = 1;
u8 log_client_conf_enabled = 1;

static int (*log_remote_print)(void *, const char *);
static void *log_remote_arg;

void print_remote_set(int (*print_func)(void *, const char *), void *arg)
{
	log_remote_print = print_func;
	log_remote_arg = arg;
}

const char log_sev_chars[] = LOG_SEV_CHARS;

static const char * const log_sevs[] = LOG_SEVS;

#ifdef AYLA_FreeRTOS		/* XXX move to OS abstraction layer */
#define LOG_THREAD_CT	16

static void *os_curthread(void)
{
	return xTaskGetCurrentTaskHandle();
}
#endif

#ifdef LOG_THREAD_CT
static struct name_val log_tasks[LOG_THREAD_CT + 1];	/* NULL-terminated */

/*
 * Set thread ID string which will be put in log lines for the current thread.
 * Keep it short.  Name string is not copied.
 */
void log_thread_id_set(const char *name)
{
	struct name_val *nv;
	int task_id;

	task_id = (int)os_curthread();

#ifdef LOG_LOCK
	xSemaphoreTake(log_lock, portMAX_DELAY);
#endif
	for (nv = log_tasks; nv < &log_tasks[ARRAY_LEN(log_tasks) - 1]; nv++) {
		if (!nv->name || nv->val == task_id) {
			nv->name = name;
			nv->val = task_id;
			break;
		}
	}
#ifdef LOG_LOCK
	xSemaphoreGive(log_lock);
#endif
	if (nv >= &log_tasks[ARRAY_LEN(log_tasks) - 1]) {
		log_err(LOG_MOD_DEFAULT, "log_tasks table is full");
	}
}

/*
 * Unset thread ID string
 */
void log_thread_id_unset(void)
{
	struct name_val *nv;
	int task_id;

	task_id = (int)os_curthread();

#ifdef LOG_LOCK
	xSemaphoreTake(log_lock, portMAX_DELAY);
#endif
	for (nv = log_tasks; nv < &log_tasks[ARRAY_LEN(log_tasks) - 1]; nv++) {
		if (!nv->name || nv->val == task_id) {
			break;
		}
	}
	for (; nv < &log_tasks[ARRAY_LEN(log_tasks) - 1]; nv++) {
		*nv = *(nv + 1);
		if (!nv->name) {
			break;
		}
	}
#ifdef LOG_LOCK
	xSemaphoreGive(log_lock);
#endif
}

static const char *log_thread_id(void)
{
	return lookup_by_val(log_tasks, (int)os_curthread());
}
#endif /* LOG_THREAD_CT */

/*
 * Return the string for a log level.  Used by log_client.
 */
const char *log_sev_get(enum log_sev sev)
{
	if (sev >= LOG_SEV_LIMIT) {
		return ".";
	}
	return log_sevs[sev];
}

/*
 * Check if a log mod & sev is enabled
 */
int log_mod_sev_is_enabled(u8 mod_nr, enum log_sev sev)
{
	u32 mask;

	mod_nr &= LOG_MOD_MASK;
	mask = mod_nr < LOG_MOD_CT ? log_mods[mod_nr].mask : ~0;
	return mask & ((u32)1 << sev);
}

/*
 * Put log message into log_line buffer.
 */
size_t log_put_va_sev(u8 mod_nr, enum log_sev sev,
	const char *fmt, ADA_VA_LIST args)
{
	size_t rlen;
	size_t len;
	size_t rc;
#if defined(AYLA_FreeRTOS) || defined(QCA4010_SDK)
	struct clock_time ct;
	char time_stamp[CLOCK_FMT_LEN];
	u32 rough_time;
	static u32 last_rough_time;
	u32 mtime;
	u32 msec = 0;
#endif
	const char *mod_name;
	char *body;
	char *msg;
#ifdef LOG_THREAD_CT
	const char *thread_id;
#endif

	if (*fmt == LOG_EXPECTED[0]) {
		fmt++;
	} else if (!log_mod_sev_is_enabled(mod_nr, sev)) {
		return 0;
	}
	rlen = sizeof(log_line) - 1;
	len = 0;
#if defined(AYLA_FreeRTOS) || defined(QCA4010_SDK)
	clock_get(&ct);
	msec = ct.ct_usec / 1000;
#endif
#if defined(AYLA_FreeRTOS)
	mtime = clock_ms();
#elif defined(QCA4010_SDK)
	mtime = time_now();
#endif
#ifdef LOG_LOCK
	xSemaphoreTake(log_lock, portMAX_DELAY);
#endif
	if (mod_nr != LOG_MOD_NONE) {
		len = snprintf(log_line, rlen, "%s", log_prefix);
	}
#if defined(AYLA_FreeRTOS) || defined(QCA4010_SDK)
	if (clock_source() > CS_DEF) {
		clock_fmt(time_stamp, sizeof(time_stamp), ct.ct_sec);

		/*
		 * Show full date once an hour or if full date
		 * hasn't been shown, otherwise just show hh:mm:ss + ms.
		 */
		rough_time = ct.ct_sec / (60 * 60);
		len += snprintf(log_line + len, rlen, "%s.%3.3lu ",
		    &time_stamp[rough_time == last_rough_time ?
		    CLOCK_FMT_TIME : 0],
		    msec);
		last_rough_time = rough_time;
	} else {
		len += snprintf(log_line + len, rlen, "%lu ", mtime);
	}
#endif
	if (sev != LOG_SEV_NONE) {
		len += snprintf(log_line + len, rlen - len,
#ifdef LOG_SEV_SHORT
		    "%c ",
		    log_sev_chars[sev]);
#else
		    "%s:  ",
		    log_sev_get(sev));
#endif /* LOG_SEV_SHORT */
	}

#ifdef LOG_THREAD /* add first letter of task name */
	{
		signed char task = pcTaskGetTaskName(NULL)[0];

		if (task != 't') {	/* omit tcpip_thread */
			len += snprintf(log_line + len, rlen - len, "(%c) ",
			    task);
		}
	}
#endif /* LOG_THREAD */

#ifdef LOG_THREAD_CT
	thread_id = log_thread_id();
	if (thread_id) {
		len += snprintf(log_line + len, rlen - len, "%s ", thread_id);
	}
#endif /* LOG_THREAD_CT */

	mod_name = log_mod_get_name(mod_nr);
	if (mod_name) {
		len += snprintf(log_line + len, rlen - len, "%s: ", mod_name);
	}
	body = log_line + len;
	len += vsnprintf(body, rlen - len, fmt, args);

#ifndef NO_LOG_BUF
	if (log_enabled && !(mod_nr & LOG_MOD_NOSEND)) {
		log_buf_put(mod_nr, sev, mtime, ct.ct_sec, msec, body,
		    len - (body - log_line));
	}
#endif /* NO_LOG_BUF */

	if (sev != LOG_SEV_NONE && log_line[len - 1] != '\n' && rlen > len) {
		log_line[len++] = '\n';
	}
	log_line[len] = '\0';
	msg = log_line;
	rc = len;
#ifdef LOG_SERIAL
	log_print(msg);
#endif
#ifdef LOG_LOCK
	xSemaphoreGive(log_lock);
#endif
	return rc;
}

/*
 * Put log message into log_line buffer.
 */
size_t log_put_va(u8 mod_nr, const char *fmt, ADA_VA_LIST args)
{
	u8 sev;

	sev = *(u8 *)fmt;		/* first char of fmt may be severity */
	if (sev >= LOG_BASE && sev < LOG_BASE + LOG_SEV_LIMIT) {
		fmt++;
		sev -= LOG_BASE;
	} else {
		sev = LOG_SEV_NONE;
	}
	return log_put_va_sev(mod_nr, sev, fmt, args);
}

/*
 * Put into log from LwIP thread.
 */
void log_put_raw(const char *fmt, ...)
{
	ADA_VA_LIST args;
	ADA_VA_START(args, fmt);
	log_put_va(LOG_MOD_DEFAULT, fmt, args);
	ADA_VA_END(args);
}

void log_put(const char *fmt, ...)
{
	ADA_VA_LIST args;
	ADA_VA_START(args, fmt);
	log_put_va(LOG_MOD_DEFAULT, fmt, args);
	ADA_VA_END(args);
}

void log_put_mod(u8 mod_nr, const char *fmt, ...)
{
	ADA_VA_LIST args;
	ADA_VA_START(args, fmt);
	log_put_va(mod_nr, fmt, args);
	ADA_VA_END(args);
}

void log_put_mod_sev(u8 mod_nr, enum log_sev sev, const char *fmt, ...)
{
	ADA_VA_LIST args;
	ADA_VA_START(args, fmt);
	log_put_va_sev(mod_nr, sev, fmt, args);
	ADA_VA_END(args);
}

void log_mask_init(enum log_mask mask)
{
	log_mask_change(NULL, mask, 0);
}

void log_mask_init_min(enum log_mask mask, enum log_mask min_mask)
{
	log_mask_minimum = min_mask;
	log_mask_init(mask);
}

void log_init(void)
{
#ifdef LOG_LOCK
	vSemaphoreCreateBinary(log_lock);
#endif
}

/*
 * Enabling/disabling inserting log messages into buffer
 */
int log_enable(int enable)
{
	int old_val = log_enabled;

	log_enabled = enable;
	return old_val;
}

/*
 * Print out bytes as hex
 */
void log_bytes_in_hex(u8 mod_nr, void *buf, int len)
{
	char tmpbuf[48 + 12 + 1]; /* 16 * 3 + 12 */
	int i, j, off;

	for (i = 0; i < len; ) {
		off = 0;
		for (j = 0; j < 16 && i < len; j++) {
			off += snprintf(tmpbuf + off,
			    sizeof(tmpbuf) - off, "%2.2x ",
			    ((u8 *)buf)[i]);
			if ((j + 1) % 4 == 0) {
				off += snprintf(tmpbuf + off,
				    sizeof(tmpbuf) - off, " ");
			}
			i++;
		}
		log_put_mod_sev(mod_nr, LOG_SEV_DEBUG, tmpbuf);
	}
}

int printcli(const char *fmt, ...)
{
	ADA_VA_LIST args;
	char buf[512];
	size_t len;

	ADA_VA_START(args, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, args);
	ADA_VA_END(args);

	if (buf[len - 1] != '\n' && len < sizeof(buf)) {
		buf[len++] = '\n';
	}
	if (len == sizeof(buf)) {
		len--;
	}
	buf[len++] = '\0';
	if (log_remote_print) {
		log_remote_print(log_remote_arg, buf);
	} else {
		print(buf);
	}
	return len;
}

int printcli_s(const char *fmt, ...)
{
	ADA_VA_LIST args;
	char buf[512];
	size_t len;

	ADA_VA_START(args, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, args);
	ADA_VA_END(args);

	if (len == sizeof(buf)) {
		len--;
	}
	buf[len++] = '\0';
	if (log_remote_print) {
		log_remote_print(log_remote_arg, buf);
	} else {
		print(buf);
	}
	return len;
}
