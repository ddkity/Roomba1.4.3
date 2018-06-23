/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */

#ifndef __AYLA_LOG_H__
#define __AYLA_LOG_H__

#include <stdarg.h>
#include <stddef.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>

#define LOG_SERIAL			/* define to do printfs to serial */

#define	LOG_SIZE	2048
#define LOG_LINE	200		/* size of log_line buf */

/*
 * Log message severity prefix.
 */
#define LOG_INFO	"\x81"
#define LOG_WARN	"\x82"
#define LOG_ERR		"\x83"
#define LOG_DEBUG	"\x84"
#define LOG_FAIL	"\x85"
#define LOG_PASS	"\x86"
#define LOG_METRIC	"\x87"
#define LOG_DEBUG2	"\x89"
#define LOG_BASE	0x80	/* delta from log prefix to log_sev */

/*
 * Character that can appear after the severity to indicate mandatory logging
 * of messages that are expected by testing scripts.
 */
#define LOG_EXPECTED	"\xf0"	/* log this message regardless of masks */

extern u8 log_client_conf_enabled;

enum log_sev {
	LOG_SEV_NONE = 0,
	LOG_SEV_INFO = 1,
	LOG_SEV_WARN = 2,
	LOG_SEV_ERR = 3,
	LOG_SEV_DEBUG = 4,
	LOG_SEV_FAIL = 5,
	LOG_SEV_PASS = 6,
	LOG_SEV_METRIC = 7,
				/* 8 was nosend - reserved */
	LOG_SEV_DEBUG2 = 9,
	LOG_SEV_LIMIT		/* limit, must be last */
};

/*
 * Name table initializers for log severities.
 */
#define LOG_SEVS {				\
		[LOG_SEV_NONE] = "none",	\
		[LOG_SEV_FAIL] = "FAIL",	\
		[LOG_SEV_PASS] = "pass",	\
		[LOG_SEV_INFO] = "info",	\
		[LOG_SEV_DEBUG] = "debug",	\
		[LOG_SEV_DEBUG2] = "debug2",	\
		[LOG_SEV_WARN] = "warning",	\
		[LOG_SEV_ERR] = "error",	\
		[LOG_SEV_METRIC] = "metric",	\
	}

/*
 * Name table initializer for single-character version of log severity.
 */
#define LOG_SEV_CHARS {				\
		[LOG_SEV_NONE] = ' ',		\
		[LOG_SEV_FAIL] = 'F',		\
		[LOG_SEV_PASS] = 'P',		\
		[LOG_SEV_INFO] = 'i',		\
		[LOG_SEV_DEBUG] = 'd',		\
		[LOG_SEV_DEBUG2] = 'd',		\
		[LOG_SEV_WARN] = 'W',		\
		[LOG_SEV_ERR] = 'E',		\
		[LOG_SEV_METRIC] = 'm',		\
	}

PREPACKED_ENUM enum log_mask {
	LOG_DEFAULT = (BIT(LOG_SEV_NONE) |
		BIT(LOG_SEV_ERR) | BIT(LOG_SEV_WARN)),
	LOG_MAX = BIT(LOG_SEV_LIMIT) - 1
} PACKED_ENUM;
ASSERT_SIZE(enum, log_mask, 2);

PREPACKED_ENUM enum log_mod_id {
	LOG_MOD_NONE = 0,	/* log module name & time not desired */
	LOG_MOD_DEFAULT = 1,	/* default application subsystem */
	LOG_MOD_APP_BASE = 2,	/* first app-specific subsystem */
	LOG_MOD_APP_MAX = 14,	/* maximum app-specific subsystem */
	LOG_MOD_CT		/* must be last - number of subsystems */
} PACKED_ENUM;
ASSERT_SIZE(enum, log_mod_id, 1);

#define LOG_MOD_MASK	0x3f	/* mask for module number */
#define LOG_MOD_NOSEND	0x80	/* flag bit: do not send to logging service */

struct log_mod {
	enum log_mask mask;
};

/*
 * Log buffer header before each message.
 * The maximum message is 255 bytes long.  Longer messages may be split or
 * truncated.
 */
struct log_msg_head {
	u8 magic;	/* magic number of v2 log buffer */
	u8 len;		/* length of the message body in bytes */
	u8 mod_nr;	/* index + 1 of module that emitted this message */
	u8 sev;		/* severity */
	u8 resvd[1];
	u16 msec;
	u32 time;	/* unix time of the log message (for the log service) */
	u32 mtime;	/* module monotonic time */
};

#define LOG_V2_MAGIC	0xf5	/* magic "length" to distinguish v2 from v1 */

struct log_msg_tail {
	u8 len;		/* length of the message body in bytes */
};

/*
 * Log interfaces.
 */
void log_init(void);		/* initialize logging - required with an OS */
void log_put(const char *fmt, ...) ADA_ATTRIB_FORMAT(1, 2);
void log_put_raw(const char *fmt, ...) ADA_ATTRIB_FORMAT(1, 2);
size_t log_put_va(u8 mod_nr, const char *fmt, va_list);
size_t log_put_va_sev(u8 mod_nr, enum log_sev sev,
				const char *fmt, ADA_VA_LIST args);
void log_put_mod_sev(u8 mod_nr, enum log_sev sev, const char *fmt, ...)
				ADA_ATTRIB_FORMAT(3, 4);
const char *log_sev_get(enum log_sev);
void log_setup_udp(void);

struct log_mod *log_mod_get(u8 mod_nr);		/* lookup module by mod_nr */
const char *log_mod_get_name(u8 mod_nr);	/* lookup name by mod_nr */

extern const char log_sev_chars[];

/*
 * Setup default log masks for all subsystems.
 */
void log_mask_init(enum log_mask mask);
void log_mask_init_min(enum log_mask mask, enum log_mask mask_min);
int log_mask_change(const char *mod, enum log_mask on_mask,
			enum log_mask off_mask);
int ada_log_mask_change(unsigned int mod_nr, enum log_mask on_mask,
			enum log_mask off_mask);

/*
 * Disable/Enable inserting log messages into buffer
 */
int log_enable(int);

/*
 * Add message to log buffer.
 */
void log_buf_put(u8 mod_nr, enum log_sev, u32 mtime,
		u32 time, u32 msec, const char *buf, size_t);

/*
 * Copy messages from log buffer.
 * Messages will have log_msg_head structure before each one.
 */
size_t log_buf_get(unsigned long snapshot,
		unsigned int line_limit, void *buf, size_t len,
		u8 for_service);

/*
 * Check if there are more messages to be sent to the service.
 */
int log_buf_more_to_service(void);

/*
 * Wipe out rest of the messages queued to service.
 */
void log_buf_reset(void);

/*
 * We've finished sending out the log of serv_out.
 * Update log_but.serv_out to the new value.
 */
void log_buf_incr_serv_out(void);

/*
 * Save log to non-volatile storage if possible.
 */
void log_save(void);

/*
 * Check if a log mod & sev is enabled
 */
int log_mod_sev_is_enabled(u8 mod_nr, enum log_sev sev);

/*
 * Get info on log snapshots.
 */
struct log_snap {
	u32 time;
	u32 size;
};
int log_snap_stat(struct log_snap *buf, unsigned int count);
int log_snap_erase(void);
int log_snap_count(size_t *space_left);
void log_snap_status(void);
void log_snap_show(unsigned long snapshot, int time_only);
void log_snap_cmd(int argc, char **argv);

extern u8 log_snap_saved;	/* cached result from log_snap_count */

/*
 * Log info/debug messages.  These automatically append newlines.
 */
void log_put_mod(u8 mod, const char *fmt, ...)
		 ADA_ATTRIB_FORMAT(2, 3);

#define log_info(...)	log_put_mod(LOG_MOD_DEFAULT, LOG_INFO __VA_ARGS__)
#define log_err(mod_nr, ...)	log_put_mod(mod_nr, LOG_ERR __VA_ARGS__)
#define log_warn(mod_nr, ...)	log_put_mod(mod_nr, LOG_WARN __VA_ARGS__)
#define log_debug(mod_nr, ...)	log_put_mod(mod_nr, LOG_DEBUG __VA_ARGS__)

/*
 * Change global log settings from CLI.
 */
void ada_log_cli(int argc, char **argv);
extern const char ada_log_cli_help[];

/*
 * Logging for various purposes in test programs.
 */
void test_pass(const char *fmt, ...) ADA_ATTRIB_FORMAT(1, 2);
void test_fail(const char *fmt, ...) ADA_ATTRIB_FORMAT(1, 2);
void test_result(int pass, const char *fmt, ...)
	ADA_ATTRIB_FORMAT(2, 3);
int test_summary(void);
void test_reset(void);

extern int _write(int file, const char *ptr, int len);

/*
 * upper-layer-provided log_module settings and names.
 */
extern struct log_mod log_mods[LOG_MOD_CT];
extern const char *const log_mod_names[LOG_MOD_CT];
extern const char *log_prefix;
extern enum log_mask log_mask_minimum;

void log_client_set(const char *, char *, const char *);
void log_client_init(void);
void log_client_trycallback(void);
const char *log_client_host(void);
void log_client_cli(int argc, char **argv);
u8 log_client_enabled(void);
int log_client_enable(int);
int log_client_host_set(void);
void log_client_reset(void);

int print(const char *);	/* low level print string for cli */
void log_print(const char *);	/* low level print string for logs */

int printcli(const char *fmt, ...) ADA_ATTRIB_FORMAT(1, 2);
int printcli_s(const char *fmt, ...) ADA_ATTRIB_FORMAT(1, 2);
void print_remote_set(int (*print_func)(void *, const char *), void *arg);

/*
 * Log module I/O as printable ASCII.
 */
void log_io(const void *buf, size_t len, const char *fmt, ...)
	ADA_ATTRIB_FORMAT(3, 4);

/*
 * Print out bytes as hex
 */
void log_bytes_in_hex(u8 mod_nr, void *buf, int len);

/*
 * Log bytes from buffer, with message.
 */
void log_bytes(u8 mod_nr, enum log_sev sev, const void *buf, size_t len,
		const char *fmt, ...) ADA_ATTRIB_FORMAT(5, 6);

/*
 * Set the log-line ID for the current thread.
 */
void log_thread_id_set(const char *id);

/*
 * Unset the log-line ID for the current thread.
 */
void log_thread_id_unset(void);

#endif /*  __AYLA_LOG_H__ */
