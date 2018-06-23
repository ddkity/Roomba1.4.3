/*
 * Copyright 2011-2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CONF_H__
#define __AYLA_CONF_H__

#include <ayla/ayla_spi_mcu.h>
#include <ayla/ayla_proto_mcu.h>
#include <ayla/conf_token.h>
#include <ayla/conf_flash.h>
#include <sys/types.h>

#define CONF_PATH_MAX		16	/* maximum depth of config path */
#define CONF_VAL_MAX		400	/* maximum length of value TLV */

enum conf_error {
	CONF_ERR_NONE,
	CONF_ERR_LEN,
	CONF_ERR_UTF8,
	CONF_ERR_PATH,		/* unsupported path */
	CONF_ERR_TYPE,		/* unsupported type */
	CONF_ERR_RANGE,		/* value out of range */
	CONF_ERR_PERM,		/* access permission */
};

struct conf_entry {
	enum conf_token token;
	void (*export)(void);
	enum conf_error (*set)(int src, enum conf_token *, size_t,
				struct ayla_tlv *);
	enum conf_error (*get)(int src, enum conf_token *, size_t);
	void (*commit)(int from_ui);
};

extern const struct conf_entry * const conf_table[];

#ifndef CONF_NO_ID_FILE
extern const struct conf_entry * const conf_id_table[];
#endif /* CONF_NO_ID_FILE */

struct conf_mcu_dev {
	int (*init)(void);
	struct pbuf *(*pbuf_alloc)(size_t, void (*callback)(void));
	void (*pbuf_realloc)(struct pbuf *, u16);
	void (*enq_tx)(struct pbuf *pbuf);
	void (*set_ads)(void);
	void (*clear_ads)(void);
	void (*stay_busy)(void);
	void (*show)(void);
	void (*ping)(void *, size_t);
};

struct conf_state {
	enum conf_token path[CONF_PATH_MAX];
	struct conf_file *file;
	size_t off;
	size_t file_off;
	enum conf_inode inode;
	enum conf_inode conf_cur;
	enum conf_inode conf_other;
	u8 path_len;
	u8 name_len;
	u8 gen_id;
	u8 applied:1;
	u8 loaded:1;
	u8 old_format:1;
	u8 not_valid:1;
	u8 migrate_factory:1;
	u8 show_conf:1;		/* don't save, doing 'show conf' */
	u8 save_as_factory:1;	/* saving conf as factory config */
	u8 file_crc;		/* accumulated file CRC */
	u8 *next;
	char *file_err;		/* file error message, if any */
	size_t rlen;
	enum conf_error error;
};
extern struct conf_state conf_state;

extern const struct conf_mcu_dev *mcu_dev;
extern enum conf_token mcu_interface;
extern struct net_callback *conf_rst;
extern u8 conf_factory;
extern u8 conf_was_reset;
extern u8 conf_serv_override;
extern u8 conf_setup_pending;
extern u8 conf_mfg_pending;

enum conf_error conf_entry_set(int src, enum conf_token *tokens, size_t count,
				struct ayla_tlv *tlv);
enum conf_error conf_entry_get(int src, enum conf_token *tokens, size_t count);

ssize_t tlv_put(void *, size_t, enum ayla_tlv_type, const void *, size_t);
ssize_t tlv_put_str(void *, size_t, const char *);
ssize_t tlv_put_int(void *, size_t, s32);
ssize_t tlv_put_uint(void *, size_t, u32);

/*
 * Put response to commit.
 */
void conf_put(enum conf_token, enum ayla_tlv_type, const void *val,
		ssize_t len);
void conf_put_str(enum conf_token, const char *);
void conf_put_str_ne(enum conf_token, const char *);
void conf_put_s32(enum conf_token, s32 val);
void conf_put_s32_nz(enum conf_token, s32 val);
void conf_put_u32(enum conf_token, u32 val);
void conf_put_u32_nz(enum conf_token, u32 val);
void conf_delete(enum conf_token token);

/*
 * Put response to get.
 */
void conf_resp(enum ayla_tlv_type, const void *val, size_t len);
void conf_resp_str(const char *);
void conf_resp_u32(u32 val);
void conf_resp_s32(s32 val);
void conf_resp_bool(u32 val);

/*
 * conf_get() fills in the token value from a type (or smaller type for ints),
 * up to the available length.
 *
 * Returns the actual length used, or 0 if variable was not present or
 * incompatible in the configuration.
 *
 * These set an error as a side-effect if encountered.
 *
 * Note this will not work for certificates and larger values.  TBD.
 */
size_t conf_get(struct ayla_tlv *, enum ayla_tlv_type, void *val, size_t len);

s32 conf_get_s32(struct ayla_tlv *);
u32 conf_get_u32(struct ayla_tlv *);
s16 conf_get_s16(struct ayla_tlv *);
u16 conf_get_u16(struct ayla_tlv *);
s8 conf_get_s8(struct ayla_tlv *);
u8 conf_get_u8(struct ayla_tlv *);
u8 conf_get_bit(struct ayla_tlv *);	/* value must be 0 or 1 */
s32 conf_get_int32(struct ayla_tlv *tlv);

int conf_cd(enum conf_token);
void conf_depth_restore(int);
void conf_cd_table(u8);
void conf_cd_in_parent(enum conf_token);
void conf_cd_parent(void);
void conf_cd_root(enum conf_token);
void conf_set_error(enum conf_error);

enum conf_error conf_set_tlv(const struct conf_entry *, enum conf_token *,
				int ntokens, struct ayla_tlv *);
enum conf_error conf_cli_set_tlv(enum conf_token *,
				int ntokens, struct ayla_tlv *);

int conf_persist(enum conf_token root, void (*func)(void *), void *arg);
void conf_save_item(enum conf_token *path, size_t path_len,
	enum ayla_tlv_type type, const void *val, size_t len);
void conf_reset_factory(void);
void conf_restore_startup(const char *from);
void conf_restore_factory(const char *from);

const char *conf_string(enum conf_token);
enum conf_token conf_token_parse(const char *);

/*
 * Handling for files inside config.
 */
void *conf_file_read(enum conf_token *tokens, unsigned int ntokens,
		enum ayla_tlv_type type, size_t offset,
		void *buf, size_t *lenp);
int conf_write_start(size_t len, enum conf_token *, unsigned int ntokens);
int conf_write_append(void *buf, size_t len);
int conf_write_end(void);

/*
 * Lookup conf_entry (subsystem ops) for conf file and first path element.
 * Returns NULL if nothing found.
 */
const struct conf_entry * const *
conf_entry_lookup(enum conf_inode inode, enum conf_token token);

extern const struct conf_entry client_conf_entry;
extern const struct conf_entry gpio_conf_entry;
extern const struct conf_entry np_conf_entry;
extern const struct conf_entry log_conf_entry;
extern const struct conf_entry conf_sys_conf_entry;
extern const struct conf_entry conf_sys_id_entry;
extern const struct conf_entry conf_oem_entry;
extern const struct conf_entry power_conf_entry;
extern const struct conf_entry metric_conf_entry;
extern const struct conf_entry server_conf_entry;
extern const struct conf_entry server_locale_conf_entry;
extern const struct conf_entry sched_conf_entry;
extern const struct conf_entry file_conf_entry;
#ifdef HAS_HW_CONF
extern const struct conf_entry hw_conf_entry;
#endif
#ifdef ETHERNET_SUPPORT
extern const struct conf_entry eth_conf_entry;
#endif
#if defined(MFI) || defined(HOMEKIT)
extern const struct conf_entry mfi_conf_entry;
#endif
void conf_init(void);
void conf_tlv_recv(void *, size_t);

size_t conf_tlv_len(const struct ayla_tlv *);

/*
 * Argument to conf_access. Read vs. write operation as encoded in type.
 */
#define CONF_OP_IS_WRITE(a)	(0x80000000 & (a))
#define CONF_OP_READ		0x00000000
#define CONF_OP_WRITE		0x80000000

/*
 * Argument to conf_access. Source of request.
 */
#define CONF_OP_SRC(a)		(0x0000000f & (a))
#define CONF_OP_SRC_FILE	0x00000000
#define CONF_OP_SRC_ADS		0x00000001
#define CONF_OP_SRC_SERVER	0x00000002
#define CONF_OP_SRC_MCU		0x00000003
#define CONF_OP_SRC_CLI		0x00000004

/*
 * Argument to conf access. Subsystem ID as encoded in type.
 */
#define CONF_OP_SS(a)		(0x00000ff0 & (a))
#define CONF_OP_SS_ID		0x00000000	/* ID fields, mac addr */
#define CONF_OP_SS_MODE		0x00000010	/* mfg_mode/setup_mode */
#define CONF_OP_SS_PWR		0x00000020	/* power settings */
#define CONF_OP_SS_LOG		0x00000030	/* logging levels */
#define CONF_OP_SS_CLIENT	0x00000040	/* client */
#define CONF_OP_SS_METRIC	0x00000050	/* metric */
#define CONF_OP_SS_OEM		0x00000060	/* OEM */
#define CONF_OP_SS_WIFI		0x00000070	/* Wifi */
#define CONF_OP_SS_IP		0x00000080	/* IP configuration */
#define CONF_OP_SS_LOCALE	0x00000090	/* Locale */
#define CONF_OP_SS_CLIENT_ENA	0x000000a0	/* client enable */
#define CONF_OP_SS_LOG_ENA	0x000000b0	/* log client enable */
#define CONF_OP_SS_SETUP_APP	0x000000c0	/* Wifi IOS setup app */
#define CONF_OP_SS_GPIO		0x000000d0	/* GPIO-mode settings */
#define CONF_OP_SS_TIME		0x000000e0	/* Time settings */
#define CONF_OP_SS_HW		0x000000f0	/* Hardware specific settings */
#define CONF_OP_SS_ETH		0x00000100	/* Ethernet */
#define CONF_OP_SS_CLIENT_REG	0x00000110	/* client reg_token subtree */
#define CONF_OP_SS_HAP		0x00000120	/* homekit subtree */
#define CONF_OP_SS_OEM_MODEL	0x00000130	/* oem model */
#define CONF_OP_SS_CLIENT_SRV_REGION \
				0x00000140	/* client server region */
#define CONF_OP_SS_SERVER	0x00000150	/* server */
#define CONF_OP_SS_SERVER_PROP	0x00000160	/* server prop */

int conf_access(u32 type);

int mfg_mode_ok(void);
int conf_save_as_factory(void);
int mfg_or_setup_mode_ok(void);
void conf_show(void);
int conf_show_name(const char *);

/*
 * Log configuration message.
 */
void conf_log(const char *fmt, ...) ADA_ATTRIB_FORMAT(1, 2);

/*
 * System config items.
 */
#define CONF_MODEL_MAX		24	/* max string length for device ID */
#define CONF_DEV_ID_MAX		20	/* max string length for device ID */
#define CONF_MFG_SN_MAX		32	/* max string length for mfg serial */
#define CONF_DEV_SN_MAX		20	/* max string length for DSN */
#define CONF_OEM_MAX		20	/* max string length for OEM strings */
#define CONF_OEM_KEY_MAX	256	/* max length of encrypted OEM key */
#define CONF_OEM_VER_MAX	40	/* max length of oem_host_version */
#define CONF_ADS_HOST_MAX (CONF_OEM_MAX + 1 + CONF_MODEL_MAX + 1 + 24)
					/* max ADS hostname length incl NUL */

extern char conf_sys_model[CONF_MODEL_MAX];
extern char conf_sys_dev_id[];
extern char conf_sys_serial[];
extern char conf_sys_mfg_model[];
extern char conf_sys_mfg_serial[];
extern char oem_host_version[];		/* GPIO mode only */
extern u8 oem_host_version_sent;	/* GPIO mode only */
extern u8 oem_key[];
extern u16 oem_key_len;
extern u8 conf_sys_mac_addr[6];
extern u8 conf_mfg_mode;
extern u8 conf_setup_mode;
extern u8 conf_id_reset_en;		/* ID in OTP was amended */
extern u8 conf_id_set;			/* ID was set and should be written */
extern u32 conf_mfg_test_time;		/* time when mfg test passed */

void oem_save(void);			/* save OEM configuration */
enum conf_error oem_set_key(char *key, size_t len, const char *model);

/*
 * Converts a string path into conf tokens.
 */
int conf_str_to_tokens(char *haystack, enum conf_token *tk, int tk_len);
int conf_path_parse(enum conf_token *tokens, int ntokens, const char *name);

/*
 * Converts tokens path into a string
 */
int conf_tokens_to_str(enum conf_token *tk, int tk_len, char *buf, int blen);

/*
 * Send the time information to the MCU.
 * time + timezone_valid + timezone (if valid) +
 * dst_valid + dst_active (if valid) + dst_change (if valid)
 */
void conf_send_mcu_time_info(void);

/*
 * Cli interface for some conf sys settings
 */
void conf_sys_cli(int argc, char **argv);

/*
 * CLI interface for showing and saving configuration.
 */
void conf_cli(int argc, char **argv);

/*
 * Add a single entry to the configuration table.
 */
void conf_table_entry_add(const struct conf_entry *);

/*
 * Perform deferred actions on recently-set items.
 */
void conf_commit(void);

/*
 * Start saving config items as factory config
 */
void conf_factory_start(void);

/*
 * Stop saving config items as factory config
 */
void conf_factory_stop(void);

#endif /* __AYLA_CONF_H__ */
