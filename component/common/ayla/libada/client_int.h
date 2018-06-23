/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CLIENT_INT_H__
#define __AYLA_CLIENT_INT_H__

/*
 * Internal client definitions.
 */

#define CLIENT_SERVER_DOMAIN_US    "aylanetworks.com"
#define CLIENT_SERVER_HOST_DEFAULT "ads-dev"
#define CLIENT_SERVER_HOST_DEF_FMT "ads-dev.%s"
#define CLIENT_SERVER_HOST_OEM_FMT "%s-%s-device.%s"

#define CLIENT_SERVER_DEFAULT	CLIENT_SERVER_HOST_DEFAULT "." \
					CLIENT_SERVER_DOMAIN_US
#define CLIENT_SERVER_STAGE  "staging-ads.ayladev.com" /* staging server */

#define CLIENT_POLL_INTERVAL	300	/* default polling time, seconds */
#define CLIENT_POLL_MIN		5	/* minimum polling time, seconds */
#define CLIENT_CMD_RETRY_WAIT	180000	/* retry wait for cmd retry */
#define CLIENT_LISTEN_WARN_WAIT 30000	/* ms before listen enable warning */

#define CLIENT_KEY_LEN		16	/* maximum key length */

#define CLIENT_BUF_SIZE		560	/* buffer alloc for client */
#define CLIENT_API_MAJOR	1	/* API version we support */
#define CLIENT_API_MINOR	0	/* API minor version we support */

#define CLIENT_GET_REQ_LEN	100	/* size of buffer for DSN GET request */
#define CLIENT_AUTH_FAILS	3	/* max authentication failures */

#define MAX_CMD_RESP		5000	/* max length of GET cmds in bytes */

#define MAX_S3_URL_LEN		512	/* max length of S3 server's URL */

/*
 * Macro to make logging easier
 */
#define CLIENT_LOGF(_level, _format, ...) \
	client_log(_level "%s: " _format, __func__, ##__VA_ARGS__)

#define CLIENT_DEBUG_EN		/* XXX temporary */

#ifdef CLIENT_DEBUG_EN
#define CLIENT_DEBUG(_level, _format, ...) \
	CLIENT_LOGF(_level, _format, ##__VA_ARGS__)
#else
#define CLIENT_DEBUG(_level, _format, ...)
#endif /* CLIENT_DEBUG_EN */

/*
 * OTA json request, parser expects this many tokens.
 *
 * 3 name-val pairs, 2 start of objects, 3 extra strings + 1 extra name-val
 */
#define OTA_JSON_PUT_TOKENS (7 * 2 + 3)
#define OTA_GET_CHUNK_SIZE      2048

#define CLIENT_REG_JSON_TOKENS	8

PREPACKED_ENUM enum client_connect_target {
	CCT_ADS,		/* connect to ADS with TLS */
	CCT_ADS_HTTP,		/* connect to ADS without TLS */
	CCT_IMAGE_SERVER,
	CCT_FILE_PROP_SERVER,
	CCT_LAN,
	CCT_REMOTE,
} PACKED_ENUM;

/*
 * LAN (local applications) definitions.
 */
#define CLIENT_LANIP_JSON	14	/* max # of tokens in lanip response */
#define CLIENT_LAN_KEEPALIVE	30	/* default LAN keepalive time, secs */
#define CLIENT_LAN_KEEPALIVE_GRACE 15	/* extra keepalive time allowed, secs */

#define	CLIENT_TIME_FUDGE	1	/* # secs +/- that mod time can be */

#define LOGCLIENT_JSON_PUT	20
#define CLIENT_LAN_OTA_HDR_SZ	256	/* size of encrypted header */

enum client_pri {
	CQP_HIGH,
	CQP_DEF,
	CQP_LOW,
	CQP_COUNT	/* must be last */
};

#define CLIENT_HIGH_QLEN	4
#define CLIENT_DEF_QLEN		8
#define CLIENT_LOW_QLEN		4

struct client_lan_reg;

struct client_state {
	enum client_conn_state conn_state;
	char client_key[CLIENT_KEY_LEN]; /* client key on server */
	char reg_type[16];		/* registration type */
	char setup_token[CLIENT_SETUP_TOK_LEN]; /* connection setup token */
	char *setup_location;		/* location (if given) during setup */
	enum client_connect_target tgt; /* whom we're connected to */
	const char *region;		/* server region code from table */
	u16 client_info_flags;		/* flags for client info diffs */
	u8 serv_conn:1;			/* internet connectivity to service */
	u8 ping_time:1;			/* use HTTP /ping to get time */
	u8 get_all:1;			/* get all props/cmds */
	u8 ads_listen:1;		/* host mcu enabling GETs from ads */
	u8 prefer_get:1;		/* prioritize GETs over POSTs */
	u8 np_started:1;		/* notify service started */
	u8 np_up:1;			/* notify service is live */
	u8 np_event:1;			/* an event is pending */
	u8 xml_init:1;			/* parse is ready for xml */
	u8 partial_content:1;		/* set to 1 if 206 status code rec */
	u8 cmd_pending:1;		/* set to 1 if ADS requested cmd */
	u8 cmd_delayed:1;		/* set to 1 if we need to delay rsp */
	u8 get_echo_inprog:1;		/* set to 1 if GET + Echo is in prog */
	u8 lan_cmd_pending:1;		/* set to 1 if a LAN requested cmd */
	u8 poll_ads:1;			/* set to 1 if polling ADS */
	u8 mcu_overflow:1;		/* 1 if mcu can't consume data */
	u8 get_cmds_fail:1;		/* 1 if get commands failed */
	u8 np_any_event:1;		/* 1 if received any ANS events */
	u8 np_up_once:1;		/* 1 if notify has every succeeded */
	u8 reset_at_commit:1;		/* 1 to reset when committing */
	u8 cmd_rsp_pending:1;		/* 1 if cmd_rsp is pending from mcu */
	u8 wait_for_file_put:1;		/* 1 if waiting for a DP PUT */
	u8 wait_for_file_get:1;		/* 1 if waiting for a DP GET */
	u8 unexp_op:1;			/* 1 if host mcu tried unexp op */
	u16 recved_len;			/* length of recved from ADS so far */
	/* prop update from MCU callback function */
	enum ada_err (*prop_send_cb)(enum prop_cb_status, void *);
	void *prop_send_cb_arg;		/* arg for the prop_send_cb */
	u32 connect_time;		/* time of last connection */
	u8 retries;
	u8 auth_fails;			/* authorization failures */
	u8 dest_mask;			/* dest mask for update from host */
	u8 failed_dest_mask;		/* failed dests for prop update */
	u8 valid_dest_mask;		/* mask of all the valid dests */

	/*
	 * Queues for requests.
	 */
	struct net_callback *current_request; /* callback in progress */
	struct net_callback_queue *callback_queue[CQP_COUNT];

	/*
	 * cmd being received from service.
	 */
	struct {
		u32 id;			/* id of the command */
		char method[16];	/* reverse-REST method req on device */
		char res_data[360];	/* resource + data of the command */
		char *data;		/* where data starts in res_data */
		char *resource;		/* where resource starts in res_data */
		char uri[PROP_LOC_LEN];	/* uri to put the result */
		u32 output_len;		/* length of the output sent so far */
	} cmd;

	struct {
		char host[40];
		char uri[40];
		char protocol[6];
	} log_server;

	struct {
		char host[65];
		char *uri;
		u8 ssl;
		u8 lan;
		u8 remote;
		u16 port;
	} ota_server;

	struct {
		enum {
			COS_NONE = 0,	/* nothing going on */
			COS_NOTIFIED,	/* notified OTA driver */
			COS_STALL,	/* can't deliver more yet */
			COS_IN_PROG,	/* downloading patch */
			COS_CMD_STATUS,	/* send reverse-REST status */
		} in_prog;
		u8 data_recvd:1;	/* data received for current GET */
		u8 url_fetched:1;
		u8 auth_fail:1;		/* set to 1 if we had an OTA unauth */
		u8 retries:3;		/* # times MCU was notified of OTA */
		u8 chunk_retries:3;	/* times we tried to fetch a chunk */
		u8 pad;			/* padding length discarded at end */
		u16 http_status;	/* reverse-REST status */
		u32 prev_off;
		u32 off;
		u32 max_off;
		enum ada_ota_type type;		/* current OTA type */
		char *version;
		u8 *img_sign;	/* SHA-256 signature of LAN OTA image */
		struct adc_aes aes_ctx;
		struct adc_sha256 sha_ctx;
		struct recv_payload recv_buf; /* Decrypted LAN OTA data */
	} ota;

	const struct ada_ota_ops *ota_ops[OTA_TYPE_CT];

	/*
	 * Status for OTA command.
	 * This can be given independently from an ongoing download.
	 * If it relates to the current download, it'll be given after the put.
	 */
	struct {
		u8 status;		/* OTA status code (may be zero) */
		enum ada_ota_type type;
	} ota_status;

	u8 np_cipher_key[NP_KEY_LEN];	/* binary AES key for ANS */
	u32 np_cipher_key_len;
	u16 conf_port;			/* dest port of server conn */
	struct xml_state xml_state;
	char xml_buf[XML_MAX_TEXT];	/* for sending properties */
	size_t buf_len;			/* length used in buf */
	char buf[CLIENT_BUF_SIZE];
	struct http_client http_client;
	struct server_req cmd_req;

	enum client_http_req request;

	struct client_lan_reg *http_lan; /* LAN for HTTP or NULL */
	struct client_lan_reg *lan_cmd_responder;

	struct {
		u8 lanip_random_key[CLIENT_LANIP_KEY_SIZE];
	} lanip;

	struct prop_recvd *echo_prop;	/* prop structure to echo */
	u8 echo_dest_mask;		/* dest mask of the echo */

	struct http_client *cont_recv_hc;
	struct net_callback next_step_cb; /* cb for next req */
	struct net_callback notify_cb;
	size_t long_val_index;
	struct adc_dev *aes_dev;	/* cryptography device, if needed */

	struct timer cmd_timer;
	struct timer listen_timer;
	struct timer poll_timer;
	struct timer req_timer;
	struct timer lan_reg_timer;

	struct client_event_handler *event_head;
};

struct client_event_handler {
	void (*handler)(void *arg, enum ada_err);
	void *arg;
	struct client_event_handler *next;
};

extern struct net_callback ada_conf_reset_cb;
extern u8 ada_conf_reset_factory;

extern struct client_state client_state;
extern struct prop_recvd prop_recvd;		/* incoming property */

extern const struct xml_tag client_xml_cmds[];
extern const struct xml_tag client_xml_prop[];

#define CLIENT_HAS_KEY(a) ((a)->client_key[0] != '\0')

void client_tcp_recv_done(struct client_state *);
void client_wait(struct client_state *, u32 delay);
struct http_client *client_req_new(enum client_connect_target tgt);
struct http_client *client_req_ads_new(void);
void client_req_start(struct http_client *, enum http_method,
		const char *uri, const struct http_hdr *);
void client_wakeup(void);

void client_prop_init(struct client_state *);
enum ada_err client_prop_send_done(struct client_state *, u8 success,
				void *, u8 dest, struct http_client *);
enum ada_err client_recv_prop_done(struct http_client *);

enum ada_err client_prop_cmds_recv(struct http_client *, void *, size_t);
enum ada_err client_recv_prop_val(struct http_client *, void *, size_t);
enum ada_err client_recv_prop_cmds(struct http_client *, void *, size_t);
enum ada_err client_recv_cmds(struct http_client *, void *, size_t);
enum ada_err client_recv_xml(struct http_client *hc, void *buf, size_t len);
enum ada_err client_prop_set(struct prop_recvd *);

void prop_page_json_get_one(struct server_req *);
void conf_json_get(struct server_req *);
void conf_json_put(struct server_req *);

int client_prop_name(struct xml_state *, int argc, char **argv);
int client_prop_val(struct xml_state *, int argc, char **argv);

int client_put_ota_status(struct client_state *);
int client_ota_fetch_image(struct client_state *);
void client_ota_set_sts_rpt(struct client_state *, u16 sts);
void client_ota_save_done(struct client_state *);
void client_ota_server(struct client_state *);
void client_ota_cleanup(struct client_state *);
void ada_ota_report_int(enum ada_ota_type, enum patch_state);

void client_conf_reg_persist(void);

#endif /* __AYLA_CLIENT_INT_H__ */
