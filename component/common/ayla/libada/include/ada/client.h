/*
 * Copyright 2011-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CLIENT_H__
#define __AYLA_CLIENT_H__

#define CLIENT_SETUP_TOK_LEN	10	/* max setup token length incl NUL */

/*
 * Total wait time Wi-Fi should wait for device service to report connection.
 */
#define CLIENT_PROP_WAIT	20000	/* property wait, milliseconds */
#define CLIENT_WAIT	(CLIENT_CONN_WAIT + CLIENT_PROP_WAIT)	/* ms */

#define CLIENT_CONN_WAIT	15000	/* TCP connect wait, matches hc */
#define CLIENT_LOCAL_WAIT	3000	/* lan response wait, milliseconds */
#define CLIENT_TRY_THRESH	5	/* threshold till wait time increase */
#define CLIENT_RETRY_WAIT1	10000	/* init retry wait, milliseconds */
#define CLIENT_RETRY_WAIT2	300000	/* retry wait till threshold */
#define CLIENT_RETRY_WAIT3	600000	/* retry wait after threshold */

//add by yujunwu
extern int g_first_get_cmds;

//add by huangjituan
extern int g_TimezoneChange;

enum client_conn_state {
	CS_DOWN,
	CS_DISABLED,	/* network up but client not enabled */
	CS_WAIT_CONN,	/* wait for connection to service */
	CS_WAIT_ID,	/* waiting to get client ID */
	CS_WAIT_INFO_PUT, /* waiting to put client info */
	CS_WAIT_CMD_PUT,  /* waiting to resp to cmd */
	CS_WAIT_GET,	/* waiting for GET response */
	CS_WAIT_LANIP_GET, /* waiting for GET response to lanip key */
	CS_WAIT_POST,	/* waiting for POST response */
	CS_WAIT_OTA_GET,  /* waiting for GET response of OTA patch fetch */
	CS_WAIT_OTA_PUT, /* waiting for send OTA status */
	CS_WAIT_CMD_STS_PUT, /* waiting to send belated cmd status */
	CS_WAIT_ECHO,	/* waiting for response for an echo post */
	CS_WAIT_EVENT,	/* waiting for event or polling interval */
	CS_WAIT_RETRY,	/* waiting to retry after connection or I/O error */
	CS_WAIT_PING,	/* waiting for ping reply from service */
	CS_WAIT_REG_WINDOW, /* waiting for POST response to start_reg_window */
	CS_WAIT_PROP_RESP, /* waiting to POST a property response */
	CS_WAIT_PROP,	/* waiting for request from property subsystem */
	CS_ERR,		/* unable to continue due to error */
};

enum client_http_req {
	CS_GET_INDEX,	/* GET dsns req */
	CS_GET_CMDS,	/* GET cmds req */
	CS_GET_LANIP,	/* GET lanip key */
	CS_POST_DATA,	/* POST data/prop req */
	CS_POST_DP_LOC,	/* POST DP_LOC req */
	CS_PUT_DP,	/* PUT Long DP req */
	CS_PUT_DP_CLOSE, /* PUT DP to mark it closed */
	CS_PUT_DP_FETCH, /* PUT Long DP fetch req */
	CS_GET_DP,	/* GET Long DP req */
	CS_GET_DP_LOC,	/* GET Location of Long DP */
	CS_PUT_INFO,	/* PUT Client Info req */
	CS_GET_OTA,	/* GET OTA patch */
	CS_PUT_OTA,	/* Put OTA failure */
	CS_GET_VAL,	/* Get Prop Val Req */
	CS_GET_ALL_VALS,/* Get All To-Dev Req */
	CS_PING,	/* PING req */
	CS_IDLE,	/* No on-going req */
};

struct client_lan_reg;
struct prop;
struct prop_dp_meta;

void client_init(void);
enum wifi_error client_status(void);
const char *client_host(void);
void client_set_setup_token(const char *);
void client_set_setup_location(char *);
void client_cli(int argc, char **argv);
void client_log(const char *fmt, ...)
	ADA_ATTRIB_FORMAT(1, 2);
void client_server_reset(void);

extern u8 mcu_feature_mask;

/*
 * Tcp Recv Payload
 */
struct recv_payload {
	void *data;
	size_t len;
	size_t consumed;
};

enum prop_cb_status;

/*
 * Mon_Spi is available for more pbufs. Ask http_client to resend.
 */
void client_tcp_recv_resend(void);

/*
 * Set callback to be used when ready to send a property to the service.
 * The client calls the callback when connected and ready to send the property.
 * The argument will be non-zero if the send is done and acked by the server.
 */
void client_send_callback_set(enum ada_err (*callback)(enum prop_cb_status stat,
				void *arg), u8 dest_mask);

/*
 * Returns a mask of the failed destinations
 */
u8 client_get_failed_dests(void);

/*
 * Aborts any ongoing file operations
 */
void client_abort_file_operation(void);

/*
 * Send data.  May be called only from the send_callback set above.
 */
enum ada_err client_send_data(struct prop *);

/*
 * Send dp loc request to server.
 */
enum ada_err client_send_dp_loc_req(const char *name,
			const struct prop_dp_meta *);

/*
 * Send dp put to server.
 */
enum ada_err client_send_dp_put(const u8 *prop_val, size_t prop_val_len,
		const char *prop_loc, u32 offset, size_t tot_len, u8 eof);

/*
 * Close FILE DP put
 */
enum ada_err client_close_dp_put(const char *loc);

/*
 * Fetch the s3 location of the file datapoint
 */
enum ada_err client_get_dp_loc_req(const char *prop_loc);

/*
 * Fetch the datapoint at the location and offset.
 */
enum ada_err client_get_dp_req(const char *prop_loc,
				u32 data_off, u32 data_end);

/*
 * Indicate to the service that MCU has fetched the dp.
 */
enum ada_err client_send_dp_fetched(const char *prop_loc);

/*
 * Notify client that a 206 (partial content) was received
 * in the previous get. So re-mark the np_event flag.
 */
void client_notify_if_partial(void);

/*
 * Send changed data to LAN App
 */
enum ada_err client_send_lan_data(struct client_lan_reg *, struct prop *, int);

struct mem_file {
	void *buf;
	size_t len;
	size_t max_len;
};

extern u8 ssl_enable;
enum conf_token;

int client_auth_encrypt(void *key, size_t key_len,
			void *buf, size_t, const char *req);
int client_auth_gen(void *key, size_t key_len,
			void *buf, size_t len, const char *req);

/*
 * metric command handler
 */
void metric_cli(int argc, char **argv);

/*
 * Perform cli commands for the client metrics
 */
int client_metric_cli(const char *flag, u32 val);

/*
 * Perform cli commands for the http metrics
 */
int client_metric_http(const char *flag, u32 val);

/*
 * Perform cli commands for the ssl metrics
 */
int client_metric_ssl(const char *flag, u32 val);

/*
 * Perform cli commands for the tcp metrics
 */
int client_metric_tcp(const char *flag, u32 val);

/*
 * Perform cli commands for all metrics
 */
int client_metric_all(const char *flag, u32 val);

/*
 * Print out metric status information
 */
void client_print_metric_status(void);

/*
 * Export config options for client metrics for writing config file
 */
void client_export_metrics(void);

/*
 * Get metric configuration item.
 */
enum conf_error
client_get_metrics(enum conf_token *token, size_t len);

/*
 * Set metric configuration item.
 */
enum conf_error
client_set_metrics(enum conf_token *token, size_t len, struct ayla_tlv *tlv);

/*
 * Initialize the metric config in case it isn't in the config
 */
void client_metric_init(void);

/*
 * Return a pointer to client-cli metric status
 */
struct status_info *client_get_cli_status(void);

/*
 * Return a pointer to client-http metric status
 */
struct status_info *client_get_http_status(void);

/*
 * Return a pointer to client-ssl metric status
 */
struct status_info *client_get_ssl_status(void);

/*
 * Return a pointer to client-tcp metric status
 */
struct status_info *client_get_tcp_status(void);

/*
 * Get vaue of "name" from ADS. If name isn't given, get all props.
 */
enum ada_err client_get_prop_val(const char *name);

/*
 * Convert string to "cents" value.
 */
long client_prop_strtocents(const char *val, char **errptr);

/*
 * Allow client to fetch prop and cmd updates from ADS
 */
void client_enable_ads_listen(void);

/*
 * Return current connectivy information
 */
u8 client_get_connectivity_mask(void);

/*
 * Return current events to send
 */
u8 client_get_event_mask(void);

/*
 * Update pending event mask
 */
void client_set_event_mask(u8 mask);

/*
 * Return 1 if the LAN mode is enabled in client
 */
int client_lanmode_is_enabled(void);

/*
 * Return 1 if a user is registered to this device
 */
int client_is_reg_user(void);

/*
 * Start registration window.
 */
void client_reg_window_start(void);

#ifdef SERVER_DEV_PAGES
/*
 * Sets the callback so that client sends the sched debug info
 */
void client_set_sched_debug_cb(int value);
#endif

/*
 * Set the clock
 */
void client_clock_set(u32 new_time, enum clock_src src);

/*
 * Reset the mcu overflow flag (in case its set)
 */
void client_reset_mcu_overflow(void);

/*
 * Set MCU's feature mask. Called from data_tlv.
 */
void client_set_mcu_features(u8 features);

/*
 * Continue receiving, e.g., after flow control by host MCU stopped receive.
 */
enum ada_err client_continue_recv(void *);

/*
 * Set region for ADS.
 */
int client_set_region(const char *region);

/*
 * Set configured hostname for ADS.
 */
int client_set_server(const char *server);

/*
 * Indicate that the client_conf may have been changed by the platform.
 */
void client_commit(void);

/*
 * Hold client for future requests.
 * This may be used for operations that require multiple HTTP requests.
 *
 * Returns non-zero on failure, if client is already held.
 */
int client_hold(void);

/*
 * Release hold, prior to issuing new HTTP request.
 * Returns non-zero on failure, if hold was cleared, e.g., by link loss.
 */
int client_release(void);

/*
 * Platform routines to provide buffers to the client fror use in LAN receive.
 */
#define CLIENT_LAN_BUF_LEN 1540		/* minimum buffer size */

void *client_lan_buf_alloc(void);
void client_lan_buf_free(void *);

struct https_metrics;			/* semi-opaque structure */
struct https_metrics *client_metric_get(void);

int ada_init(void);
int ada_client_up(void);
void ada_client_down(void);

/*
 * Register for callback when ADS reachability changes, or a new
 * connection attempt fails.
 * This callback is made inside the client thread, and must not block.
 * Multiple callbacks may be registered, and they'll all be called.
 * Callbacks may not be unregistered for now.
 */
void ada_client_event_register(void (*fn)(void *arg, enum ada_err), void *arg);

/*
 * Get signal strength from network layer, usually Wi-Fi.
 * Returns 0 on success, -1 if not supported.
 */
int adap_net_get_signal(int *signal);

#endif /* __AYLA_CLIENT_H__ */
