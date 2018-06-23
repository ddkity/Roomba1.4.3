/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_LAN_INT_H__
#define __AYLA_LAN_INT_H__

/*
 * LAN (local applications) definitions.
 */
#define CLIENT_LAN_RETRY_LIMIT	2	/* tries before giving up on loc cli */
#define CLIENT_LAN_RETRY_WAIT	1000	/* loc cli retry wait, milliseconds */
#define CLIENT_LAN_CONN_WAIT	5000	/* loc cli connect wait, millisec */
#define CLIENT_LAN_URI_LEN	25	/* max URI length for LAN app */
#define CLIENT_LAN_KEY_LEN	32	/* LAN Key length */
#define CLIENT_LAN_REGS		2	/* max number of LAN registrations */
#define CLIENT_LAN_JSON		30	/* max # of tokens in lan response */
#define CLIENT_LAN_ENC_BUF_SIZE 96	/* buffer alloc - lan encr/decrypt */
#define CLIENT_LAN_EXCH_VER	1	/* LAN exchange version # */
#define CLIENT_LAN_PROTO_NUM	1	/* proto # of LAN encryption */
#define CLIENT_LAN_SIGN_SIZE	32	/* sign size of LAN packet exchanges */
#define CLIENT_LAN_RAND_SIZE	16	/* random data size for LAN key exch */
#define CLIENT_LAN_SEED_SIZE	(4 * CLIENT_LAN_RAND_SIZE + 2)
#define CLIENT_LAN_IV_SIZE	16	/* CBC IV Seed */
#define CLIENT_LAN_ENC_SIZE	32	/* AES256 Enc Key Size */
#define CLIENT_LAN_REFRESH_LIM	10	/* # of refresh before mod does GET */
#define CLIENT_LAN_BLK_SIZE	48	/* block size of each lan send */
#define CLIENT_RSA_KEY_MINLEN	128	/* min RSA key len (bytes) */
#define CLIENT_RSA_KEY_MAXLEN   384     /* max RSA key len (bytes) */
#define CLIENT_RSA_KEY_BASE64   ((((CLIENT_RSA_KEY_MAXLEN + 2) / 3) * 4) + 1)
#define CLIENT_RSA_PUBKEY_LEN   (CLIENT_RSA_KEY_MAXLEN + 32) /* ASN1 mod+exp */
#define CLIENT_RSA_SIGN_MAX_LEN 256	/* decrypt buffer size */

/*
 * Parse result from request to create or refresh LAN.
 */
struct lan_parse {
	char uri[CLIENT_LAN_URI_LEN];
	u32 host_addr;
	u16 port;
	u8 notify;
	struct adc_rsa_key *pubkey;	/* RSA public key, when needed */
};

/*
 * LAN registration entries.
 */
struct client_lan_reg {
	u8 id;				/* id of cli (pos. in dest_mask) */
	u32 mtime;			/* time of creation or refresh */
	char uri[CLIENT_LAN_URI_LEN];	/* URI is empty if entry is invalid */
	enum client_conn_state conn_state; /* current state of client */
	struct http_client http_client;	/* http client of conn */

	/*
	 * State flags.
	 * The comment gives the meaning when the flag is set.
	 */
	u8 pending:1;			/* updates pending */
	u8 prefer_get:1;		/* GET is preferred */
	u8 valid_key:1;			/* key has been exchanged */
	u8 cmd_pending:1;		/* reverse-REST command requested */
	u8 cmd_rsp_pending:1;		/* waiting for cmd rsp from prop_mgr */
	u8 rsa_ke:1;			/* did secure-wifi setup RSA key exch */
	u8 recv_decrypted:1;		/* recv_buf has been decrypted */
	u8 recv_cmds:1;			/* have received commands */

	u16 send_seq_no;		/* seq no of outgoing packets */
	u32 connect_time;		/* time of last connection */
	char buf[CLIENT_LAN_ENC_BUF_SIZE]; /* buf for key exch and requests */
	u16 recved_len;			/* length of recved so far */
	u16 refresh_count;		/* # of refresh in a row without np */

	struct prop *send_prop;
	size_t send_val_offset;		/* offset of the cur val being sent */

	struct adc_rsa_key *pubkey;	/* RSA public key, if secure Wi-Fi */
	char random_one[CLIENT_LAN_RAND_SIZE + 1]; /* rand str for sess enc */
	char time_one[CLIENT_LAN_RAND_SIZE]; /* rand time for sess enc */
	u8 mod_sign_key[CLIENT_LAN_SIGN_SIZE]; /* module signature key */
	u8 app_sign_key[CLIENT_LAN_SIGN_SIZE]; /* lan signature key */
#ifndef AES_GET_IV_SUPPORT
#error AES_GET_IV_SUPPORT must be defined as either 1 or 0
#endif
#if AES_GET_IV_SUPPORT		/* may save AES context space */
	u8 mod_iv_seed[CLIENT_LAN_IV_SIZE]; /* module CBC iv seed */
	u8 app_iv_seed[CLIENT_LAN_IV_SIZE]; /* app CBC iv seed */
	u8 mod_enc_key[CLIENT_LAN_ENC_SIZE]; /* module AES 256 key */
	u8 app_enc_key[CLIENT_LAN_ENC_SIZE]; /* app AES 256 key */
	u8 mod_int_seed[CLIENT_LAN_IV_SIZE]; /* interm module CBC iv seed */
#else
	struct adc_aes aes_tx;		/* AES context for sending to app */
	struct adc_aes aes_rx;		/* AES context for receiving from app */
#endif /* AES_GET_IV_SUPPORT */
	char leftover[8];
	struct adc_hmac_ctx sign_ctx;	/* ctx for sign calc */

	char *recv_buf;			/* ptr to the char buf for recving */
	size_t recv_buf_len;		/* length of recv buffer */

	struct timer timer;
};

extern struct client_lan_reg client_lan_reg[];

/*
 * Internal interfaces between ADS client and LAN client.
 */

/*
 * Initialize LAN subsystem.
 */
void client_lan_init(void);

/*
 * Reset all LAN clients.
 */
void client_lan_reset(struct client_state *state);

/*
 * Run next LAN client, if any.
 */
int client_lan_cycle(struct client_state *);

/*
 * Temporary functions planned to become static again.
 */
void client_finish_echo(struct client_state *, u8 finished_id);
void client_send_post(struct http_client *);
void client_connectivity_update(void);
void client_lan_reg_timeout(struct timer *);

/*
 * Put head of reverse-REST response.
 */
void client_cmd_put_head(struct server_req *, unsigned int status,
			const char *content_type);

/*
 * Start reverse-REST command.
 */
void client_rev_rest_cmd(struct http_client *, u8 priv);

#endif /* __AYLA_LAN_INT_H__ */
