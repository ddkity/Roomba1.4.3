/*
 * Copyright 2011-2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_NOTIFY_PROTO_H__
#define __AYLA_NOTIFY_PROTO_H__

/*
 * Algorithm definitions.
 */
#define NP_MIN_PROBE	10	/* seconds for minimum probe */
#define NP_MAX_PROBE	300	/* seconds for maximum probe */
#define NP_INIT_PROBE	30	/* seconds for initial probe request */
#define NP_PROBE_GRACE	2	/* seconds by which a probe can be late */
#define NP_INIT_PROBES	4	/* probe receptions required before increase */

#define NP_MAX_TRY	5	/* max number of request tries */
#define NP_RESP_WAIT	4	/* seconds for response wait */

#define NP_MAX_DSN	20	/* max length of DSN expected */

#define NP_PROBE_INTERVAL 300	/* seconds between ANS reachability check */

/*
 * Packet Definitions.
 */
#define NP_VERS		1	/* protocol version */
#define NP_VERS_OLD	0	/* old (pre-encryption) protocol version */

#define NP_UDP_PORT	55055	/* server port */
#define NP_UDP_PORT2	55056	/* alternate server port */

#define NP_PAD		16	/* pad payload len to multiple of 16 for AES */
#define NP_IV_LEN	16	/* initialization vector length */

/*
 * Message opcodes.
 */
enum np_op {
	NP_REG = 1,		/* registration */
	NP_REG_RESP = 2,
	NP_REQ_PROBE = 3,	/* request probe */
	NP_REQ_PROBE_RESP = 4,
	NP_PROBE = 5,		/* probe */
	NP_PROBE_RESP = 6,
	NP_KEEP_ALIVE = 7,	/* keep-alive */
	NP_KEEP_ALIVE_RESP = 8,
	NP_NOTIFY = 9,		/* event notification */
	NP_NOTIFY_RESP = 10,
	NP_UNREG = 11,		/* unregister */
	NP_UNREG_RESP = 12,
};

#define NP_OPS {				\
	[NP_REG] = "reg",			\
	[NP_REG_RESP] = "reg resp",		\
	[NP_REQ_PROBE] = "req probe",		\
	[NP_REQ_PROBE_RESP] = "req probe resp",	\
	[NP_PROBE] = "probe",			\
	[NP_PROBE_RESP] = "probe resp",		\
	[NP_KEEP_ALIVE] = "keep-alive",		\
	[NP_KEEP_ALIVE_RESP] = "keep-alive resp", \
	[NP_NOTIFY] = "notify",			\
	[NP_NOTIFY_RESP] = "notify resp",	\
	[NP_UNREG] = "unreg",			\
	[NP_UNREG_RESP] = "unreg resp",		\
}

enum np_error {
	NP_ERR_NONE = 0,	/* no error */
	NP_ERR_NOT_REG = 1,	/* client is not registered on the server */
	NP_ERR_MSG_FAILED = 2,	/* an earlier probe or event message failed */
	NP_ERR_RESOURCE = 3,	/* the server can't handle more clients */
	NP_ERR_SEQ = 4,		/* wrong sequence */
};

enum np_format {
	NP_FMT_DSN = 0,		/* message contains DSN and cleartext NP */
	NP_FMT_KEY = 1,		/* (obsoleted by 4) reg_key and cleartext NP */
	NP_FMT_DSN_ERR = 2,	/* error reply in DSN encapsulation */
	NP_FMT_KEY_ERR = 3,	/* error reply in KEY encapsulation */
	NP_FMT_IV_KEY = 4,	/* message contains reg_key, IV, encrypted NP */
};

/*
 * Message encapsulation header for registration message containing DSN.
 */
PREPACKED struct np_encaps_dsn {
	u8	format;		/* format */
	u8	error;		/* error code */
	u8	dsn_len;	/* DSN length */
	char	dsn[0];		/* device serial number, NUL-terminated */
} PACKED;

/*
 * Message encapsulation header for all messages except registration.
 */
PREPACKED struct np_encaps_key {
	u8	format;		/* format */
	u8	resvd[3];	/* reserved */
	be32	reg_key;	/* opaque registration key */
	u8	iv[NP_IV_LEN];	/* initialization vector for encryption */
} PACKED;

/*
 * Signature (SHA-1) of the encapsulation plus the key.
 * Sent after registration message payload.
 */
PREPACKED struct np_sig {
	u8	sig[20];
} PACKED;

/*
 * Message header.
 */
PREPACKED struct np_head {
	u8	ver;		/* version */
	u8	op;		/* opcode */
	be16	seq;		/* sequence number */
	be32	time;		/* timestamp, ms since arbitrary epoch */
} PACKED;

/*
 * Register message.
 * This follows np_encaps_dsn.
 */
PREPACKED struct np_register {
	struct np_head head;
	be16	probe_delay;	/* seconds until requested probe, if non-zero */
} PACKED;

/*
 * Registration response.
 */
PREPACKED struct np_reg_resp {
	struct np_encaps_key encaps;
	struct np_head head;
	be16	ka_period;	/* last keep-alive interval used by client */
	u8	error;
} PACKED;

/*
 * Keep-alive message.
 */
PREPACKED struct np_keep_alive {
	struct np_encaps_key encaps;
	struct np_head head;
	be16	ka_period;	/* keep-alive period being used, seconds */
} PACKED;

/*
 * Request Probe message.
 */
PREPACKED struct np_req_probe {
	struct np_encaps_key encaps;
	struct np_head head;
	be16	probe_delay;	/* seconds until requested probe, if non-zero */
} PACKED;

/*
 * Probe message.
 */
PREPACKED struct np_probe {
	struct np_encaps_key encaps;
	struct np_head head;
} PACKED;

/*
 * Event message.
 */
PREPACKED struct np_event {
	struct np_encaps_key encaps;
	struct np_head head;
} PACKED;

/*
 * Unregister message.
 */
PREPACKED struct np_unregister {
	struct np_encaps_key encaps;
	struct np_head head;
	u8	addr_len;	/* IP address length (zero if no address) */
	u8	proto;		/* IP address protocol (zero for IPv4) */
	u8	addr[0];	/* IP address to use for service */
} PACKED;

/*
 * Response for Unregister, Request Probe, Probe,
 * Keep-Alive, and Event messages.
 */
PREPACKED struct np_resp {
	struct np_encaps_key encaps;
	struct np_head head;
	u8	error;
} PACKED;

#endif /* __AYLA_NOTIFY_PROTO_H__ */
