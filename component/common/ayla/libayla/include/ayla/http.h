/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_HTTP_H__
#define __AYLA_HTTP_H__

#define HTTP_ARGS	20	/* maximum tokens per line */
#define HTTP_MAX_TEXT	450	/* max text in any line */

struct http_state;

/*
 * Tag description table entry.
 */
struct http_tag  {
	const char *name;
	void (*parse)(struct http_state *, int argc, char **argv);
};

enum http_parse_state {
	HS_IDLE = 0,
	HS_INIT,	/* building "HTTP" or other string followed by blank */
	HS_TAG,		/* building tag (looking for :) */
	HS_TEXT_WS,	/* skipping white space before or inside text */
	HS_TEXT,	/* building body of tag */
	HS_CR,		/* saw CR */
	HS_CRLF,	/* saw CRLF */
	HS_CRLFCR,	/* found CRLF + CR */
	HS_DONE,	/* finished with header */
	HS_ERROR,	/* error encountered.  Ignore further input */
};

struct http_state {
	const struct http_tag *list;	/* tag list for handlers */
	u8	depth;		/* current stack depth */
	u8	argc;		/* number of argument pointers filled in */
	u16	bytes;		/* input bytes handled */
	u32	status;		/* HTTP status or Chunk Size */
	char	*textp;		/* pointer to next empty byte in text_buf */
	enum http_parse_state state;
	char *argv[HTTP_ARGS];	/* argument pointers into text_buf */
	char text_buf[HTTP_MAX_TEXT];
	u8	chunked;	/* bool for chunked-header parsing */
	u8	chunk_set;	/* bool for determining if chunk-size is set */
};

/*
 * Initialize HTTP parser state.
 */
void http_parse_init(struct http_state *, const struct http_tag *);
void http_chunk_init(struct http_state *, const struct http_tag *);

/*
 * Parse HTTP input string.
 * Match tags against the table provided, and call parse functions with
 * the values obtained.
 *
 * This may be called multiple times as buffers are received, and will
 * continue from where it left off.
 *
 * Returns < 0 on error.
 * Returns length consumed on success.  If less than size_t, the length
 * is the offset of the start of the body of the HTTP message.
 */
int http_parse(struct http_state *, void *buf, size_t);

/*
 * HTTP Protocol status values.
 */
#define HTTP_STATUS_CONTINUE	100
#define HTTP_STATUS_OK		200
#define HTTP_STATUS_CREATED	201
#define HTTP_STATUS_ACCEPTED	202
#define HTTP_STATUS_NO_CONTENT	204
#define HTTP_STATUS_PAR_CONTENT	206
#define HTTP_STATUS_MULTI_STATUS 207
#define HTTP_STATUS_REDIR_MIN	300
#define HTTP_STATUS_REDIR_PERM	301
#define HTTP_STATUS_FOUND	302
#define HTTP_STATUS_REDIR_MAX	399
#define HTTP_STATUS_BAD_REQ	400
#define HTTP_STATUS_UNAUTH	401
#define HTTP_STATUS_FORBID	403
#define HTTP_STATUS_NOT_FOUND	404
#define HTTP_STATUS_NOT_ACCEPT	406
#define HTTP_STATUS_CONFLICT	409
#define HTTP_STATUS_PRECOND_FAIL 412
#define HTTP_STATUS_REQ_LARGE	413
#define HTTP_STATUS_EXP		417
#define HTTP_STATUS_TOO_MANY	429
#define HTTP_STATUS_INTERNAL_ERR 500
#define HTTP_STATUS_SERV_UNAV	503

#endif /* __AYLA_HTTP_H__ */
