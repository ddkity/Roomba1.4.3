/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ayla/utypes.h>
#ifdef HTTP_TEST
#include <stdio.h>
#define log_put printf
#else
#include <ayla/log.h>
#endif
#include <ayla/http.h>

void http_parse_init(struct http_state *state, const struct http_tag *list)
{
	memset(state, 0, sizeof(*state));
	state->list = list;
	state->state = HS_INIT;
	state->argv[0] = state->text_buf;
	state->argc = 1;
	state->textp = state->text_buf;
	state->chunked = 0;
}

void http_chunk_init(struct http_state *state, const struct http_tag *list)
{
	memset(state, 0, sizeof(*state));
	state->list = list;
	state->state = HS_TEXT_WS;
	state->argv[0] = state->text_buf;
	state->argc = 1;
	state->textp = state->text_buf;
	state->chunked = 1;
	state->chunk_set = 0;
}


static const struct http_tag *
http_tag_find(const struct http_tag *table, const char *name)
{
	const struct http_tag *tag;

	if (!table) {
		return NULL;
	}
	for (tag = table; tag->name; tag++) {
		if (!strcasecmp(name, tag->name)) {
			return tag;
		}
	}
	return NULL;
}

/*
 * Add a character to the current tag or text accumulation.
 */
static int http_putc(struct http_state *state, unsigned char byte)
{
	if (state->textp >= &state->text_buf[HTTP_MAX_TEXT - 1]) {
		log_put("http_putc: text limit exceeded\n");
		return -1;
	}
	*state->textp++ = byte;
	return 0;
}

/*
 * Add an argument
 */
static int http_put_arg(struct http_state *state, char *arg)
{
	if (state->argc >= HTTP_ARGS) {
		log_put("http_parse: argc exceeded\n");
		return -1;
	}
	state->argv[state->argc++] = arg;
	return 0;
}

static int http_ws(u8 byte)
{
	return byte == ' ' || byte == '\t';
}

int http_parse(struct http_state *state, void *buf, size_t len)
{
	unsigned char *bp = buf;
	unsigned char byte;
	enum http_parse_state http_state;
	const struct http_tag *tag;
	char *errptr;
	size_t tlen;

	state->bytes++;
	http_state = state->state;

	for (tlen = 0; http_state != HS_DONE && tlen < len; tlen++) {
		byte = *bp++;
		switch (http_state) {
		case HS_INIT:
			if (http_ws(byte)) {
				if (http_putc(state, '\0')) {
					goto error;
				}
				http_state = HS_TEXT_WS;
				break;
			}
			if (http_putc(state, byte)) {
				goto error;
			}
			break;

		case HS_TEXT_WS:
			if (http_ws(byte)) {
				break;
			}

			if (http_put_arg(state, state->textp)) {
				goto error;
			}
			http_state = HS_TEXT;
			/* fall-through */
		case HS_TEXT:
			if (byte == '\r' || (byte == ';' && state->chunked)) {
				if (http_putc(state, '\0')) {
					goto error;
				}
				http_state = HS_CR;
				break;
			}
			if (http_ws(byte)) {
				if (http_putc(state, '\0')) {
					goto error;
				}
				http_state = HS_TEXT_WS;
				break;
			}
			if (http_putc(state, byte)) {
				goto error;
			}
			break;

		case HS_CR:
			if (state->chunked) {
				if (!state->chunk_set) {
					if (!strcmp(state->argv[0], "") &&
					    byte == '\n') {
						http_chunk_init(state, NULL);
						http_state = HS_TEXT_WS;
						break;
					}
					state->chunk_set = 1;
					state->status =
					    (u32)strtoul(state->argv[0],
					    &errptr, 16);
					if (*errptr != '\0') {
						goto error;
					}
					if (state->status != 0 &&
					    byte == '\n') {
						http_state = HS_DONE;
						break;
					}
					state->textp = state->text_buf;
					state->argc = 1;
					if (http_putc(state, byte)) {
						goto error;
					}
					http_state = HS_TAG;
					break;
				}
				if (byte == '\n') {
					http_state = HS_CRLF;
					break;
				}
				goto tag_find;
			}

			if (byte != '\n') {
				log_put("http_parse: missing LF\n");
				goto error;
			}

			http_state = HS_CRLF;
			break;

		case HS_CRLF:
			/*
			 * Start of new line.  Look for continuation or '\r'.
			 */
			if (http_ws(byte)) {
				http_state = HS_TEXT_WS;
				break;
			}

			if (strncmp(state->argv[0], "HTTP", 4) == 0 &&
			    state->argc > 2) {
				state->status = (u32)strtoul(state->argv[1],
				    &errptr, 10);
				if (*errptr != '\0') {
					state->status = 0;
				}
			}
			/*
			 * End of previous line.  Handle the token here.
			 */
tag_find:
			tag = http_tag_find(state->list, state->argv[0]);
			if (tag && tag->parse) {
				tag->parse(state,
				    state->argc - 1, state->argv + 1);
			}
			if (byte == '\r') {
				http_state = HS_CRLFCR;
				break;
			}

			state->textp = state->text_buf;
			state->argc = 1;
			if (http_putc(state, byte)) {
				goto error;
			}
			http_state = HS_TAG;
			break;

		case HS_TAG:
			if (byte == ':' || (byte == '=' && state->chunked)) {
				if (http_putc(state, '\0')) {
					goto error;
				}
				http_state = HS_TEXT_WS;
				break;
			}
			if (byte == '\r' && state->chunked) {
				http_state = HS_CRLFCR;
			}
			if (http_putc(state, byte)) {
				goto error;
			}
			break;

		case HS_CRLFCR:
			if (byte != '\n') {
				log_put("http_parse: missing final LF\n");
				goto error;
			}
			http_state = HS_DONE;
			break;

		case HS_IDLE:
			log_put("http_parse: not initialized\n");
			goto error;
		case HS_ERROR:
			goto error;
		default:
			log_put("http_parse: unknown state %u\n", state->state);
			goto error;
		}
	}
	state->state = http_state;
	return tlen;
error:
	state->state = HS_ERROR;
	return -1;
}
