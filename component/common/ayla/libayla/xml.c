/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <ayla/utypes.h>
#include <ayla/xml.h>

#ifdef XML_TEST
#include <stdio.h>
#define log_put printf
#else
#include <ayla/log.h>
#endif /* XML_TEST */

void xml_parse_init(struct xml_state *state, const struct xml_tag *list)
{
	memset(state, 0, sizeof(*state));
	state->stack[0].list = list;
	state->state = XS_TEXT_SKIP;
	state->argv[0] = state->text_buf;
	state->textp = state->text_buf;
}

static const struct xml_tag *
xml_tag_find(const struct xml_tag *table, const char *name)
{
	const struct xml_tag *tag;

	if (!table) {
		return NULL;
	}
	for (tag = table; tag->name; tag++) {
		if (!strcmp(name, tag->name)) {
			return tag;
		}
	}
	return NULL;
}

/*
 * Add a character to the current tag or text accumulation.
 */
static int xml_putc(struct xml_state *state, unsigned char byte)
{
	if (state->textp >= &state->text_buf[XML_MAX_TEXT - 1]) {
		log_put("xml_putc: text limit exceeded\n");
		return -1;
	}
	*state->textp++ = byte;
	return 0;
}

/*
 * Add an argument
 */
static int xml_put_arg(struct xml_state *state, char *arg)
{
	if (state->argc >= XML_ARGS) {
		log_put("xml_parse: argc exceeded\n");
		return -1;
	}
	state->argv[state->argc++] = arg;
	return 0;
}

static int xml_ws(u8 byte)
{
	return byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r';
}

/*
 * Decode arguments in place, which are NUL-terminated.
 */
static int xml_decode_args(int argc, char **argv, char **leftover)
{
	char *arg;
	ssize_t rc;
	int argcount = argc;

	while (argcount-- > 0) {
		arg = *argv++;
		rc = xml_decode(arg, MAX_U16, arg, MAX_U16, leftover);
		if (rc < 0) {
bad_encoding:
			log_put("xml_parse: bad encoding\n");
			return -1;
		}
		if (*leftover && argc != 1) {
			goto bad_encoding;
		}
	}
	return 0;
}

int xml_parse(struct xml_state *state, void *buf, size_t len)
{
	unsigned char *bp = buf;
	unsigned char byte;
	enum xml_parse_state xml_state;
	struct xml_tag_state *ts;
	const struct xml_tag *tag;
	size_t len_used;
	char *name;
	int argc;
	char **argv;
	int rc = 0;
	char *leftoverptr;
	char leftover[10];
	int i;

	state->bytes++;
	xml_state = state->state;
	ts = &state->stack[state->depth];
	leftover[0] = '\0';
	for (len_used = 0; len_used < len; len_used++) {
		byte = *bp++;
		switch (xml_state) {
		case XS_TEXT_START:
			if (byte == '<') {
				xml_state = XS_TAG_START;
				break;
			}
			if (xml_ws(byte) && (ts->flags & XT_KEEP_WS) == 0) {
				break;
			}
			if (xml_put_arg(state, state->textp)) {
				goto error;
			}
			if (xml_putc(state, byte)) {
				goto error;
			}
			xml_state = XS_TEXT;
			break;

		case XS_TEXT:
			if (byte == '<') {
				if (xml_putc(state, '\0')) {
					goto error;
				}
				xml_state = XS_TAG_START;
				break;
			}
			if (xml_ws(byte) && (ts->flags & XT_KEEP_WS) == 0) {
				break;
			}
			name = state->argv[state->argc - 2];
			if (state->textp >=
			    &state->text_buf[XML_MAX_TEXT - strlen(name) - 4]) {
				/*
				 * if there's no space in the buffer
				 * for closing tag
				 */
				if (!(ts->flags & XT_GIVE_PARTIAL)) {
					goto error;
				}
				*state->textp++ = '\0';
				/*
				 * Check depth
				 */
				if (state->depth == 0) {
					log_put("xml_parse: "
					    "parse stack underflow\n");
					goto error;
				}
				tag = xml_tag_find((ts - 1)->list, name);
				if (tag && tag->parse) {
					argc = state->argc - ts->arg_base;
					argv = state->argv + ts->arg_base;
					leftoverptr = NULL;
					if (xml_decode_args(argc, argv,
					    &leftoverptr)) {
						goto error;
					}
					if (leftoverptr) {
						strncpy(leftover,
						    leftoverptr,
						    sizeof(leftover) - 1);
						*leftoverptr = '\0';
					}
					state->is_partial = 1;
					rc = tag->parse(state, argc, argv);
				}
				state->textp = state->argv[state->argc - 1];
			}
			for (i = 0; leftover[i] != '\0'; i++) {
				xml_putc(state, leftover[i]);
			}
			leftover[0] = '\0';
			xml_putc(state, byte);
			if (rc == -1) {
				/* caller can't accept, wait for cb */
				len_used++;
				goto out;
			}
			break;

		case XS_TEXT_SKIP:
			if (byte == '<') {
				xml_state = XS_TAG_START;
			}
			break;

		case XS_TAG_START:
			if (byte == '!') {
				xml_state = XS_TAG_BANG;
				break;
			} else if (byte == '?') {
				xml_state = XS_TAG_QUEST;
				break;
			} else if (byte == '/') {
				xml_state = XS_TAG_SLASH;
				break;
			}
			if (xml_putc(state, '\0')) {
				goto error;
			}
			if (xml_put_arg(state, state->textp)) {
				goto error;
			}
			xml_state = XS_TAG_MID;
			/* fall through */
		case XS_TAG_MID:
			/*
			 * Accumulating a tag.
			 */
			if (byte == ' ') {
				/*
				 * tag attribute.  Ignore for now.
				 * put NUL over space.
				 */
				if (xml_putc(state, '\0')) {
					goto error;
				}
			} else if (byte == '/') {
				/*
				 * <tag /> format found
				 */
				 xml_state = XS_TAG_GT;
			} else if (byte == '>') {
				/*
				 * NUL-terminate arg
				 */
				if (xml_putc(state, '\0')) {
					goto error;
				}

				/*
				 * Finished collecting tag name.
				 * Look it up in the list.
				 */
				name = state->argv[state->argc - 1];
				tag = xml_tag_find(ts->list, name);

				/*
				* Push state for parsing the new tag.
				*/
				if (state->depth >= XML_MAX_DEPTH) {
					log_put("xml_parse: "
					    "tag depth limit exceeded. "
					    "tag '%s'\n", name);
					goto error;
				}
				state->depth++;
				ts++;
				ts->list = tag ? tag->subtags : NULL;
				ts->flags = tag ? tag->flags : 0;
				ts->arg_base = state->argc;
				xml_state = XS_TEXT_START;
			} else if (xml_putc(state, byte)) {
				goto error;
			}
			break;

		case XS_TAG_GT:
			if (byte != '>') {
				goto error;
			}
			if (state->depth == 0) {
				xml_state = XS_DONE;
			} else {
				xml_state = XS_TEXT_START;
			}
			break;

		case XS_TAG_SLASH:
			/*
			 * Start of end tag.
			 * Allocate argument to hold tag value.
			 */
			if (xml_putc(state, '\0')) {
				goto error;	/* terminate prev arg */
			}
			if (xml_put_arg(state, state->textp)) {
				goto error;
			}
			xml_state = XS_TAG_MID;
			/* fall through */
		case XS_END_TAG_MID:
			/*
			 * Accumulating an end tag.
			 */
			xml_state = XS_END_TAG_MID;
			if (byte == '>') {
				/*
				 * Finished collecting tag name.
				 * Should match with current tag.
				 * Find in parent list.
				 */
				if (xml_putc(state, '\0')) {
					goto error;
				}
				state->argc--;		/* remove end arg */
				name = state->argv[state->argc];
				if (strcmp(name,
				    state->argv[ts->arg_base - 1])) {
					log_put("xml_parse: "
					    "unmatched tag %s\n", name);
					goto error;
				}

				/*
				 * Pop tag state.
				 */
				if (state->depth == 0) {
					log_put("xml_parse: "
					    "parse stack underflow\n");
					goto error;
				}
				state->depth--;
				tag = xml_tag_find((ts - 1)->list, name);
				if (tag && tag->parse) {
					argc = state->argc - ts->arg_base;
					argv = state->argv + ts->arg_base;
					leftoverptr = NULL;
					if (xml_decode_args(argc, argv,
					    &leftoverptr)) {
						goto error;
					}
					if (leftoverptr) {
						goto error;
					}
					state->is_partial = 0;
					rc = tag->parse(state, argc, argv);
				}
				state->argc = ts->arg_base - 1;
				state->textp = state->argv[state->argc];
				ts--;
				xml_state = XS_TEXT_START;
				if (state->depth == 0) {
					xml_state = XS_DONE;
				}
				if (rc == -1) {
					/* caller can't accept, wait for cb */
					len_used++;
					goto out;
				}
				break;
			}
			if (xml_putc(state, byte)) {
				goto error;
			}
			break;

		case XS_TAG_BANG:
		case XS_TAG_QUEST:
			if (byte == '>') {
				xml_state = XS_TEXT_START;
			}
			break;
		case XS_DONE:
			if (xml_ws(byte) && (ts->flags & XT_KEEP_WS) == 0) {
				break;
			}
			log_put("xml_parse: extra text '%c' after done\n",
			    byte);
			goto error;
		case XS_IDLE:
			log_put("xml_parse: not initialized\n");
			goto error;
		case XS_ERROR:
			goto error;
		default:
			log_put("xml_parse: unknown state %u\n", state->state);
			goto error;
		}
	}
out:
	state->state = xml_state;
	return len_used;
error:
	state->state = XS_ERROR;
	return -1;
}
