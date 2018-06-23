/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_XML_H__
#define __AYLA_XML_H__

#define XML_ARGS	20	/* maximum UTF-8 values per token */
#define XML_MAX_DEPTH	6	/* max depth of XML tree */

/*
 * Max length of text in any tag, including nested tags.
 */
#define XML_MAX_TEXT	800	/* needed for OEM-key + other info */

/*
 * Maximum length of an XML-encoded string that is x bytes long unencoded.
 * This is pessimistic, assuming all unencoded bytes are quotes for example,
 * which encodes to "&quot;", a 6:1 expansion.
 */
#define XML_LEN_EXPAND(x) ((x) * 6)

/*
 * Flags for use in XML tags.
 */
enum xml_tag_flags {
	XT_NONE = 0,
	XT_KEEP_WS = (1 << 0),	/* keep any white space in text */
	XT_GIVE_PARTIAL = (1 << 1),	/* accept partial blocks of data */
};

struct xml_state;

/*
 * Tag description table entry.
 */
struct xml_tag {
	const char *name;
	enum xml_tag_flags flags;
	const struct xml_tag *subtags;
	int (*parse)(struct xml_state *, int argc, char **argv);
};

/*
 * Macros for xml_tag table initialization.
 */
#define XML_TAGF(_name, _flags, _subtags, _parse) \
	{				\
		.name = _name,		\
		.flags = _flags,	\
		.subtags = _subtags,	\
		.parse = _parse,	\
	}

#define XML_TAG(_name, _subtags, _parse) \
	XML_TAGF(_name, 0, _subtags, _parse)

#define XML_TAG_WS(_name, _subtags, _parse) \
	XML_TAGF(_name, XT_KEEP_WS, _subtags, _parse)

enum xml_parse_state {
	XS_IDLE = 0,
	XS_TEXT_SKIP,	/* skipping the tag contents */
	XS_TEXT_START,	/* ready for first byte of text or a tag */
	XS_TEXT,	/* collecting values for a tag */
	XS_TAG_START,	/* saw "<" */
	XS_TAG_QUEST,	/* saw "<?" */
	XS_TAG_BANG,	/* saw "<!" */
	XS_TAG_SLASH,	/* saw "</" */
	XS_TAG_MID,	/* parsing a tag */
	XS_TAG_GT,	/* expecting a > next */
	XS_END_TAG_MID,	/* parsing an end-tag */
	XS_DONE,	/* finished with input */
	XS_ERROR,	/* error encountered.  Ignore further input */
};

struct xml_tag_state {
	const struct xml_tag *list;	/* tag list for subtags */
	char *text_base;	/* textp after opening tag */
	enum xml_tag_flags flags;
	u8 arg_base;		/* argument base index */
};

struct xml_state {
	u8	depth;		/* current stack depth */
	u8	argc;		/* number of argument pointers filled in */
	u16	bytes;		/* input bytes handled */
	char	*textp;		/* pointer to next empty byte in text_buf */
	enum xml_parse_state state;
	char *argv[XML_ARGS];	/* argument pointers into text_buf */
	struct xml_tag_state stack[XML_MAX_DEPTH];
	char text_buf[XML_MAX_TEXT];
	u8	is_partial:1;	/* working with partial data */
};

/*
 * Initialize XML parser state.
 */
void xml_parse_init(struct xml_state *, const struct xml_tag *);

/*
 * Parse XML input string accessed by calling read_byte(),
 * match tags against the table provided, and call parse functions with
 * the values obtained.
 *
 * This may be called multiple times as buffers are received, and will
 * continue from where it left off.
 *
 * Returns < 0 on error.
 */
int xml_parse(struct xml_state *, void *buf, size_t);

/*
 * Do XML character set encoding.
 */
ssize_t xml_encode(char *dest, size_t, const char *src, size_t, size_t *);

/*
 * Do XML character set decoding.
 * Note that this may modify the source string.
 */
ssize_t xml_decode(char *dest, size_t, char *src, size_t, char **);

#endif /* __AYLA_XML_H__ */
