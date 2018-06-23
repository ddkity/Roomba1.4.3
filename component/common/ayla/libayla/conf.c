/*
 * Copyright 2011-2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/tlv.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/endian.h>
#include <ayla/crc.h>
#include <ayla/clock.h>
#include <ayla/utf8.h>
#include <ayla/malloc.h>

#define CONF_SHOW_ALL	0	/* if 1, "conf show" shows even duplicates */

static const char * const conf_tokens[] = {
#define CONF_TOKEN(val, name)	[val] = #name,
#include <ayla/conf_tokens.h>
#undef CONF_TOKEN
};

struct conf_tree {
	struct conf_tree *child;	/* subtree */
	struct conf_tree *sib;		/* sibling */
	enum conf_token token;		/* name token at this level */
	size_t off;			/* offset of value token or ~0 */
	size_t fact_off;		/* offset of factory value or ~0 */
};

struct conf_tlv_buf {
	u8 *val;			/* space for value TLV */
	int val_len;			/* size of that space */
	u8 *name;			/* space for name TLV */
	int name_len;			/* size of that space */
};

#define CONF_OFF_INV	((size_t)~0)	/* invalid offset */

struct conf_state conf_state;

u8 conf_mfg_mode = 1;
u8 conf_mfg_pending = 1;
u8 conf_setup_mode = 1;
u8 conf_setup_pending = 1;
u8 conf_id_reset_en;
#ifdef AYLA_BC
static u8 conf_id_old_format;
#endif /* AYLA_BC */
static struct conf_tree *conf_tree;

/*
 * Dynamic pointer to config table.
 * This starts out pointing to the application's base config table,
 * but may be re-allocated to add entries.
 */
static const struct conf_entry * const *conf_master_table = conf_table;

#define CONF_FIND_FACTORY	0x1	/* look for factory conf only */
#define CONF_FIND_FIRST		0x2	/* stop after finding first */
#define CONF_FIND_PREFIX	0x4	/* match name as prefix */

static int conf_find_tlv(struct ayla_tlv *name, size_t *soff, size_t eoff,
    size_t *fact_off, u8 type);
static int conf_next_tlv(struct conf_file *file, struct conf_tlv_buf *bufs,
    size_t *off, size_t *next_off, struct ayla_tlv **nt, struct ayla_tlv **vt);
static struct conf_tree *conf_tree_add(struct conf_tree **tree,
    struct ayla_tlv *name_tlv, size_t off, int del);
static struct conf_tree *conf_tree_lookup(struct conf_tree *tree,
    enum conf_token path[], int plen, int del);
static struct conf_tree *conf_tree_lookup_tlv(struct conf_tree *tree,
    struct ayla_tlv *, int del);
static int conf_get_tokens(enum conf_token *argv, int argc_max,
			u8 *name, size_t name_len);

static s32 conf_get_int_common(struct ayla_tlv *);
static u32 conf_get_uint_common(struct ayla_tlv *);

void conf_log(const char *fmt, ...)
{
	ADA_VA_LIST args;

	ADA_VA_START(args, fmt);
	log_put_va(MOD_LOG_CONF, fmt, args);
	ADA_VA_END(args);
}

#ifndef CONF_NO_ID_FILE
void conf_id_reset(void)
{
#if defined(ARCH_stm32f2) || defined(ARCH_stm32f4)
	if (conf_id_old_format) {
		printcli("id reset not possible");
		return;
	}
#endif
	conf_id_reset_en = 1;
}
#endif

int conf_save_as_factory(void)
{
	struct conf_state *state = &conf_state;

	if (state->save_as_factory) {
		return 1;
	}
	if (conf_mfg_mode | conf_mfg_pending |
	    conf_setup_mode | conf_setup_pending) {
		return 1;
	}
	return 0;
}

/*
 * Call conf_entry set op for specified node.
 * Returns 0 on success.
 */
enum conf_error conf_entry_set(int src, enum conf_token *tk, size_t ct,
				struct ayla_tlv *tlv)
{
	const struct conf_entry * const *tp;
	const struct conf_entry *ep;
	enum conf_error rc;

	for (tp = conf_master_table; (ep = *tp) != NULL; tp++) {
		if (ep->token == *tk) {
			conf_state.error = 0;
			rc = ep->set(src, tk + 1, ct - 1, tlv);
			if (rc == CONF_ERR_NONE) {
				rc = conf_state.error;
			}
			if (rc != CONF_ERR_PATH) {
				return rc;
			}
		}
	}
	return CONF_ERR_PATH;
}

/*
 * Call conf_entry get op for specified node.
 * Returns 0 on success.
 */
enum conf_error conf_entry_get(int src, enum conf_token *tk, size_t ct)
{
	const struct conf_entry * const *tp;
	const struct conf_entry *ep;
	enum conf_error rc;

	for (tp = conf_master_table; (ep = *tp) != NULL; tp++) {
		if (ep->token == *tk) {
			conf_state.error = 0;
			rc = ep->get(src, tk + 1, ct - 1);
			if (rc == CONF_ERR_NONE) {
				rc = conf_state.error;
			}
			if (rc != CONF_ERR_PATH) {
				return rc;
			}
		}
	}
	return CONF_ERR_PATH;
}

/*
 * return configuration string for token.
 */
const char *conf_string(enum conf_token token)
{
	if (token >= ARRAY_LEN(conf_tokens)) {
		return NULL;
	}
	return conf_tokens[token];
}

/*
 * return configuration token for string.
 */
enum conf_token conf_token_parse(const char *arg)
{
	enum conf_token token;

	for (token = 0; token < sizeof(conf_tokens) / sizeof(conf_tokens[0]);
	     token++) {
		if (conf_tokens[token] != NULL &&
		    strcmp(conf_tokens[token], arg) == 0) {
			return token;
		}
	}
	return CT_INVALID_TOKEN;
}

static const char * const tlv_names[] = {
	[ATLV_NAME] = "name",
	[ATLV_INT] = "int",
	[ATLV_UINT] = "uint",
	[ATLV_BIN] = "bin",
	[ATLV_UTF8] = "utf-8",
	[ATLV_CONF] = "conf",
	[ATLV_ERR] = "err",
	[ATLV_FORMAT] = "format",
	[ATLV_FRAG] = "frag",
	[ATLV_NOP] = "nop",
	[ATLV_FLOAT] = "float",
	[ATLV_CONF_FACTORY] = "conf_fact",
};

size_t conf_tlv_len(const struct ayla_tlv *tlv)
{
	size_t tlen = tlv->len;
	enum ayla_tlv_type type = tlv->type;

	if (type & ATLV_FILE) {
		tlen |= (type & ~ATLV_FILE) << 8;
	}
	return tlen;
}

static u8 conf_table_follows(enum conf_token tok)
{
	return tok == CT_n || tok == CT_profile || tok == CT_mod;
}

static char *conf_path_format(char *buf, size_t len, int argc,
				enum conf_token *argv)
{
	enum conf_token tok;
	u8 table = 0;
	ssize_t tlen = 0;

	buf[0] = '\0';
	while (argc-- > 0) {
		tok = *argv++;
		if (table) {
			tlen += snprintf(buf + tlen, len - tlen,
				"%u%s", tok, argc ? "/" : "");
			table = 0;
			continue;
		}
		table = conf_table_follows(tok);
		tlen += snprintf(buf + tlen, len - tlen, "%s%s",
		    conf_string(tok), argc ? "/" : "");
	}
	return buf;
}

int conf_path_parse(enum conf_token *tokens, int ntokens, const char *name)
{
	enum conf_token tok;
	int ntok = 0;
	unsigned long val;
	u8 table = 0;
	ssize_t tlen = 0;
	char path_buf[40];
	char *errptr;
	const char *cp;
	const char *elem = name;

	/* XXX TBD: replace this with the similar conf_str_to_tokens() */

	while (*elem) {
		cp = strchr(elem, '/');
		if (cp) {
			tlen = cp - elem;
		} else {
			tlen = strlen(elem);
		}
		if (tlen > sizeof(path_buf) - 1) {
			return -1;
		}
		memcpy(path_buf, elem, tlen);
		path_buf[tlen] = '\0';

		if (cp) {
			elem = cp + 1;
		} else {
			elem += tlen;
		}

		if (table) {
			table = 0;
			val = strtoul(path_buf, &errptr, 10);
			if (*errptr != '\0') {
				printcli("%s: strtoul parse failed on %s",
				    __func__, path_buf);
				return -1;
			}
			tok = val;
		} else {
			tok = conf_token_parse(path_buf);
			if (tok == CT_INVALID_TOKEN) {
				printcli("%s: token parse failed on %s",
				    __func__, path_buf);
				return -1;
			}
			table = conf_table_follows(tok);
		}
		if (!ntokens) {
			printcli("%s: too nany tokens for %s",
			    __func__, name);
			return -1;
		}
		*tokens++ = tok;
		ntokens--;
		ntok++;
	}
	return ntok;
}

static void conf_tlv_fmt(char *obuf, size_t len, struct ayla_tlv *tlv)
{
	enum ayla_tlv_type type;
	u8 *vp;
	char buf[40];
	size_t tlen = conf_tlv_len(tlv);
	u32 val;
	s32 sval;
	u32 slen;
	enum conf_token path[CONF_PATH_MAX];
	int plen;

	obuf[0] = '\0';
	obuf[len - 1] = '\0';	/* guarantee newline */
	len--;

	type = tlv->type;
	if (type & ATLV_FILE) {
		type = ATLV_FILE;
	}

	switch (type) {
	case ATLV_NAME:
	case ATLV_UTF8:
		if (tlen > sizeof(buf) - 1) {
			tlen = sizeof(buf) - 1;
		}
		memcpy(buf, tlv + 1, tlen);
		buf[tlen] = '\0';
		snprintf(obuf, len, "\"%s\"", buf);
		break;

	case ATLV_INT:
	case ATLV_UINT:
	case ATLV_BOOL:
	case ATLV_ERR:
	case ATLV_FORMAT:
		if (type == ATLV_UINT) {
			val = conf_get_uint_common(tlv);
			snprintf(obuf, len, "%lu = 0x%lx", val, val);
		} else if (type == ATLV_BOOL) {
			val = conf_get_uint_common(tlv);
			snprintf(obuf, len, "%lu", val);
		} else {
			sval = conf_get_int_common(tlv);
			snprintf(obuf, len, "%ld = 0x%lx", sval, sval);
		}
		break;

	case ATLV_BIN:
	case ATLV_FRAG:
	case ATLV_NOP:
	case ATLV_FLOAT:
	case ATLV_FILE:
	case ATLV_SCHED:
		slen = 0;
		vp = (u8 *)(tlv + 1);
		slen = snprintf(obuf, len, "len %u ", (unsigned int)tlen);
		while (tlen-- > 0 && slen < sizeof(buf)) {
			slen += snprintf(obuf + slen, len - slen,
				"%2.2x ", *vp++);
		}
		break;

	case ATLV_CONF:
	case ATLV_CONF_FACTORY:
		tlen--;
		/* fall-through */
	case ATLV_CONF_CD:
	case ATLV_CONF_CD_ABS:
	case ATLV_CONF_CD_PAR:
		/*
		 * These occur only old format config files.
		 * Convert the value to tokens and format as a path.
		 */
		plen = conf_get_tokens(path, CONF_PATH_MAX,
		    (u8 *)(tlv + 1), tlen);
		if (plen > 0) {
			conf_path_format(obuf, len, plen, path);
		}
		break;

	case ATLV_DELETE:
		snprintf(obuf, len, "delete");
		break;

	default:
		snprintf(obuf, len, "unknown type %u L %u",
		    tlv->type, (unsigned int)tlen);
		break;
	}
}

#if !defined(WMSDK)
static int conf_need_compress(int name_cnt, size_t val_len)
{
	struct conf_state *state = &conf_state;

	if (state->off + name_cnt * 4 + val_len >
	    state->file->max_len - sizeof(struct conf_head)) {
		return 1;
	} else {
		return 0;
	}
}

static int conf_compress(enum conf_inode from_inode, enum conf_inode to_inode,
    int factory_reset)
{
	struct conf_state *state = &conf_state;
	struct conf_file *from_file, *to_file;
	struct ayla_tlv *name_tlv, *val_tlv;
	size_t next_off, tmp;
	size_t val_off;
	size_t tlen;
	u8 ft;
	u8 namebuf[sizeof(struct ayla_tlv) + CONF_PATH_MAX * sizeof(u32)];
	struct conf_tlv_buf bufs;
	struct conf_tree *node;

	conf_log(LOG_DEBUG "compress: inode %u -> %u",
	    from_inode, to_inode);
	if (conf_flash_open_read(from_inode, &from_file, NULL) < 0 ||
	    conf_flash_open_write(to_inode, &to_file) < 0) {
		conf_log(LOG_ERR "compress: readwrite open error");
		return -1;
	}

	conf_flash_erase_if_needed(to_inode);
	state->off = 0;
	next_off = 0;
	bufs.val = state->next;
	bufs.val_len = state->rlen;
	bufs.name = namebuf;
	bufs.name_len = sizeof(namebuf);

	while (1) {
		val_off = next_off;
		if (conf_next_tlv(from_file, &bufs, &val_off, &next_off,
			&name_tlv, &val_tlv) < 0) {
			break;
		}
		if (name_tlv->type == ATLV_CONF_FACTORY) {
			ft = CONF_FIND_FIRST | CONF_FIND_FACTORY;
		} else {
			if (factory_reset) {
				continue;
			}
			ft = CONF_FIND_FIRST;
		}
		tmp = next_off;
		if (conf_tree) {
			node = conf_tree_lookup_tlv(conf_tree, name_tlv, 0);
			if (!node || (node && node->off > val_off)) {
				/*
				 * This is not the last written value
				 * for this name.
				 */
				continue;
			}
		} else {
			if (!conf_find_tlv(name_tlv, &tmp, MAX_S32, &tmp, ft)) {
				/*
				 * This is not the last written value
				 * for this name.
				 */
				continue;
			}
		}
		if (val_tlv->type == ATLV_DELETE) {
			/*
			 * Deleted TLV, don't carry over.
			 */
			continue;
		}
		tmp = conf_tlv_len(val_tlv);
		tmp += conf_flash_file_align(to_file, tmp);
		tlen = tmp;
		tmp += conf_tlv_len(name_tlv);
		tmp += conf_flash_file_align(to_file, tmp);
		tmp += 2 * sizeof(struct ayla_tlv);
		tlen += 2 * sizeof(struct ayla_tlv);

		/*
		 * Copy value and name TLVs.
		 */
		if (conf_tree) {
			conf_tree_add(&conf_tree, name_tlv, state->off, 0);
		}
		for (; tmp; tmp -= tlen) {
			tlen = tmp;
			if (tlen > state->rlen) {
				tlen = state->rlen;
			}
			val_tlv = conf_flash_read(from_file, val_off,
			    state->next, tlen);
			if (!val_tlv) {
				goto read_err;
			}
			val_off += tlen;
			if (conf_flash_write_blk(to_file, state->off,
				val_tlv, tlen)) {
				conf_log(LOG_ERR "compress: write err");
				continue;
			}
			state->off += tlen;
		}
	}
read_err:
	conf_flash_write_head(to_file, ++state->gen_id);
	conf_flash_erase(from_inode);

	/*
	 * Data copied. Now adjust conf_state.
	 */
	tmp = state->conf_cur;
	state->conf_cur = state->conf_other;
	state->conf_other = tmp;
	state->file = to_file;
	state->inode = to_inode;
	state->file_off = 0;
	conf_flash_flush(to_inode);

	return 0;
}

static int conf_check_fit(size_t val_len)
{
	struct conf_state *state = &conf_state;

	if (state->show_conf) {
		return 0;
	}
	if (state->inode == state->conf_cur &&
	    conf_need_compress(state->path_len + 1, val_len)) {
		if (conf_compress(state->conf_cur, state->conf_other, 0)) {
			return -1;
		}
	}
	return 0;
}
#else
int conf_check_fit(size_t val_len);
#endif

static void conf_walk(struct conf_state *state)
{
	const struct conf_entry * const *tp;
	u8 conf_buf[CONF_VAL_MAX];

	state->error = CONF_ERR_NONE;
	state->next = conf_buf;
	state->rlen = sizeof(conf_buf);
#ifdef CONF_NO_ID_FILE
	tp = conf_master_table;
#else
	if (state->inode == CI_ID) {
		tp = conf_id_table;
	} else {
		tp = conf_master_table;
	}
#endif /* CONF_NO_ID_FILE */
	for (; (*tp) != NULL && state->error == 0; tp++) {
		conf_cd_root((*tp)->token);
		if ((*tp)->export) {
			(*tp)->export();
		}
	}
}

/*
 * Save running configuration.
 */
int conf_save(enum conf_inode inode)
{
	struct conf_state *state = &conf_state;
	struct conf_file *file;
#ifndef CONF_NO_ID_FILE
	struct flash_dev *dev;
	u32 tmp = state->off;
	int off;
#endif /* CONF_NO_ID_FILE */
	int rc;

#ifdef CONF_NO_ID_FILE
	if (inode == CI_ID) {
		return 0;
	}
#endif /* CONF_NO_ID_FILE */

	if (inode != CI_ID) {
		inode = conf_state.conf_cur;
	}
	if (conf_flash_open_write(inode, &file) < 0) {
		conf_log(LOG_ERR "save: readwrite open error");
		return -1;
	}

	if (inode == CI_ID) {
#ifndef CONF_NO_ID_FILE
		state->off = 0;

		/*
		 * If re-writing OTP area, advance past the non-erased and
		 * locked areas.
		 */
		if (conf_id_reset_en) {
			dev = conf_flash_open(file->dev);
			if (dev->ops->find_writeable) {
				off = dev->ops->find_writeable(dev,
				    file->loc + state->off +
				    sizeof(struct conf_head),
				    file->max_len - sizeof(struct conf_head));
				if (off < 0) {
					conf_log(LOG_ERR
					    "save: id not rewritable");
					return -1;
				}
				state->off += off;
			}
		} else {
			conf_flash_write_head(file, ++state->gen_id);
		}
#endif /* CONF_NO_ID_FILE */
	} else if (state->not_valid) {
		conf_flash_write_head(file, ++state->gen_id);
		state->not_valid = 0;
	}
	state->inode = inode;
	state->file = file;
	conf_walk(state);
	/*
	 * we have to do the following so that if a GET happens
	 * we return the new values instead of the old values.
	 */
	conf_mfg_mode = conf_mfg_pending;
	conf_setup_mode = conf_setup_pending;

#ifndef CONF_NO_ID_FILE
	if (inode == CI_ID) {
		conf_flash_lock(state->file, state->off);
		state->off = tmp;
	}
#endif /* CONF_NO_ID_FILE */
	if (state->error == CONF_ERR_NONE) {
		rc = 0;
	} else {
		conf_log(LOG_ERR "save: rlen %u error %u",
		    (unsigned int)state->rlen, state->error);
		rc = -1;
	}
	conf_flash_flush(inode);
	return rc;
}

int conf_save_config(void)
{
	return conf_save(conf_state.conf_cur);
}

/*
 * Caller is going to save specific variables inside (*func).
 */
int conf_persist(enum conf_token root, void (*func)(void *arg), void *arg)
{
	struct conf_state *state = &conf_state;
	u8 conf_buf[CONF_VAL_MAX];
	int rc;

	if (state->not_valid) {
		return -1;
	}
	state->error = CONF_ERR_NONE;
	state->inode = state->conf_cur;
	state->next = conf_buf;
	state->rlen = sizeof(conf_buf);

	conf_cd_root(root);
	func(arg);
	rc = state->error;

	conf_flash_flush(state->inode);
	return (rc != CONF_ERR_NONE);
}

/*
 * Save a single variable in the configuration.
 */
void conf_save_item(enum conf_token *path, size_t path_len,
	enum ayla_tlv_type type, const void *val, size_t len)
{
	struct conf_state *state = &conf_state;
	u8 conf_buf[CONF_VAL_MAX];

	state->error = CONF_ERR_NONE;
	state->inode = state->conf_cur;
	state->next = conf_buf;
	state->rlen = sizeof(conf_buf);

	memcpy(state->path, path, (path_len - 1) * sizeof(*path));
	state->path_len = path_len - 1;
	conf_put(path[path_len - 1], type, val, len);
}

ssize_t tlv_put(void *buf, size_t buflen, enum ayla_tlv_type type,
	const void *val, size_t len)
{
	struct ayla_tlv *tlv;

	if ((len > 0xff && type != ATLV_FILE) || len > 0x7eff ||
	    buflen < sizeof(*tlv) + len) {
		conf_state.error = CONF_ERR_LEN;
		memset(buf, 0, buflen);
		return -1;
	}
	tlv = buf;
	tlv->type = type | (len >> 8);
	tlv->len = len;
	memcpy(tlv + 1, val, len);
	return len + sizeof(*tlv);
}

ssize_t tlv_put_str(void *buf, size_t buflen, const char *val)
{
	return tlv_put(buf, buflen, ATLV_UTF8, val, strlen(val));
}

ssize_t tlv_put_int(void *buf, size_t buflen, s32 val)
{
	void *p;
	s16 vv;
	s8 v;
	u8 len;

	if (val <= MAX_S8 && val >= MIN_S8) {
		len = sizeof(v);
		v = (s8)val;
		p = &v;
	} else if (val <= MAX_S16 && val >= MIN_S16) {
		vv = (s16)val;
		p = &vv;
		len = sizeof(vv);
	} else {
		p = &val;
		len = sizeof(val);
	}
	return tlv_put(buf, buflen, ATLV_INT, p, len);
}

ssize_t tlv_put_uint(void *buf, size_t buflen, u32 val)
{
	void *p;
	u16 vv;
	u8 v;
	u8 len;

	if (val <= MAX_U8) {
		len = sizeof(v);
		v = (u8)val;
		p = &v;
	} else if (val <= MAX_U16) {
		vv = (u16)val;
		p = &vv;
		len = sizeof(vv);
	} else {
		p = &val;
		len = sizeof(val);
	}
	return tlv_put(buf, buflen, ATLV_UINT, p, len);
}

/*
 * Fill in response in buffer.
 */
void conf_resp(enum ayla_tlv_type type, const void *val, size_t len)
{
	struct conf_state *state = &conf_state;
	size_t tlen;

	tlen = tlv_put(state->next, state->rlen, type, val, len);
	state->next += tlen;
	state->rlen -= tlen;
}

void conf_resp_str(const char *str)
{
	conf_resp(ATLV_UTF8, str, strlen(str));
}

void conf_resp_u32(u32 val)
{
	u8 buf[4];

	if (val & 0xffff0000) {
		put_ua_be32(&buf, val);
		conf_resp(ATLV_UINT, buf, 4);
	} else if (val & 0xff00) {
		put_ua_be16(&buf, val);
		conf_resp(ATLV_UINT, buf, 2);
	} else {
		buf[0] = val;
		conf_resp(ATLV_UINT, buf, 1);
	}
}

void conf_resp_s32(s32 val)
{
	u8 buf[4];

	if (val < MIN_S16 || val > MAX_S16) {
		put_ua_be32(&buf, val);
		conf_resp(ATLV_INT, buf, 4);
	} else if (val < MIN_S8 || val > MAX_S8) {
		put_ua_be16(&buf, val);
		conf_resp(ATLV_INT, buf, 2);
	} else {
		buf[0] = val;
		conf_resp(ATLV_INT, buf, 1);
	}
}

void conf_resp_bool(u32 val)
{
	u8 v;

	v = val != 0;
	conf_resp(ATLV_BOOL, &v, sizeof(v));
}

/*
 * Put up to 4 UTF-8 bytes to a buffer from a int value up to 0x10ffff.
 *
 * 4-byte UTF-8 can handle up to 21-bit values, but Unicode further restricts
 * this to values up to 0x10ffff.
 */
int utf8_put_wchar(u8 *bp, u32 val)
{
	if (val > 0x10ffff) {
		return -1;
	}
	if (val >= 0x10000) {
		/* 21 bits */
		bp[0] = 0xf0 + ((val >> 18) & 7);
		bp[1] = 0x80 + ((val >> 12) & 0x3f);
		bp[2] = 0x80 + ((val >> 6) & 0x3f);
		bp[3] = 0x80 + (val & 0x3f);
		return 4;
	}
	if (val >= 0x800) {
		/* 16 bits */
		bp[0] = 0xe0 + ((val >> 12) & 0xf);
		bp[1] = 0x80 + ((val >> 6) & 0x3f);
		bp[2] = 0x80 + (val & 0x3f);
		return 3;
	}
	if (val >= 0x80) {
		/* 11 bits */
		bp[0] = 0xc0 + ((val >> 6) & 0x1f);
		bp[1] = 0x80 + (val & 0x3f);
		return 2;
	}
	/* 7 bits */
	bp[0] = val;
	return 1;
}

static int utf8_put_wchars(enum conf_token *arr, int arr_len, void *vp)
{
	int i, tmp;
	u8 *ptr = vp;

	for (i = 0; i < arr_len; i++) {
		tmp = utf8_put_wchar(ptr, arr[i]);
		if (tmp <= 0) {
			return -1;
		}
		ptr += tmp;
	}
	return ptr - (u8 *)vp;
}

static int conf_get_tokens(enum conf_token *argv, int argc_max,
			u8 *name, size_t name_len)
{
	u32 token[CONF_PATH_MAX];
	int argc;
	int i;

	argc = utf8_gets(token, CONF_PATH_MAX, name, name_len);
	if (argc < 0 || argc > argc_max) {
		return -1;
	}
	for (i = 0; i < argc; i++) {
		if (sizeof(enum conf_token) == sizeof(u8)) {
			if (token[i] > MAX_U8) {
				return -1;
			}
		} else if (sizeof(enum conf_token) == sizeof(u16)) {
			if (token[i] > MAX_U16) {
				return -1;
			}
		}
		argv[i] = token[i];
	}
	return argc;
}

int conf_cd(enum conf_token token)
{
	struct conf_state *state = &conf_state;

	ASSERT(state->path_len < ARRAY_LEN(state->path));
	state->path[state->path_len++] = token;
	return state->path_len - 1;
}

void conf_cd_in_parent(enum conf_token token)
{
	conf_cd_parent();
	conf_cd(token);
}

void conf_cd_parent(void)
{
	struct conf_state *state = &conf_state;
	if (state->path_len) {
		state->path_len--;
	}
}

void conf_cd_table(u8 index)
{
	conf_cd((enum conf_token)index);
}

void conf_cd_root(enum conf_token token)
{
	struct conf_state *state = &conf_state;

	state->path_len = 1;
	state->path[0] = token;
}

void conf_depth_restore(int path_len)
{
	struct conf_state *state = &conf_state;

	state->path_len = path_len;
}

static int conf_print_is_hidden(enum conf_token *path, int plen)
{
	if (plen == 3 && path[0] == CT_client && path[2] == CT_private_key) {
		return 1;
	}
	if (plen == 4 && path[0] == CT_wifi && path[3] == CT_key) {
		return 1;
	}
	if (plen == 3 && path[0] == CT_wifi && path[1] == CT_setup_mode &&
	    path[2] == CT_key) {
		return 1;
	}
	if (plen == 2 && path[0] == CT_acc &&
	    (path[1] == CT_private_key || path[1] == CT_key ||
		path[1] == CT_serial)) {
		return 1;
	}
	if (plen == 4 && path[0] == CT_acc && path[3] == CT_key) {
		return 1;
	}
	return 0;
}

static void conf_print(const char *type, struct ayla_tlv *name,
			struct ayla_tlv *val)
{
	char nbuf[CONF_PATH_MAX * 15];
	char vbuf[CONF_VAL_MAX];
	enum conf_token path[CONF_PATH_MAX];
	int plen;

	plen = conf_get_tokens(path, CONF_PATH_MAX,
	    (u8 *)(name + 1), name->len - 1);
	if (plen < 0) {
		printcli("%s: get tokens failed", __func__);
		return;
	}
	if (plen >= 2 && path[0] == CT_client && path[1] == CT_gif) {
		return;
	}
	conf_path_format(nbuf, sizeof(nbuf), plen, path);
	if (conf_print_is_hidden(path, plen)) {
		printcli("  %s %s = %s",
		    type, nbuf, val->len ? "(set)" : "\"\"");
		return;
	}
	conf_tlv_fmt(vbuf, sizeof(vbuf), val);
	printcli("  %s %s = %s", type, nbuf, vbuf);
}

#if !defined(WMSDK) 
/*
 * Compare the TLV at the given offset in the current file to the supplied one.
 * Return zero on equal comparison, non-zero on anything mismatch or error.
 */
static int conf_tlv_compare(size_t off, const struct ayla_tlv *val)
{
	struct conf_state *state = &conf_state;
	struct ayla_tlv *old_val;
	u8 tmp_buf[CONF_VAL_MAX];
	void *val_ptr;
	size_t tlen;

	tlen = conf_tlv_len(val);
	if (tlen > sizeof(tmp_buf)) {
		return -1;
	}
	old_val = conf_flash_read(state->file, off, tmp_buf, sizeof(*old_val));
	if (old_val && old_val->type == val->type &&
	    old_val->len == val->len) {
	    	if (tlen == 0) {
			return 0;
		}
		/* if type and len are equal tlen will be correct */
		val_ptr = conf_flash_read(state->file,
		    off + sizeof(*old_val), tmp_buf, tlen);
		if (val_ptr) {
			return memcmp(val + 1, val_ptr, tlen);
		}
	}
	return -1;
}

/*
 * Store TLV val with a name given in path to flash.
 */
void conf_put_name_val(enum conf_token *path, int plen,
		struct ayla_tlv *val)
{
	struct conf_state *state = &conf_state;
	int tlen, nlen;
	char namebuf[sizeof(struct ayla_tlv) + CONF_PATH_MAX * sizeof(u32)];
	struct ayla_tlv *name;
	u8 crc, find_type;
	size_t off;
	size_t fact_off;
	int has_val;
	struct conf_tree *node;

	/*
	 * Construct name tlv.
	 */
	name = (struct ayla_tlv *)namebuf;
	nlen = utf8_put_wchars(path, plen, name + 1);
	if (nlen < 0) {
		goto err;
	}
	if (conf_save_as_factory()) {
		name->type = ATLV_CONF_FACTORY;
		find_type = 0;
	} else if (state->migrate_factory) {
		name->type = ATLV_CONF_FACTORY;
		find_type = CONF_FIND_FACTORY;
	} else {
		name->type = ATLV_CONF;
		find_type = 0;
	}
	if (val->type == ATLV_DELETE) {
		find_type |= CONF_FIND_PREFIX;
	}
	name->len = nlen + 1;
	nlen += sizeof(struct ayla_tlv);

	if (CONF_SHOW_ALL && state->show_conf) {
		conf_print("r", name, val);
		return;
	}

	/*
	 * See if the value in flash is the same as the one we're going
	 * to write in now. If yes, then there is no need to write this.
	 * If writing a factory item, the most recent factory item must
	 * also be the same as well.
	 */
	off = 0;
	has_val = 0;
	fact_off = CONF_OFF_INV;
	if (!state->migrate_factory) {
		if (conf_tree && state->inode != CI_ID) {
			node = conf_tree_lookup(conf_tree, path, plen,
			    val->type == ATLV_DELETE);
			if (node) {
				off = node->off;
				fact_off = node->fact_off;
				has_val = 1;
			}
		} else if (!conf_find_tlv(name, &off, MAX_S32,
		     &fact_off, find_type)) {
			has_val = 1;
		}
	}
	tlen = conf_tlv_len(val);
	if (!state->migrate_factory && has_val) {
		/*
		 * Can skip writing if the existing value is the same,
		 * but if writing a factory item, make sure the previous
		 * factory item is also the same, to allow for factory reset.
		 */
		if (name->type == ATLV_CONF_FACTORY) {
			if (val->type != ATLV_DELETE &&
			    (fact_off == CONF_OFF_INV ||
			    !conf_tlv_compare(fact_off, val)) &&
			    (fact_off == off ||
			    !conf_tlv_compare(off, val))) {
				return;
			}
		} else if (!conf_tlv_compare(off, val)) {
			return;
		}
	} else if (val->type == ATLV_DELETE) {
		return;		/* nothing matched which we need to delete */
	}

	if (state->show_conf) {
		conf_print("r", name, val);
		return;
	}

	if (conf_tree && state->inode != CI_ID) {
		conf_tree_add(&conf_tree, name, state->off,
		    val->type == ATLV_DELETE);
	}
	tlen += sizeof(*val);
	tlen += conf_flash_file_align(state->file, tlen);

	crc = crc8(val, tlen, CRC8_INIT);
	conf_flash_write_blk(state->file, state->off, val, tlen);
	state->off += tlen;

	crc = crc8(namebuf, nlen, crc);
	namebuf[nlen++] = crc;

	nlen += conf_flash_file_align(state->file, nlen);
	conf_flash_write_blk(state->file, state->off, namebuf, nlen);
	state->off += nlen;

	return;
err:
	conf_state.error = CONF_ERR_UTF8;
}
#endif

static void conf_put_state_val(enum conf_token token, struct ayla_tlv *val)
{
	struct conf_state *state = &conf_state;

	state->path[state->path_len] = token;
	conf_put_name_val(state->path, state->path_len + 1, val);
}

void conf_put(enum conf_token token, enum ayla_tlv_type type, const void *val,
    ssize_t len)
{
	struct conf_state *state = &conf_state;

	conf_check_fit(len);
	len = tlv_put(state->next, state->rlen, type, val, len);
	if (len < 0) {
		return;
	}
	conf_put_state_val(token, (struct ayla_tlv *)state->next);
}

void conf_delete(enum conf_token token)
{
	struct conf_state *state = &conf_state;

	conf_check_fit(0);
	if (tlv_put(state->next, state->rlen, ATLV_DELETE, NULL, 0) < 0) {
		return;
	}
	conf_put_state_val(token, (struct ayla_tlv *)state->next);
}

void conf_put_str(enum conf_token token, const char *val)
{
	conf_put(token, ATLV_UTF8, val, strlen(val));
}

/*
 * Put string if not empty.
 */
void conf_put_str_ne(enum conf_token token, const char *val)
{
	if (val[0]) {
		conf_put_str(token, val);
	} else {
		conf_delete(token);
	}
}

void conf_put_s32(enum conf_token token, s32 val)
{
	struct conf_state *state = &conf_state;
	ssize_t len;

	conf_check_fit(sizeof(s32));
	len = tlv_put_int(state->next, state->rlen, val);
	if (len < 0) {
		return;
	}
	conf_put_state_val(token, (struct ayla_tlv *)state->next);
}

void conf_put_s32_nz(enum conf_token token, s32 val)
{
	if (val) {
		conf_put_s32(token, val);
	} else {
		conf_delete(token);
	}
}

void conf_put_u32(enum conf_token token, u32 val)
{
	struct conf_state *state = &conf_state;
	ssize_t len;

	conf_check_fit(sizeof(u32));
	len = tlv_put_uint(state->next, state->rlen, val);
	if (len < 0) {
		return;
	}
	conf_put_state_val(token, (struct ayla_tlv *)state->next);
}

void conf_put_u32_nz(enum conf_token token, u32 val)
{
	if (val) {
		conf_put_u32(token, val);
	} else {
		conf_delete(token);
	}
}

void conf_set_error(enum conf_error error)
{
	conf_state.error = error;
}

/*
 * Get a value from a TLV, and return its length.
 * Set an error as a side-effect if it occurs.
 * Add NUL-termination if there is room whether or not it is a string.
 */
size_t conf_get(struct ayla_tlv *tlv, enum ayla_tlv_type type,
		void *val, size_t len)
{
	char *dest = val;
	size_t dlen = tlv->len;

	if (type == ATLV_FILE && (tlv->type & ATLV_FILE) != 0) {
		dlen |= (tlv->type & ~ATLV_FILE) << 8;
	} else if (tlv->type != type) {
		conf_state.error = CONF_ERR_TYPE;
		return 0;
	}
	if (dlen > len) {
		conf_state.error = CONF_ERR_LEN;
		return 0;
	}
	memcpy(val, TLV_VAL(tlv), dlen);
	if (dlen < len) {
		dest[dlen] = '\0';
	}
	return dlen;
}


static s32 conf_get_int_common(struct ayla_tlv *tlv)
{
	s32 val;
	s16 val16;

	switch (tlv->len) {
	case sizeof(u32):
		memcpy(&val, TLV_VAL(tlv), sizeof(val));
		break;
	case sizeof(u16):
		memcpy(&val16, TLV_VAL(tlv), sizeof(val16));
		val = val16;
		break;
	case sizeof(s8):
		val = *(s8 *)TLV_VAL(tlv);
		break;
	default:
		conf_state.error = CONF_ERR_LEN;
		val = 0;
		break;
	}
	return val;
}

static u32 conf_get_uint_common(struct ayla_tlv *tlv)
{
	u32 val;
	u16 val16;

	switch (tlv->len) {
	case sizeof(u32):
		memcpy(&val, TLV_VAL(tlv), sizeof(val));
		break;
	case sizeof(u16):
		memcpy(&val16, TLV_VAL(tlv), sizeof(val16));
		val = val16;
		break;
	case sizeof(u8):
		val = *(u8 *)TLV_VAL(tlv);
		break;
	default:
		conf_state.error = CONF_ERR_LEN;
		val = 0;
		break;
	}
	return val;
}

s32 conf_get_s32(struct ayla_tlv *tlv)
{
	if (tlv->type != ATLV_INT) {
		conf_state.error = CONF_ERR_TYPE;
		return 0;
	}
	return (s32)conf_get_int_common(tlv);
}

u32 conf_get_u32(struct ayla_tlv *tlv)
{
	if (tlv->type != ATLV_UINT) {
		conf_state.error = CONF_ERR_TYPE;
		return 0;
	}
	return conf_get_uint_common(tlv);
}

s16 conf_get_s16(struct ayla_tlv *tlv)
{
	s16 val;
	s32 tval;

	tval = conf_get_s32(tlv);
	val = (s16)tval;
	if (val != tval) {
		conf_state.error = CONF_ERR_RANGE;
		return 0;
	}
	return val;
}

u16 conf_get_u16(struct ayla_tlv *tlv)
{
	u16 val;
	u32 tval;

	tval = conf_get_u32(tlv);
	val = (u16)tval;
	if (val != tval) {
		conf_state.error = CONF_ERR_RANGE;
		return 0;
	}
	return val;
}

s8 conf_get_s8(struct ayla_tlv *tlv)
{
	s8 val;
	s32 tval;

	tval = conf_get_s32(tlv);
	val = (s8)tval;
	if (val != tval) {
		conf_state.error = CONF_ERR_RANGE;
		return 0;
	}
	return val;
}

u8 conf_get_u8(struct ayla_tlv *tlv)
{
	u8 val;
	u32 tval;

	tval = conf_get_u32(tlv);
	val = (u8)tval;
	if (val != tval) {
		conf_state.error = CONF_ERR_RANGE;
		return 0;
	}
	return val;
}

u8 conf_get_bit(struct ayla_tlv *tlv)	/* value must be 0 or 1 */
{
	u8 val;

	if (tlv->type == ATLV_BOOL) {
		val = *(u8 *)TLV_VAL(tlv);
	} else {
		val = conf_get_u8(tlv);
	}
	if (val > 1) {
		conf_state.error = CONF_ERR_RANGE;
		return 0;
	}
	return val;
}

s32 conf_get_int32(struct ayla_tlv *tlv)
{
	int value;

	if (tlv->type == ATLV_INT) {
		value = conf_get_int_common(tlv);
	} else if (tlv->type == ATLV_UINT) {
		value = (s32)conf_get_uint_common(tlv);
		if (value < 0) {
			conf_state.error = CONF_ERR_RANGE;
			return 0;
		}
	} else {
		conf_state.error = CONF_ERR_TYPE;
		return 0;
	}
	return value;
}

/*
 * Parse name, fill in state, return number of elements.
 * return negative value on error.
 */
static int conf_parse_name(struct conf_state *state, struct ayla_tlv *tlv)
{
	size_t rlen = tlv->len;
	int i;

	i = state->path_len;
	if (!state->old_format) {
		rlen--;
	}
	i = conf_get_tokens(state->path + i, CONF_PATH_MAX - i,
	    TLV_VAL(tlv), rlen);
	if (i >= 0) {
		state->name_len = i;
	}
	return i;
}

static int conf_cd_name(struct conf_state *state, struct ayla_tlv *tlv)
{
	if (conf_parse_name(state, tlv) < 0) {
		return -1;
	}
	state->path_len += state->name_len;
	state->name_len = 0;
	return 0;
}

void conf_commit(void)
{
	const struct conf_entry * const *tp;

	for (tp = conf_master_table; (*tp) != NULL; tp++) {
		if ((*tp)->commit != NULL) {
			(*tp)->commit(0);
		}
	}
}

enum conf_error conf_set_tlv(const struct conf_entry *entry,
				enum conf_token *tk,
				int ntokens, struct ayla_tlv *tlv)
{
	enum conf_error error;

	conf_state.error = CONF_ERR_NONE;
	error = entry->set(CONF_OP_SRC_CLI, tk, ntokens, tlv);
	return error == CONF_ERR_NONE ? conf_state.error : error;
}

enum conf_error conf_cli_set_tlv(enum conf_token *tk, int ntokens,
				struct ayla_tlv *tlv)
{
	enum conf_error error;

	error = conf_entry_set(CONF_OP_SRC_CLI, tk, ntokens, tlv);
	return error == CONF_ERR_NONE ? conf_state.error : error;
}

static int conf_read_tlv(struct conf_state *state, struct ayla_tlv *tlv)
{
	int rc;
	int argc;
	enum conf_token *argv;
	enum conf_error err;
	enum ayla_tlv_type type;
	char buf[100];

	type = tlv->type;
	if (type & ATLV_FILE) {
		type = ATLV_FILE;	/* remove length info locally */
	}

	switch (type) {
	case ATLV_CONF:
	case ATLV_CONF_FACTORY:
		rc = conf_parse_name(state, tlv);
		break;
	case ATLV_CONF_CD:
		rc = conf_cd_name(state, tlv);
		break;
	case ATLV_CONF_CD_ABS:
		state->path_len = 0;
		rc = conf_cd_name(state, tlv);
		break;
	case ATLV_CONF_CD_PAR:
		if (state->path_len > 0) {
			state->path_len--;
		}
		rc = conf_cd_name(state, tlv);
		break;
	case ATLV_NAME:
	case ATLV_INT:
	case ATLV_UINT:
	case ATLV_BOOL:
	case ATLV_BIN:
	case ATLV_UTF8:
	case ATLV_FLOAT:
	case ATLV_FILE:
	case ATLV_SCHED:
		rc = -1;
		argc = state->path_len + state->name_len;
		if (argc == 0) {
			break;
		}
		argv = state->path;

		if (state->migrate_factory) {
			conf_put_name_val(argv, argc, tlv);
			err = 0;
			rc = 0;
			break;
		}
		err = conf_entry_set(CONF_OP_SRC_FILE, argv, argc, tlv);
		if (err) {
			conf_path_format(buf, sizeof(buf), argc, argv);
			if (err == CONF_ERR_PATH) {
#ifdef DEBUG
				conf_log(LOG_WARN
				    "conf_read_tlv: error %u path '%s'",
				    err, buf);
#endif /* DEBUG */
			} else {
				conf_log(LOG_ERR
				    "conf_read_tlv: error %u path '%s'",
				    err, buf);
				state->error = err;
			}
			rc = 0;		/* ignore conf var */
		} else {
			state->applied = 1;
		}
		break;
	default:
		rc = -1;
		break;
	}
	return rc;
}

#if defined(AYLA_BC) || defined(QCA4010)|| defined(AMEBA)
void conf_reset_factory(void)
{
	struct conf_state *state = &conf_state;
	u8 conf_buf[CONF_VAL_MAX];

	state->next = conf_buf;
	state->rlen = sizeof(conf_buf);
	conf_compress(state->conf_cur, state->conf_other, 1);
	state->next = NULL;
	state->rlen = 0;
}
#endif

int conf_access(u32 type)
{
	int src, ss;

	src = CONF_OP_SRC(type);
	ss = CONF_OP_SS(type);

	if (src == CONF_OP_SRC_FILE) {
		return 0;
	}
	if (CONF_OP_IS_WRITE(type)) {
		if (ss == CONF_OP_SS_ID && !mfg_mode_ok()) {
			/*
			 * Id settings only in mfg mode.
			 */
			return CONF_ERR_PERM;
		}
		if ((ss == CONF_OP_SS_OEM || ss == CONF_OP_SS_HW) &&
		    !mfg_or_setup_mode_ok()) {
			/*
			 * OEM/HW settings only in mfg/setup mode.
			 */
			return CONF_ERR_PERM;
		}
		if (ss == CONF_OP_SS_OEM_MODEL && src != CONF_OP_SRC_MCU &&
		    !mfg_or_setup_mode_ok()) {
			/*
			 * OEM model only in mfg/setup mode, unless set by MCU
			 */
			return CONF_ERR_PERM;
		}
		if ((ss == CONF_OP_SS_SERVER) && src != CONF_OP_SRC_FILE) {
			/*
			 * Server commands only set by file.
			 */
			return CONF_ERR_PERM;
		}
	}
	switch (src) {
	case CONF_OP_SRC_ADS:
		/*
		 * Everything goes.
		 */
		return 0;
	case CONF_OP_SRC_SERVER:
		switch (ss) {
		default:
			if (!CONF_OP_IS_WRITE(type)) {
				return 0;
			}
			return CONF_ERR_PERM;
		}
		/* fall through */
	case CONF_OP_SRC_MCU:
		switch (ss) {
		case CONF_OP_SS_PWR:
		case CONF_OP_SS_CLIENT_ENA:
		case CONF_OP_SS_CLIENT_REG:
		case CONF_OP_SS_CLIENT_SRV_REGION:
		case CONF_OP_SS_ETH:
		case CONF_OP_SS_OEM:
		case CONF_OP_SS_OEM_MODEL:
		case CONF_OP_SS_LOG:
		case CONF_OP_SS_WIFI:
		case CONF_OP_SS_SERVER_PROP:
		case CONF_OP_SS_SETUP_APP:
		case CONF_OP_SS_TIME:
		case CONF_OP_SS_HW:
		case CONF_OP_SS_HAP:
			return 0;
		default:
			if (!CONF_OP_IS_WRITE(type)) {
				return 0;
			}
			return CONF_ERR_PERM;
		}
		break;
	case CONF_OP_SRC_CLI:
		if (ss == CONF_OP_SS_SETUP_APP && !mfg_or_setup_mode_ok()) {
			/*
			 * IOS setup app can only be set in mfg/setup mode.
			 */
			return CONF_ERR_PERM;
		}
		return 0;
	default:
		break;
	}
	return CONF_ERR_PATH;
}

#ifdef AYLA_BC
static int conf_load_old(enum conf_inode inode, struct conf_file *file)
{
	struct conf_state *state = &conf_state;
	struct ayla_tlv *tlv;
	char read_buf[1024];
	size_t len;
	size_t off;
	size_t rlen;
	size_t tlen;

	len = conf_flash_get_length(file);
	if (len == 0) {
		conf_log(LOG_WARN "load: conf empty inode %d", inode);
		return -1;
	}

	state->error = CONF_ERR_NONE;
	state->inode = inode;
	state->path_len = 0;
	state->applied = 0;
	state->old_format = 1;
	rlen = 0;
	tlv = NULL;

	for (off = 0; off < len; ) {
		if (tlv == NULL || rlen < sizeof(*tlv) ||
		    rlen < sizeof(*tlv) + conf_tlv_len(tlv)) {
			rlen = len - off;
			if (rlen > sizeof(read_buf)) {
				rlen = sizeof(read_buf);
			}
			tlv = conf_flash_read(file, off, read_buf, rlen);
			if (tlv == NULL) {
				conf_log(LOG_ERR "load: conf read error %d",
				    inode);
				break;		/* XXX no back-out for now */
			}
		}
		if (conf_read_tlv(state, tlv) < 0) {
			break;
		}
		tlen = sizeof(*tlv) + conf_tlv_len(tlv);
		tlv = (struct ayla_tlv *)((char *)tlv + tlen);
		off += tlen;
		rlen -= tlen;
	}
	state->old_format = 0;
	if (state->applied) {
		conf_commit();
	}
	return 0;
}

/*
 * Move old config over. We'll construct the new config to CI_STARTUP.
 *
 * First move the factory config over, and then save the currently running
 * config.
 */
static void conf_migrate_old(struct conf_state *state)
{
	struct conf_file *infile, *outfile;

	if ((conf_flash_open_read(CI_FACTORY, &infile, NULL) < 0) ||
	    (conf_flash_open_write(CI_STARTUP, &outfile) < 0)) {
		return;
	}
	state->file = outfile;

	/*
	 * Make space for the migrated configuration.
	 */
	conf_flash_erase_if_needed(CI_STARTUP);

	/*
	 * This load factory config, and writes it right back to in new
	 * format.
	 */
	state->migrate_factory = 1;
	conf_load_old(CI_FACTORY, infile);
	state->migrate_factory = 0;

	conf_flash_write_head(state->file, ++state->gen_id);
	conf_flash_erase(CI_FACTORY);

	/*
	 * Save the current config (probably not as factory config).
	 */
	conf_save_config();
}
#endif /* AYLA_BC */

ssize_t conf_put_tokens(void *buf, size_t buf_len,
			enum conf_token *toks, int ntok)
{
	ssize_t rc;
	ssize_t len = 0;

	while (ntok--) {
		if (len >= buf_len) {
			return -1;
		}
		rc = utf8_encode((unsigned char *)buf + len, buf_len - len,
		    *toks++);
		if (rc < 0) {
			return -1;
		}
		len += rc;
	}
	return len;
}

/*
 * Read TLV.
 * Use the buffer if needed.
 * If the TLV doesn't entirely fit in the buffer, only the type and length
 * may be valid.
 * Even if the TLV value doesn't fit in the buffer, read it to compute the CRC.
 */
static struct ayla_tlv *conf_tlv_read(struct conf_file *file, size_t *off,
			 void *buf, size_t buf_len, u8 *crc)
{
	struct ayla_tlv *tlv;
	size_t len;
	size_t tlen;
	size_t coff = *off;
	void *data;

	if (coff + sizeof(*tlv) + sizeof(struct conf_head) > file->max_len) {
		return NULL;
	}
	tlv = conf_flash_read(file, coff, buf, sizeof(*tlv));
	if (!tlv) {
		conf_log(LOG_INFO "%s: read error offset %zx",
		    __func__, coff);
		return NULL;
	}
	if (tlv->type == ATLV_RESERVED) {	/* reached erased area */
		if (conf_state.inode == CI_ID) {
			*off = coff + 1;
			return tlv;
		}
		return NULL;
	}
	*crc = crc8(tlv, sizeof(*tlv), *crc);
	coff += sizeof(*tlv);

	len = conf_tlv_len(tlv);
	len += conf_flash_file_align(file, len);

	while (len > 0) {
		tlen = len;
		if (tlen > buf_len - sizeof(*tlv)) {
			tlen = buf_len - sizeof(*tlv);
		}
		data = conf_flash_read(file, coff, (char *)buf + sizeof(*tlv),
		    tlen);
		if (!data) {
			conf_log(LOG_ERR "%s: flash read error off %x len %u",
			    __func__, (unsigned int)coff, (unsigned int)tlen);
			return NULL;
		}
		*crc = crc8(data, tlen, *crc);
		coff += tlen;
		len -= tlen;
	}
	*off = coff;
	return tlv;
}

/*
 * Get the next valid name/value pair from the configuration file.
 *
 * bufs points to a read buffers, which may or may not be used.
 * maxlen gives the size of the buffer.
 *
 * start_off points to the starting offset on entry, which is updated to
 * point to the starting offset of the pair (the value) on success.
 *
 * next_off points to a place to store the offset to continue the read
 * for the next TLV.  On failure, the offset will be set to the point
 * where further writes can be made if the end was reached.
 *
 * nt and vt point to TLV pointers for the name and value TLVs, which may
 * point into the buffer, or may point at mapped flash location.
 *
 * The caller may pass start_off and next_off pointing to the same location.
 * start_off will only be fetched once, and next_off will be stored
 * after start_off is stored.
 *
 * returns 0 on success, -1 on error or if the end of the config is reached.
 */
static int conf_next_tlv(struct conf_file *file,  struct conf_tlv_buf *bufs,
    size_t *start_off, size_t *next_off,
    struct ayla_tlv **nt, struct ayla_tlv **vt)
{
	struct ayla_tlv *val_tlv, *name_tlv;
	size_t coff;
	size_t len;
	u8 cr;

	coff = *start_off;
reread:
	*start_off = coff;
	*next_off = coff;
	cr = CRC8_INIT;
	val_tlv = conf_tlv_read(file, &coff, bufs->val, bufs->val_len, &cr);
	if (!val_tlv) {
		return -1;
	}
	if (val_tlv->type == ATLV_RESERVED) {
		goto reread;		/* only for OTP ID file */
	}

	len = conf_tlv_len(val_tlv);
	len += conf_flash_file_align(file, len);

	*next_off = coff;
	name_tlv = conf_tlv_read(file, &coff, bufs->name, bufs->name_len, &cr);
	if (!name_tlv) {
		return -1;
	}
	if (name_tlv->type != ATLV_CONF &&
	    name_tlv->type != ATLV_CONF_FACTORY) {
		coff = *next_off;
		goto reread;
	}

	if (cr != 0) {
		conf_log(LOG_WARN "%s: CRC error", __func__);
		goto reread;
	}
	*nt = name_tlv;
	*vt = val_tlv;
	*next_off = coff;
	return 0;
}

/*
 * Find a config item.
 * The TLV pointer is returned, using the supplied buffer if needed.
 * Sets *soff to the file offset of the data TLV.
 * Returns NULL if not found or read error.
 */
static struct ayla_tlv *conf_item_find(enum conf_token *tokens,
		unsigned int ntokens,
		enum ayla_tlv_type type, size_t *soff, struct ayla_tlv *tlv_buf)
{
	struct conf_state *state = &conf_state;
	u8 token_buf[CONF_PATH_MAX + 1 + sizeof(struct ayla_tlv)];
	struct ayla_tlv *tlv;
	struct conf_tree *node;
	size_t fact_off;

	tlv = (struct ayla_tlv *)token_buf;
	tlv->type = ATLV_CONF;
	tlv->len = ntokens + 1;
	memcpy(tlv + 1, tokens, ntokens);

	if (conf_tree) {
		node = conf_tree_lookup(conf_tree, tokens, ntokens, 0);
		if (!node) {
			return NULL;
		}
		*soff = node->off;
	} else {
		*soff = 0;
		if (conf_find_tlv(tlv, soff, MAX_S32, &fact_off, 0)) {
			return NULL;
		}
	}
	tlv = conf_flash_read(state->file, *soff, tlv_buf, sizeof(*tlv_buf));
	if (!tlv) {
		return tlv;
	}
	if (type != tlv->type && (tlv->type & ATLV_FILE) != type) {
		return NULL;
	}
	return tlv;
}

/*
 * Read data for a config item.
 * Return a pointer to the data.
 * Uses the supplied buffer, if needed.
 */
void *conf_file_read(enum conf_token *tokens, unsigned int ntokens,
		enum ayla_tlv_type type, size_t offset,
		void *buf, size_t *lenp)
{
	struct conf_state *state = &conf_state;
	struct ayla_tlv *tlv;
	size_t file_off;
	size_t data_len;
	struct ayla_tlv tlv_buf;
	size_t tlen;
	void *data;

	tlv = conf_item_find(tokens, ntokens, type, &file_off, &tlv_buf);
	if (!tlv) {
		return NULL;
	}
	data_len = conf_tlv_len(tlv);
	if (offset >= data_len) {
		return NULL;
	}
	tlen = data_len - offset;
	if (*lenp < tlen) {
		tlen = *lenp;
	}
	file_off += sizeof(*tlv) + offset;
	data = conf_flash_read(state->file, file_off, buf, tlen);

	if (!data) {
		*lenp = 0;
		return NULL;
	}
	*lenp = tlen;
	return data;
}

/*
 * Create a config FILE item with a given size.
 * The data will be supplied by conf_file_write().
 * Returns 0 on success, negative value on error.
 */
int conf_write_start(size_t len, enum conf_token *path, unsigned int plen)
{
	struct conf_state *state = &conf_state;
	struct ayla_tlv tlv;
	u8 conf_buf[CONF_VAL_MAX];
	int rc;

	len += conf_flash_file_align(state->file, len);
	if (len > MAX_S16) {
		return -1;
	}

	/*
	 * Supply conf_check_fit() with a buffer.
	 */
	state->error = CONF_ERR_NONE;
	state->inode = state->conf_cur;
	state->next = conf_buf;
	state->rlen = sizeof(conf_buf);

	/*
	 * Delete any old copy of the file before checking for fit
	 * and compressing.  Both old and new may not fit.
	 */
	ASSERT(plen <= CONF_PATH_MAX);
	memcpy(state->path, path, plen * sizeof(*path));
	state->path_len = plen - 1;
	conf_delete(path[plen - 1]);
	state->path_len = plen;

	rc = conf_check_fit(len);
	state->next = NULL;
	state->rlen = 0;
	if (rc) {
		return -1;
	}

	tlv.type = ATLV_FILE | ((len >> 8) & 0xff);
	tlv.len = len & 0xff;
	state->file_crc = crc8(&tlv, sizeof(tlv), CRC8_INIT);
	rc = conf_flash_write_blk(state->file, state->off, &tlv, sizeof(tlv));
	state->file_off = state->off + sizeof(tlv);
	state->off += sizeof(tlv) + len;
	state->file_err = NULL;
	return rc;
}

/*
 * Append data for a config item which has been created as erased.
 * Returns zero on success, negative on error.
 * Errors may be deferred until close.
 */
int conf_write_append(void *buf, size_t len)
{
	struct conf_state *state = &conf_state;
	int rc;

	if (state->file_err) {
		return 0;	/* will report error at close */
	}
	if (!state->file_off || state->file_off > state->off) {
		state->file_err = "compressed";
		return 0;
	}
	if (conf_flash_file_align(state->file, len)) {
		state->file_err = "unaligned";
		return 0;
	}
	if (len > state->off - state->file_off) {
		state->file_err = "truncated";
		len = state->off - state->file_off;
	}
	state->file_crc = crc8(buf, len, state->file_crc);
	rc = conf_flash_write_blk(state->file, state->file_off, buf, len);
	if (rc) {
		state->file_err = "flash write err";
		conf_log(LOG_ERR "write_append: off %zx len %x rc %d",
		    state->file_off, len, rc);
	}
	state->file_off += len;
	return 0;
}

int conf_write_end(void)
{
	struct conf_state *state = &conf_state;
	char namebuf[sizeof(struct ayla_tlv) + CONF_PATH_MAX * sizeof(u32)];
	struct ayla_tlv *name;
	int nlen;

	ASSERT(state->file_off <= state->off);

	/*
	 * Construct name tlv.
	 */
	name = (struct ayla_tlv *)namebuf;
	nlen = utf8_put_wchars(state->path, state->path_len, name + 1);
	if (nlen < 0) {
		goto err;
	}
	if (conf_save_as_factory() || state->migrate_factory) {
		name->type = ATLV_CONF_FACTORY;
	} else {
		name->type = ATLV_CONF;
	}
	name->len = nlen + 1;
	nlen += sizeof(struct ayla_tlv);

	namebuf[nlen] = crc8(namebuf, nlen, state->file_crc);
	nlen++;

	nlen += conf_flash_file_align(state->file, nlen);
	conf_flash_write_blk(state->file, state->off, namebuf, nlen);
	state->off += nlen;

	if (state->file_err) {
		conf_log(LOG_WARN "write_end: %s during append",
		    state->file_err);
		conf_delete(state->path[--state->path_len]);
		return -1;
	}
	return 0;
err:
	return -1;
}

/*
 * Find a TLV in the current file matching the name TLV provided.
 *
 * cmp is the TLV to match
 * soff initially points to the offset from which to search
 * on exit that location is updated with offset of the found value TLV.
 * *fact_off will be set to point to offset of the latest factory setting found.
 * eoff is the maximum offset to search.
 * type is a bitmask for of flags controlling the search:
 *	CONF_FIND_PREFIX means to look for a longer non-deleted value.
 *	CONF_FIND_FACTORY means only match factory config items.
 *	CONF_FIRST means to return the first match in the range
 *		otherwise the last value found is returned
 *
 * returns zero if the TLV is found, non-zero otherwise.
 */
static int conf_find_tlv(struct ayla_tlv *cmp, size_t *soff, size_t eoff,
    size_t *fact_off, u8 type)
{
	struct conf_file *file;
	u8 valbuf[CONF_VAL_MAX];
	u8 namebuf[sizeof(struct ayla_tlv) + CONF_PATH_MAX * sizeof(u32)];
	struct conf_tlv_buf bufs;
	size_t off, prev_off;
	struct ayla_tlv *name_tlv, *val_tlv;
	int rc = -1;

	if (conf_flash_open_read(conf_state.inode, &file, NULL) < 0) {
		if (!conf_flash_erased(&file, sizeof(file))) {
			return -1;	/* do not log error on empty file */
		}
		conf_log(LOG_ERR "find_tlv: conf error inode %d", CI_STARTUP);
		return -1;
	}

	off = *soff;
	*fact_off = CONF_OFF_INV;

	bufs.val = valbuf;
	bufs.val_len = sizeof(valbuf);
	bufs.name = namebuf;
	bufs.name_len = sizeof(namebuf);

	while (off < eoff) {
		prev_off = off;
		if (conf_next_tlv(file, &bufs, &prev_off, &off,
			&name_tlv, &val_tlv) < 0) {
			break;
		}
		if (name_tlv->len > cmp->len) {
			if ((type & CONF_FIND_PREFIX) == 0 ||
			    val_tlv->type == ATLV_DELETE) {
				/*
				 * Looking for a non-deleted conf val that
				 * has longer name than the compared value.
				 */
				continue;
			}
			if (memcmp(name_tlv + 1, cmp + 1, cmp->len - 1)) {
				continue;
			}
		} else {
			if (val_tlv->type != ATLV_DELETE &&
			    name_tlv->len != cmp->len) {
				/*
				 * Delete TLV names can be shorter than the
				 * compared name, as you can delete a whole
				 * branch.
				 */
				continue;
			}
			if (memcmp(name_tlv + 1, cmp + 1, name_tlv->len - 1)) {
				continue;
			}
		}

		/*
		 * Name matches.
		 */
		if (name_tlv->type == ATLV_CONF_FACTORY) {
			*fact_off = prev_off;
		} else if (type & CONF_FIND_FACTORY) {
			continue;
		}
		*soff = prev_off;
		rc = 0;
		if (type & CONF_FIND_FIRST) {
			break;
		}
	}
	return rc;
}

static int conf_show_flash_var(enum conf_inode inode, size_t len,
			struct ayla_tlv *match)
{
	struct conf_file *file;
	u8 valbuf[CONF_VAL_MAX];
	u8 namebuf[sizeof(struct ayla_tlv) + CONF_PATH_MAX * sizeof(u32)];
	struct conf_tlv_buf bufs;
	char off_buf[10];
	size_t off;
	size_t tlv_off;
	size_t find_off;
	size_t fact_off;
	struct ayla_tlv *name;
	struct ayla_tlv *val;
	const char *type;
	struct conf_tree *node;

	if (conf_flash_open_read(inode, &file, NULL) < 0) {
		if (!conf_flash_erased(&file, sizeof(file))) {
			return -1;	/* do not log error on empty file */
		}
		conf_log(LOG_ERR "%s: conf error inode %d", __func__, inode);
		return -1;
	}

	bufs.val = valbuf;
	bufs.val_len = sizeof(valbuf);
	bufs.name = namebuf;
	bufs.name_len = sizeof(namebuf);

	for (off = 0; off < len; ) {
		tlv_off = off;
		if (conf_next_tlv(file, &bufs, &tlv_off, &off, &name,
			&val) < 0) {
			break;
		}
		if (match && (name->len - 1 != match->len ||
		    memcmp(name + 1, match + 1, match->len))) {
			continue;
		}
		if (!CONF_SHOW_ALL) {
			if (val->type == ATLV_DELETE) {
				continue;
			}
			find_off = off;
			if (conf_tree) {
				node = conf_tree_lookup_tlv(conf_tree, name, 1);
				if (!node || (node && node->off > tlv_off)) {
					continue;
				}
			} else {
				if (!conf_find_tlv(name, &find_off, MAX_S32,
				    &fact_off, CONF_FIND_FIRST)) {
					continue;
				}
			}
		}
		if (inode == CI_ID) {
			type = "i";
		} else if (name->type == ATLV_CONF) {
			type = "s";
		} else if (name->type == ATLV_CONF_FACTORY) {
			type = "f";
		} else {
			type = "UNK";
		}
		if (CONF_SHOW_ALL) {
			snprintf(off_buf, sizeof(off_buf), "%4x %s", tlv_off,
			    type);
			type = off_buf;
		}
		conf_print(type, name, val);
	}
	return 0;
}

/*
 * Initialize the config tree with a place-holder node.
 * This speeds up initial saves.
 */
static void conf_tree_init(void)
{
#ifdef FLASH_CONF_CACHE
	union {
		struct ayla_tlv tlv;	/* room for TLV + 1 byte value */
		u8 buf[sizeof(struct ayla_tlv) + 2];
	} un;

	un.tlv.type = ATLV_CONF_FACTORY;
	un.tlv.len = 2;
	un.buf[sizeof(un.tlv)] = CT_sys;
	un.buf[sizeof(un.tlv) + 1] = 0;
	conf_tree_add(&conf_tree, &un.tlv, CONF_OFF_INV, 0);
#endif
}

/*
 * Recursively delete a config tree or subtree.
 * Our depth is limited by CONF_PATH_MAX.
 */
static void conf_tree_delete(struct conf_tree *tree)
{
	if (tree) {
		conf_tree_delete(tree->child);
		conf_tree_delete(tree->sib);
		free(tree);
	}
}

static struct conf_tree *conf_tree_add(struct conf_tree **tree,
				struct ayla_tlv *name_tlv, size_t off, int del)
{
	enum conf_token path[CONF_PATH_MAX];
	enum conf_token token;
	int plen;
	int depth;
	struct conf_tree *node;
	struct conf_tree *new;
	struct conf_tree **prev;

	plen = conf_get_tokens(path, CONF_PATH_MAX,
	    (u8 *)(name_tlv + 1), name_tlv->len - 1);

	prev = tree;
	depth = 0;
	while (depth < plen) {
		token = path[depth];

		/*
		 * Find token at this level.
		 * Tree is sorted by token, so if we find a greater token,
		 * insert it before that.
		 */
		for (node = *prev; node; prev = &node->sib, node = *prev) {
			if (token == node->token) {
				if (depth == plen - 1) {
					goto found;
				}
				goto deeper;
			}
			if (token < node->token) {
				break;
			}
		}

		/*
		 * Insert new node between *prev and node on sibling chain.
		 */
		if (del && depth == plen - 1) {
			return NULL;
		}
		new = malloc(sizeof(*new));
		ASSERT(new);
		if (!new) {
			conf_log(LOG_ERR "conf_tree_add: malloc failed");
			return NULL;
		}
		new->sib = node;
		new->token = token;
		new->child = NULL;
		node = new;
		*prev = new;
		node->fact_off = CONF_OFF_INV;

		if (depth == plen - 1) {
			goto found;
		}
		node->off = CONF_OFF_INV;
deeper:
		prev = &node->child;
		depth++;
	}
	return NULL;

found:
	/*
	 * Handle delete
	 */
	if (del) {
		if (node->child) {
			conf_tree_delete(node->child);
			node->child = NULL;
		}
		*prev = node->sib;
		free(node);
	} else {
		node->off = off;
		if (name_tlv->type == ATLV_CONF_FACTORY) {
			node->fact_off = off;
		}
	}
	return node;
}

/*
 * Read through TLVs in tree, recursively.
 * Our depth is limited by CONF_PATH_MAX.
 */
static void conf_tree_read(struct conf_tree *tree, struct conf_file *file,
			struct conf_tlv_buf *bufs)
{
	struct conf_state *state = &conf_state;
	struct conf_tree *node;
	struct ayla_tlv *name_tlv, *val_tlv;
	size_t off;

	for (node = tree; node; node = node->sib) {
		if (node->child) {
			conf_tree_read(node->child, file, bufs);
		}
		off = node->off;
		if (off == CONF_OFF_INV) {
			continue;
		}
		if (conf_next_tlv(file, bufs, &off, &off, &name_tlv,
			&val_tlv) < 0) {
			conf_log(LOG_ERR "%s: read failed off %zx",
			    __func__, node->off);
			break;
		}
		conf_read_tlv(state, name_tlv);
		conf_read_tlv(state, val_tlv);
	}
}

static struct conf_tree *conf_tree_lookup(struct conf_tree *tree,
				enum conf_token path[], int plen, int del)
{
	struct conf_tree *node;

	for (node = tree; node; node = node->sib) {
		if (node->token > path[0]) {
			break;
		}
		if (node->token != path[0]) {
			continue;
		}
		if (plen == 1 && (del || node->off != CONF_OFF_INV)) {
			return node;
		}
		return conf_tree_lookup(node->child, &path[1], plen - 1, del);
	}
	return NULL;
}

/*
 * Convert UTF8-encoded tokens to conf_token array and do lookup.
 */
static struct conf_tree *conf_tree_lookup_tlv(struct conf_tree *tree,
				struct ayla_tlv *name, int del)
{
	enum conf_token path[CONF_PATH_MAX];
	int plen;

	plen = conf_get_tokens(path, CONF_PATH_MAX,
	    (u8 *)(name + 1), name->len - 1);
	if (plen < 1) {
		return NULL;
	}
	return conf_tree_lookup(tree, path, plen, del);
}

#if CONF_SHOW_ALL
static void cn_print(struct conf_tree *tree, int depth)
{
	int i;
	struct conf_tree *node;

	for (node = tree; node; node = node->sib) {
		for (i = 0; i < depth; i++) {
			printf("    ");
		}
		printf("%d(%s) %x %x\n", node->token, conf_string(node->token),
		    node->off != CONF_OFF_INV ? node->off & 0xfffff : 0,
		    node->fact_off != CONF_OFF_INV ?
		    node->fact_off & 0xfffff : 0);
		if (node->child) {
			cn_print(node->child, depth + 1);
		}
	}
}

static void cn_printall(struct conf_tree *node)
{
	cn_print(node, 0);
}

void conf_printall(void)
{
	cn_printall(conf_tree);
}
#endif

static int conf_load_new(enum conf_inode inode, struct conf_file *file)
{
	struct conf_state *state = &conf_state;
	struct ayla_tlv *name_tlv, *val_tlv;
	size_t off;
	u8 valbuf[CONF_VAL_MAX];
	u8 namebuf[sizeof(struct ayla_tlv) + CONF_PATH_MAX * sizeof(u32)];
	struct conf_tlv_buf bufs;

	state->error = CONF_ERR_NONE;
	state->inode = inode;
	state->file = file;
	state->path_len = 0;
	state->off = 0;
	state->applied = 0;
	state->old_format = 0;

	bufs.val = valbuf;
	bufs.val_len = sizeof(valbuf);
	bufs.name = namebuf;
	bufs.name_len = sizeof(namebuf);

	while (1) {
		off = state->off;
		if (conf_next_tlv(file, &bufs, &off, &state->off, &name_tlv,
			&val_tlv) < 0) {
			break;
		}
		conf_tree_add(&conf_tree, name_tlv, off,
		    val_tlv->type == ATLV_DELETE);
	}

	conf_tree_read(conf_tree, file, &bufs);

#ifndef FLASH_CONF_CACHE
	conf_tree_delete(conf_tree);
	conf_tree = NULL;
#else
	if (inode == CI_ID) {
		conf_tree_delete(conf_tree);
		conf_tree = NULL;
	}
#endif
	if (state->applied) {
		conf_commit();
	}
	return 0;
}

int conf_load(enum conf_inode inode)
{
	struct conf_file *file;
	struct conf_head head;
	int rc;

	if (conf_flash_open_read(inode, &file, &head) < 0) {
		conf_log(LOG_ERR "load: conf error inode %d", inode);
		return -1;
	}
#ifdef AYLA_BC
	if (head.v2_config == 0) {
		if (inode == CI_ID) {
			conf_id_old_format = 1;
		}
		rc = conf_load_old(inode, file);
	} else {
		rc = conf_load_new(inode, file);
	}
#else
	rc = conf_load_new(inode, file);
#endif /* AYLA_BC */
	return rc;
}

/*
 * Show specified variable in flash - if found.
 * Returns 0 on success, 1 if not found, negative on other errors.
 */
static int conf_show_flash_name(enum conf_inode inode, const char *name)
{
	char nbuf[CONF_PATH_MAX * 4 + sizeof(struct ayla_tlv)];
	struct ayla_tlv *tlv;
	enum conf_token path[CONF_PATH_MAX];
	ssize_t rc;
	int plen;

	plen = conf_path_parse(path, CONF_PATH_MAX, name);
	if (plen <= 0) {
		printcli("%s: parse error on %s", __func__, name);
		return -1;
	}
	tlv = (struct ayla_tlv *)nbuf;
	tlv->type = ATLV_CONF;
	rc = conf_put_tokens(tlv + 1, sizeof(nbuf) - sizeof(*tlv), path, plen);
	if (rc < 0 || rc > MAX_U8) {
		printcli("%s: put_tokens failed for %s", __func__, name);
		return -1;
	}
	tlv->len = (u8)rc;
	return conf_show_flash_var(inode, MAX_S32, tlv);
}

static int conf_show_flash(enum conf_inode inode, size_t len)
{
	return conf_show_flash_var(inode, len, NULL);
}

int conf_load_config(void)
{
	struct conf_state *state = &conf_state;
	struct conf_file *cur, *other;
	struct conf_head head, head2;
	int rc, rc2;

	state->loaded = 1;
	rc = conf_flash_open_read(CI_STARTUP, &cur, &head);
	rc2 = conf_flash_open_read(CI_FACTORY, &other, &head2);
	if (rc == 0 && rc2) {
st_valid:
		state->conf_cur = CI_STARTUP;
		state->conf_other = CI_FACTORY;
		state->gen_id = head.gen_id;
	} else if (rc2 == 0 && rc) {
fa_valid:
		cur = other;
		head = head2;
		state->conf_cur = CI_FACTORY;
		state->conf_other = CI_STARTUP;
		state->gen_id = head2.gen_id;
	} else if (rc == 0 && rc2 == 0) {
		/*
		 * Both valid. Compare the generation ID then, we must've
		 * restarted just before erasing.
		 */
		if ((char)head.gen_id - (char)head2.gen_id >= 0) {
			goto st_valid;
		} else {
			goto fa_valid;
		}
	} else {
		conf_log(LOG_ERR "load: configuration not found");
		state->conf_cur = CI_STARTUP;
		state->conf_other = CI_FACTORY;
		state->gen_id = 0;
		state->not_valid = 1;
		state->off = 0;
		/*
		 * Erase config slots.
		 */
		conf_flash_erase_if_needed(CI_STARTUP);
		conf_flash_erase_if_needed(CI_FACTORY);
		conf_tree_init();
		conf_commit();		/* treat as empty config */
		return 0;
	}
#ifdef AYLA_BC
	if (head.v2_config == 0) {
		state->conf_cur = CI_STARTUP;
		state->conf_other = CI_FACTORY;
		state->gen_id = 0;
		rc = conf_load_old(state->conf_cur, cur);
		conf_migrate_old(state);
		return rc;
	}
#endif /* AYLA_BC */
	conf_flash_erase_if_needed(state->conf_other);
	rc = conf_load_new(state->conf_cur, cur);
	return rc;
}

/*
 * Display the configuration.
 */
void conf_show(void)
{
	struct conf_state *state = &conf_state;
	u8 conf_buf[CONF_VAL_MAX];

	state->error = CONF_ERR_NONE;
	state->next = conf_buf;
	state->rlen = sizeof(conf_buf);

#ifndef CONF_NO_ID_FILE
	if (CONF_SHOW_ALL) {
		state->inode = CI_ID;
		conf_show_flash(CI_ID, (size_t)MAX_U32);
	}
#endif

	state->inode = state->conf_cur;
	conf_show_flash(state->inode, state->off);

	state->show_conf = 1;
	conf_walk(state);
	state->show_conf = 0;

	printcli("  types: f = factory, s = startup, r = running");
}

int conf_show_name(const char *name)
{
	struct conf_state *state = &conf_state;
	u8 conf_buf[CONF_VAL_MAX];
	int rc;

	state->error = CONF_ERR_NONE;
	state->inode = state->conf_cur;
	state->next = conf_buf;
	state->rlen = sizeof(conf_buf);

	rc = conf_show_flash_name(state->inode, name);
	state->next = NULL;
	return rc;
}

void conf_cli(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "show")) {
		if (argc == 2) {
			conf_show();
			return;
		}
		if (argc == 3) {
			conf_show_name(argv[2]);
			return;
		}
	}
	if (argc == 2 && !strcmp(argv[1], "save")) {
		conf_save_config();
		return;
	}
	printcli("usage: conf show [name]\n"
	    "       conf save\n");
}

/*
 * Converts a string path into conf tokens.
 */
int conf_str_to_tokens(char *haystack, enum conf_token *tk, int tk_len)
{
	int index = 0;
	char *cp;
	char *errptr;
	unsigned long ulval;

	while (*haystack != '\0') {
		if (index >= tk_len) {
			return -1;
		}
		cp = strchr(haystack, '/');
		if (cp) {
			*cp = '\0';
		}
		tk[index] = conf_token_parse(haystack);
		if (tk[index] == CT_INVALID_TOKEN) {
			/* check if haystack is an integer */
			ulval = strtoul(haystack, &errptr, 10);
			if (*errptr != '\0' || ulval > MAX_U8) {
				conf_log(LOG_ERR
				    "bad token for parsing %s", haystack);
				return -1;
			}
			tk[index] = (enum conf_token)ulval;
		}
		index++;
		if (!cp) {
			return index;
		}
		haystack = cp + 1;
	}

	return index;
}

/*
 * Converts a token path into a conf string.
 */
int conf_tokens_to_str(enum conf_token *tk, int tk_len, char *buf, int blen)
{
	conf_path_format(buf, blen, tk_len, tk);
	return strlen(buf);
}


static unsigned int conf_table_len(const struct conf_entry * const *table)
{
	unsigned int count = 0;

	while (*table++) {
		count++;
	}
	return count;
}

/*
 * Add a new entry to the end of the conf_master_table.
 */
void conf_table_entry_add(const struct conf_entry *entry)
{
	const struct conf_entry * const *old = conf_master_table;
	const struct conf_entry **new;
	unsigned int old_count;

	old_count = conf_table_len(old);

	new = malloc((old_count + 2) * sizeof(*old));
	ASSERT(new);
	if (!new) {
		return;
	}

	memcpy(new, old, old_count * sizeof(*new));
	new[old_count] = entry;
	new[old_count + 1] = NULL;

	conf_master_table = new;
	if (old != conf_table) {
		free((void *)old);
	}
}

/*
 * Start saving config items as factory config
 */
void conf_factory_start(void)
{
	struct conf_state *state = &conf_state;

	state->save_as_factory = 1;
}

/*
 * Stop saving config items as factory config
 */
void conf_factory_stop(void)
{
	struct conf_state *state = &conf_state;

	state->save_as_factory = 0;
}
