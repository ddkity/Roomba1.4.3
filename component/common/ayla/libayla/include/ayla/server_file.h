/*
 * Copyright 2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_SERVER_FILE_H__
#define __AYLA_SERVER_FILE_H__

#include <ayla/conf_token.h>
#include <ayla/log.h>

/*
 * Definitions for files inside config items for internal server use.
 */

#define SERVER_FILE_MAX_SPACE	10000	/* max space for all files */
#define SERVER_FILE_NAME_LEN	20	/* longest file name supported */
#define SERVER_FILE_TYPE_LEN	20	/* longest type string supported */
#define SERVER_FILE_MAX_INDEX	MAX_S8	/* max file index */
#define SERVER_FILE_TOKENS	5	/* tokens for server/file/n/<n>/xxx */

struct server_file {
	struct server_file *next; /* list linkage */
	u8 index;		/* file number <n> */
	size_t len;		/* file length */
	char type[SERVER_FILE_TYPE_LEN];
	char name[SERVER_FILE_NAME_LEN];
};

struct server_file *server_file_lookup(const char *name);
struct server_file *server_file_create(unsigned int index);
struct server_file *server_file_create_name(const char *name);

int server_file_len_set(struct server_file *file, size_t len,
			const char *caller, enum log_mod_id subsys);

void server_file_export(struct server_file *);
void server_file_export_all(void);
void server_file_iterate(void (*handler)(struct server_file *file, void *),
			void *arg);

struct ayla_tlv;

enum conf_error server_file_set(int src, enum conf_token *token,
				size_t len, struct ayla_tlv *tlv);

#endif /* __AYLA_SERVER_FILE_H__ */
