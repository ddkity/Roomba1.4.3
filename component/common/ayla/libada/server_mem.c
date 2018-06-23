/*
 * Copyright 2011-2016 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <stdio.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/http.h>
#include <ada/err.h>
#include <net/net.h>
#include <ada/server_req.h>

void server_send_static(struct server_req *req)
{
	const struct server_buf *sbuf = req->url->arg;
	char content_type[100];
	size_t tlen;
	size_t off = 0;
	register size_t content_len;

	/*
	 * See if there's a custom version of this file provided by the app.
	 */
	if (!adap_server_file_get(req)) {
		return;
	}
#ifdef XXD_BIN_TO_C
	content_len = *sbuf->len;
#else
	content_len = sbuf->len;
#endif
	snprintf(content_type, sizeof(content_type), "Content-Type: %s\r\n"
	    "Cache-Control: private, max-age=3600\r\n"
#ifndef AMEBA
	    "Content-Length: %u\r\n"
	    , sbuf->content_type, (unsigned int)content_len);
#else
	    , sbuf->content_type);
#endif

	req->put_head(req, HTTP_STATUS_OK, content_type);

	while (off < content_len) {
		tlen = content_len - off;
		if (tlen > SERVER_BUFLEN) {
			tlen = SERVER_BUFLEN;
		}
		server_put_pure_len(req, (char *)sbuf->buf + off, tlen);
		off += tlen;
	}
}
