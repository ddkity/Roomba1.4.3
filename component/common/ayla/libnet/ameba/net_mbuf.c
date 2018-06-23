/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <stdlib.h>
#include <string.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ada/err.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <net/net.h>
#include <net/ada_mbuf.h>

struct ada_mbuf *ada_mbuf_alloc(unsigned int size)
{
	struct ada_mbuf *am;

	am = (struct ada_mbuf *)malloc(sizeof(*am) + size);
	if (!am) {
		return am;
	}
	memset(am, 0, sizeof(*am));
	am->alloc_len = size;
	am->tot_len = size;
	am->len = size;
	return am;
}

/*
 * Free entire chain of mbufs.
 * This is perfectly fine to call with a NULL pointer (saves code space).
 */
void ada_mbuf_free(struct ada_mbuf *am)
{
	struct ada_mbuf *next = am;

	while (next) {
		am = next;
		next = am->next;
		free(am);
	}
}

void ada_mbuf_trim(struct ada_mbuf *am, int len)
{
	ASSERT(len <= am->tot_len);
	ASSERT(len <= am->len);
	am->tot_len = len;
	am->len = len;
}

/*
 * Add len to the front of the mbuf.
 * Currently len must be negative, which removes data from the front
 * XXX Perhaps should return the remaining mbuf in case it isn't contiguous?
 */
int ada_mbuf_header(struct ada_mbuf *am, int len)
{
	if (len > 0 || -len > am->len) {
		return -1;
	}
	am->tot_len += len;
	am->len += len;
	am->start -= len;
	return 0;
}

void ada_mbuf_cat(struct ada_mbuf *head, struct ada_mbuf *tail)
{
	struct ada_mbuf *prev;

	ASSERT(head);
	ASSERT(tail);

	prev = head;
	while (prev->next) {
		prev = prev->next;
	}
	prev->next = tail;
	head->tot_len += tail->tot_len;
}

struct ada_mbuf *ada_mbuf_coalesce(struct ada_mbuf *am)
{
	struct ada_mbuf *mb;
	struct ada_mbuf *new;
	size_t len;
	size_t tlen;
	char *out;

	len = am->tot_len;
	if (len == ada_mbuf_len(am)) {
		return am;
	}

	/*
	 * Note: the first mbuf (or others) may have enough room, but
	 * for simplicity, we just allocate a new one.  Improve later.
	 */
	new = ada_mbuf_alloc(len);
	if (!new) {
		return NULL;
	}
	out = ada_mbuf_payload(new);

	for (mb = am; mb && len > 0; mb = mb->next) {
		tlen = ada_mbuf_len(mb);	/* length to append to new */
		ASSERT(tlen <= len);

		memcpy(out, ada_mbuf_payload(mb), tlen);

		out += tlen;
		len -= tlen;
	}
	ada_mbuf_free(am);		/* free entire old chain */
	return new;
}
