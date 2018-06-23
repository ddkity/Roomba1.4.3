/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ADA_MBUF_H__
#define __AYLA_ADA_MBUF_H__

#include <lwip/pbuf.h>
#include <string.h>

struct netif;

struct ada_mbuf {		/* semi-opaque to users of this API */
	struct ada_mbuf *next;
	unsigned int tot_len;	/* total valid length of chain */
	unsigned int len;	/* valid data in buffer */
	unsigned int start;	/* starting offset in buffer */
	unsigned int alloc_len;	/* allocated size of buffer that follows */
};

static inline void *ada_mbuf_payload(struct ada_mbuf *am)
{
	return (char *)(am + 1) + am->start;
}

static inline unsigned int ada_mbuf_tot_len(struct ada_mbuf *am)
{
	return am->tot_len;
}

static inline unsigned int ada_mbuf_len(struct ada_mbuf *am)
{
	return am->len;
}

static inline struct netif *ada_mbuf_netif(struct ada_mbuf *am)
{
	return NULL;
}

struct ada_mbuf *ada_mbuf_alloc(unsigned int size);

void ada_mbuf_free(struct ada_mbuf *am);

void ada_mbuf_trim(struct ada_mbuf *am, int len);

/*
 * Add len to the front of the mbuf.
 * Currently len must be negative, which removes data from the front
 */
int ada_mbuf_header(struct ada_mbuf *am, int len);
void ada_mbuf_cat(struct ada_mbuf *head, struct ada_mbuf *tail);
struct ada_mbuf *ada_mbuf_coalesce(struct ada_mbuf *);

#endif /* __AYLA_ADA_MBUF_H__ */
