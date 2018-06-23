/*
 * Copyright 2012-2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_MALLOC_HIST_H__
#define __AYLA_MALLOC_HIST_H__

#include <sys/queue.h>

#define MALLOC_HIST_COUNTS	16
#define MALLOC_HIST_SIZES	{ 16, 24, 32, 48, 64, 128, 256, 1024, \
				   1100, 1200, 1300, 1600, 1800, 2048, \
				   3072, 0x7fffffff }

struct malloc_list {
	LIST_ENTRY(malloc_list) list;
	unsigned int size;
	unsigned int magic;
};

struct malloc_hist_bucket {
	unsigned int allocs;
	unsigned int frees;
	unsigned int size_min;
	unsigned int size_max;
#ifdef MALLOC_LISTS
	LIST_HEAD(, malloc_list) head;
#endif /* MALLOC_LISTS */
};

struct malloc_hist {
	struct malloc_hist_bucket calls;
	struct malloc_hist_bucket bytes;
	struct malloc_hist_bucket bucket[MALLOC_HIST_COUNTS];
};

extern struct malloc_hist malloc_hist;

struct malloc_hist_bucket *malloc_hist_bucket(int size);
void malloc_hist_alloc(size_t size);
void malloc_hist_free(size_t size);

/*
 * Returns the number of bytes remaining in the heap.
 */
unsigned long malloc_heap_space(void);

#endif /* __AYLA_MALLOC_HIST_H__ */
