/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_MALLOC_H__
#define __AYLA_MALLOC_H__

#ifdef AMEBA

#define calloc ayla_calloc

void *ayla_calloc(size_t count, size_t size);
#define ayla_free vPortFree

#elif defined(WMSDK)
#include <wm_os.h>

#define malloc os_mem_alloc
#define realloc os_mem_realloc
#define free os_mem_free
#define calloc ayla_calloc

static inline void *ayla_calloc(size_t count, size_t size)
{
	return os_mem_calloc(count * size);
}
#endif /* WMSDK */

#endif /* __AYLA_MALLOC_H__ */
