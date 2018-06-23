/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>
#include <ayla/malloc.h>
#include <FreeRTOS.h>

void *ayla_calloc(size_t count, size_t size)
{
	void *ptr;

	size *= count;
	ptr = pvPortMalloc(size);

	/* Mbedtls library need initalise the allocated memory */
	if (ptr) {
		memset(ptr, 0, size);
	}

	return ptr;
}
