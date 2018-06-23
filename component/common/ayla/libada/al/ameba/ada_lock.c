/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <sys/types.h>

#include <FreeRTOS.h>
#include <semphr.h>

#include <ayla/assert.h>
#include "ada_lock.h"

struct ada_lock *ada_lock_create(const char *name)
{
	return (struct ada_lock *)xSemaphoreCreateMutex();
}

void ada_lock(struct ada_lock *lockp)
{
	xSemaphoreTake(lockp, portMAX_DELAY);
}

void ada_unlock(struct ada_lock *lockp)
{
	xSemaphoreGive(lockp);
}
