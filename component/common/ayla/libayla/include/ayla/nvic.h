/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_NVIC_H__
#define __AYLA_NVIC_H__

/*
 * Enable NVIC vector interrupt.
 */
static inline void nvic_enable(u32 vector)
{
	NVIC->ISER[vector >> 5] = 1U << (vector & 0x1f);
}

static inline void nvic_disable(u32 vector)
{
	NVIC->ICER[vector >> 5] = 1U << (vector & 0x1f);
}

#endif /* __AYLA_NVIC_H__ */
