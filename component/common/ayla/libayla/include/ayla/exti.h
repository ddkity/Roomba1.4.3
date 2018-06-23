/*
 * Copyright 2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_EXTI_H__
#define __AYLA_EXTI_H__

struct exti_handler {
	void (*handler)(struct exti_handler *, u16 mask);
	struct exti_handler *next;
	u16 pin_mask;
};

enum exti_mode {
	EM_RISING,
	EM_FALLING,
	EM_EITHER_EDGE,
	EM_DISABLED,
};

void exti_reg(struct exti_handler *hp);
#ifdef GPIO_POLLING
void exti_poll(void);
#endif
void exti_unreg(struct exti_handler *hp);
void exti_mode_set(u8 pin_id, enum exti_mode mode);
void exti_disable(u8 pin_id);

/*
 * This doesn't belong here but helps keep library independent of WICED headers.
 */
extern void wiced_platform_notify_irq(void);

#endif /* __AYLA_EXTI_H__ */
