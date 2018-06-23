/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */
#ifndef __AYLA_LED_KEY_H__
#define __AYLA_LED_KEY_H__

enum gpio {
	led_cloud,
	led_green,
	led_blue,
	key_blue,
	key_register,

	led_max = led_blue,
	key_max = key_register,
};

void init_led_key(void);

int get_key(enum gpio key);

void set_led(enum gpio led, int on);

#endif /* __AYLA_LED_KEY_H__ */
