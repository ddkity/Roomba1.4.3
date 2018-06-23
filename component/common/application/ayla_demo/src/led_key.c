/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */
#include <gpio_api.h>
#include "led_key.h"

#define ARRAY_LEN(v) (sizeof(v)/sizeof(v[0]))

static const struct gpio_info
{
	PinName		pin;
	PinDirection	dir;
	PinMode		mode;
	int		val;
} gpio_info[] = {
	[led_cloud] = {
		PB_4,
		PIN_OUTPUT,
		PullNone,
		1
	},
	[led_green] = {
		PC_0,
		PIN_OUTPUT,
		PullNone,
		1
	},
	[led_blue] = {
		PC_1,
		PIN_OUTPUT,
		PullNone,
		1
	},
	[key_blue] = {
		PC_3,
		PIN_INPUT,
		PullUp
	},
	[key_register] = {
		PC_2,
		PIN_INPUT,
		PullUp
	}
};

static gpio_t gpio[ARRAY_LEN(gpio_info)];

void init_led_key(void)
{
	int i;

	for (i = 0; i < ARRAY_LEN(gpio_info); i++) {
		gpio_init(&gpio[i], gpio_info[i].pin);
		gpio_dir(&gpio[i], gpio_info[i].dir);
		gpio_mode(&gpio[i], gpio_info[i].mode);
		if (gpio_info[i].dir == PIN_OUTPUT) {
			gpio_write(&gpio[i], gpio_info[i].val);
		}
	}
}

int get_key(enum gpio key)
{
	if (key > led_max && key <= key_max) {
		return !gpio_read(&gpio[key]);
	}
	return 0;
}

void set_led(enum gpio led, int on)
{
	if (led <= led_max) {
		gpio_write(&gpio[led], !on);
	}
}
