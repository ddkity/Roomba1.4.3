/*
 * Copyright 2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_GPIO_H__
#define __AYLA_GPIO_H__

#include <ayla/assert.h>
#include <ayla/tlv.h>
#include <ayla/module_io.h>

/*
 * This enum definition is in configuration files / flash.  Don't change it.
 */
enum gpio_mode_mask {
	GM_ENABLE = BIT(0),	/* pin is in use for GPIO */
	GM_OUT = BIT(1),	/* pin is an output */
	GM_ANALOG = BIT(2),	/* pin is analog */
	GM_OD = BIT(3),		/* output is open-drain */
	GM_PU = BIT(4),		/* enable pull-up */
	GM_PD = BIT(5),		/* enable pull-down */
	GM_ACTV_LOW = BIT(6),	/* pin is active low */
	GM_TOGGLE = BIT(7),	/* toggle the associated output pin on assert */
	GM_PERSIST = BIT(8),	/* save value changes */
	GM_SET = BIT(9),	/* set associated output pin on assert */
	GM_RESET = BIT(10),	/* reset associated output pin on assert */
	GM_COPY = BIT(11),	/* copy input to associated output on change */
} PACKED;

/*
 * Map PA0 to bank 15, pin 0, so GPIO number 0 is unused.
 */
#define GPIO_PIN_PA0	__GPIO_PIN(GPIO_BANK_CT - 1, 0)

#define GPIO_PIN(bank, pin) \
	(((bank) | (pin)) ? __GPIO_PIN(bank, pin) : GPIO_PIN_PA0)

#define __GPIO_PIN(bank, pin) \
	(((bank) * GPIO_BANK_PINS) + ((pin) % GPIO_BANK_PINS))

#define GPIO_PA(n)	GPIO_PIN(0, n)
#define GPIO_PB(n)	GPIO_PIN(1, n)
#define GPIO_PC(n)	GPIO_PIN(2, n)
#define GPIO_PD(n)	GPIO_PIN(3, n)
#define GPIO_PE(n)	GPIO_PIN(4, n)
#define GPIO_PF(n)	GPIO_PIN(5, n)
#define GPIO_PG(n)	GPIO_PIN(6, n)
#define GPIO_PH(n)	GPIO_PIN(7, n)
#define GPIO_PI(n)	GPIO_PIN(8, n)

/*
 * GPIO pin usage flags.
 * These are used in the table of available module I/O pins.
 */
enum gpio_usage {
	GPIO_WKUP = BIT(0),	/* pin used wakeup from MCU */
	GPIO_SPI = BIT(1),	/* pin used for SPI from MCU */
	GPIO_UART = BIT(2),	/* pin used for UART from MCU */
	GPIO_NO_INTR = BIT(3),	/* external interrupt not available */
} PACKED;

struct gpio_mod_io {
	u8	pin;
	enum gpio_usage	usage;
	enum gpio_mode_mask mode;
	struct gpio *gpio;
};

#define GPIO_INIT_MODE(_pin, _usage, _mode) { \
	.pin = (_pin), \
	.usage = (_usage), \
	.mode = (_mode) \
}

#define GPIO_INIT(_pin, _usage)	GPIO_INIT_MODE(_pin, _usage, 0)


static inline u8 gpio_pin(u8 bank, u8 pin)
{
	return GPIO_PIN(bank, pin);
}

static inline u8 gpio_pin_bit(u8 pin)
{
	return pin % GPIO_BANK_PINS;
}

static inline u8 gpio_pin_bank(u8 pin)
{
	if (pin == GPIO_PIN_PA0) {
		return 0;
	}
	return pin / GPIO_BANK_PINS;
}

/*
 * BC definitions.
 */
enum pin_speed {
	PS_SLOW = 0,
	PS_MED = 1,
	PS_FAST = 2,
	PS_FASTER = 3
};

void module_gpio_set(u8 pin, enum gpio_mode_mask, int val);
int module_gpio_get(u8 pin);
void module_gpio_init(u8 pin_id, enum gpio_mode_mask mode, u8 val,
			enum pin_speed speed);
void module_gpio_af_init(u8 pin_id, enum gpio_mode_mask mode, u8 af,
			enum pin_speed speed);
void module_gpio_i2c(u8 *scl, u8 *sda);

struct prop;
enum gpio_mode_mask gpio_prop_mode_get(const char *name, u8 src);
int gpio_prop_get_imm(const char *name, u8 src);
int gpio_prop_set(const char *name, const void *vp,
			enum ayla_tlv_type type, u8 src);
void gpio_set_connectivity(void);

void gpio_cli(int argc, char **argv);
void gpio_run_identify(void *arg);
void gpio_reset_mcu(void);

/*
 * Device status bits.
 * These values are ORed together.
 */
enum device_status {
	DS_INIT = BIT(0),	/* GPIO status initialized */
	DS_WIFI_INIT = BIT(1),	/* Wi-Fi has joined a station */
	DS_WIFI_SETUP = BIT(2), /* Wi-Fi setup in progress */
	DS_WIFI_UP = BIT(3),	/* Wi-Fi has joined a station */
	DS_SERVICE = BIT(4),	/* Connection to ADS successful */
	DS_USER = BIT(5),	/* A user is registered */
	DS_RESETTING = BIT(6),	/* Looming reset */
	DS_TEST_WAIT = BIT(7),	/* looming test mode */
};
void gpio_device_status_set(enum device_status);
void gpio_device_status_reset(enum device_status);
void gpio_host_ver_send(void);
void gpio_mode_set(int enable);
void gpio_prop_event_set(const char *name, void (*callback)(void *), void *arg);

#endif /* __AYLA_GPIO_H__ */
