/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_SERIAL_H__
#define __AYLA_SERIAL_H__

#define SERIAL_PORTS		2
#define SERIAL_CONS		0
#define SERIAL_MCU		1
#define SERIAL_CONS_BAUD	115200

struct muart_parameters {
	u32 baudrate;
	u32 mode;
};
extern struct muart_parameters muart_cfg;

#define AUART_PARITY(a)         (0x00000003 & (a))
#define AUART_PARITY_NONE       0x00000000
#define AUART_PARITY_ODD        0x00000001
#define AUART_PARITY_EVEN       0x00000002

void serial_init(int uart, u32 speed, int (*get_tx)(void), int (*rx_intr)(u8));
void serial_start_tx(int uart);
void serial_rx_unblock(int uart);
void serial_speed(int uart, u32 speed);
void serial_speed_mode(int uart, u32 speed, u32 mode);
int serial_check_baudrate(u32 baudrate);
int serial_check_mode(u32 mode);
int serial_isbusy(int uart);

#ifdef POLLING_SERIAL
void serial_poll(int uart);
#endif
#ifdef STOP_MODE_SUPPORT
int serial_isbusy(int uart);
void serial_stopmode_enter(void (*woke_up_cb)(void));
void serial_stopmode_exit(void);
#endif

#define SERIAL_PRI	12		/* interrupt priority */

void uart_irq(void);
void trap_cons_out(char c);

#endif /* __AYLA_SERIAL_H__ */
