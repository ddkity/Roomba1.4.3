/*
 * Copyright 2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef _LIB_AYLA_I2C_INTERNAL_H_
#define _LIB_AYLA_I2C_INTERNAL_H_

void *i2c_hw_init(unsigned speed, u8 scl, u8 sda);
int i2c_hw_isbusy(void *dev);
int i2c_hw_start(void *dev);
int i2c_hw_stop(void *dev);
int i2c_hw_tx_addr(void *dev, u8 address, int write);
int i2c_hw_tx_data(void *dev, u8 data);
int i2c_hw_rx_data(void *dev, u8 *data, int last_byte);

#endif
