/*
 * Copyright 2014 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef _LIB_AYLA_I2C_H_
#define _LIB_AYLA_I2C_H_

int i2c_init(unsigned speed, u8 scl, u8 sda);
int i2c_read(u8 address, void *addr, int alen, void *data, int dlen);
int i2c_write(u8 address, void *addr, int alen, void *data, int dlen);

#endif /* _LIB_AYLA_I2C_H_ */
