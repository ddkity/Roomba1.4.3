/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */

#ifndef __AYLA_BOOTINFO_H__
#define __AYLA_BOOTINFO_H__

/*
 * This is how bootloader can pass parameters to app.
 * This is located at end of SRAM, so beginning of structure is at:
 * SRAM_END - sizeof (struct bootinfo).
 * Structure can grow from the front.
 */
extern struct bootinfo _bootinfo;

struct bootinfo {
	unsigned int fs_loc;
	unsigned char _pad;
	unsigned char file2boot;
	unsigned char len;
	unsigned char magic;
};
#define BOOTINFO_MAGIC 0xc3

#endif
