/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_PVD_H__
#define __AYLA_PVD_H__

void pvd_init(void);
int pvd_flash_write_size(void); /* 32 bit bs 8 bits at a time */

#endif /* __AYLA_PVD_H__ */
