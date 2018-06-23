/*
 * Copyright 2013 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_RANDOM_H__
#define __AYLA_RANDOM_H__

/*
 * Supplied by application.
 */
void random_fill(void *, size_t);

/*
 * for internal use from random_fill() only.
 */
ssize_t hw_random_fill(void *, size_t);

#endif /* __AYLA_RANDOM_H__ */
