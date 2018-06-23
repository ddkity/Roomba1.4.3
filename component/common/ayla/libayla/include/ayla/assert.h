/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ASSERT_H__
#define __AYLA_ASSERT_H__

#ifdef _HAS_ASSERT_F_
void __assert_f(const char *file, int line);
#else
#define __assert_f(a, b) __asm__("bkpt")
#endif

#define AYLA_ASSERT(expr)				\
	do {						\
		if (!(expr)) {				\
			__assert_f(__FILE__, __LINE__);	\
		}					\
	} while (0)

#ifndef ASSERT
#define ASSERT AYLA_ASSERT
#endif

#ifdef DEBUG
#define AYLA_ASSERT_DEBUG(expr) AYLA_ASSERT(expr)
#else
#define AYLA_ASSERT_DEBUG(expr) do { (void)(expr); } while (0)
#endif /* DEBUG */

#ifndef ASSERT_DEBUG
#define ASSERT_DEBUG		AYLA_ASSERT_DEBUG
#endif

#define AYLA_ASSERT_NOTREACHED()			\
	do {						\
		__assert_f(__FILE__, __LINE__);		\
	} while (1)

#ifndef ASSERT_NOTREACHED
#define ASSERT_NOTREACHED	AYLA_ASSERT_NOTREACHED
#endif

/*
 * Force a compile error if an expression is false or can't be evalutated.
 */
#define ASSERT_COMPILE(name, expr) \
	extern char __ASSERT_##__name[(expr) ? 1 : -1]

/*
 * Force a compile error if size of type is not as expected.
 */
#define ASSERT_SIZE(kind, name, size) \
	ASSERT_COMPILE(kind ## name, sizeof(kind name) == (size))

#endif /* __AYLA_ASSERT_H__ */
