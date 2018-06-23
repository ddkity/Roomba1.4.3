/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_COMPILER_IAR_H__
#define __AYLA_COMPILER_IAR_H__

#ifndef PREPACKED
#define PREPACKED __packed
#endif

#ifndef PACKED
#define PACKED
#endif

#ifndef PREPACKED_ENUM
#define PREPACKED_ENUM
#endif

#ifndef PACKED_ENUM
#define PACKED_ENUM
#endif

#ifndef ADA_ATTRIB_FORMAT
#define ADA_ATTRIB_FORMAT(a, b)
#endif

#ifndef ADA_VA_LIST
#define ADA_VA_LIST va_list
#endif

#ifndef ADA_VA_START
#define ADA_VA_START va_start
#endif

#ifndef ADA_VA_END
#define ADA_VA_END va_end
#endif

#ifndef WEAK
#define WEAK __weak
#endif

#endif
