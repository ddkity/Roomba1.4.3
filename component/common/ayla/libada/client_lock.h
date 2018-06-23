/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CLIENT_LOCK_H__
#define __AYLA_CLIENT_LOCK_H__

#ifdef CLIENT_MT

/*
 * Multi-threaded version, requiring locks.
 */
#define client_lock() client_lock_int(__func__, __LINE__);
#define client_unlock() client_unlock_int(__func__, __LINE__);
#define notify_lock() notify_lock_int(__func__, __LINE__);
#define notify_unlock() notify_unlock_int(__func__, __LINE__);

void client_lock_int(const char *, int);
void client_unlock_int(const char *, int);
void client_lock_stamp(const char *func, int line);
extern u8 client_locked;		/* for ASSERTs only */
void notify_lock_int(const char *, int);
void notify_unlock_int(const char *, int);
void notify_lock_init(void);

#else

/*
 * Single-threaded version, always running in TCP/IP thread.
 */
static inline void client_lock(void)
{
}

static inline void client_unlock(void)
{
}

static inline void client_lock_stamp(const char *func, int line)
{
}

#define client_locked 1			/* satisfy ASSERTs */

static inline void notify_lock(void)
{
}

static inline void notify_unlock(void)
{
}

static inline void notify_lock_init(void)
{
}

#endif /* CLIENT_MT */

#endif /* __AYLA_CLIENT_LOCK_H__ */
