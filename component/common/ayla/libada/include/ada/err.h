/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_ADA_ERR_H__
#define __AYLA_ADA_ERR_H__

enum ada_err {
	AE_OK = 0,		/* no error */
	AE_BUF = -1,		/* network buf shortage - retry later */
	AE_ALLOC = -2,		/* resource shortage */
	AE_ERR = -3,		/* non-specific error */
	AE_NOT_FOUND = -4,	/* object (e.g., property) not found */
	AE_INVAL_VAL = -5,	/* invalid value */
	AE_INVAL_TYPE = -6,	/* invalid type */
	AE_IN_PROGRESS = -7,	/* successfully started, but not finished */
	AE_BUSY = -8,		/* another operation is in progress */
	AE_LEN = -9,		/* invalid length */
	AE_INVAL_STATE = -10,	/* API called without correct prerequisites */
	AE_TIMEOUT = -11,	/* operation timed out */
	AE_ABRT = -12,		/* connection aborted */
	AE_RST = -13,		/* connection reset */
	AE_CLSD = -14,		/* connection closed */
	AE_NOTCONN = -15,	/* not connected */
	AE_INVAL_NAME = -16,	/* invalid property name */
	AE_RDONLY = -17,	/* ADA tried to set a from-device property */
	AE_CERT_EXP = -18	/* SSL certificate not valid due to time */
	/* Note: update ADA_ERR_STRINGS table below when adding new values */
};

/*
 * GCC bug 52085: if this is not included before a function prototype uses the
 * enum, the enum will have size 4 instead of 1.
 * Having different sizes in different files will break structure layouts.
 * Fixed in GCC 6.  See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52085
 */
ASSERT_SIZE(enum, ada_err, 1);	/* defend against gcc bug */

#define ADA_ERR_STRINGS {			\
	[-AE_OK] = "none",			\
	[-AE_BUF] = "buf",			\
	[-AE_ALLOC] = "alloc failed",		\
	[-AE_ERR] = "error",			\
	[-AE_NOT_FOUND] = "not found",		\
	[-AE_INVAL_VAL] = "inv val",		\
	[-AE_INVAL_TYPE] = "inv type",		\
	[-AE_IN_PROGRESS] = "in progress",	\
	[-AE_BUSY] = "busy",			\
	[-AE_LEN] = "len",			\
	[-AE_INVAL_STATE] = "inv state",	\
	[-AE_TIMEOUT] = "timeout",		\
	[-AE_ABRT] = "conn abrt",		\
	[-AE_RST] = "conn reset",		\
	[-AE_CLSD] = "conn closed",		\
	[-AE_NOTCONN] = "not conn",		\
	[-AE_INVAL_NAME] = "inv name",		\
	[-AE_RDONLY] = "read-only property",	\
	[-AE_CERT_EXP] = "cert time",		\
}

const char *ada_err_string(enum ada_err);

#endif /* __AYLA_ADA_ERR_H__ */
