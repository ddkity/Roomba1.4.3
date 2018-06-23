/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CONF_TOKEN_H__
#define __AYLA_CONF_TOKEN_H__

#define CONF_TOKEN(val, name)	CT_##name = val,

enum conf_token {
	CT_INVALID_TOKEN = 0,	/* not to be converted to a name */

#include <ayla/conf_tokens.h>
	CT_TOTAL, /* Must always be the last token */
};

#undef CONF_TOKEN
#endif /* __AYLA_CONF_TOKEN_H__ */
