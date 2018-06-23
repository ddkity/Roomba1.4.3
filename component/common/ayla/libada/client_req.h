/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CLIENT_REQ_H__
#define __AYLA_CLIENT_REQ_H__

enum client_req_pri {
	ADCP_PUT_FILE_PROP,
	ADCP_GET_PING,
	ADCP_GET_DSN,
	ADCP_PUT_INFO,
	ADCP_PUT_OTA_STATUS,
	ADCP_LAN_CYCLE,
	ADCP_CMD_PUT,
	ADCP_CMD_GET,
	ADCP_POST_RESP,
	ADCP_LAN_REQ,
	ADCP_PROP_REQ,
	ADCP_REG_WINDOW_START,
	ADCP_OTA_FETCH,
	ADCP_POST_ECHO,
	ADCP_REQ_COUNT	/* must be last */
};

/*
 * Mask of above steps not always requiring access to the cloud services
 * These steps should be done even if we don't have a device ID or have
 * had errors authenticating.
 */
#define ADCP_STEPS_WITH_NO_ADS ( \
	BIT(ADCP_GET_PING) | \
	BIT(ADCP_LAN_CYCLE) | \
	BIT(ADCP_POST_RESP) | \
	BIT(ADCP_OTA_FETCH) | \
	0)

struct client_state;
extern u32 client_step_mask;

/*
 * Each non-NULL client req handler is called in priority order until one
 * returns zero, indicating it started some activity using http.
 *
 * The handler returns non-zero if it cannot run at the present time.
 *
 * Handlers are left pending until explicitly cleared.
 */
struct client_step {
	int (*handler)(struct client_state *state);
};

void client_step_set(enum client_req_pri pri,
			int (*handler)(struct client_state *));

static inline void client_step_enable(enum client_req_pri pri)
{
	client_step_mask |= BIT(pri);
}

static inline void client_step_disable(enum client_req_pri pri)
{
	client_step_mask &= ~BIT(pri);
}

static inline int client_step_is_enabled(enum client_req_pri pri)
{
	return (client_step_mask & BIT(pri)) != 0;
}
#endif /* __AYLA_CLIENT_REQ_H__ */
