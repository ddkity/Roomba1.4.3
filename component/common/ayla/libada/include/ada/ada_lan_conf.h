/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __ADA_LAN_CONF_H__
#define __ADA_LAN_CONF_H__

#define CLIENT_LANIP_KEY_SIZE	32	/* lanip key size */

struct ada_lan_conf {
	u8 enable;
	u8 auto_echo;
	u16 lanip_key_id;
	u16 keep_alive;
	char lanip_key[CLIENT_LANIP_KEY_SIZE + 1];
};

#define CLIENT_LANIP_HAS_KEY(a) ((a)->lanip_key[0] != '\0')
#define CLIENT_LANIP_WIPE_KEY(a) ((a)->lanip_key[0] = '\0')

extern struct ada_lan_conf ada_lan_conf;

/*
 * Save LANIP information to persistent storage.
 */
void ada_conf_lanip_save(void);

#endif /* __ADA_LAN_CONF_H__ */
