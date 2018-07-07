/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */
#ifndef __AYLA_DEMO_CONF_H__
#define __AYLA_DEMO_CONF_H__

/*
 * ODM company name for factory log.
 */
#define ODM_NAME  "ILIFE SWEEPER" /* replace with your company name */

/*
 * OEM info
 *
 * The OEM and oem_model strings determine the template on the first connect
 * and the host name for the service.
 *
 * If these are changed, the encrypted OEM secret must be re-encrypted
 * unless the oem_model "*" (wild-card) when the oem_key was encrypted.
 */
#define DEMO_OEM_ID	"cdbae6fc"	/* replace with your Ayla OEM ID */
#define DEMO_ILIFE_MODEL "ilife-0-0"
#define DEMO_OUTLET_MODEL "smartplug1"

/* define a key to enable the setup mode for development */
#define DEMO_SETUP_ENABLE_KEY "aylacn"
//#define DEMO_SETUP_ENABLE_KEY "ilifecn"

/*
 * Names for demo schedules.
 * Set this to {} if schedules are not used.
 */
#define DEMO_SCHED_NAMES { "schedule_in" }


/*
 * string length limits
 */
#define CONF_PATH_STR_MAX	64	/* max len of conf variable name */
#define CONF_ADS_HOST_MAX (CONF_OEM_MAX + 1 + CONF_MODEL_MAX + 1 + 24)
					/* max ADS hostname length incl NUL */
#define ADA_PUB_KEY_LEN	400

extern char conf_sys_model[];
extern char conf_sys_serial[];
extern char conf_sys_mfg_model[];
extern char conf_sys_mfg_serial[];

//extern const char mod_sw_build[];
//extern const char mod_sw_version[];
//extern u8 conf_connected;

void client_conf_init(void);

void sched_conf_load(void);

void demo_ota_init(void);

#endif /* __AYLA_DEMO_CONF_H__ */
