/*
 * Copyright 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CLIENT_OTA_H__
#define __AYLA_CLIENT_OTA_H__

#include <ayla/patch.h>

/*
 * Over-the-air (OTA) Firmware update interfaces.
 */

/*
 * Host image is fetched in this size chunks. Best if it is a multiple
 * of max size that can fit into a TLV.
 */
#ifdef AMEBA
#define S3_OTA_GET_MCU_CHUNK_SIZE  (1 * 1024)
#define OTA_GET_MCU_CHUNK_SIZE  (2 * 1024)
#elif !defined(AYLA_BC)
#define OTA_GET_MCU_CHUNK_SIZE  (4 * 1024)
#else
#define OTA_GET_MCU_CHUNK_SIZE  (255 * 8)
#endif
#define OTA_CHUNK_RETRIES	5

/*
 * Types of OTA.
 */
PREPACKED_ENUM enum ada_ota_type {
	OTA_MODULE = 0,		/* Wi-Fi module (may include application) */
	OTA_HOST = 1,		/* external host MCU */
	OTA_TYPE_CT		/* number of OTA types */
} PACKED_ENUM;

/*
 * OTA operations.
 */
struct ada_ota_ops {
	/*
	 * OTA notify - indicates that an OTA is available.
	 * If supplied, call ada_ota_start(type) when ready.
	 */
	enum patch_state (*notify)(unsigned int len, const char *version);

	/*
	 * Receive a portion of the OTA update.
	 */
	enum patch_state (*save)(unsigned int offset, const void *, size_t);

	/*
	 * Handle the completion of the OTA update.
	 * Will report status via ada_ota_report() immediately if image was bad.
	 */
	void (*save_done)(void);

	/*
	 * Clear status of the OTA - it has been reported to the service.
	 * Optional.
	 */
	void (*status_clear)(void);
};

/*
 * Register handler for OTA
 */
void ada_ota_register(enum ada_ota_type, const struct ada_ota_ops *);

/*
 * Give permission for OTA to start.
 */
void ada_ota_start(enum ada_ota_type);

/*
 * Report status of OTA update.
 */
void ada_ota_report(enum ada_ota_type, enum patch_state);

/*
 * Continue OTA saves after reporting a stall.
 */
void ada_ota_continue(void);

#endif /* __AYLA_CLIENT_OTA_H__ */
