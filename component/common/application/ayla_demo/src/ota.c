/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */
#define HAVE_UTYPES
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include <device_lock.h>
#include <ota_8195a.h>
#undef LOG_INFO
#undef LOG_DEBUG
#undef CONTAINER_OF

#include <ayla/utypes.h>
#include <ayla/clock.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/tlv.h>
#include <ayla/conf.h>

#include <ada/libada.h>
#include <ada/client_ota.h>
#include <net/base64.h>
#include <net/net.h>
#include "conf.h"

struct demo_ota {
	u32 exp_len;
	u32 rx_len;

	u32 partition_addr;
	u32 partition_size;
	u8 save_done;
};
static struct demo_ota demo_ota;

static enum patch_state demo_ota_notify(unsigned int len, const char *ver)
{
	struct demo_ota *ota = &demo_ota;

	log_put(LOG_INFO "OTA notification: length %u version \"%s\"\r\n",
	    len, ver);

	if (len < 4) {
		return PB_ERR_PHEAD;
	}

	ota->exp_len = len;
	ota->rx_len = 0;
	ota->save_done = 0;

#ifdef AYLA_DEMO_TEST
	ada_api_call(ADA_OTA_START, OTA_HOST);
#else
	ada_ota_start(OTA_HOST);
#endif
	return PB_DONE;
}

static enum patch_state demo_ota_save(unsigned int offset, const void *buf,
	size_t len)
{
	struct demo_ota *ota = &demo_ota;
	flash_t flash_ota;
	u32 exp_len;
	u32 i, k, flash_checksum;
	_file_checksum checksum;
	int ret;
	unsigned char chkbuf[512];

	if (ota->rx_len == 0) {
		ota->partition_addr = update_ota_prepare_addr();
		/* Since debug message in update_ serial function without \n */
		printf("\n");
		if (ota->partition_addr == ~0) {
			return PB_ERR_STATE;
		}
#if SWAP_UPDATE
		ota->partition_addr = update_ota_swap_addr(ota->exp_len,
		    ota->partition_addr);
		/* Since debug message in update_ serial function without \n */
		printf("\n");
		if (ota->partition_addr == ~0) {
			return PB_ERR_STATE;
		}
#endif
		ota->partition_size = update_ota_erase_upg_region(ota->exp_len,
		    0, ota->partition_addr);
		/* Since debug message in update_ serial function without \n */
		printf("\n");
	}

	if (ota->rx_len != offset) {
		log_put(LOG_WARN "OTA save: offset skip at %lu", offset);
		return PB_ERR_FATAL;
	}
	ota->rx_len += len;

	if (ota->rx_len > ota->exp_len) {
		log_put(LOG_WARN "OTA save: rx at %lu past len %lu",
		    ota->rx_len, ota->exp_len);
		return PB_ERR_FATAL;
	}

	device_mutex_lock(RT_DEV_LOCK_FLASH);
	ret = flash_stream_write(&flash_ota, ota->partition_addr+offset,
	    len, buf);
	device_mutex_unlock(RT_DEV_LOCK_FLASH);
	if (ret < 0) {
		return PB_ERR_WRITE;
	}

	if (ota->rx_len < ota->exp_len) {
		return PB_DONE;
	}

	exp_len = ota->exp_len - 4;
	flash_checksum = 0;
	for (i = 0; i < exp_len; i += sizeof(chkbuf)) {
		len = sizeof(chkbuf);
		if (i + len > exp_len) {
			len = exp_len - i;
		}
		device_mutex_lock(RT_DEV_LOCK_FLASH);
		flash_stream_read(&flash_ota, ota->partition_addr + i,
		    len, chkbuf);
		device_mutex_unlock(RT_DEV_LOCK_FLASH);
		for (k = 0; k < len; k++)
			flash_checksum += chkbuf[k];
	}

	device_mutex_lock(RT_DEV_LOCK_FLASH);
	flash_stream_read(&flash_ota, ota->partition_addr + exp_len,
	    sizeof(checksum), &checksum);
	device_mutex_unlock(RT_DEV_LOCK_FLASH);

	ret = update_ota_checksum(&checksum, flash_checksum,
	    ota->partition_addr);
	/* Since debug message in update_ serial function without \n */
	printf("\n");
	if (ret < 0) {
		log_put(LOG_WARN "OTA save: CRC check fail!");
		return PB_ERR_FILE_CRC;
	}
	ota->save_done = 1;

	return PB_DONE;
}

static void demo_ota_save_done(void)
{
	struct demo_ota *ota = &demo_ota;
	enum patch_state status;

	if (!ota->save_done) {
		log_put(LOG_WARN "OTA save_done: OTA not completely saved");
		status = PB_ERR_FATAL;
#ifdef AYLA_DEMO_TEST
		ada_api_call(ADA_OTA_REPORT, OTA_HOST, status);
#else
		ada_ota_report(OTA_HOST, status);
#endif
		return;
	}

	vTaskDelay(200);
	ota_platform_reset();
}

static struct ada_ota_ops demo_ota_ops = {
	.notify = demo_ota_notify,
	.save = demo_ota_save,
	.save_done = demo_ota_save_done,
};

void demo_ota_init(void)
{
	ada_ota_register(OTA_HOST, &demo_ota_ops);
}
