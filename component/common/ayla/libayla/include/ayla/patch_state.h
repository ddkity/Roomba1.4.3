/*
 * Copyright 2012, 2015 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_PATCH_STATE_H__
#define __AYLA_PATCH_STATE_H__

/*
 * Patch state (and error) codes.
 *
 * These codes must not change without coordination with ADS.
 */
PREPACKED_ENUM enum patch_state {
	PB_DONE = 0,		/* no error, or completely patched block */

	/*
	 * Patch not matching software version.
	 */
	PB_ERR_NEW_CRC = 0x01,	/* block would have CRC error after patch */
	PB_ERR_STALL = 0x02,	/* transfer stalled (not reported to service) */
	PB_ERR_MEM = 0x03,	/* resource problem (not retried) */

	/*
	 * Problems with the download.
	 */
	PB_ERR_NOTIFY = 0x07,	/* failed to notify MCU */
	PB_ERR_CONNECT = 0x08,  /* failed to connect to image server */
	PB_ERR_GET = 0x09,	/* service gave error during download */
	PB_ERR_URL = 0x0a,	/* invalid URL protocol or path for OTA */
	PB_ERR_TYPE = 0x0b,	/* invalid patch type */
	PB_ERR_VER = 0x0c,	/* request didn't provide version */
	PB_ERR_SIZE = 0x0d,	/* request didn't provide size */
	PB_ERR_REQ = 0x0e,	/* other errors with the OTA command */

	/*
	 * Codes indicating an invalid patch.
	 */
	PB_ERR_DECOMP = 0x10,	/* patch file decompression error */
	PB_ERR_OP_LEN = 0x11,	/* segment length extends past end-of-file */
	PB_ERR_FATAL = 0x12,	/* unspecified fatal error in applying patch */
	PB_ERR_OP = 0x13,	/* segment has invalid opcode */
	PB_ERR_STATE = 0x14,	/* patch program in invalid state */
	PB_ERR_CRC = 0x15,	/* block has CRC error before the patch */
	PB_ERR_COPIES = 0x16,	/* more than one block is in copied state */
	PB_ERR_PHEAD = 0x17,	/* patch head version or length error */
	PB_ERR_FILE_CRC = 0x18,	/* patch file has CRC error */

	/*
	 * Possible hardware issues.
	 */
	PB_ERR_ERASE = 0x20,	/* block erase failed */
	PB_ERR_WRITE = 0x21,	/* block write-back failed */
	PB_ERR_SCRATCH_SIZE = 0x22, /* scratch block length too short */
	PB_ERR_DIFF_BLKS = 0x23, /* old and new code are in diff blocks */
	PB_ERR_OLD_BLKS = 0x24, /* old code of patch spans two blocks */
	PB_ERR_NEW_BLKS = 0x25, /* new code of patch spans two blocks */
	PB_ERR_SCR_ERASE = 0x26, /* scratch block erase error */
	PB_ERR_SCR_WRITE = 0x27, /* scratch block write error */
	PB_ERR_PROG = 0x28,	/* error reading/writing progress byte */
	PB_ERR_PROT = 0x29,	/* block to be patched is not state PB_START */

	/*
	 * Module / patcher software problems.
	 */
	PB_ERR_NOFILE = 0x30,	/* patch file not found */
	PB_ERR_HEAD = 0x31,	/* patch file read of head failed */
	PB_ERR_NO_PROG = 0x33,	/* patch file not followed by progress area */
	PB_ERR_INV_PROG = 0x34,	/* invalid progress area */
	PB_ERR_READ = 0x35,	/* patch file read error */
	PB_ERR_DECOMP_INIT = 0x36, /* patch file decompression init error */
	PB_ERR_PREV = 0x37,	/* previous patch attempt failed */
	PB_ERR_OPEN = 0x39,	/* error opening flash device */
	PB_ERR_BOOT = 0x3a,	/* patcher did not boot, bb may be downlevel */

	/*
	 * In-progress state codes.
	 */
	PB_COPIED = 0x3f,	/* old version may have been erased */
	PB_START = 0x7f,	/* block ready to have patch applied */
	PB_NONE = 0xff,		/* block should be left alone */
} PACKED_ENUM;

ASSERT_COMPILE(progress, sizeof(enum patch_state) == 1);

#endif /* __AYLA_PATCH_STATE_H__ */
