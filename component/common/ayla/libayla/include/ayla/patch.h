/*
 * Copyright 2012 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_PATCH_H__
#define __AYLA_PATCH_H__

#include <ayla/patch_state.h>

/*
 * Patch file format:
 *
 * Patch has conf_head and conf_tail with inode number CI_PATCH.
 * After the conf_tail there are TBD bytes initialized to 0xff
 * that will be cleared by the patcher to indicate patch progress.
 *
 * struct conf_head	(see ayla/conf_flash.h)
 * struct patch_head
 * --- begin compressed portion (gzipped)
 * This is followed by a number of sections consisting of:
 *	struct section_head
 *	section data (optional)
 * --- end of compressed portion
 * struct conf_tail with CRC over entire patch to this point
 * patch_progress bytes
 */

#define PATCH_FMT_VER	1	/* version of this patch format */

PREPACKED_ENUM enum patch_op {
	PO_NONE = 0,		/* unused opcode */
	PO_DIFF = 1,		/* add values to old image to make new image */
	PO_INSERT = 2,		/* insert bytes into new image */
	PO_SKIP = 3,		/* move to offset in old image (can be neg) */
	PO_COPY = 4,		/* copy bytes from old image to new image */
	PO_CRC = 5,             /* crc32 check value of new data, reset calc */
} PACKED_ENUM;

ASSERT_COMPILE(patch_op, sizeof(enum patch_op) == 1);

struct patch_head {
	u8	version;	/* patch format version  */
	u8	header_len;	/* size of this structure */
	u8	program[10];	/* e.g., "bc" */
	u8	old_version[3]; /* e.g., 0,19,1 */
	u8	new_version[3]; /* e.g., 0,19,2 */
	u8	model[12];	/* e.g., "AY001MUS" */
};

struct section_head {
	enum patch_op opcode;	/* opcode - one byte */
	u8	len[4];		/* data length or amount to skip, big-endian */
};
ASSERT_COMPILE(section_head, sizeof(struct section_head) == 5);

#ifdef FLASH_PATCH_UNITS	/* this section not always needed */

/*
 * Per-block progress bar values.
 * The overall status is at index 0.  Other status bytes are per flash block.
 *
 * When the patch is downloaded, the status for the blocks that can be
 * modified is set to 0x7f.  Other blocks status remains at 0xff.
 * When the new version of a block is in the scratch area and can be copied
 * back, it's status will be changed to 0x3f.
 * Once a block is successfully copied back, the status is set to zero.
 * If any error occurs, then the error number, between 0 and 0x7f, is set.
 *
 * The overall status is set to 0x7f by BC to command that a patch be applied.
 * After that, the boot program will run the patcher until that byte is set
 * to 0 or an error number.
 */

#define PATCH_PROG_MAGIC	0xbb

struct patch_progress {
	u8 magic;		/* starting magic 0xbb */
	u8 len;			/* bytes in progress area */
	u8 sectors;		/* sectors for progress */
	u8 debug;		/* debug / test progress */
	u32 patch_offset;	/* offset in patch file where patch failed */
	u32 patch_addr;		/* address in new version where patch failed */
	enum patch_state overall;
	enum patch_state block[FLASH_PATCH_UNITS];
};
#endif /* FLASH_PATCH_UNITS */

/*
 * Magic numbers for passing values through battery-backed-up registers.
 * See bb_ops.h.
 */
#define PATCH_BB_MASK	0xff00
#define PATCH_BB_OP	0xea00
#define PATCH_BB_STAT	0xeb00

#endif /* __AYLA_PATCH_H__ */
