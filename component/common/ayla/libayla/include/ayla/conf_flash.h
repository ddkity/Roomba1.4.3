/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CONF_FLASH_H__
#define __AYLA_CONF_FLASH_H__

#include <ayla/utypes.h>

#define CONF_MAGIC 0xc1		/* magic value for config file */
#define CONF_VERSION 1		/* version number for config header */
#define CONF_SBP_VERSION 2	/* version number superblock pointer header */

#define CONF_BLOCK_SIZE	2048	/* flash block size */
#define CONF_BLOCK_MASK	(1024 - 1)

/* Args for reading the wififw from flash */
#define WIFI_FW_OFF 0
#define WIFI_FW_SZ  1

/*
 * Flash file I-node numbers.
 * Do not change these values except for CI_FILES.
 */
enum conf_inode {
	CI_ID = 0,		/* Identification items */
	CI_FACTORY = 1,		/* factory configuration */
	CI_STARTUP = 2,		/* startup configuration */
	CI_MOD_IMAGE = 3,	/* module firmware image */
	CI_WIFI_IMAGE = 4,	/* Wi-Fi firmware image */
	CI_FLUP = 5,		/* flash update program */
	CI_BOOT = 6,		/* boot program */
	CI_LOG = 7,		/* saved log entries */
	CI_MFG_TEST = 8,	/* manufacturing test program */
	CI_PATCHER = 9,		/* patch applying program */
	CI_PATCH = 0x0a,	/* patch data */
	CI_MOD_IMAGE2 = 0x0b,	/* 2nd module firmware image */
	CI_FILES		/* must be last, number of files */
};

/*
 * struct name_val initializer to convert between inode numbers and names.
 * Keep this in sync with enum conf_inode, above.
 */
#define CONF_INODE_NAMES { \
	{ .name = "id", .val = CI_ID }, \
	{ .name = "factory", .val = CI_FACTORY }, \
	{ .name = "startup", .val = CI_STARTUP }, \
	{ .name = "mod_image", .val = CI_MOD_IMAGE }, \
	{ .name = "wifi_image", .val = CI_WIFI_IMAGE }, \
	{ .name = "flup", .val = CI_FLUP }, \
	{ .name = "boot", .val = CI_BOOT }, \
	{ .name = "log", .val = CI_LOG }, \
	{ .name = "mfg_test", .val = CI_MFG_TEST }, \
	{ .name = "patcher", .val = CI_PATCHER }, \
	{ .name = "patch", .val = CI_PATCH }, \
	{ .name = "mod_image2", .val = CI_MOD_IMAGE2 }, \
	{ .name = NULL, .val = -1 } \
}

enum conf_dev {
	CDEV_LOCAL,		/* local flash */
	CDEV_EXT,		/* outboard flash on SPI1 */
	CDEV_MFG,		/* outboard flash on SPI2 */
	CDEV_OTP,		/* one-time-programmable area on-chip */
	CDEV_COUNT		/* must be last, count of devices */
};


/*
 * Keep this in sync with enum conf_inode, above.
 * struct name_val initializer to convert between inode numbers and names.
 */
#define CONF_DEV_NAMES { \
	{ .name = "int", .val = CDEV_LOCAL }, \
	{ .name = "ext", .val = CDEV_EXT }, \
	{ .name = "mfg", .val = CDEV_MFG }, \
	{ .name = NULL, .val = -1 } \
}

/*
 * Header for several in-flash structures helps identify them.
 *
 * The v2_config flag in config files means that the config uses an incremental
 * arrangement allowing appending to the config without erasing the block.
 * In program file headers it means that the program understands that the ID
 * config may be amended by appending replacement value/name pairs.
 */
struct conf_head {
	u8	magic;		/* indicates config area */
	u8	version;	/* config file format version */
	u8	inode;		/* inode number, used for archives only */
	u8	gen_id:7;	/* generation ID */
	u8	v2_config:1;	/* version 2 config TLVs (see note above) */
	u32	len;		/* length of the containing structure */
	u32	data_len;	/* number of valid bytes following head */
	u8	file_ver[3];	/* major, minor, micro version */
	u8	_resvd2[1];	/* reserved for future use */
};

struct conf_head_ext {
	u32     next_blk;
	struct conf_head head;
};

struct conf_blk_head {
	u32     crc;
	u32	len;		/* length of the block */
	u32     next_blk;        /* offset to next conf_blk_head (if present) */
	u32     _resvd;
};

/*
 * Tail for in-flash structures.  Contains length to find the head, and CRC.
 * Do not grow this structure.  It must be at the very end of flash space.
 */
struct conf_tail {
	u32	len;		/* length of containing structure */
	le32	crc;		/* CRC-32 of containing structure */
};

struct conf_file {
	u8	dev;		/* device */
	u8	_resvd[3];
	u32	loc;		/* starting offset on device */
	u32	max_len;	/* maximum length reserved */
};

/*
 * Configuration location information (super-block).
 * This structure sits at the end of the local flash and tells us where the
 * configurations are.
 * This is expected to be rewritten very infrequently if at all.
 */
#define CI_MAX_FILES	\
	((CONF_BLOCK_SIZE - sizeof(struct conf_head) - \
	    sizeof(struct conf_tail)) / sizeof(struct conf_file))

struct conf_super_prototype {
	struct conf_head head;	/* must be first */
	struct conf_file file[CI_MAX_FILES];	/* file discriptors */
	struct conf_tail tail;	/* must be last */
};

/*
 * Pointer structure which can precede the image header in the boot block.
 */
struct conf_pointer {
	u8	magic;		/* indicates config area */
	u8	version;	/* config file format version */
	u8	_resvd1[2];	/* not used */
	u32	pointer;	/* pointer to something */
	u32	_resvd2[2];	/* number of valid bytes following head */
};

/*
 * Space in on-chip flash.
 */
extern char _start_config[];	/* provided by linker script */
extern char _end_config[];	/* provided by linker script */

/*
 * Device interface.
 * Unifies interface for internal and external flash.
 */
struct flash_dev {
	u32 size;
	u16 sector_size;
	u8 write_align;
	const struct flash_ops *ops;
	void *driver;		/* for use by driver */
};

enum flash_lock_type {
	FLOCK_NONE = 0,		/* no lock */
	FLOCK_RDONLY = 1,	/* lock against programming (reversible) */
	FLOCK_RDONLY_PERM = 2,	/* permanently lock against programming  */
	FLOCK_RDONLY_SEC = 3,	/* prevent from being read by debugging tools */
};

struct flash_ops {
	int (*erase)(struct flash_dev *, u32 offset, size_t);
	int (*write)(struct flash_dev *, u32 offset, const void *buf, size_t);
	int (*read)(struct flash_dev *, u32 offset, void *buf, size_t);
	void *(*map)(struct flash_dev *, u32 offset, size_t);
	int (*lock)(struct flash_dev *, enum flash_lock_type,
			u32 offset, size_t);
	u32 (*sector_size)(struct flash_dev *, u32 offset);
	int (*find_writeable)(struct flash_dev *, u32 offset, size_t);
};

void conf_put_name_val(enum conf_token *path, int plen,
		struct ayla_tlv *val);

/*
 * Device operations.
 */
void *conf_flash_dev_read(struct flash_dev *, u32 offset, void *, size_t);

/*
 * File interface.
 */
int conf_flash_dev_attach(enum conf_dev, struct flash_dev *);
struct flash_dev *conf_flash_open(enum conf_dev);
u32 conf_flash_sector_size(struct flash_dev *, u32 offset);

int conf_flash_write_superblock(enum conf_dev, u32 offset, size_t, size_t,
		u32 sb_loc, const struct conf_file *, u32 nfiles);

int conf_flash_open_write(enum conf_inode, struct conf_file **);
int conf_flash_open_read(enum conf_inode, struct conf_file **,
		struct conf_head *);
void conf_flash_flush(enum conf_inode);	/* flush cached data to flash */

int conf_flash_write_head(struct conf_file *, u8 gen_id);
int conf_flash_write(enum conf_inode, size_t offset, void *, size_t);
int conf_flash_write_blk(struct conf_file *, size_t offset, void *, size_t);
int conf_flash_lock(struct conf_file *file, size_t len);
size_t conf_flash_get_length(struct conf_file *);
size_t conf_flash_get_archive_length(struct conf_file *, unsigned int index);
int conf_flash_get_archive_crc(struct conf_file *file,
    unsigned int index, u32 *crcp);
int conf_flash_read_head(struct conf_file *file, u32 offset,
	struct conf_head *head_buf);
void *conf_flash_read(struct conf_file *, size_t off, void *buf, size_t);
void *conf_flash_read_archive(struct conf_file *, unsigned int index,
	size_t off, void *buf, size_t);
struct conf_head *conf_flash_read_archive_head(struct conf_file *file,
	unsigned int index, struct conf_head *head_buf, size_t *head_offp);
size_t conf_flash_get_append_space(enum conf_inode inode, u32 *offsetp);
int conf_flash_erase(enum conf_inode);
void conf_flash_erase_if_needed(enum conf_inode inode);
size_t conf_flash_file_align(struct conf_file *file, size_t off);

void conf_flash_init(void);
void conf_plat_flash_init(void);
int conf_flash_copy(struct conf_file *from, struct conf_file *to);
u32 conf_ext_flash_wififw(int);

/*
 * Conf file operations.
 */
int conf_load(enum conf_inode);
int conf_load_config(void);
int conf_save(enum conf_inode);
int conf_save_config(void);
int conf_copy(enum conf_inode from_inode, enum conf_inode to_node);

/*
 * Indicate that old ID should be overwritten or appended to with new ID.
 */
void conf_id_reset(void);

/*
 * Utility functions.
 */
int conf_flash_erased(void *, size_t);

/*
 * Driver init routines.
 */
void flash_hw_init(void);

#endif /* __AYLA_CONF_FLASH_H__ */
