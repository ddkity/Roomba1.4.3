/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#define HAVE_UTYPES
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

#include <flash_api.h>
#include <device_lock.h>
#undef LOG_INFO
#undef LOG_DEBUG
#undef CONTAINER_OF

#include <ayla/utypes.h>
#include <ayla/endian.h>
#include <ayla/assert.h>
#include <ayla/ayla_proto_mcu.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <ayla/crc.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>

#define TOTAL_FLASH_SIZE	0x100000

#define CONF_FLASH_BLOCK_SIZE	4096
#define CONF_FLASH_MEDIA	0

#define START_CONF_SIZE		(16 * 1024)
#define FACTORY_CONF_SIZE	(16 * 1024)

#define START_CONF_ADDRESS	(FACTORY_CONF_ADDRESS - START_CONF_SIZE)
#define FACTORY_CONF_ADDRESS	(TOTAL_FLASH_SIZE - FACTORY_CONF_SIZE)

/*
 * Each supported file has its own flash_state.
 */
struct flash_state {
	u8 open:1;		/* opened */
	u8 written:1;		/* wrote on it */
	uint handle;
	struct conf_file file;	/* file structure for single inode */
};

static struct flash_state flash_state[] = {
	[CI_FACTORY] = {
		.file = {
			.loc = FACTORY_CONF_ADDRESS,
			.max_len = 16 * 1024,
		},
	},
	[CI_STARTUP] = {
		.file = {
			.loc = START_CONF_ADDRESS,
			.max_len = 16 * 1024,
		},
	},
};


static int rtk_flash_read(uint dset_handle, u8 *buffer,
    u32 len, u32 offset)
{
	flash_t flash;

	if (len > 0) {
		device_mutex_lock(RT_DEV_LOCK_FLASH);
		flash_stream_read(&flash, dset_handle+offset, len, buffer);
		device_mutex_unlock(RT_DEV_LOCK_FLASH);
	}

	return 0;
}

static int rtk_flash_write(uint dset_handle, u8 *buffer,
    u32 len, u32 offset)
{
	flash_t obj;

	device_mutex_lock(RT_DEV_LOCK_FLASH);
	flash_stream_write(&obj, offset, len, buffer);
	device_mutex_unlock(RT_DEV_LOCK_FLASH);

	return 0;
}

static struct flash_state *conf_flash_state(enum conf_inode inode)
{
	if (inode > ARRAY_LEN(flash_state) || inode < 0) {
		return NULL;
	}
	return &flash_state[inode];
}

int conf_flash_erased(void *buf, size_t len)
{
	u32 *bp;
	u8 *cp = buf;

	for (cp = buf; ((u32)cp & 0x3) != 0 && len > 0; cp++, len--) {
		if (*cp != 0xff) {
			return 0;
		}
	}
	for (bp = (u32 *)cp; len >= sizeof(u32); bp++, len -= sizeof(u32)) {
		if (*bp != 0xffffffff) {
			return 0;
		}
	}
	for (cp = (u8 *)bp; len > 0; cp++, len--) {
		if (*cp != 0xff) {
			return 0;
		}
	}
	return 1;
}

/*
 * Initialize flash state.
 */
void conf_flash_init(void)
{
}

/*
 * read or map a section of a file, such as the header.
 */
static void *conf_flash_raw_read(struct conf_file *file, u32 offset,
	void *buf, size_t len)
{
	struct flash_state *state =
	    CONTAINER_OF(struct flash_state, file, file);
	int status;

	if (offset + len > file->max_len) {
		return NULL;
	}
	status = rtk_flash_read(file->loc, buf, len, offset);
	if (status != 0) {
		return NULL;
	}
	return buf;
}

/*
 * write a section of a file.
 */
static int conf_flash_raw_write(struct conf_file *file, u32 offset,
	void *buf, size_t len)
{
	struct flash_state *state =
	    CONTAINER_OF(struct flash_state, file, file);
	uint status;

	if (offset + len - file->loc > file->max_len) {
		return -1;
	}
	status = rtk_flash_write(file->loc, buf, len, offset);
	if (status != 0) {
		return -1;
	}
	state->written = 1;
	return 0;
}

void conf_flash_flush(enum conf_inode inode)
{
	struct flash_state *state;
	int status;

	state = conf_flash_state(inode);
	if (!state) {
		conf_log(LOG_ERR "%s: inode %u out of range", __func__, inode);
		return;
	}
	if (!state->open || !state->written) {
		return;
	}
	state->written = 0;
}

/*
 * Open a configuration file in flash.
 * Fills in a caller-supplied structure that can be used for further reads.
 */
int conf_flash_open_write(enum conf_inode inode, struct conf_file **fh)
{
	struct flash_state *state;

	*fh = NULL;
	state = conf_flash_state(inode);
	if (!state) {
		conf_log(LOG_ERR "%s: inode %u out of range\n",
		    __func__, inode);
		return -1;
	}
	if (state->open) {
		*fh = &state->file;
		return 0;
	}
	state->open = 1;
	*fh = &state->file;
	return 0;
}

/*
 * Read a file header.
 * The offset parameter may be non-zero for appended files.
 * On failure other than for I/O problems, the header will
 * be copied into *head_buf anyway.
 */
int conf_flash_read_head(struct conf_file *file, u32 offset,
	struct conf_head *head_buf)
{
	struct conf_head *head;
	u32 *vector;
	u32 entry;
	u8 magic;
	int rc = -1;
	size_t min_len;

	head = conf_flash_raw_read(file, offset, head_buf, sizeof(*head_buf));
	if (!head) {
		log_err(LOG_MOD_DEFAULT, "conf_flash_read_head: read failed");
		return -1;
	}

	magic = head->magic;
	if (magic != CONF_MAGIC) {
		if (conf_flash_erased(head, sizeof(*head))) {
			goto out;
		}

		/*
		 * Look for file header before program entry point.
		 */
		vector = (u32 *)head;
		entry = vector[1] & ~1 & 0xfff;	/* entry in first 4K */
		if (offset + entry >= sizeof(*head) &&
		    offset + entry < file->max_len) {
			head = conf_flash_raw_read(file,
			    offset + entry - sizeof(*head),
			    head_buf, sizeof(*head_buf));
		}
		if (!head || head->magic != CONF_MAGIC) {
			log_warn(LOG_MOD_DEFAULT,
			    "conf_flash_read_head: bad magic %x",
			    magic);
			goto out;
		}
		min_len = head->data_len + sizeof(struct conf_tail);
	} else {
		min_len = head->data_len + sizeof(struct conf_head);
	}
	if (head->version != CONF_VERSION) {
		log_warn(LOG_MOD_DEFAULT,
		    "conf_flash_read_head: bad version %x",
		    head->version);
		goto out;
	}

	/*
	 * Check length to avoid looping on zero head->len.
	 * Config files do not have tails, so don't insist on that.
	 * If head is in midst of program, data_len does include sizeof(head).
	 */
	if (head->len < min_len) {
		log_warn(LOG_MOD_DEFAULT, "conf_flash_read_head: bad head len");
		goto out;
	}
	rc = 0;

	/*
	 * If raw_read just returned a pointer to the in-flash header,
	 * copy it to the buffer.
	 * Copy even if we might return an error,
	 * so caller can see if it is erased.
	 */
out:
	if (head != head_buf) {
		memcpy(head_buf, head, sizeof(*head_buf));
	}
	return rc;
}

int conf_flash_open_read(enum conf_inode inode, struct conf_file **fh,
	struct conf_head *h)
{
	struct conf_head head_buf;
	struct conf_file *file;
	int rc;

	*fh = NULL;
	if (conf_flash_open_write(inode, &file) < 0) {
		return -1;
	}
	rc = conf_flash_read_head(file, 0, &head_buf);
	if (rc) {
		return rc;
	}
	*fh = file;
	if (h) {
		memcpy(h, &head_buf, sizeof(*h));
	}
	return 0;
}

/*
 * Erase entire file area
 */
int conf_flash_erase(enum conf_inode inode)
{
	struct flash_state *state;
	struct conf_file *file;
	uint32_t address;
	flash_t obj;

	state = conf_flash_state(inode);
	if (!state) {
		conf_log(LOG_ERR "conf_flash_erase: inode %u out of range",
		    inode);
		return -1;
	}
	state->open = 0;
	state->written = 0;
	switch (inode) {
	case CI_FACTORY:
	case CI_STARTUP:
		address = state->file.loc;
		conf_log(LOG_INFO "Erase flash address: 0x%x\n", address);
		device_mutex_lock(RT_DEV_LOCK_FLASH);
		flash_erase_sector(&obj, address);
		flash_erase_sector(&obj, address+0x1000);
		flash_erase_sector(&obj, address+0x2000);
		flash_erase_sector(&obj, address+0x3000);
		device_mutex_unlock(RT_DEV_LOCK_FLASH);
		break;
	default:
		break;
	}


	/*
	 * Reopen file to get handle.
	 */
	return conf_flash_open_write(inode, &file);
}

/*
 * Erase file area, but only if it's not erased already.
 * Assume QCOM does this.
 */
void conf_flash_erase_if_needed(enum conf_inode inode)
{
	struct conf_file *file;
	char tmpbuf[32], *tmp;
	size_t off, rlen;

	if (conf_flash_open_write(inode, &file) < 0) {
		return;
	}
	for (off = 0; off < file->max_len; off += sizeof(tmpbuf)) {
		rlen = min(sizeof(tmpbuf), file->max_len - off);
		tmp = conf_flash_raw_read(file, off, tmpbuf, rlen);
		if (!tmp || !conf_flash_erased(tmp, rlen)) {
			conf_flash_erase(inode);
			break;
		}
	}
}

/*
 * Write a file in parts
 */
int
conf_flash_write_head(struct conf_file *file, u8 gen_id)
{
	struct conf_head head;
	int rc;

	if (sizeof(struct conf_head) > file->max_len) {
		log_err(LOG_MOD_DEFAULT,
		    "conf_flash_write_head: can't fit file header");
		return -1;
	}
	memset(&head, 0, sizeof(head));
	head.magic = CONF_MAGIC;
	head.version = CONF_VERSION;
	head.gen_id = gen_id;
	head.v2_config = 1;
	head.data_len = file->max_len - sizeof(head);
	head.len = file->max_len;

	rc = conf_flash_raw_write(file, file->loc, &head, sizeof(head));
	if (rc < 0) {
		conf_log(LOG_ERR "conf_flash_write error\n");
	}
	return rc;
}

int conf_flash_write_blk(struct conf_file *file, size_t offset,
	void *v, size_t len)
{
	int rc;
	u32 loc;

	loc = file->loc + offset + sizeof(struct conf_head);
	if (offset + len > file->max_len) {
		log_err(LOG_MOD_DEFAULT,
		    "conf_flash_write: len %u off %x out of range",
		    (unsigned int)len, (unsigned int)offset);
		return -1;
	}
	rc = conf_flash_raw_write(file, loc, v, len);
	if (rc < 0) {
		conf_log(LOG_ERR "conf_flash_write error loc %lx\n", loc);
		return -1;
	}
	return 0;
}

/*
 * Write entire file with new contents.
 */
int conf_flash_write(enum conf_inode inode, size_t offset,
	void *buf, size_t len)
{
	struct flash_dev *dev;
	struct conf_file *file;
	struct conf_head head;
	struct conf_tail tail;
	int rc;
	u32 loc;
	u32 crc;
	u32 pad;

	if (!offset && conf_flash_erase(inode)) {
		conf_log(LOG_ERR "conf_flash_write erase failed");
		return -1;
	}
	if (conf_flash_open_write(inode, &file) < 0) {
		return -1;
	}
	pad = len % sizeof(u32);
	if (pad) {
		pad = sizeof(u32) - pad;
	}
	dev = conf_flash_open(file->dev);
	ASSERT(dev);

	loc = file->loc + offset;
	if (offset + len + pad > file->max_len || loc % dev->write_align) {
		log_err(LOG_MOD_DEFAULT,
		    "conf_flash_write: len %u off %x out of range",
		    (unsigned int)len, (unsigned int)offset);
		return -1;
	}

	memset(&head, 0, sizeof(head));
	memset(&tail, 0, sizeof(tail));
	head.magic = CONF_MAGIC;
	head.version = CONF_VERSION;
	head.data_len = len;
	len += pad;
	head.len = sizeof(head) + sizeof(tail) + len;
	tail.len = sizeof(head) + sizeof(tail) + len;

	crc = crc32(&head, sizeof(head), CRC32_INIT);
	crc = crc32(buf, len, crc);
	crc = crc32(&tail, sizeof(tail) - sizeof(crc), crc);
	tail.crc = cpu_to_le32(crc);

	rc = conf_flash_raw_write(file, loc, &head, sizeof(head));
	if (rc < 0) {
		goto err;
	}
	loc += sizeof(head);
	rc = conf_flash_raw_write(file, loc, buf, len);
	if (rc < 0) {
		goto err;
	}
	loc += len;
	rc = conf_flash_raw_write(file, loc, &tail, sizeof(tail));
	if (rc < 0) {
err:
		conf_log(LOG_ERR "conf_flash_write error loc %lx", loc);
		return -1;
	}
	return 0;
}

int conf_flash_lock(struct conf_file *file, size_t len)
{
	return 0;
}

/*
 * Return available length and offset for appending a new file inside the
 * flash allocation of the existing file.
 */
size_t conf_flash_get_append_space(enum conf_inode inode, u32 *offsetp)
{
	struct conf_file *file;
	struct conf_head head;
	u32 offset;
	size_t rlen;
	int rc;

	if (conf_flash_open_write(inode, &file) < 0) {
		return 0;
	}
	rlen = file->max_len;
	rlen -= sizeof(struct conf_head) + sizeof(struct conf_tail);
	for (offset = 0; rlen > 0; rlen -= head.len, offset += head.len) {
		head.magic = 0;		/* invalidate head buffer */
		rc = conf_flash_read_head(file, offset, &head);
		if (rc < 0) {
			if (conf_flash_erased(&head, sizeof(head))) {
				*offsetp = offset;
				return rlen;
			}
			break;
		}
		if (head.len > rlen) {
			break;
		}
	}
	return 0;
}

struct conf_head *conf_flash_read_archive_head(struct conf_file *file,
	unsigned int index, struct conf_head *head_buf, size_t *head_offp)
{
	struct conf_head *head = head_buf;
	unsigned int count = 0;
	size_t head_off = 0;
	int rc;

	if (file->max_len == 0) {
		return NULL;
	}
	for (count = 0; count <= index; count++) {
		*head_offp = head_off;
		if (head_off + sizeof(*head) > file->max_len) {
			log_debug(LOG_MOD_DEFAULT,
			    "%s: head offset %u out of range. count %u",
			    __func__, (unsigned int)head_off, count);
			return NULL;
		}
		rc = conf_flash_read_head(file, head_off, head);
		if (rc) {
			log_debug(LOG_MOD_DEFAULT,
			    "conf_flash_read: dev %u head read failed",
			    file->dev);
			return NULL;
		}
		head_off += head->len;
	}
	return head;
}

/*
 * Read or map a section of an archive.
 */
void *conf_flash_read_archive(struct conf_file *file, unsigned int index,
	size_t offset, void *buf, size_t len)
{
	struct conf_head head_buf;
	struct conf_head *head = &head_buf;
	size_t head_off = 0;
	void *map;

	head = conf_flash_read_archive_head(file, index, &head_buf, &head_off);
	if (!head) {
		return NULL;
	}
	map = conf_flash_raw_read(file,
	    head_off + sizeof(*head) + offset, buf, len);
	if (!map) {
		log_err(LOG_MOD_DEFAULT,
		    "conf_flash_read: dev %u read failed", file->dev);
	}
	return map;
}

/*
 * Map a section of a config file open for read.
 * The caller supplies a buffer in case a direct mapping isn't possible.
 */
void *conf_flash_read(struct conf_file *file, size_t offset,
	void *buf, size_t len)
{
	return conf_flash_read_archive(file, 0, offset, buf, len);
}

/*
 * Read the CRC in the tail of the given file.
 * This is for version checking, not for the CRC itself.
 * Returns non-zero on error.
 */
int conf_flash_get_archive_crc(struct conf_file *file,
    unsigned int index, u32 *crcp)
{
	struct conf_head head_buf;
	struct conf_tail tail_buf;
	struct conf_tail *tail;
	size_t head_off = 0;
	struct conf_head *head = &head_buf;
	unsigned int count;
	int rc;

	if (file->max_len == 0) {
		return -1;
	}
	for (count = 0; count <= index; count++) {
		if (head_off + sizeof(*head) > file->max_len) {
			log_debug(LOG_MOD_DEFAULT,\
			    "%s: head offset %u out of range. count %u",
			    __func__, (unsigned int)head_off, count);
			return -1;
		}
		rc = conf_flash_read_head(file, head_off, head);
		if (rc) {
			log_debug(LOG_MOD_DEFAULT,\
			    "conf_flash_read: dev %u head read failed",
			    file->dev);
			return -1;
		}
		if (count != index) {
			head_off += head->len;
		}
	}
	tail = conf_flash_raw_read(file, head_off + head->len - sizeof(*tail),
	     &tail_buf, sizeof(tail_buf));
	if (!tail) {
		return -1;
	}
	*crcp = tail->crc;
	return 0;
}

/*
 * Get valid length for a file that is open for read.
 * Also checks CRC.
 * Returns 0 for any problem.
 */
size_t conf_flash_get_archive_length(struct conf_file *file, unsigned int index)
{
	struct conf_head head_buf;
	struct conf_head *head;
	char buf[256];
	void *map;
	size_t head_off = 0;
	size_t tlen;
	u32 offset = 0;
	u32 rlen;
	u32 crc;

	head = conf_flash_read_archive_head(file, index, &head_buf, &head_off);
	if (!head) {
		return 0;
	}

	crc = CRC32_INIT;
	rlen = head->len;
	for (offset = 0; rlen > 0; offset += tlen, rlen -= tlen) {
		tlen = rlen;
		if (tlen > sizeof(buf)) {
			tlen = sizeof(buf);
		}
		map = conf_flash_raw_read(file, head_off + offset, buf, tlen);
		if (!map) {
			return 0;
		}
		crc = crc32(map, tlen, crc);
	}
	if (crc != 0) {
		conf_log(LOG_ERR "conf_flash_get_length: crc error\n");
		return 0;
	}
	return head->data_len;
}

size_t conf_flash_get_length(struct conf_file *file)
{
	return conf_flash_get_archive_length(file, 0);
}

/*
 * Aligning write offset, given write alignment restrictions of the
 * target flash device.
 */
size_t conf_flash_file_align(struct conf_file *file, size_t off)
{
	return 0;
}
