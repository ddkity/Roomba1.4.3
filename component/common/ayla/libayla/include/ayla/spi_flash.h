/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_SPI_FLASH_H__
#define __AYLA_SPI_FLASH_H__

#ifdef PLATFORM_AY001MTP	/* Ayla module, possibly with test board */
#define SPI_FLASH_COUNT	2
#elif defined(PLATFORM_AY001MAB) || defined(PLATFORM_AY001MUX)
#define SPI_FLASH_COUNT	1
#else
#define SPI_FLASH_COUNT	0
#endif /* PLATFORM_AY001MTP */

struct spi_flash_id {
	u8 id[3];	/* manufacturer and device ID */
	u8 blocks;	/* number of blocks */
	char *name;	/* part number */
	u16 sectors;	/* size in sectors */
	u16 sec_size;	/* sector size in bytes */
};

/*
 * SPI Flash commands.  May be Macronix specific.
 * Please keep these sorted numerically.
 */
#define SF_WRSR 0x01	/* write status register */
#define	SF_PP	0x02	/* page program (write) */
#define SF_READ 0x03	/* read data */
#define SF_WRDI	0x04	/* write disable */
#define SF_RDSR 0x05	/* read status register */
#define SF_WREN	0x06	/* write enable */
#define SF_SE	0x20	/* sector erase */
#define	SF_BE	0x52	/* block erase */
#define	SF_CE	0x60	/* chip erase */
#define SF_REMS 0x90	/* read manufacturer and device ID */
#define SF_RDID	0x9f	/* read ID */

#define SF_SR_SRWD	(1 << 7)	/* register write disabled */
#define SF_SR_BP_BIT	2		/* bits 2-4: block level protection */
#define SF_SR_BP_MASK	7
#define	SF_SR_WEL	(1 << 1)	/* write enable latch */
#define	SF_SR_WIP	(1 << 0)	/* write in progress */

#define SF_PAGE_SIZE	256		/* size for page program (write) */

#if SPI_FLASH_COUNT > 0

void spi_flash_init(void);
const struct spi_flash_id *spi_flash_probe(int devn, u8 id_buf[3]);
int spi_flash_is_erased(int devn, u32 offset, u32 len);

extern const struct spi_flash_id spi_flash_ids[];

#else /* SPI_FLASH_COUNT */

#define spi_flash_init()	do { } while (0)
#define spi_flash_probe(devn, buf) NULL
#define spi_flash_is_erased(devn, offset, len)	0

#endif /* SPI_FLASH_COUNT */

#endif /* __AYLA_SPI_FLASH_H__ */
