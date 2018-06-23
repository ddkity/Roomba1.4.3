/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_SPI_MCU_H__
#define __AYLA_SPI_MCU_H__

#include <ayla/utypes.h>
#include <ayla/tlv.h>

/*
 * Protocols.
 */
enum aspi_proto {
	ASPI_PROTO_CMD = 0x00,	/* command/control operations */
	ASPI_PROTO_DATA = 0x01,	/* Ayla Data service operations */
	ASPI_PROTO_PING = 0x02,	/* echo test protocol */
	ASPI_PROTO_LOG = 0x03,	/* log message */
};

/*
 * Module slave status byte.
 */
#define ASPI_MSTAT_INVAL_BIT 7	/* if set, indicates invalid status */
#define ASPI_MSTAT_ADS_BUSY_BIT 3 /* Ayla Dev Service is busy processing cmd */
#define ASPI_MSTAT_ERR_BIT 2	/* error on last command */
#define ASPI_MSTAT_ATTN_BIT 1	/* pending message to master */
#define ASPI_MSTAT_BUSY_BIT 0	/* busy processing command */

#define ASPI_MSTAT_NONE 0		/* no status */
#define ASPI_MSTAT_INVAL (1 << ASPI_MSTAT_INVAL_BIT)
#define ASPI_MSTAT_READY (1 << ASPI_MSTAT_READY_BIT)
#define ASPI_MSTAT_ERR	(1 << ASPI_MSTAT_ERR_BIT)
#define ASPI_MSTAT_ATTN	(1 << ASPI_MSTAT_ATTN_BIT)
#define ASPI_MSTAT_BUSY	(1 << ASPI_MSTAT_BUSY_BIT)

/*
 * Ayla SPI frame definitions.
 * Frame is start byte followed by two-byte length.
 */
#define ASPI_NO_CMD	0	/* non-start value */

#define ASPI_CMD_MASK	0xc0	/* mask for MO commands */
#define ASPI_CMD_MO	0x80	/* master to slave transfer */
#define ASPI_CMD_MI	0xf1	/* slave to master transfer */
#define ASPI_CMD_MI_RETRY 0xf2	/* retry last slave to master transfer */
#define ASPI_LEN_MASK	0x3f	/* length mask */
#define ASPI_LEN_MULT	8	/* length multiplier */

#define ASPI_LEN(x)	(((x) + ASPI_LEN_MULT - 1) / ASPI_LEN_MULT)

#define ASPI_XTRA_CMDS	5	/* number of repeated commands allowed */

#endif /* __AYLA_SPI_MCU_H__ */
