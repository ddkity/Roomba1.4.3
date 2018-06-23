/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_TLV_H__
#define __AYLA_TLV_H__

/*
 * Ayla TLV for commands.
 */
PREPACKED struct ayla_tlv {
	u8	type;		/* type code */
	u8	len;		/* length of value */
				/* value follows immediately */
} PACKED;

#define TLV_VAL(tlv)	((void *)(tlv + 1))
#define TLV_MAX_LEN	255
#define TLV_MAX_STR_LEN	1024

PREPACKED_ENUM enum ayla_tlv_type {
	ATLV_INVALID = 0x00,	/* Invalid TLV type */
	ATLV_NAME = 0x01,	/* variable name, UTF-8 */
	ATLV_INT = 0x02,	/* integer, with length 1, 2, 4, or 8 */
	ATLV_UINT = 0x03,	/* unsigned integer, 1, 2, 4, or 8 bytes */
	ATLV_BIN = 0x04,	/* unstructured bytes */
	ATLV_UTF8 = 0x05,	/* text */
	ATLV_CONF = 0x06,	/* configuration name indices */
	ATLV_ERR = 0x07,	/* error number */
	ATLV_FORMAT = 0x08,	/* formatting hint */
	ATLV_FRAG = 0x09,	/* fragment descriptor for longer values */
	ATLV_NOP = 0x0a,	/* no-op, ignored TLV inserted for alignment */
	ATLV_FLOAT = 0x0b,	/* IEEE floating point value */
	ATLV_CONF_CD = 0x0c,	/* base path for following config names */
	ATLV_CONF_CD_ABS = 0x0d, /* absolute path for following config names */
	ATLV_CONF_CD_PAR = 0x0e, /* new path in parent directory */
	ATLV_BOOL = 0x0f,	/* boolean value, 1 or 0 */
	ATLV_CONT = 0x10,	/* continuation token for AD_SEND_NEXT_PROP */
	ATLV_OFF = 0x11,	/* offset in data point or other transfer */
	ATLV_LEN = 0x12,	/* length of data point or other transfer */
	ATLV_LOC = 0x13,	/* location of data point or other item */
	ATLV_EOF = 0x14,	/* end of file, e.g., end of data point */
	ATLV_BCD = 0x15,	/* fixed-point decimal number */
	ATLV_CENTS = 0x16,	/* integer value 100 times the actual value */
	ATLV_NODES = 0x17,	/* bitmap of dests or src for prop updates */
	ATLV_ECHO = 0x18,	/* indicates prop update is an echo */
	ATLV_FEATURES = 0x19,	/* bitmap of the supported features in MCU */
	ATLV_CONF_FACTORY = 0x1a,	/* configuration name indices */
	ATLV_DELETE = 0x1b,	/* configuration variable deleted */
	ATLV_REGINFO = 0x1c,	/* user registration info */
				/* reserved gap */
	ATLV_SCHED = 0x20,	/* schedule property */
	ATLV_UTC = 0x21,	/* indicates date/time in schedules are UTC */
	ATLV_AND = 0x22,	/* ANDs the top two conditions in schedule */
	ATLV_DISABLE = 0x23,	/* disables the schedule */
	ATLV_INRANGE = 0x24,	/* stack is true if current time is in range */
	ATLV_ATSTART = 0x25,	/* stack is true if current time is at start */
	ATLV_ATEND = 0x26,	/* stack is true if current time is at end */
	ATLV_STARTDATE = 0x27,	/* date must be after value */
	ATLV_ENDDATE = 0x28,	/* date must be before value */
	ATLV_DAYSOFMON = 0x29,	/* 32-bit mask indicating which day of month */
	ATLV_DAYSOFWK = 0x2a,	/* days of week specified as 7-bit mask */
	ATLV_DAYOCOFMO = 0x2b,	/* day occurence in month */
	ATLV_MOOFYR = 0x2c,	/* months of year */
	ATLV_STTIMEEACHDAY = 0x2d,	/* time of day must be after value */
	ATLV_ENDTIMEEACHDAY = 0x2e,	/* time of day must be before value */
	ATLV_DURATION = 0x2f,	/* must not last more than this (secs) */
	ATLV_TIMEBFEND = 0x30,	/* time must be <value> secs before end */
	ATLV_INTERVAL = 0x31,	/* start every <value> secs since start */
	ATLV_SETPROP = 0x32,	/* value is the property to be toggled */
	ATLV_VERSION = 0x33,	/* version of schedule */
	ATLV_DPMETA = 0x34,	/* datapoint metadata */
				/* reserved gap */
	ATLV_FILE = 0x80,	/* mask for 0x80 thru 0xfe incl. 15-bit len */
	ATLV_RESERVED = 0xff
} PACKED_ENUM;

ASSERT_SIZE(enum, ayla_tlv_type, 1);

#define AYLA_TLV_TYPE_NAMES {		\
	[ATLV_INVALID] = "invalid",	\
	[ATLV_NAME] = "name",		\
	[ATLV_INT] = "integer",		\
	[ATLV_UINT] = "uint",		\
	[ATLV_BIN] = "bin",		\
	[ATLV_UTF8] = "string",		\
	[ATLV_CONF] = "config",		\
	[ATLV_ERR] = "error",		\
	[ATLV_FORMAT] = "format",	\
	[ATLV_FRAG] = "frag",		\
	[ATLV_NOP] = "no",		\
	[ATLV_FLOAT] = "float",		\
	[ATLV_CONF_CD] = "cd",		\
	[ATLV_CONF_CD_ABS] = "cdabs",	\
	[ATLV_CONF_CD_PAR] = "cdpar",	\
	[ATLV_BOOL] = "boolean",	\
	[ATLV_CONT] = "continue",	\
	[ATLV_BCD] = "decimal",		\
	[ATLV_CENTS] = "decimal",	\
}

/*
 * TLV for a 32-bit integer.
 */
PREPACKED struct ayla_tlv_int {
	struct ayla_tlv head;
	be32	data;
} PACKED;

/*
 * Formatting-hint TLV.
 * This TLV should be between the name and value TLVs, if used.
 * It is only a hint for automatically-generated web pages.
 */
PREPACKED struct ayla_tlv_fmt {
	struct ayla_tlv head;
	u8	fmt_flags;	/* formatting hint flag (see below) */
} PACKED;

/*
 * fmt_flag values.
 */
#define AFMT_READ_ONLY	(1 << 0) /* indicates variable is not settable */
#define AFMT_HEX	(1 << 1) /* value should be formatted in hex */

/*
 * reserved destination masks
 */
#define NODES_ADS	0x01	/* mask for service */
#define NODES_SCHED	0x80	/* mask for schedule props */
#define NODES_HOMEKIT	NODES_SCHED /* mask for homekit */

#endif /* __AYLA_TLV_H__ */
