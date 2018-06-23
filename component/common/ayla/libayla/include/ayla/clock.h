/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CLOCK_H__
#define __AYLA_CLOCK_H__

#define DAYLIGHT_OFFSET	3600	/* daylight offset (secs) */

/*
 * Time source codes.
 * Larger numbers indicate more reliable clock sources.
 * Do not change the existing numbers, for upgrade compatibility.
 */
enum clock_src {
	CS_NONE = 0,		/* never been set */
	CS_MIN = 0x1120,
	CS_DEF = 0x1130,	/* set to CLOCK_START */
	CS_PERSIST = 0x1135,	/* from persisted data store (flash/nvram) */
	CS_HTTP = 0x113c,	/* from cloud via HTTP request */
	CS_LOCAL = 0x1140,	/* set by internal web server */
	CS_MCU_LO = 0x1250,	/* set by MCU. low priority */
	CS_SERVER = 0x1260,	/* set using server time */
	CS_SNTP = CS_SERVER,	/* set using SNTP, not kept in sync */
	CS_NTP = 0x1270,	/* set using NTP */
	CS_MCU_HI = 0x1280,	/* set by MCU. high priority */
	CS_LIMIT		/* must be last */
};

/*
 * Unsigned time in seconds and microseconds.
 * This is similar to the Unix timeval, but not all platforms define that, so
 * we need our own.  This cannot be used in differences.
 */
struct clock_time {
	u32 ct_sec;
	u32 ct_usec;
};

/*
 * Timezone settings
 */
struct timezone_settings {
	u8 valid;		/* 1 if settings should be followed */
	s16 mins;		/* mins west of UTC */
};

/*
 * Daylight settings
 */
struct daylight_settings {
	u8 valid;		/* 1 if settings should be followed */
	u8 active;		/* 1 if DST is active before change */
	u32 change;		/* when DST flips inactive/active */
};

/*
 * Calendar information about a particular time
 */
struct clock_info {
	u32 time;		/* time that this struct represents */
	u32 month_start;	/* start time of the month */
	u32 month_end;		/* end time of the month */
	u32 day_start;		/* start time of the day */
	u32 day_end;		/* end time of the day */
	u32 secs_since_midnight;/* secs since midnight */
	u32 year;		/* current year */
	u8 month;		/* current month starting from 1 */
	u8 days;		/* current day of month */
	u8 hour;		/* current hour */
	u8 min;			/* current min */
	u8 sec;			/* current seconds */
	u8 days_left_in_month;	/* # days left in current month */
	u8 day_of_week;		/* day of the week. Mon = 1, Sun = 7 */
	u8 day_occur_in_month;	/* occurence of day in month. i.e. 2nd sun */
	u8 is_leap:1;		/* flag to signify if year is leap year */
};

/*
 * Convert time represented by separate integers for year, month, day, etc.,
 * to UTC time in seconds since January 1, 1970.
 * This may have problems after Jan 18, 2038 when bit 31 turns on.
 * Similar to gmtime_r() from libc.
 * Returns 0 on success, non-zero if invalid time given.
 */
int clock_ints_to_time(u32 *timep, u32 year, u32 month, u32 day,
			 u32 hour, u32 minute, u32 second);

/*
 * convert time to "MM/DD/YYYY hh:mm:ss" format
 */
void clock_fmt(char *buf, size_t len, u32 time);
u32 clock_utc(void);
u32 clock_local(const u32 *utc);

u32 clock_get(struct clock_time *);

int clock_set(u32, enum clock_src);
void clock_set_hw(u32, enum clock_src);
void clock_set_sw(u32, u32);
int clock_drift_sw(s32 drift_msecs);
u32 clock_ms(void);
u64 clock_total_ms(void);
void clock_init(void);
int clock_is_leap(u32 year);
void clock_fill_details(struct clock_info *clk, u32 time);
void clock_incr_day(struct clock_info *clk);
void clock_decr_day(struct clock_info *clk);
void clock_incr_month(struct clock_info *clk);
void clock_decr_month(struct clock_info *clk);
u8 clock_get_day_occur_in_month(u32 days);
u32 clock_local_to_utc(u32 local, u8 skip_fb);

#ifdef CLOCK_PERSIST
void clock_persist(void);
#endif

enum clock_src clock_source(void);

extern volatile u32 uptime;	/* seconds since boot */
extern struct clock_time boot_rel_time; /* time of startup according to RTC */
extern u32 clock_set_mtime;	/* time when clock last set, ms */
extern struct timezone_settings timezone_info;	/* timezone settings */
extern struct daylight_settings daylight_info;	/* daylight settings */

#define	CLOCK_EPOCH	1970U	/* must match Unix Epoch for SSL */
#define	CLOCK_EPOCH_DAY	4	/* day of the week for Jan 1, CLOCK_EPOCH */

#define CLOCK_FMT_LEN	24	/* max len of clock_fmt() output (20 + pad) */
#define CLOCK_FMT_TIME	11	/* index of time in clock_fmt() output */

/*
 * default value to be set in clock after power loss.
 * This is so that the SSL certificates will appear valid.
 */
#define CLOCK_START 1483228800	/* Jan 1, 2017 00:00 UTC */

/*
 * Compare two times or sequence numbers with wrap-around.
 */
static inline int clock_gt(u32 a, u32 b)
{
	return (int)(a - b) > 0;
}

void clock_delay(u32 msecs);

u32 clock_parse(const char *);

#endif /* __AYLA_CLOCK_H__ */
