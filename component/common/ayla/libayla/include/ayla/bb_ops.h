/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_BB_OPS_H__
#define __AYLA_BB_OPS_H__

/*
 * Operations performed by the boot program.
 * These are passed to the booter via STM32 backup data registers.
 */

/*
 * battery backed-up register numbers.
 * Register 0 reserved, it doesn't exist on STM32F1xx.
 * Registers may be 16 or 32 bits.
 */
enum bb_reg {
	BB_BKP_OP = 1,		/* boot opcode register */
	BB_BKP_ARG = 2,		/* arg for boot opcode */
	BB_BKP_RTC_SRC = 3,	/* source of clock setting */
	BB_BKP_PATCH = 4,	/* patch command or status */
	BB_BKP_SCHED_RUN = 5,	/* last_run_time of scheds */
	BB_BKP_SCHED_OVFLO = 6,	/* bot 16-bits of above for stm32f1 */
};

/*
 * ops
 */
enum bb_op {
	BB_OP_NONE = 0,		/* reserved - power-on reset */
	BB_OP_BOOT = 1,		/* boot specified file */
};

void bb_enable(void);
void bb_disable(void);
void bb_write_en(void);
void bb_write_dis(void);
u16 bb_read(enum bb_reg);
void bb_write(enum bb_reg, u16);
u32 bb_read_32(enum bb_reg);
void bb_write_32(enum bb_reg, u32);
void bb_reboot_to(enum conf_inode inode);

#endif /* __AYLA_BB_OPS_H__ */
