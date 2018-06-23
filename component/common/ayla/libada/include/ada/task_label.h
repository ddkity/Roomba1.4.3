/*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __TASK_LABEL_H__
#define __TASK_LABEK_H__

#define TASK_LABEL_MAIN			"m"
#define TASK_LABEL_CLIENT		"c"
#define TASK_LABEL_DEMO			"a"
#define TASK_LABEL_STREAM		"s"
#define TASK_LABEL_NETTIMER		"t"
#define TASK_LABEL_NETPOLL		"p"
#define TASK_LABEL_WEBSERVER		"w"

WEAK void taskstat_dbg_start(void);
WEAK void taskstat_dbg_stop(void);

#endif /* __ADA_TASK_LABEL_H__ */
