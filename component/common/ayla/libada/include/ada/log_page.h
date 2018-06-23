/*
 * Copyright 2016 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_LOG_PAGE_H__
#define __AYLA_LOG_PAGE_H__

void log_page_get(struct server_req *);
void log_page_json_get(struct server_req *);
void log_page_mods_json_get(struct server_req *);
void log_page_mods_json_put(struct server_req *);
void log_page_snaps_json_get(struct server_req *);
void log_page_snaps_json_delete(struct server_req *);
void log_page_json_get(struct server_req *);

void log_page_get_init(void);		/* init pages for getting logs */
void log_page_mods_init(void);		/* init pages for controlling */
void log_page_snaps_init(void);		/* init pages related to snapshots */

#endif /* __AYLA_LOG_PAGE_H__ */
