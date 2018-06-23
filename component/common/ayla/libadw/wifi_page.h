/*
 * Copyright 2016 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_WIFI_PAGE_H__
#define __AYLA_WIFI_PAGE_H__

#ifdef STATIC_WEB_CONTENT_IN_MEMORY

LINKER_TEXT_ARRAY_DECLARE(lock_gif_txt);
LINKER_TEXT_SIZE_DECLARE(lock_gif_txt);
LINKER_TEXT_ARRAY_DECLARE(refresh_gif_txt);
LINKER_TEXT_SIZE_DECLARE(refresh_gif_txt);
LINKER_TEXT_ARRAY_DECLARE(wifi_html_txt);
LINKER_TEXT_SIZE_DECLARE(wifi_html_txt);
LINKER_TEXT_ARRAY_DECLARE(wifi_js_txt);
LINKER_TEXT_SIZE_DECLARE(wifi_js_txt);

#endif


#endif /* __AYLA_WIFI_PAGE_H__ */
