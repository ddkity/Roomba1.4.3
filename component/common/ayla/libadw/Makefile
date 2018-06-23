#
# Copyright 2017 Ayla Networks, Inc.  All rights reserved.
#

NAME = libadw
AYLA_SRC = ..

SOURCES := \
	adw_wifi_conf.c \
	wifi.c \
	wifi_page.c \
	wifi_ameba.c \
	wifi_ameba_drv.c  \
	text/lock.gif.c \
	text/refresh.gif.c \
	text/wifi.html.c \
	text/wifi.js.c  \
	$(NULL)

include $(AYLA_SRC)/make/common_defs.mk
include $(AYLA_SRC)/make/common_cc.mk

# type gpio_t need compile switch --enum_is_int
$(BUILD)/wifi_ameba_drv.o: wifi_ameba_drv.c Makefile
	@echo CC $<
	@$(MKDIR) $(@D)
	@$(CC) $(CFLAGS) --enum_is_int $< -o $@
