#
# Copyright 2017 Ayla Networks, Inc.  All rights reserved.
#

NAME = ayla_demo
AYLA_SRC = ../../ayla

SOURCES := \
	src/demo_conf.c \
	src/demo_common.c \
	src/demo_ledevb.c \
	src/demo_sched.c \
	src/demo_wifi.c \
	src/demo_stub.c \
	src/led_key.c \
	src/ota.c \
	$(NULL)

include $(AYLA_SRC)/make/common_defs.mk
include $(AYLA_SRC)/make/common_cc.mk

# type gpio_t need compile switch --enum_is_int
$(BUILD)/src/led_key.o: src/led_key.c Makefile
	@echo CC $<
	@$(MKDIR) $(@D)
	@$(CC) $(CFLAGS) --enum_is_int $< -o $@
