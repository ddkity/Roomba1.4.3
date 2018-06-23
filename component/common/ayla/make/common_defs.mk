#
# Copyright 2017 Ayla Networks, Inc.  All rights reserved.
#

CSTYLE = cstyle
BUILD := $(AYLA_SRC)/build/$(NAME)-$(BUILD_TOOL)
TOOLCHAIN_DIR = $(AYLA_SRC)/../../../tools/arm-none-eabi-gcc
LIB := $(AYLA_SRC)/lib/$(NAME).a
CROSS_COMPILE = $(TOOLCHAIN_DIR)/4.8.3-2014q1/bin/arm-none-eabi-

DEFINES += AMEBA
ifeq ($(BUILD_TOOL),iar)
	DEFINES += AMEBA_IAR
endif
DEFINES += STATIC_WEB_CONTENT_IN_MEMORY
DEFINES += LOG_SEV_SHORT
DEFINES += CLIENT_MT
DEFINES += _HAS_ASSERT_F_
DEFINES += AYLA_FreeRTOS
DEFINES += NO_LOG_BUF
DEFINES += LOG_LOCK
DEFINES += CONF_NO_ID_FILE
DEFINES += XXD_BIN_TO_C
DEFINES += CONFIG_PLATFORM_8195A
DEFINES += AYLA_WIFI_SUPPORT
DEFINES += FLASH_CONF_CACHE

INCLUDES += $(AYLA_SRC)/libada
INCLUDES += $(AYLA_SRC)/libada/include
INCLUDES += $(AYLA_SRC)/libayla/include
INCLUDES += $(AYLA_SRC)/ext/jsmn
INCLUDES += $(AYLA_SRC)/libnet/include
INCLUDES += $(AYLA_SRC)/libnet/ameba/include
INCLUDES += $(AYLA_SRC)/libadw/include
INCLUDES += $(AYLA_SRC)/libadw/ameba
INCLUDES += $(AYLA_SRC)/../api
INCLUDES += $(AYLA_SRC)/../api/platform
INCLUDES += $(AYLA_SRC)/../api/network/include
INCLUDES += $(AYLA_SRC)/../network
INCLUDES += $(AYLA_SRC)/../network/lwip/lwip_v1.4.1/src/include
INCLUDES += $(AYLA_SRC)/../network/lwip/lwip_v1.4.1/src/include/ipv4
INCLUDES += $(AYLA_SRC)/../network/lwip/lwip_v1.4.1/src/include/lwip
INCLUDES += $(AYLA_SRC)/../network/lwip/lwip_v1.4.1/src/include/posix
INCLUDES += $(AYLA_SRC)/../network/lwip/lwip_v1.4.1/port/realtek
INCLUDES += $(AYLA_SRC)/../network/ssl/ssl_ram_map/rom
INCLUDES += $(AYLA_SRC)/../network/ssl/mbedtls-2.4.0/include
INCLUDES += $(AYLA_SRC)/../mbed/hal
INCLUDES += $(AYLA_SRC)/../mbed/hal_ext
INCLUDES += $(AYLA_SRC)/../mbed/targets/hal/rtl8195a
INCLUDES += $(AYLA_SRC)/../drivers/wlan/realtek/include
INCLUDES += $(AYLA_SRC)/../drivers/wlan/realtek/src/osdep
INCLUDES += $(AYLA_SRC)/../../os/os_dep/include
INCLUDES += $(AYLA_SRC)/../../os/freertos/
INCLUDES += $(AYLA_SRC)/../../os/freertos/freertos_v8.1.2/Source/include
INCLUDES += $(AYLA_SRC)/../../os/freertos/freertos_v8.1.2/Source/portable/IAR/ARM_CM3
INCLUDES += $(AYLA_SRC)/../../soc/realtek/8195a/cmsis
INCLUDES += $(AYLA_SRC)/../../soc/realtek/8195a/cmsis/device
INCLUDES += $(AYLA_SRC)/../../soc/realtek/8195a/fwlib
INCLUDES += $(AYLA_SRC)/../../soc/realtek/8195a/fwlib/rtl8195a
INCLUDES += $(AYLA_SRC)/../../soc/realtek/8195a/misc/platform
INCLUDES += $(AYLA_SRC)/../../soc/realtek/8195a/misc/rtl_std_lib/include
INCLUDES += $(AYLA_SRC)/../../soc/realtek/common/bsp
INCLUDES += $(AYLA_SRC)/../../../project/realtek_ameba1_va0_example/inc
ifeq ($(BUILD_TOOL),iar)
	INCLUDES += $(AYLA_SRC)/include
endif

OBJS := $(SOURCES:%.c=$(BUILD)/%.o)

CFLAGS += $(addprefix -D,$(DEFINES))
CFLAGS += $(addprefix -I,$(INCLUDES))

ifeq ($(BUILD_TOOL),iar)
	CC = iccarm.exe
	AR = iarchive.exe --create
	MKDIR = mkdir -p

	CFLAGS += --silent -D CONFIG_PLATFORM_8195A
	CFLAGS += --diag_suppress Pa050,Pa039,Pe188,Pe550,Pe177,Pe550,Pe167,Pe068,Pe186,Pe223,Pe550,Be006,Pe089,Pa089,Pe549,Pe301
	CFLAGS += --debug --endian=little --cpu=Cortex-M3 --section .rodata=.sdram.data -e --char_is_signed
	CFLAGS += --fpu=None --section .text=.sdram.text -Ohz --use_c++_inline
else
	CC = $(CROSS_COMPILE)gcc -c
	AR = $(CROSS_COMPILE)ar r
	MKDIR = mkdir -p

	CFLAGS += -DM3 -DCONFIG_PLATFORM_8195A -DGCC_ARMCM3
	CFLAGS += -mcpu=cortex-m3 -mthumb -g2 -w -O2 -Wno-pointer-sign -fno-common -fmessage-length=0 -ffunction-sections
	CFLAGS += -fdata-sections -fomit-frame-pointer -fno-short-enums -DF_CPU=166000000L -std=gnu99 -fsigned-char
endif

ifeq ($(BUILD_TOOL),gcc)
	DEPS := $(SOURCES:%.c=$(BUILD)/%.d)
else
	DEPS :=
endif

ifeq ($(CSTYLE),)
	CSTYLES :=
else
	CSTYLE_IGNORE_FILE := $(shell cat $(AYLA_SRC)/.style_ok)
	CSTYLES_H := $(shell find * -type f -name '*.h')
	CSTYLES_H := $(filter-out $(CSTYLE_IGNORE_FILE), $(CSTYLES_H))
	CSTYLES_C := $(filter-out $(CSTYLE_IGNORE_FILE), $(SOURCES))

	CSTYLES := $(CSTYLES_H:%.h=$(BUILD)/%.hcs)
	CSTYLES += $(CSTYLES_C:%.c=$(BUILD)/%.cs)
endif
