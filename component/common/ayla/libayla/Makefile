#
# Copyright 2017 Ayla Networks, Inc.  All rights reserved.
#

NAME = libayla
AYLA_SRC = ..

SOURCES := \
	arch/ameba/clock.c \
	arch/ameba/conf_flash.c \
	arch/ameba/malloc.c \
	clock_fmt.c \
	clock_sw.c \
	clock_utils.c \
	cmd_handle.c \
	conf.c \
	crc.c \
	crc16.c \
	crc8.c \
	endian.c \
	format_mac.c \
	format_string.c \
	hostname_valid.c \
	http.c \
	jsmn_get.c \
	jsmn_iterate.c \
	json_format_string.c \
	log.c \
	log_cmd.c \
	log_conf.c \
	log_io.c \
	lookup_by_name.c \
	lookup_by_val.c \
	parse_argv.c \
	parse_date.c \
	parse_hex.c \
	parse_mac.c \
	parse_url.c \
	timer.c \
	uri_arg_allowed_map.c \
	uri_decode.c \
	uri_encode.c \
	utf8.c \
	xml.c \
	xml_decode.c \
	xml_encode.c \
	$(AYLA_SRC)/ext/jsmn/jsmn.c \
	$(NULL)

include $(AYLA_SRC)/make/common_defs.mk
include $(AYLA_SRC)/make/common_cc.mk
