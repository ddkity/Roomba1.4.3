#
# Copyright 2017 Ayla Networks, Inc.  All rights reserved.
#

LIB_DIRS = \
	libada \
	libayla \
	libnet \
	libadw \
	$(NULL)

.PHONY: all $(LIB_DIRS)

all: $(LIB_DIRS)

$(LIB_DIRS):
	@echo " -------------------------------"
	@echo "  Build library $@ ..."
	@echo " -------------------------------"
	@make -C $@

