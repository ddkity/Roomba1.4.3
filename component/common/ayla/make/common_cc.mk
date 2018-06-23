#
# Copyright 2017 Ayla Networks, Inc.  All rights reserved.
#

.PHONY: toolchain

$(LIB): toolchain $(BUILD) $(DEPS) $(CSTYLES) $(OBJS)
	@echo AR $(notdir $@)
	@$(MKDIR) $(@D)
	@$(AR) $@ $(OBJS)

$(BUILD):
	@$(MKDIR) $@

#
# Toolchain for gcc sdk
#
toolchain:
ifeq ($(BUILD_TOOL),gcc)
	[ -d $(TOOLCHAIN_DIR)/4.8.3-2014q1 ] || ( \
  		tar -jxf $(TOOLCHAIN_DIR)/gcc-arm-none-eabi-4_8-2014q1-20140314-linux.tar.bz2 -C $(TOOLCHAIN_DIR); \
  		mv $(TOOLCHAIN_DIR)/gcc-arm-none-eabi-4_8-2014q1 $(TOOLCHAIN_DIR)/4.8.3-2014q1 \
	)
endif

#
# Rule to make dependencies files
#
$(BUILD)/%.d: %.c Makefile
ifeq ($(BUILD_TOOL),iar)
	@echo DEP $(notdir $@)
	@$(MKDIR) $(@D)
	@$(CC) $(CFLAGS) $< --dependencies=m $@
	@rm $(subst .c,.o,$<)
	@cat $@ | grep -v Program | sed -e 's#\\#/#g' -e 's#\b[A-Z]:#/cygdrive/\l&#g' -e 's#:/#/#g' > $@
else
	@($(MKDIR) $(@D); $(CC) -MM $(CPPFLAGS) $(CFLAGS) $< | \
		sed 's,\($*\)\.o[ :]*,$(BUILD)/\1.o $(BUILD)/\1.o3 $@ : ,g' \
			> $@) || rm -f $@
endif

#-include $(DEPS)

#
# Object file rules
#
$(BUILD)/%.o: %.c Makefile
	@echo CC $<
	@$(MKDIR) $(@D)
	@$(CC) $(CFLAGS) $< -o $@

#
# Style check rules
#
$(BUILD)/%.cs: %.c
	@echo "cstyle $(notdir $@)"; $(CSTYLE) $< && ($(MKDIR) $(@D); touch $@)

$(BUILD)/%.hcs: %.h
	@echo "cstyle $(notdir $@)"; $(CSTYLE) $< && ($(MKDIR) $(@D); touch $@)

.PHONY: clean
clean:
	rm -f $(OBJS) $(DEPS) $(CSTYLES) $(LIB)
