/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ayla/utypes.h>
#include <ayla/log.h>

static void log_show(const char *name, u32 log_mask)
{
	printcli("logging %10s: %s%s%s%s%s%s%s%s%s",
	    name,
	    (log_mask & BIT(LOG_SEV_ERR)) ? "error. " : "",
	    (log_mask & BIT(LOG_SEV_WARN)) ? "warning. " : "",
	    (log_mask & BIT(LOG_SEV_INFO)) ? "info. " : "",
	    (log_mask & BIT(LOG_SEV_DEBUG)) ? "debug. " : "",
	    (log_mask & BIT(LOG_SEV_DEBUG2)) ? "debug2. " : "",
	    (log_mask & BIT(LOG_SEV_METRIC)) ? "metric. " : "",
	    (log_mask & BIT(LOG_SEV_PASS)) ? "tests passing. " : "",
	    (log_mask & BIT(LOG_SEV_FAIL)) ? "tests failing. " : "",
	    (log_mask == 0) ? "nothing." : "");
}

/*
 * Change logging levels for one module (subsystem) according to the
 * on_mask and off_mask supplied, while respecting the global minimum mask.
 * Returns the new mask for the module.
 */
static enum log_mask log_mask_change_index(unsigned int mod_nr,
		 enum log_mask on_mask, enum log_mask off_mask)
{
	struct log_mod *mod;
	u32 log_mask;

	mod = &log_mods[mod_nr];
	log_mask = mod->mask;
	log_mask = (log_mask | on_mask) & ~off_mask;
	log_mask |= log_mask_minimum;
	mod->mask = log_mask;
	return log_mask;
}

/*
 * Change logging levels for one or all modules (subsystems) according to the
 * on_mask and off_mask supplied, while respecting the global minimum mask.
 * If mod_name is NULL or "all" then this applies to all modules.
 * If show is non-zero, display the settings.
 * Return -1 if no module matches matches.
 */
static int log_mask_change_show(const char *mod_name, enum log_mask on_mask,
			enum log_mask off_mask, int show)
{
	u32 log_mask;
	int rc = -1;
	unsigned int mod_nr;
	const char *name;

	for (mod_nr = 0; mod_nr < LOG_MOD_CT; mod_nr++) {
		name = log_mod_names[mod_nr];
		if (!name) {
			continue;
		}
		if (mod_name && strcmp(mod_name, "all") &&
		    strcmp(mod_name, name)) {
			continue;
		}
		rc = 0;
		log_mask = log_mask_change_index(mod_nr, on_mask, off_mask);
		if (show) {
			log_show(name, log_mask);
		}
	}
	return rc;
}

int log_mask_change(const char *mod_name, enum log_mask on_mask,
			enum log_mask off_mask)
{
	return log_mask_change_show(mod_name, on_mask, off_mask, 0);
}

/*
 * Libada interface for enabling / disabling log settings.
 * Same as log_mask_change, but uses number instead of name.
 * Returns -1 if module number is out of range.
 */
int ada_log_mask_change(unsigned int mod_nr, enum log_mask on_mask,
			enum log_mask off_mask)
{
	if (mod_nr > LOG_MOD_CT) {
		return -1;
	}
	log_mask_change_index(mod_nr, on_mask, off_mask);
	return 0;
}

void log_snap_cmd(int argc, char **argv)
{
	unsigned long index;
	char *errptr;
	char *opt;
	int count;
	size_t space;

	argc--;
	argv++;
	if (argc > 0) {
		opt = argv[0];
		index = strtoul(opt, &errptr, 10);
		if (*errptr == '\0' && index) {
			count = log_snap_count(&space);
			if (index > count) {
				printcli("no snapshot %u", (int)index);
			} else {
				log_snap_show(index, 0);
			}
		} else if (!strcmp(opt, "list")) {
			count = log_snap_count(&space);
			for (index = 1; index <= count; index++) {
				log_snap_show(index, 1);
			}
		} else if (!strcmp(opt, "save")) {
			log_save();
		} else if (!strcmp(opt, "erase")) {
			log_snap_erase();
		} else {
			printcli("log-snap: unknown snap option");
			return;
		}
	}
	count = log_snap_count(&space);
	printcli("snapshots saved: %d space for %u more",
	   count, (unsigned int)(space / LOG_SIZE));
}

const char ada_log_cli_help[] = "[--mod <subsys>] [<level> ...]";

void ada_log_cli(int argc, char **argv)
{
	int on;
	u32 mask;
	u32 on_mask = 0;
	u32 off_mask = 0;
	char *cp;
	const char *mod_name = NULL;

	argc--;
	argv++;
	while (argc-- > 0) {
		cp = *argv++;
		on = 1;

		if (!strcmp(cp, "--mod")) {
			if (argc == 0) {
				printcli("log: --mod needs argument");
				return;
			}
			argc--;
			mod_name = *argv++;
			continue;
		}

		if (*cp == '+') {
			cp++;
		} else if (*cp == '-') {
			on = 0;
			cp++;
		}
		if (!strcmp(cp, "pass")) {
			mask = BIT(LOG_SEV_PASS);
		} else if (!strcmp(cp, "fail")) {
			mask = BIT(LOG_SEV_FAIL);
		} else if (!strcmp(cp, "info")) {
			mask = BIT(LOG_SEV_INFO);
		} else if (!strcmp(cp, "debug")) {
			mask = BIT(LOG_SEV_DEBUG);
			if (!on) {
				mask |= BIT(LOG_SEV_DEBUG2);
			}
		} else if (!strcmp(cp, "debug2")) {
			mask = BIT(LOG_SEV_DEBUG2);
			if (on) {
				mask |= BIT(LOG_SEV_DEBUG);
			}
		} else if (!strcmp(cp, "metric")) {
			mask = BIT(LOG_SEV_METRIC);
		} else if (!strcmp(cp, "all")) {
			mask = ~0;
		} else if (!strcmp(cp, "none")) {
			on = 0;
			mask = ~(BIT(LOG_SEV_ERR) | BIT(LOG_SEV_WARN));
		} else {
			printcli("log: invalid log level \"%s\"", cp);
			return;
		}
		if (on) {
			on_mask |= mask;
		} else {
			off_mask |= mask;
		}
	}
	if (log_mask_change_show(mod_name, on_mask, off_mask, 1)) {
		printcli("log: unknown module");
	}
}
