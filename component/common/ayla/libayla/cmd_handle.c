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
#include <sys/types.h>

#include <ayla/utypes.h>
#include <ayla/parse.h>
#include <ayla/cmd.h>

int cmd_handle(const struct cmd_info *cmds, char *buf)
{
	char *argv[CMD_ARGV_LIMIT];
	int argc;

	argc = parse_argv(argv, CMD_ARGV_LIMIT, buf);
	if (argc >= CMD_ARGV_LIMIT - 1) {
		return -1;
	}
	return cmd_handle_argv(cmds, argc, argv);
}

int cmd_handle_argv(const struct cmd_info *cmds, int argc, char **argv)
{
	const struct cmd_info *cmd;

	if (argc > 0) {
		for (cmd = cmds; cmd->name; cmd++) {
			if (!strcmp(cmd->name, argv[0])) {
				break;
			}
		}
		cmd->handler(argc, argv);
	}
	return 0;
}
