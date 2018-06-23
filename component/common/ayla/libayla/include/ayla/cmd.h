/*
 * Copyright 2011 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_CMD_H__
#define __AYLA_CMD_H__

#define CMD_ARGV_LIMIT	20	/* limit on number of args for a command */

struct cmd_info {
	const char *name;
	void (*handler)(int, char **);
	const char *help;
};

#define CMD_INIT(_name, _handler, _help) \
	{ .name = _name, .handler = _handler, .help = _help}

#define CMD_END_DEFAULT(_handler) CMD_INIT(NULL, _handler, NULL)

int cmd_handle(const struct cmd_info *cmds, char *cmd);
int cmd_handle_argv(const struct cmd_info *cmds, int argc, char **argv);

#endif /* __AYLA_CMD_H__ */
