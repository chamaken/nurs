#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nurs/nurs.h>
#include <internal.h>

#include "test.h"

static char *hint2path(const char *progname, const char *hint)
{
	char *d = strdup(progname);
	char *s = calloc(1, 4096);
	assert(d && s);

	dirname(d);
	snprintf(s, 4096, "%s/data/03_%s.json", d, hint);
	free(d);
	return s;
}

int main(int argc, char *argv[])
{
	struct {
		void *(*regist)(const char *, uint16_t);
		int (*unregist)(const char *);
		char *hint;
		bool register_assert;
	} *cmd, success_cmds[] = {
		{
			(void *(*)(const char *, uint16_t))nurs_plugins_register_jsonf,
			nurs_plugins_unregister_jsonf,
			"first",
			false,
		},
		{NULL, NULL, NULL, false},
	};

	log_settle(NULL, NURS_DEBUG, "\t", true, true);
	plugin_init();

	for (cmd = success_cmds; cmd->regist; cmd++) {
		char *path = hint2path(argv[0], cmd->hint);
		assertf(cmd->register_assert ? cmd->regist(path, 0) : !cmd->regist(path, 0),
			"should success to register %s", path);
		free(path);
	}

	for (cmd = success_cmds; cmd->regist; cmd++) {
		char *path = hint2path(argv[0], cmd->hint);
		assertf(!cmd->unregist(path),
			"should success to unregister %s", path);
		free(path);
	}

	return EXIT_SUCCESS;
}
