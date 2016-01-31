#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nurs/nurs.h>
#include <internal.h>

#include "test.h"

enum {
	CONFIG_ZEILE_0,
	CONFIG_ZEILE_1,
	CONFIG_ZEILE_2,
	CONFIG_ZEILE_DEFAULT,
	CONFIG_EMPTY_STRING,
	CONFIG_SPALTE_0,
	CONFIG_SPALTE_1,
	CONFIG_SPALTE_2,
	CONFIG_SPALTE_DEFAULT,
	CONFIG_BOOL_ON_1,
	CONFIG_BOOL_ON_2,
	CONFIG_BOOL_TRUE_1,
	CONFIG_BOOL_TRUE_2,
	CONFIG_BOOL_YES_1,
	CONFIG_BOOL_YES_2,
	CONFIG_BOOL_1_1,
	CONFIG_BOOL_1_2,
	CONFIG_BOOL_FALSE_1,
	CONFIG_BOOL_FALSE_2,
	CONFIG_BOOL_FALSE_3,
	CONFIG_BOOL_FALSE_4,
	CONFIG_PARSER_FUNC,
	CONFIG_PARSER_NAME,
	CONFIG_GLOBAL_MAX,
};

enum {
	CONFIG_INTEGER,
	CONFIG_STRING,
	CONFIG_BOOLEAN,
	CONFIG_TYPE_MISMATCH_MAX,
};

static int parser_f(const char *args)
{
	static int times;
	switch (times) {
	case 0:
		assertf(!strcmp(args, "0:1:2:3;4:5:6:7"),
			"should 1st parser_func be `0:1:2:3;4:5:6:7'");
		break;
	case 1:
		assertf(!strcmp(args, "8: 9 :	a:b	:c:d:e:f"),
			"should 2nd parser_func be `8: 9 :	a:b	:c:d:e:f'");
		break;
	case 2:
		assertf(!strlen(args),
			"should 3rd parser_func be `'");
		break;
	default:
		break;
	}
	times++;
	return 0;
}

int export_cb_parser_s(const char *args)
{
	printf("parser_name - args: %s\n", args);
	return 0;
}
EXPORT(export_cb_parser_s);

static int error_parser(const char *args)
{
	return -1;
}

static struct nurs_config_def global_config_def = {
	.len		= CONFIG_GLOBAL_MAX,
	.keys	= {
		[CONFIG_ZEILE_0] = {
			.name	= "zeile0",
			.type	= NURS_CONFIG_T_STRING,
		},
		[CONFIG_ZEILE_1] = {
			.name	= "zeile1",
			.type	= NURS_CONFIG_T_STRING,
			.flags	= NURS_CONFIG_F_MULTI,
		},
		[CONFIG_ZEILE_2] = {
			.name	= "zeile2",
			.type	= NURS_CONFIG_T_STRING,
		},
		[CONFIG_ZEILE_DEFAULT] = {
			.name	= "zeile_default",
			.type	= NURS_CONFIG_T_STRING,
			.string	= "default string",
		},
		[CONFIG_EMPTY_STRING] = {
			.name	= "empty_string",
			.type	= NURS_CONFIG_T_STRING,
		},
		[CONFIG_SPALTE_0] = {
			.name	= "spalte0",
			.type	= NURS_CONFIG_T_INTEGER,
			.flags	= NURS_CONFIG_F_MULTI,
		},
		[CONFIG_SPALTE_1] = {
			.name	= "spalte1",
			.type	= NURS_CONFIG_T_INTEGER,
		},
		[CONFIG_SPALTE_2] = {
			.name	= "spalte 2",
			.type	= NURS_CONFIG_T_INTEGER,
		},
		[CONFIG_SPALTE_DEFAULT] = {
			.name	= "spalte_default",
			.type	= NURS_CONFIG_T_INTEGER,
			.integer = 111,
		},
		[CONFIG_BOOL_ON_1] = {
			.name	= "b_on_1",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_ON_2] = {
			.name	= "b_on_2",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_TRUE_1] = {
			.name	= "b_true_1",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_TRUE_2] = {
			.name	= "b_true_2",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_YES_1] = {
			.name	= "b_yes_1",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_YES_2] = {
			.name	= "b_yes_2",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_1_1] = {
			.name	= "b_1_1",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_1_2] = {
			.name	= "b_1_2",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_FALSE_1] = {
			.name	= "b_false_1",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_FALSE_2] = {
			.name	= "b_false_2",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_FALSE_3] = {
			.name	= "b_false_3",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_BOOL_FALSE_4] = {
			.name	= "b_false_4",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
		[CONFIG_PARSER_FUNC] = {
			.name	= "parser_func",
			.type	= NURS_CONFIG_T_CALLBACK,
			.flags	= NURS_CONFIG_F_MULTI,
			.parser	= parser_f,
		},
		[CONFIG_PARSER_NAME] = {
			.name	= "parser_name",
			.type	= NURS_CONFIG_T_CALLBACK,
			.flags	= NURS_CONFIG_F_MULTI,
			.parser_cb_s	= "export_cb_parser_s",
			.resolve_parser = true,
			/* {.parser_cb_s	= "parser_s"}, */
		},
	},
};

static struct nurs_config_def no_equal_config_def = {
	.len		= 1,
	.keys	= {
		[0] = {
			.name	= "key",
			.type	= NURS_CONFIG_T_STRING,
		},
	},
};

static struct nurs_config_def type_mismatch_config_def = {
	.len		= CONFIG_TYPE_MISMATCH_MAX,
	.keys	= {
		[CONFIG_INTEGER] = {
			.name	= "integer",
			.type	= NURS_CONFIG_T_INTEGER,
		},
		[CONFIG_STRING] = {
			.name	= "string",
			.type	= NURS_CONFIG_T_STRING,
		},
		[CONFIG_BOOLEAN] = {
			.name	= "boolean",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
	},
};

static struct nurs_config_def unbalanced_quote_config_def = {
	.len		= 2,
	.keys	= {
		[0] 	= {
			.name	= "key1",
			.type	= NURS_CONFIG_T_STRING,
		},
		[1] 	= {
			.name	= "key2",
			.type	= NURS_CONFIG_T_STRING,
		},
	},
};

static struct nurs_config_def mandatory_config_def = {
	.len		= 1,
	.keys	= {
		[0] 	= {
			.name	= "mandatory",
			.type	= NURS_CONFIG_T_STRING,
			.flags	= NURS_CONFIG_F_MANDATORY,
		},
	},
};

static struct nurs_config_def error_parser_config_def = {
	.len		= 1,
	.keys	= {
		[0]	= {
			.name	= "mandatory",
			.type	= NURS_CONFIG_T_CALLBACK,
			.flags	= NURS_CONFIG_F_MULTI,
			.parser = error_parser,
		},
	},
};

static void test_config_fopen(const void *data)
{
	const char *fname = data;

	assertf(config_fopen("non-existing-file") < 0,
		"should fail to fopen not existing config file");
	assertf(!config_fopen(fname),
		"should success to open a right config file");
	assertf(config_fopen(fname) > 0,
		"should retun positive when already opened file again");
	assertf(!config_fclose(),
		"should success to close config file");
	assertf(config_fclose(),
		"should fail to close in not opened status");
}

static void test_config_global(const void *data)
{
	const char *fname = data;
	struct nurs_config *config;

	assertf(!config_fopen(fname),
		"should success to open a right config file");

	assertf(config = config_parse_section("global", &global_config_def),
		"should success to a valid global section");

	assertf(strncmp(nurs_config_string(config, CONFIG_ZEILE_0),
			"zeile0-string", NURS_STRING_LEN) == 0,
		"ZEILE_0 shuold be equal to ``zeile0-string''");

	assertf(strncmp(nurs_config_string(config, CONFIG_ZEILE_1),
			"zeile1-string", NURS_STRING_LEN) == 0,
		"ZEILE_1 shoule be equal to ``zeile1-string''");

	assertf(strncmp(nurs_config_string(config, CONFIG_ZEILE_2),
			"zeile 2 \"string\"", NURS_STRING_LEN) == 0,
		"ZEILE_2 should be equal to ``zeile1 2 \"string\"''");

	assertf(strncmp(nurs_config_string(config, CONFIG_ZEILE_DEFAULT),
			"default string", NURS_STRING_LEN) == 0,
		"ZEILE_DEFAUL should be equal to ``default string");

	assertf(strncmp(nurs_config_string(config, CONFIG_EMPTY_STRING),
			"", NURS_STRING_LEN) == 0,
		"EMPTY_STRING should be empty");

	/* TODO: needs errno consideration */
	errno = 0;
	assertf(nurs_config_string(config, UINT8_MAX) == NULL,
		"invalid index str should be equal to NULL");
	assertf(errno,
		"errno should be set after invalid index");

	assertf(nurs_config_string(config, CONFIG_SPALTE_0) == NULL,
		"should return NULL to get int value as string");

	assertf(nurs_config_integer(config, CONFIG_SPALTE_0) == 715,
		"SPALTE_0 should be equal to 715");

	assertf(nurs_config_integer(config, CONFIG_SPALTE_1) == 0715,
		"SPALTE_1 should be equal to 0715");

	assertf(nurs_config_integer(config, CONFIG_SPALTE_2) == 0x715,
		"SPALTE_2 should be equal to 0x715");

	assertf(nurs_config_integer(config, CONFIG_SPALTE_DEFAULT) == 111,
		"SPALTE_DEFAULT should be equal to 111");

	assertf(nurs_config_boolean(config, CONFIG_BOOL_ON_1),
		"CONFIG_BOOL_ON_1 should be true");
	assertf(nurs_config_boolean(config, CONFIG_BOOL_ON_2),
		"CONFIG_BOOL_ON_2 should be true");
	assertf(nurs_config_boolean(config, CONFIG_BOOL_TRUE_1),
		"CONFIG_BOOL_TRUE_1 should be true");
	assertf(nurs_config_boolean(config, CONFIG_BOOL_TRUE_2),
		"CONFIG_BOOL_TRUE_2 should be true");
	assertf(nurs_config_boolean(config, CONFIG_BOOL_YES_1),
		"CONFIG_BOOL_YES_1 should be true");
	assertf(nurs_config_boolean(config, CONFIG_BOOL_YES_2),
		"CONFIG_BOOL_YES_2 should be true");
	assertf(nurs_config_boolean(config, CONFIG_BOOL_1_1),
		"CONFIG_BOOL_1_1 should be true");
	assertf(nurs_config_boolean(config, CONFIG_BOOL_1_2),
		"CONFIG_BOOL_1_2 should be true");
	assertf(!nurs_config_boolean(config, CONFIG_BOOL_FALSE_1),
		"CONFIG_BOOL_FALSE_1 should be true");
	assertf(!nurs_config_boolean(config, CONFIG_BOOL_FALSE_2),
		"CONFIG_BOOL_FALSE_2 should be true");
	assertf(!nurs_config_boolean(config, CONFIG_BOOL_FALSE_3),
		"CONFIG_BOOL_FALSE_3 should be true");
	assertf(!nurs_config_boolean(config, CONFIG_BOOL_FALSE_4),
		"CONFIG_BOOL_FALSE_4 should be true");

	errno = 0;
	assertf(nurs_config_integer(config, UINT8_MAX) == 0,
		"invalid index int value should be equal to 0");
	assertf(errno,
		"errno shuold be set after invalid index");
	errno = 0;
	assertf(nurs_config_integer(config, CONFIG_ZEILE_0) == 0,
		"should return 0 to get str value as int");
	assertf(errno,
		"errno should be set after wrong type get");

	assertf(!config_fclose(),
		"should success to close config file");
	free(config);
}

static void test_config_no_equal(void *data)
{
	const char *fname = data;

	assertf(!config_fopen(fname),
		"should success to open a right config file");
	assertf(!config_parse_section("no equal", &no_equal_config_def),
		"should fail to parse invalid (no equal) config");
	assertf(!config_fclose(),
		"should success to close config file");
}

static void test_config_unbalanced_quote(void *data)
{
	const char *fname = data;

	assertf(!config_fopen(fname),
		"should success to open a right config file");
	assertf(!config_parse_section("unbalanced quote",
					   &unbalanced_quote_config_def),
		"shuold fail to parse invalid (unbalanced quote) config");
	assertf(!config_fclose(),
		"should success to close config file");
}

static void test_config_type_mismatch(void *data)
{
	const char *fname = data;
	struct nurs_config *config;

	assertf(!config_fopen(fname),
		"should success to open a right config file");

	assertf(config = config_parse_section("type mismatch",
						   &type_mismatch_config_def),
		"should success to a valid type mismatch section");

	errno = 0;
	assertf(nurs_config_integer(config, CONFIG_INTEGER) == 1,
		"should success to get a valid integer");
	assertf(!strcmp(nurs_config_string(config, CONFIG_STRING), "string"),
		"should success to get a valid string");
	assertf(nurs_config_boolean(config, CONFIG_BOOLEAN),
		"should success to get a valid boolean");
	assertf(!errno,
		"should not set errno after valid acquisition");

	errno = 0;
	assertf(!nurs_config_string(config, CONFIG_INTEGER),
		"should fail to get string to integer type");
	assertf(errno,
		"errno should be set on getting invalid type");
	errno = 0;
	assertf(!nurs_config_boolean(config, CONFIG_INTEGER),
		"should fail to get boolean to integer type");
	assertf(errno,
		"errno should be set on getting invalid type");

	errno = 0;
	assertf(!nurs_config_integer(config, CONFIG_STRING),
		"should fail to get integer to string type");
	assertf(errno,
		"errno should be set on getting invalid type");
	errno = 0;
	assertf(!nurs_config_boolean(config, CONFIG_STRING),
		"should fail to get boolean to string type");
	assertf(errno,
		"errno should be set on getting invalid type");

	errno = 0;
	assertf(!nurs_config_integer(config, CONFIG_BOOLEAN),
		"should fail to get integer to boolean type");
	assertf(errno,
		"errno should be set on getting invalid type");
	errno = 0;
	assertf(!nurs_config_string(config, CONFIG_BOOLEAN),
		"should fail to get string to boolean type");
	assertf(errno,
		"errno should be set on getting invalid type");

	assertf(!config_fclose(),
		"should success to close config file");
	free(config);
}

static void test_config_misc(void *data)
{
	const char *fname = data;
	struct nurs_config *config;

	assertf(!config_fopen(fname),
		"should success to open a right config file");

	assertf(!config_parse_section("not exist", &global_config_def),
		"shuold fail to parse not existed section");
	assertf(config = config_parse_section("no entry", &global_config_def),
		"shuold success to parse empty entry with mismatched def");
	assertf(!config_parse_section("no entry", &mandatory_config_def),
		"shuold fail to parse empty entry with mandatory flag");
	assertf(!config_parse_section("multi", &mandatory_config_def),
		"shuold fail to parse multiple entry without multi flag");
	free(config);

	mandatory_config_def.keys[0].flags = NURS_CONFIG_F_MULTI;
	assertf(config = config_parse_section("multi", &mandatory_config_def),
		"shuold success to parse multiple entry with multi flag");
	mandatory_config_def.keys[0].flags = NURS_CONFIG_F_MANDATORY;
	free(config);

	assertf(!config_parse_section("multi", &error_parser_config_def),
		"shuold fail to parse which has erronous cb");

	assertf(!config_fclose(),
		"should success to close config file");
}

int main(int argc, char *argv[])
{
	assert(!useless_init(1));
	log_settle(NULL, NURS_DEBUG, "\t", true, true);

	test_config_fopen(argv[1]);
	test_config_global(argv[1]);
	test_config_no_equal(argv[1]);
	test_config_unbalanced_quote(argv[1]);
	test_config_type_mismatch(argv[1]);
	test_config_misc(argv[1]);

	assert(!useless_fini());
	return EXIT_SUCCESS;
}
