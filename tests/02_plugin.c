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
#include <nurs/ipfix_protocol.h>
#include <internal.h>

#include "test.h"

enum {
	TEST_CONFIG_0,
	TEST_CONFIG_1,
	TEST_CONFIG_MAX,
};

enum {
	TEST_IKEY_0,
	TEST_IKEY_1,
	TEST_IKEY_MAX,
};

enum {
	TEST_OKEY_0,
	TEST_OKEY_1,
	TEST_OKEY_MAX,
};

static enum nurs_return_t
producer_organize(const struct nurs_producer *producer)
{
	return NURS_RET_OK;
}

static enum nurs_return_t
filter_interp(const struct nurs_plugin *plugin,
	      const struct nurs_input *input, struct nurs_output *output)
{
	return NURS_RET_OK;
}

static enum nurs_return_t
consumer_interp(const struct nurs_plugin *plugin,
		const struct nurs_input *input)
{
	return NURS_RET_OK;
}

static void key_destructor(void *p)
{
	printf("destruct arg: %p\n", p);
}

static struct nurs_input_def	input_template = {
	.len	= 0,
	.keys	= {
		[TEST_IKEY_0] = {0},
		[TEST_IKEY_1] = {0},
	},
};
#define INPUT_TEMPLATE_SIZE (sizeof(struct nurs_input_def) \
			     + sizeof(struct nurs_input_key_def) * 2)


static struct nurs_output_def	output_template = {
	.len	= 0,
	.keys	= {
		[TEST_OKEY_0] = {0},
		[TEST_OKEY_1] = {0},
	},
};
#define OUTPUT_TEMPLATE_SIZE (sizeof(struct nurs_output_def) \
			      + sizeof(struct nurs_output_key_def) * 2)

static void test_producer_register(const void *data)
{
	static struct nurs_producer_def producer; /* = {{0}}; */
	struct nurs_output_def *output = calloc(1, OUTPUT_TEMPLATE_SIZE);

	assert(output);
	memcpy(output, &output_template, OUTPUT_TEMPLATE_SIZE);

	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register no name producer");

	strncpy(producer.name, "test producer", NURS_NAME_LEN);
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register no version, no organize"
		" and no output producer");

	strncpy(producer.version, "invalid version", NURS_NAME_LEN);
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register invalid version, no organize"
		" and no output producer plugin");

	strncpy(producer.version, VERSION, NURS_NAME_LEN);
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register no organize and no output producer");

	producer.organize = producer_organize;
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register no output producer");

	producer.output_def = output;
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register empty output producer");

	output->len = TEST_OKEY_MAX;
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register no output name producer");

	strncpy(output->keys[TEST_OKEY_0].name, "output.0", NURS_NAME_LEN);
	strncpy(output->keys[TEST_OKEY_1].name, "output.1", NURS_NAME_LEN);
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register no output flag, type producer");

	output->keys[TEST_OKEY_0].type = NURS_KEY_T_BOOL;
	output->keys[TEST_OKEY_1].type = NURS_KEY_T_BOOL;
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register no output flag producer");

	output->keys[TEST_OKEY_0].flags = NURS_OKEY_F_ALWAYS;
	output->keys[TEST_OKEY_1].flags = NURS_OKEY_F_ALWAYS;
	assertf(nurs_producer_register(&producer) == 0,
		"should success to register minimal producer");

	assertf(nurs_producer_unregister(NULL) == -1,
		"should fail to unregister invalid producer");

	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register already registered producer");

	assertf(nurs_producer_unregister(&producer) == 0,
		"should success to unregister valid producer");

	output->keys[TEST_OKEY_0].type = NURS_KEY_T_STRING;
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register producer with lenghen key and its size 0");

	output->keys[TEST_OKEY_0].len = 32;
	assertf(nurs_producer_register(&producer) == 0,
		"should success to register producer with correct lenghen key");
	assertf(nurs_producer_unregister(&producer) == 0,
		"should success to unregister valid producer");

	output->keys[TEST_OKEY_0].flags |= NURS_OKEY_F_FREE;
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register embed and free output key flags"
		" producer");

	output->keys[TEST_OKEY_0].type = NURS_KEY_T_POINTER;
	output->keys[TEST_OKEY_0].len = 0;
	output->keys[TEST_OKEY_0].flags |= NURS_OKEY_F_DESTRUCT;
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register embed type and both FREE and DESTRUCT"
		" output key flags producer");

	output->keys[TEST_OKEY_0].flags &= (uint16_t)~NURS_OKEY_F_FREE;
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register embed type and DESTRUCT flags, but"
		" no destructor producer");

	output->keys[TEST_OKEY_0].destructor = key_destructor;
	assertf(nurs_producer_register(&producer) == 0,
		"should success to register producer with correct pointer key");
	assertf(nurs_producer_unregister(&producer) == 0,
		"should success to unregister valid producer");

	output->keys[TEST_OKEY_0].flags
		= NURS_OKEY_F_ALWAYS | NURS_OKEY_F_OPTIONAL;
	assertf(nurs_producer_register(&producer) == -1,
		"should fail to register multiple value setting means");

	free(output);
}

static void test_filter_register(const void *data)
{
	static struct nurs_filter_def filter; /* = {{0}}; */
	struct nurs_input_def *input = calloc(1, INPUT_TEMPLATE_SIZE);
	struct nurs_output_def *output = calloc(1, OUTPUT_TEMPLATE_SIZE);

	assert(input && output);
	memcpy(input, &input_template, INPUT_TEMPLATE_SIZE);
	memcpy(output, &output_template, OUTPUT_TEMPLATE_SIZE);

	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no name filter");

	strncpy(filter.name, "test filter", NURS_NAME_LEN);
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no version, no interp"
		" and no output filter");

	strncpy(filter.version, "invalid version", NURS_NAME_LEN);
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register invalid version, no interp"
		" and no output filter plugin");

	strncpy(filter.version, VERSION, NURS_NAME_LEN);
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no interp and no output filter");

	filter.interp = filter_interp;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no input/output filter");

	filter.output_def = output;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register empty output filter");

	output->len = TEST_OKEY_MAX;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no output name filter");

	strncpy(output->keys[TEST_OKEY_0].name, "output->0", NURS_NAME_LEN);
	strncpy(output->keys[TEST_OKEY_1].name, "output->1", NURS_NAME_LEN);
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no output flag, type filter");

	output->keys[TEST_OKEY_0].type = NURS_KEY_T_BOOL;
	output->keys[TEST_OKEY_1].type = NURS_KEY_T_BOOL;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no output flag filter");

	output->keys[TEST_OKEY_0].flags = NURS_OKEY_F_ALWAYS;
	output->keys[TEST_OKEY_1].flags = NURS_OKEY_F_ALWAYS;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no input filter");

	filter.input_def = input;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register with empty input filter");

	input->len = TEST_IKEY_MAX;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no input name filter");

	strncpy(input->keys[TEST_IKEY_0].name, "input.0", NURS_NAME_LEN);
	strncpy(input->keys[TEST_IKEY_1].name, "input.1", NURS_NAME_LEN);
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no input flag, type filter");

	input->keys[TEST_IKEY_0].type = NURS_KEY_T_BOOL;
	input->keys[TEST_IKEY_1].type = NURS_KEY_T_BOOL;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register no input flag filter");

	input->keys[TEST_IKEY_0].flags = NURS_IKEY_F_REQUIRED;
	input->keys[TEST_IKEY_1].flags = NURS_IKEY_F_REQUIRED;
	assertf(nurs_filter_register(&filter) == 0,
		"should success to register minimal filter");

	assertf(nurs_filter_unregister(NULL) == -1,
		"should fail to unregister invalid filter");

	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register already registered filter");

	assertf(nurs_filter_unregister(&filter) == 0,
		"should success to unregister valid filter");

	output->keys[TEST_OKEY_0].type = NURS_KEY_T_STRING;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register filter with lenghen key and its size 0");

	output->keys[TEST_OKEY_0].len = 32;
	assertf(nurs_filter_register(&filter) == 0,
		"should success to register filter with correct lenghen key");
	assertf(nurs_filter_unregister(&filter) == 0,
		"should success to unregister valid filter");

	output->keys[TEST_OKEY_0].flags |= NURS_OKEY_F_FREE;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register embed and free output key flags"
		" filter");

	output->keys[TEST_OKEY_0].type = NURS_KEY_T_POINTER;
	output->keys[TEST_OKEY_0].len = 0;
	output->keys[TEST_OKEY_0].flags |= NURS_OKEY_F_DESTRUCT;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register embed type and both FREE and DESTRUCT"
		" output key flags filter");

	output->keys[TEST_OKEY_0].flags &= (uint16_t)~NURS_OKEY_F_FREE;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register embed type and DESTRUCT flags, but"
		" no destructor filter");

	output->keys[TEST_OKEY_0].destructor = key_destructor;
	assertf(nurs_filter_register(&filter) == 0,
		"should success to register filter with correct pointer key");
	assertf(nurs_filter_unregister(&filter) == 0,
		"should success to unregister valid filter");

	output->keys[TEST_OKEY_0].flags
		= NURS_OKEY_F_ALWAYS | NURS_OKEY_F_OPTIONAL;
	assertf(nurs_filter_register(&filter) == -1,
		"should fail to register filter with multiple value setting means");

	free(output);
	free(input);
}

static void test_consumer_register(const void *data)
{
	static struct nurs_consumer_def	consumer; /* = {{0}}; */
	struct nurs_input_def *input = calloc(1, INPUT_TEMPLATE_SIZE);

	assert(input);
	memcpy(input, &input_template, INPUT_TEMPLATE_SIZE);

	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register no name consumer");

	strncpy(consumer.name, "test consumer", NURS_NAME_LEN);
	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register no version, no interp"
		" and no input consumer");

	strncpy(consumer.version, "invalid version", NURS_NAME_LEN);
	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register invalid version, no interp"
		" and no input consumer plugin");

	strncpy(consumer.version, VERSION, NURS_NAME_LEN);
	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register no interp and no input consumer");

	consumer.interp = consumer_interp;
	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register no input consumer");

	consumer.input_def = input;
	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register with empty input consumer");

	input->len = TEST_IKEY_MAX;
	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register no input name consumer");

	strncpy(input->keys[TEST_IKEY_0].name, "input.0", NURS_NAME_LEN);
	strncpy(input->keys[TEST_IKEY_1].name, "input.1", NURS_NAME_LEN);
	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register no input flag, type consumer");

	input->keys[TEST_IKEY_0].type = NURS_KEY_T_BOOL;
	input->keys[TEST_IKEY_1].type = NURS_KEY_T_BOOL;
	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register no input flag consumer");

	input->keys[TEST_IKEY_0].flags = NURS_IKEY_F_REQUIRED;
	input->keys[TEST_IKEY_1].flags = NURS_IKEY_F_REQUIRED;
	assertf(nurs_consumer_register(&consumer) == 0,
		"should success to register minimal consumer");

	assertf(nurs_consumer_unregister(NULL) == -1,
		"should fail to unregister invalid consumer");

	assertf(nurs_consumer_register(&consumer) == -1,
		"should fail to register already registered consumer");

	assertf(nurs_consumer_unregister(&consumer) == 0,
		"should success to unregister valid consumer");

	free(input);
}

static void test_coveter_register(const void *data)
{
	static struct nurs_coveter_def coveter; /* = {{0}} */

	assertf(nurs_coveter_register(&coveter) == -1,
		"should fail to register no name coveter");

	strncpy(coveter.name, "test coveter", NURS_NAME_LEN);
	assertf(nurs_coveter_register(&coveter) == -1,
		"should fail to register no version, no interp coveter");

	strncpy(coveter.version, "invalid version", NURS_NAME_LEN);
	assertf(nurs_coveter_register(&coveter) == -1,
		"should fail to register invalid version, no interp coveter");

	strncpy(coveter.version, VERSION, NURS_NAME_LEN);
	assertf(nurs_coveter_register(&coveter) == -1,
		"should fail to register no interp coveter");

	coveter.interp = consumer_interp;
	assertf(nurs_coveter_register(&coveter) == 0,
		"should success to register minimal coveter");

	assertf(nurs_coveter_unregister(NULL) == -1,
		"should fail to unregister invalid coveter");

	assertf(nurs_coveter_register(&coveter) == -1,
		"should fail to register already registered coveter");

	assertf(nurs_coveter_unregister(&coveter) == 0,
		"should success to unregister valid coveter");
}

int main(int argc, char *argv[])
{
	log_settle(NULL, NURS_DEBUG, "\t", true, true);
	plugin_init();

	test_producer_register(NULL);
	test_filter_register(NULL);
	test_consumer_register(NULL);
	test_coveter_register(NULL);

	return EXIT_SUCCESS;
}
