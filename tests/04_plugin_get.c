#include <stdlib.h>

#include <nurs/nurs.h>

#include <internal.h>

#include "test.h"

enum {
	OUTPUT_0,
	OUTPUT_1,
	OUTPUT_MAX,
};
enum {
	INPUT_0,
	INPUT_1,
	INPUT_MAX,
};

static enum nurs_return_t
filter_interp(const struct nurs_plugin *plugin,
	      const struct nurs_input *input,
	      struct nurs_output *output)
{
	return NURS_RET_OK;
}

static enum nurs_return_t
consumer_interp(const struct nurs_plugin *plugin,
		const struct nurs_input *input)
{
	return NURS_RET_OK;
}

static enum nurs_return_t
producer_organize(struct nurs_producer *producer)
{
	return NURS_RET_OK;
}

static struct nurs_output_def output = {
	.len	= OUTPUT_MAX,
	.keys	= {
		[OUTPUT_0] = {
			.name = "output.0",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[OUTPUT_1] = {
			.name = "output.1",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
	},
};
static struct nurs_input_def input = {
	.len	= INPUT_MAX,
	.keys	= {
		[INPUT_0] = {
			.name	= "input.0",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
		[INPUT_1] = {
			.name	= "input.1",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
	},
};

static struct nurs_producer_def producer = {
	.version	= VERSION,
	.name		= "producer",
	.output_def	= &output,
	.organize	= producer_organize,
};
static struct nurs_filter_def filter = {
	.version	= VERSION,
	.name		= "filter",
	.input_def	= &input,
	.output_def	= &output,
	.interp		= filter_interp,
};
static struct nurs_consumer_def consumer = {
	.version	= VERSION,
	.name		= "consumer",
	.input_def	= &input,
	.interp		= consumer_interp,
};

static struct nurs_coveter_def coveter = {
	.version	= VERSION,
	.name		= "coveter",
	.interp		= consumer_interp,
};

static void test_register_plugins(void *data)
{
	assertf(!nurs_producer_register(&producer),
		"should success to register legal minimum producer");
	assertf(!nurs_filter_register(&filter),
		"should success to register legal minimum filter");
	assertf(!nurs_consumer_register(&consumer),
		"should success to register legal minimum consumer");
	assertf(!nurs_coveter_register(&coveter),
		"should success to register legal minimum coveter");
}

static void test_unregister_plugins(void *data)
{
	assertf(!nurs_producer_unregister(&producer),
		"should success to unregister registered producer");
	assertf(!nurs_filter_unregister(&filter),
		"should success to unregister registered filter");
	assertf(!nurs_consumer_unregister(&consumer),
		"should success to unregister registered consumer");
	assertf(!nurs_coveter_unregister(&coveter),
		"should success to unregister registered coveter");
}

static void test_get_producer(void *data)
{
	struct nurs_producer *p1, *p2;

	assertf(p1 = plugin_producer_get("producer", "p1"),
		"should success to create new producer p1");
	assertf(p2 = plugin_producer_get("producer", "p2"),
		"should success to create new producer p2");
	assertf(p1 == plugin_producer_get("producer", "p1"),
		"should get the same producer by the same name and id");
	assertf(p1 != p2,
		"should be differ p1 and p2");
	assertf(nurs_producer_unregister(&producer),
		"should fail to unregister producer which refcnt is 4");
	assertf(!plugin_producer_put(p1),
		"should success to put p1");
	assertf(!plugin_producer_put(p2),
		"should success to put p2");
	assertf(plugin_producer_put(NULL),
		"should fail to put null producer");
	assertf(plugin_producer_put(NULL),
		"should fail to put null producer");
	assertf(nurs_producer_unregister(&producer),
		"should fail to unregister producer def which refcnt is 2");
	assertf(!plugin_producer_put(p1),
		"should success to put p1");
}

static void test_get_filter(void *data)
{
	struct nurs_filter *f1, *f2;

	assertf(f1 = plugin_filter_get("filter", "f1"),
		"should success to create new filter f1");
	assertf(f2 = plugin_filter_get("filter", "f2"),
		"should success to create new filter f2");
	assertf(f1 == plugin_filter_get("filter", "f1"),
		"should get the same filter by the same name and id");
	assertf(f1 != f2,
		"should be differ f1 and f2");
	assertf(nurs_filter_unregister(&filter),
		"should fail to unregister filter which refcnt is 4");
	assertf(!plugin_filter_put(f1),
		"should success to put f1");
	assertf(!plugin_filter_put(f2),
		"should success to put f2");
	assertf(plugin_filter_put(NULL),
		"should fail to put null filter");
	assertf(nurs_filter_unregister(&filter),
		"should fail to unregister filter def which refcnt is 2");
	assertf(!plugin_filter_put(f1),
		"should success to put f1");
}

static void test_get_consumer(void *data)
{
	struct nurs_consumer *cs1, *cs2;

	assertf(cs1 = plugin_consumer_get("consumer", "cs1"),
		"should success to create new consumer cs1");
	assertf(cs2 = plugin_consumer_get("consumer", "cs2"),
		"should success to create new consumer cs2");
	assertf(cs1 == plugin_consumer_get("consumer", "cs1"),
		"should get the same consumer by the same name and id");
	assertf(cs1 != cs2,
		"should be differ cs1 and cs2");
	assertf(nurs_consumer_unregister(&consumer),
		"should fail to unregister consumer which refcnt is 4");
	assertf(!plugin_consumer_put(cs1),
		"should success to put cs1");
	assertf(!plugin_consumer_put(cs2),
		"should success to put cs2");
	assertf(plugin_consumer_put(NULL),
		"should fail to put null consumer");
	assertf(nurs_consumer_unregister(&consumer),
		"should fail to unregister consumer def which refcnt is 2");
	assertf(!plugin_consumer_put(cs1),
		"should success to put cs1");
}

static void test_get_coveter(void *data)
{
	struct nurs_coveter *cv1, *cv2;

	assertf(cv1 = plugin_coveter_get("coveter", "cv1"),
		"should success to create new coveter cv1");
	assertf(cv2 = plugin_coveter_get("coveter", "cv2"),
		"should success to create new coveter cv2");
	assertf(cv1 == plugin_coveter_get("coveter", "cv1"),
		"should get the same coveter by the same name and id");
	assertf(cv1 != cv2,
		"should be differ cv1 and cv2");
	assertf(nurs_coveter_unregister(&coveter),
		"should fail to unregister coveter which refcnt is 4");
	assertf(!plugin_coveter_put(cv1),
		"should success to put cv1");
	assertf(!plugin_coveter_put(cv2),
		"should success to put cv2");
	assertf(plugin_coveter_put(NULL),
		"should fail to put null coveter");
	assertf(nurs_coveter_unregister(&coveter),
		"should fail to unregister coveter def which refcnt is 2");
	assertf(!plugin_coveter_put(cv1),
		"should success to put cv1");
}


int main(int argc, char *argv[])
{
	log_settle(NULL, NURS_DEBUG, "\t", true, true);
	plugin_init();

	test_register_plugins(NULL);
	test_get_producer(NULL);
	test_get_filter(NULL);
	test_get_consumer(NULL);
	test_get_coveter(NULL);
	test_unregister_plugins(NULL);

	return EXIT_SUCCESS;
}
