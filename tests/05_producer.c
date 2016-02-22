#include <stdlib.h>

#include <nurs/nurs.h>

#include <internal.h>

#include "test.h"

/* main.c */
extern bool nurs_show_pluginfo;

enum {
	PRODUCER_OKEY_0,
	PRODUCER_OKEY_1,
	PRODUCER_OKEY_MAX,
};
enum {
	FILTER_IKEY_0,
	FILTER_IKEY_MAX,
};
enum {
	FILTER_OKEY_2,
	FILTER_OKEY_MAX,
};
enum {
	CONSUMER_IKEY_1,
	CONSUMER_IKEY_2,
	CONSUMER_IKEY_MAX,
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
producer_organize(const struct nurs_producer *producer)
{
	return NURS_RET_OK;
}

static struct nurs_output_def producer_output_def = {
	.len	= PRODUCER_OKEY_MAX,
	.keys	= {
		[PRODUCER_OKEY_0] = {
			.name = "test.0",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[PRODUCER_OKEY_1] = {
			.name = "test.1",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
	},
};

static struct nurs_input_def filter_input_def = {
	.len	= FILTER_IKEY_MAX,
	.keys	= {
		[FILTER_IKEY_0] = {
			.name	= "test.0",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
	},
};

static struct nurs_output_def filter_output_def = {
	.len	= FILTER_OKEY_MAX,
	.keys	= {
		[FILTER_OKEY_2] = {
			.name	= "test.2",
			.type	= NURS_KEY_T_IN6ADDR,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
	},
};

static struct nurs_input_def consumer_input_def = {
	.len	= CONSUMER_IKEY_MAX,
	.keys	= {
		[CONSUMER_IKEY_1] = {
			.name	= "test.1",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_IKEY_F_OPTIONAL,
		},
		[CONSUMER_IKEY_2] = {
			.name	= "test.2",
			.type	= NURS_KEY_T_IN6ADDR,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
	},
};

static struct nurs_producer_def producer_def = {
	.version	= VERSION,
	.name		= "min.producer",
	.output_def	= &producer_output_def,
	.organize	= producer_organize,
};

static struct nurs_filter_def filter_def = {
	.version	= VERSION,
	.name		= "min.filter",
	.input_def	= &filter_input_def,
	.output_def	= &filter_output_def,
	.interp		= filter_interp,
};

static struct nurs_consumer_def consumer_def = {
	.version	= VERSION,
	.name		= "min.consumer",
	.input_def	= &consumer_input_def,
	.interp		= consumer_interp,
};

static struct nurs_coveter_def coveter_def = {
	.version	= VERSION,
	.name		= "min.coveter",
	.interp		= consumer_interp,
};

static void test_show_info(const void *data)
{
	nurs_show_pluginfo = true;
	assertf(nurs_producer_register(&producer_def) == 0,
		"minimum legal producer plugin must be shown");
	assertf(nurs_filter_register(&filter_def) == 0,
		"minimum legal filter plugin must be shown");
	assertf(nurs_consumer_register(&consumer_def) == 0,
		"minimum legal consumer plugin must be shown");
	nurs_show_pluginfo = false;
}

static void test_register_producer(void *data)
{
	struct nurs_producer *p;

	assertf(!plugin_producer_get("min.producer", "1"),
		"should fail to get unregistered producer");
	assertf(!nurs_producer_register(&producer_def),
		"should success to legal minimal producer");
	assertf(producer_def.refcnt == 1,
		"producer def's refcnt now should be 1");
	assertf(!plugin_producer_get("min.producer", NULL),
		"should fail to get invalid id producer");
	assertf(p = plugin_producer_get("min.producer", "1"),
		"should success to get a registered producer");
	assertf(producer_def.refcnt == 2,
		"producer def's refcnt now should be 2");
	assertf(p->refcnt == 1,
		"producer refcnt now should be 1");
	assertf(p == plugin_producer_get("min.producer", "1"),
		"should get the same producer");
	assertf(producer_def.refcnt == 3,
		"producer def's refcnt now should be 3");
	assertf(p->refcnt == 2,
		"producer refcnt now should be 2");
	assertf(!plugin_producer_put(p),
		"should success to put gotten producer");
	assertf(!plugin_producer_put(p),
		"should success to put gotten producer");
	assertf(producer_def.refcnt == 1,
		"producer def's refcnt now should be 1");
}

static void test_register_filter(void *data)
{
	struct nurs_filter *p;

	assertf(!plugin_filter_get("min.filter", "2"),
		"should fail to get unregistered filter");
	assertf(!nurs_filter_register(&filter_def),
		"should success to legal minimal filter");
	assertf(filter_def.refcnt == 1,
		"filter def's refcnt now should be 1");
	assertf(!plugin_filter_get("min.filter", NULL),
		"should fail to get invalid id filter");
	assertf(p = plugin_filter_get("min.filter", "2"),
		"should success to get a registered filter");
	assertf(filter_def.refcnt == 2,
		"filter def's refcnt now should be 2");
	assertf(p->refcnt == 1,
		"filter refcnt now should be 1");
	assertf(p == plugin_filter_get("min.filter", "2"),
		"should get the same filter");
	assertf(filter_def.refcnt == 3,
		"filter def's refcnt now should be 3");
	assertf(p->refcnt == 2,
		"filter refcnt now should be 2");
	assertf(!plugin_filter_put(p),
		"should success to put gotten producer");
	assertf(!plugin_filter_put(p),
		"should success to put gotten producer");
	assertf(filter_def.refcnt == 1,
		"filter def's refcnt now should be 1");
}

static void test_register_consumer(void *data)
{
	struct nurs_consumer *p;

	assertf(!plugin_consumer_get("min.consumer", "3"),
		"should fail to get unregistered consumer");
	assertf(!nurs_consumer_register(&consumer_def),
		"should success to legal minimal consumer");
	assertf(consumer_def.refcnt == 1,
		"consumer def's refcnt now should be 1");
	assertf(!plugin_consumer_get("min.consumer", NULL),
		"should fail to get invalid id consumer");
	assertf(p = plugin_consumer_get("min.consumer", "3"),
		"should success to get a registered consumer");
	assertf(consumer_def.refcnt == 2,
		"consumer def's refcnt now should be 2");
	assertf(p->refcnt == 1,
		"consumer refcnt now should be 1");
	assertf(p == plugin_consumer_get("min.consumer", "3"),
		"should get the same consumer");
	assertf(consumer_def.refcnt == 3,
		"consumer def's refcnt now should be 3");
	assertf(p->refcnt == 2,
		"consumer refcnt now should be 2");
	assertf(!plugin_consumer_put(p),
		"should success to put gotten consumer");
	assertf(!plugin_consumer_put(p),
		"should success to put gotten consumer");
	assertf(consumer_def.refcnt == 1,
		"consumer def's refcnt now should be 1");
}

static void test_register_coveter(void *data)
{
	struct nurs_coveter *p;

	assertf(!plugin_coveter_get("min.coveter", "4"),
		"should fail to get unregistered coveter");
	assertf(!nurs_coveter_register(&coveter_def),
		"should success to legal minimal coveter");
	assertf(coveter_def.refcnt == 1,
		"coveter def's refcnt now should be 1");
	assertf(!plugin_coveter_get("min.coveter", NULL),
		"should fail to get invalid id consumer");
	assertf(p = plugin_coveter_get("min.coveter", "4"),
		"should success to get a registered coveter");
	assertf(coveter_def.refcnt == 2,
		"coveter def's refcnt now should be 2");
	assertf(p->refcnt == 1,
		"coveter refcnt now should be 1");
	assertf(p == plugin_coveter_get("min.coveter", "4"),
		"should get the same consumer");
	assertf(coveter_def.refcnt == 3,
		"coveter def's refcnt now should be 3");
	assertf(p->refcnt == 2,
		"coveter refcnt now should be 2");
	assertf(!plugin_coveter_put(p),
		"should success to put gotten coveter");
	assertf(!plugin_coveter_put(p),
		"should success to put gotten coveter");
	assertf(coveter_def.refcnt == 1,
		"coveter def's refcnt now should be 1");
}

static void test_create_stack1(void *context)
{
	struct nurs_producer *producer;
	struct nurs_ioset *ioset;
	const char *line = context;

	assertf(!stack_config_parser(line),
		"simple producer/consumer stack must be created");
	assertf(!stack_settle(4),
		"simple ioset must be created");

	assert(producer = plugin_producer_get("min.producer", "1"));
	assert(ioset = list_first_entry(&producer->iosets, struct nurs_ioset, list));

	assertf(ioset->len == 4,
		"simple ioset's len must be 4 - srcout, filterin, filterout, consumerin");
	assertf(ioset->size ==
		sizeof(struct nurs_ioset)
		+ sizeof(struct nurs_output) + sizeof(struct nurs_output_key)   * 2	/* PRODUCER_OKEY_0, 1 */
		+ sizeof(struct nurs_input)  + sizeof(struct nurs_output_key *) * 1	/* FILTER_IKEY_0    */
		+ sizeof(struct nurs_output) + sizeof(struct nurs_output_key)   * 1	/* FILTER_OKEY_2    */
		+ sizeof(struct nurs_input)  + sizeof(struct nurs_output_key *) * 2,	/* CONSUMER_IKEY_1, 2   */
		"simple ioset's size must be... ");

	assert(!plugin_producer_put(producer));
}

/* after test_stack1
 * stack - "1:min.producer, 2: min.filter  ,   3  :  min.consumer" */
static void test_key_producer1(void *context)
{
	struct nurs_producer *producer = plugin_producer_get("min.producer", "1");
	struct nurs_ioset *ioset
		= list_first_entry(&producer->iosets, struct nurs_ioset, list);
	struct nurs_input *filter_input, *consumer_input;
	struct nurs_output *producer_output, *filter_output;

	/* producer[0]	filter[1, 2]	consumer[3]
	 *  test.0  >	  test.0
	 *  test.1  >	  >	    >	 test.1
	 *		  test.2    >	 test.2
	 */
	producer_output = ioset_output(ioset, 0);
	filter_input = ioset_input(ioset, 1);
	filter_output = ioset_output(ioset, 2);
	consumer_input = ioset_input(ioset, 3);
	assertf(filter_input->keys[0] == &producer_output->keys[0],
		"filter test.0 == producer test.0");
	assertf(consumer_input->keys[0] == &producer_output->keys[1],
		"consumer test.1 == producer test.1");
	assertf(consumer_input->keys[1] == &filter_output->keys[0],
		"consumer test.2 == filter test.2");

	assert(!plugin_producer_put(producer));
}

static void test_unregister(void *context)
{
	assertf(!nurs_producer_unregister(&producer_def),
		"should success to unregister registered producer");
	assertf(!nurs_filter_unregister(&filter_def),
		"should success to unregister registered producer");
	assertf(!nurs_consumer_unregister(&consumer_def),
		"should success to unregister registered producer");
	assertf(!nurs_coveter_unregister(&coveter_def),
		"should success to unregister registered producer");
}

int main(int argc, char *argv[])
{
	log_settle(NULL, NURS_DEBUG, "\t", true, true);
	plugin_init();

	test_show_info(NULL);

	test_register_producer(NULL);
	test_register_filter(NULL);
	test_register_consumer(NULL);
	test_register_coveter(NULL);
	test_create_stack1("1:min.producer, 2:	min.filter,  3 : min.consumer");
	test_key_producer1(NULL);
	assertf(stack_unsettle() == 0,
		"producers must be destroyed");
	test_unregister(NULL);

	return EXIT_SUCCESS;
}
