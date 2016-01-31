#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nurs/nurs.h>
#include <nurs/list.h>

#include <internal.h>

#include "test.h"

enum {
	PRODUCER1_OKEY_0,
	PRODUCER1_OKEY_1,
	PRODUCER1_OKEY_MAX,
};
enum {
	PRODUCER2_OKEY_0,
	PRODUCER2_OKEY_1,
	PRODUCER2_OKEY_MAX,
};
enum {
	FILTER1_IKEY_0,
	FILTER1_IKEY_1,
	FILTER1_IKEY_MAX,
};
enum {
	FILTER1_OKEY_0,
	FILTER1_OKEY_1,
	FILTER1_OKEY_MAX,
};
enum {
	FILTER2_IKEY_0,
	FILTER2_IKEY_1,
	FILTER2_IKEY_MAX,
};
enum {
	FILTER2_OKEY_0,
	FILTER2_OKEY_1,
	FILTER2_OKEY_MAX,
};
enum {
	CONSUMER_IKEY_0,
	CONSUMER_IKEY_1,
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

static struct nurs_output_def producer1_output = {
	.len	= PRODUCER1_OKEY_MAX,
	.keys	= {
		[PRODUCER1_OKEY_0] = {
			.name = "key.11",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
		[PRODUCER1_OKEY_1] = {
			.name = "key.12",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
	},
};
static struct nurs_output_def producer2_output = {
	.len	= PRODUCER2_OKEY_MAX,
	.keys	= {
		[PRODUCER2_OKEY_0] = {
			.name = "key.21",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
		[PRODUCER2_OKEY_1] = {
			.name = "key.22",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
	},
};

static struct nurs_input_def filter1_input = {
	.len	= FILTER1_IKEY_MAX,
	.keys	= {
		[FILTER1_IKEY_0] = {
			.name	= "key.11",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
		[FILTER1_IKEY_1] = {
			.name	= "key.21",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
	},
};
static struct nurs_output_def filter1_output = {
	.len	= FILTER1_OKEY_MAX,
	.keys	= {
		[FILTER1_OKEY_0] = {
			.name	= "key.31",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
		[FILTER1_OKEY_1] = {
			.name	= "key.32",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
	},
};

static struct nurs_input_def filter2_input = {
	.len	= FILTER2_IKEY_MAX,
	.keys	= {
		[FILTER2_IKEY_0] = {
			.name	= "key.22",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
		[FILTER2_IKEY_1] = {
			.name	= "key.23",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
	},
};
static struct nurs_output_def filter2_output = {
	.len	= FILTER2_OKEY_MAX,
	.keys	= {
		[FILTER2_OKEY_0] = {
			.name	= "key.12",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
		[FILTER2_OKEY_1] = {
			.name	= "key.32",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
	},
};

static struct nurs_input_def consumer_input = {
	.len	= CONSUMER_IKEY_MAX,
	.keys	= {
		[CONSUMER_IKEY_0] = {
			.name	= "key.12",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
		[CONSUMER_IKEY_1] = {
			.name	= "key.31",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
	},
};

static struct nurs_producer_def producer1 = {
	.version	= VERSION,
	.name		= "producer1",
	.output_def	= &producer1_output,
	.organize	= producer_organize,
};
static struct nurs_producer_def producer2 = {
	.version	= VERSION,
	.name		= "producer2",
	.output_def	= &producer2_output,
	.organize	= producer_organize,
};

static struct nurs_filter_def filter1 = {
	.version	= VERSION,
	.name		= "filter1",
	.input_def	= &filter1_input,
	.output_def	= &filter1_output,
	.interp		= filter_interp,
};
static struct nurs_filter_def filter2 = {
	.version	= VERSION,
	.name		= "filter2",
	.input_def	= &filter2_input,
	.output_def	= &filter2_output,
	.interp		= filter_interp,
};

static struct nurs_consumer_def consumer = {
	.version	= VERSION,
	.name		= "consumer",
	.input_def	= &consumer_input,
	.interp		= consumer_interp,
};

static struct nurs_coveter_def coveter = {
	.version	= VERSION,
	.name		= "coveter",
	.interp		= consumer_interp,
};

/****
 * all key - type boolean, flags required
 *
 * producer1		filter1			consumer
 *   | key.11		key.11 | key.31		key.12 |
 *   | key.12		key.21 | key.32		key.31 |
 *
 *
 * producer2		filter2			coveter
 *   | key.21		key.22 | key.12
 *   | key.22		key.23 | key.32
 *
 * all combination will fail, p1:cs will success:
 *   - change consumer: key.31 (consumer_input.keys[1].flags) to any,
 *   and p2:f2:cs will success
 *     - change filter2: key.23 (filter2_input.keys[1].flags) to any
 */

static void test_register_plugins(void *data)
{
	assertf(!nurs_producer_register(&producer1),
		"should success to register legal producer1");
	assertf(!nurs_producer_register(&producer2),
		"should success to register legal producer2");
	assertf(!nurs_filter_register(&filter1),
		"should success to register legal filter1");
	assertf(!nurs_filter_register(&filter2),
		"should success to register legal filter2");
	assertf(nurs_consumer_register(&consumer) == 0,
		"should success to register legal consumer");
	assertf(nurs_coveter_register(&coveter) == 0,
		"should success to register legal coveter");
}

static void test_unregister_plugins(void *data)
{
	assertf(!nurs_producer_unregister(&producer1),
		"should success to unregister producer1");
	assertf(!nurs_producer_unregister(&producer2),
		"should success to unregister producer2");
	assertf(!nurs_filter_unregister(&filter1),
		"should success to unregister filter1");
	assertf(!nurs_filter_unregister(&filter2),
		"should success to unregister filter2");
	assertf(nurs_consumer_unregister(&consumer) == 0,
		"should success to unregister consumer");
	assertf(nurs_coveter_unregister(&coveter) == 0,
		"should success to unregister coveter");
}

static void test_fail_stacks(void *data)
{
	char **line, *lines[] = {
		"p1:producer1",
		"f1:filter1",
		"cs:consumer",
		"p1:producer1, f1:filter1",
		"f1:filter1, cs:consumer",
		"p1:producer1, cs:consumer",
		"p2:producer2, cs:consumer",
		"p1:producer1, f1:filter1, cs:consumer",
		"p1:producer1, f2:filter2, cs:consumer",
		"p2:producer2, f1:filter1, cs:consumer",
		"p2:producer2, f2:filter2, cs:consumer",
		NULL,
	};
	struct nurs_plugin_def **def, *defs[] = {
		(struct nurs_plugin_def *)&producer1,
		(struct nurs_plugin_def *)&producer1,
		(struct nurs_plugin_def *)&filter1,
		(struct nurs_plugin_def *)&filter2,
		(struct nurs_plugin_def *)&consumer,
		(struct nurs_plugin_def *)&coveter,
		NULL,
	};

	for (line = lines; *line; line++)
		assertf(stack_config_parser(*line),
			"should fail to parse stack: %s", *line);

	for (def = defs; *def; def++)
		assertf((*def)->refcnt == 1,
			"should def: %s refcnt be 1", (*def)->name);
}

/****
 * producer1
 *   | key.11		consumer
 *   | key.12	-->	key.12   |
 *			(key.31) |
 *
 *
 * producer2
 *   | key.21		filter2			consumer
 *   | key.22	-->	key.22   | key.12 -->	key.12   |
 *			(key.23) | key.32	(key.31) |
 */
static void test_consumer(void *data)
{
	struct nurs_producer *producer;
	struct nurs_ioset *ioset, *ioset2;
	struct nurs_stack *stack;
	struct nurs_stack_element *element;
	struct nurs_input *input;
	struct nurs_output *output;
	int n;

	consumer_input.keys[CONSUMER_IKEY_1].flags = NURS_IKEY_F_ANY;
	assertf(!stack_config_parser("p1:producer1, cs:consumer"),
		"should success to parse adjusted consumer stack #1");

	filter2_input.keys[FILTER2_IKEY_1].flags = NURS_IKEY_F_ANY;
	assertf(!stack_config_parser("p2:producer2, f2:filter2, cs:consumer"),
		"should success to parse adjusted consumer stack #2");

	assertf(!stack_settle(16),
		"should success to settle consumer stacks");

	/*
	 * p1:producer, cs:consumer
	 */
	assertf(producer = plugin_producer_get("producer1", "p1"),
		"should success to get p1:producer1");

	assertf(producer->nstacks == 1,
		"should #stacks == 1");

	n = 0; list_for_each_entry(ioset, &producer->iosets, list) n++;
	assertf(n == 16, "should be #iosets == 16");

	stack = list_entry(producer->stacks.next, struct nurs_stack, list);
	n = 0; list_for_each_entry(element, &stack->elements, list) n++;
	assertf(n == 1, "should be p1.#elements == 1");

	element = list_entry(stack->elements.next, struct nurs_stack_element, list);
	assertf(element->plugin->def == (struct nurs_plugin_def *)&consumer,
		"should next of p1 of plugin be the consumer");

	assertf(ioset = ioset_get(producer),
		"shoule success to get ioset");
	n = 0; list_for_each_entry(ioset2, &producer->iosets, list) n++;
	assertf(n == 15, "should #ioset == 15 after get one");

	output = ioset->base;
	input = ioset_input(ioset, element->idx);
	assertf(input->keys[0] == &output->keys[1],
		"should input[0] of cs be output[1] of p1");

	assertf(!nurs_input_is_valid(input, 0),
		"should not input[0] is valid");
	assertf(!nurs_input_is_valid(input, 1),
		"should not input[1] is valid");
	/*
	 * assertf(nurs_output_set_u8(output, 1, 1),
	 *	"should success failt set output[1] (uint8_t)1");
	 * assertf(!nurs_input_is_valid(input, 0),
	 *	"should input[0] is not valid");
	 */
	assertf(!nurs_output_set_bool(output, 1, true),
		"should success to set output[1] true");
	assertf(nurs_input_is_valid(input, 0),
		"should input[0] is valid");
	assertf(!nurs_input_is_valid(input, 1),
		"should not input[1] is valid");
	assertf(nurs_input_bool(input, 0),
		"should input[0] is true");

	assertf(!ioset_clear(ioset),
		"should success to clear ioset");
	assertf(!nurs_input_is_valid(input, 0),
		"should not input[0] is valid");
	assertf(!nurs_input_is_valid(input, 1),
		"should not input[1] is valid");
	assertf(!nurs_output_set_bool(output, 1, false),
		"should success to set output[1] true");
	assertf(nurs_input_is_valid(input, 0),
		"should input[0] is valid");
	assertf(!nurs_input_is_valid(input, 1),
		"should not input[1] is valid");
	assertf(!nurs_input_bool(input, 0),
		"should input[0] is true");

	assertf(!ioset_put(producer, ioset),
		"should success to put ioset");
	n = 0; list_for_each_entry(ioset2, &producer->iosets, list) n++;
	assertf(n == 16, "should #ioset == 16 after put one");

	assertf(!ioset_destroy(producer),
		"should success to destroy ioset");
	n = 0; list_for_each_entry(ioset2, &producer->iosets, list) n++;
	assertf(n == 0, "should #ioset == 0 after destroy it");

	assertf(!plugin_producer_put(producer),
		"should success to put p1:producer1");

	/* XXX: no - p2:producer2, f2:filter2, cs:consumer */
	assertf(!stack_unsettle(),
		"should success to unsettle stacks");
	filter2_input.keys[FILTER2_IKEY_1].flags = NURS_IKEY_F_REQUIRED;
	consumer_input.keys[CONSUMER_IKEY_1].flags = NURS_IKEY_F_REQUIRED;
}

/****
 * producer1		filter1			coveter
 *   | key.11		key.11   |		key.11   |
 *   | key.12		         |		key.12   |
 *			(key.21) |	 	         |
 *			         | key.31	key.31   |
 *			         | key.32	key.32   |
 *						         |
 *						         |
 * producer2		filer2			         |
 *   | key.21			 |		key.21   |
 *   | key.22		key.22	 |		key.22   |
 *			(key.23) |		         |
 *				 | key.12	(key.12  | dup)
 *				 | key.32	(key.32  | dup)
 *
 *
 */
static volatile sig_atomic_t ioset_block = 0;
static struct nurs_producer *blocking_producer;
static struct nurs_ioset *blocking_ioset;
static void t_ioset_get_block(int signum)
{
	assertf(!ioset_put(blocking_producer, blocking_ioset),
		"should success to put blocking ioset");
	ioset_block = 1;
}

static int t_input_index(struct nurs_input *input, const char *key)
{
	int i;
	const char *s;

	for (i = 0; i < input->len; i++) {
		if (!(s = nurs_input_name(input, (uint8_t)i)))
			continue;
		if (!strcmp(s , key))
			return i;
	}
	return -1;
}

static void test_coveter(void *data)
{
	struct nurs_producer *p1, *p2;
	struct nurs_ioset *ioset11, *ioset12, *ioset21, *ioset22, *tmpio;
	struct nurs_stack *stack;
	struct nurs_stack_element *f1e, *f2e, *cv1e, *cv2e;
	struct nurs_input *f1in, *f2in, *cv1in, *cv2in, *tmpi;
	struct nurs_output *p1out, *p2out, *f1out, *f2out;
	int i11, i12, i21, i22, i31, i32;
	int n;

	filter1_input.keys[FILTER1_IKEY_1].flags = NURS_IKEY_F_ANY;
	filter2_input.keys[FILTER2_IKEY_1].flags = NURS_IKEY_F_ANY;

	assertf(!stack_config_parser("p1:producer1, f1:filter1, cv:coveter"),
		"should success to parse adjusted coveter stack #1");
	assertf(!stack_config_parser("p2:producer2, f2:filter2, cv:coveter"),
		"should success to parse adjusted coveter stack #2");
	assertf(!stack_settle(2),
		"should success to settle coveter stacks");

	assertf(p1 = plugin_producer_get("producer1", "p1"),
		"should success to get p1:prodicer1");
	assertf(p2 = plugin_producer_get("producer2", "p2"),
		"should success to get p2:producer2");

	n = 0; list_for_each_entry(ioset11, &p1->iosets, list) n++;
	assertf(n == 2, "should be #iosets of p1 == 2");
	n = 0; list_for_each_entry(ioset21, &p2->iosets, list) n++;
	assertf(n == 2, "should be #iosets of p2 == 2");

	n = 0; list_for_each_entry(stack, &p1->stacks, list) n++;
	assertf(n == 1, "should be #stacks of p1 == 1");
	n = 0; list_for_each_entry(stack, &p2->stacks, list) n++;
	assertf(n == 1, "should be #stacks of p2 == 1");

	stack = list_entry(p1->stacks.next, struct nurs_stack, list);
	n = 0; list_for_each_entry(cv1e, &stack->elements, list) n++;
	assertf(n == 2, "should be p1.#elements == 2");
	f1e = list_entry(stack->elements.next, struct nurs_stack_element, list);
	cv1e = list_entry(stack->elements.prev, struct nurs_stack_element, list);

	stack = list_entry(p2->stacks.next, struct nurs_stack, list);
	n = 0; list_for_each_entry(cv2e, &stack->elements, list) n++;
	assertf(n == 2, "should be p2.#elements == 2");
	f2e = list_entry(stack->elements.next, struct nurs_stack_element, list);
	cv2e = list_entry(stack->elements.prev, struct nurs_stack_element, list);

	assertf(ioset11 = ioset_get(p1),
		"should success to get ioset of p1");
	assertf(ioset12 = ioset_get(p1),
		"should success to get ioset of p1");
	assertf(ioset21 = ioset_get(p2),
		"should success to get ioset of p2");
	assertf(ioset22 = ioset_get(p2),
		"should success to get ioset of p2");

	/* should block ioset_get(p[12]) */
	signal(SIGALRM, t_ioset_get_block);
	blocking_producer = p1;
	blocking_ioset = ioset11;
	ioset_block = 0;
	alarm(1);
	assertf(tmpio = ioset_get(p1),
		"should success to get ioset of p1");
	assertf(ioset_block, "should be blocked to get p1 ioset");
	assertf(tmpio == ioset11,
		"should getting again p1 ioset be same as previous");

	blocking_producer = p2;
	blocking_ioset = ioset21;
	ioset_block = 0;
	alarm(1);
	assertf(tmpio = ioset_get(p2),
		"should success to get ioset of p2");
	assertf(ioset_block, "should be blocked to get p2 ioset");
	assertf(tmpio == ioset21,
		"should getting again p2 ioset be same as previous");

	p1out = ioset11->base;
	p2out = ioset21->base;
	assertf(f1in = ioset_input(ioset11, f1e->idx),
		"should success to get filter1 input of stack#1");
	assertf(f1out = ioset_output(ioset11, f1e->odx),
		"should success to get filter1 output of stack#1");
	assertf(f2in = ioset_input(ioset21, f2e->idx),
		"should success to get filter2 input of stack#2");
	assertf(f2out = ioset_output(ioset21, f2e->odx),
		"should success to get filter2 output of stack#2");
	assertf(cv1in = ioset_input(ioset11, cv1e->idx),
		"should success to get coveter input of stack#1");
	assertf(cv1in->len == 6, /* key 11, 12, 21, 22, 31, 32 */
		"should cv1 input len == 6");
	assertf(cv2in = ioset_input(ioset21, cv2e->idx),
		"should success to get coveter input of stack#2");
	assertf(cv2in->len == 6, "should cv2 input len == 6");

	assertf((i11 = t_input_index(cv1in, "key.11")) >= 0,
		"should success to find key.11 in cv1 input");
	assertf((i12 = t_input_index(cv1in, "key.12")) >= 0,
		"should success to find key.12 in cv1 input");
	assertf(t_input_index(cv1in, "key.21") < 0,
		"should fail to find key.21 in cv1 input");
	assertf(t_input_index(cv1in, "key.22") < 0,
		"should fail to find key.22 in cv1 input");
	assertf((i31 = t_input_index(cv1in, "key.31")) >= 0,
		"should success to find key.31 in cv1 input");
	assertf((i32 = t_input_index(cv1in, "key.32")) >= 0,
		"should success to find key.32 in cv1 input");

	assertf(t_input_index(cv2in, "key.11") < 0,
		"should fail to find key.11 in cv2 input");
	assertf((i12 == t_input_index(cv2in, "key.12")) >= 0,
		"should key.12 in cv1 and cv2 be the same");
	assertf((i21 = t_input_index(cv2in, "key.21")) >= 0,
		"should success to find key.21 in cv2 input");
	assertf((i22 = t_input_index(cv2in, "key.22")) >= 0,
		"should success to find key.22 in cv2 input");
	assertf(t_input_index(cv2in, "key.31") < 0,
		"should fail to find key.31 in cv2 input");
	assertf((i32 == t_input_index(cv2in, "key.32")) >= 0,
		"should key.32 in cv1 and cv2 be the same");

	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i11),
		"should not cv1 key.11 is valid");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i12),
		"should not cv1 key.12 is valid");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i21),
		"should not cv1 key.21 is valid");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i22),
		"should not cv1 key.22 is valid");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i31),
		"should not cv1 key.31 is valid");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i32),
		"should not cv1 key.31 is valid");

	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i11),
		"should not cv2 key.11 is valid");
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i12),
		"should not cv2 key.12 is valid");
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i21),
		"should not cv2 key.21 is valid");
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i22),
		"should not cv2 key.22 is valid");
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i31),
		"should not cv2 key.31 is valid");
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i32),
		"should not cv2 key.31 is valid");

	assertf(!nurs_output_set_bool(p1out, 0, true),
		"should success to set p1 key.11 true");
	assertf(!nurs_output_set_bool(p2out, 0, true),
		"should success to set p2 key.21 true");

	assertf(nurs_input_is_valid(cv1in, (uint8_t)i11),
		"should cv1 key.11 is valid");
	assertf(nurs_input_bool(cv1in, (uint8_t)i11),
		"should cv1 key.11 value is true");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i12),
		"should not cv1 key.12 is valid");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i21),
		"should not cv1 key.21 is valid");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i22),
		"should not cv1 key.22 is valid");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i31),
		"should not cv1 key.31 is valid");
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i32),
		"should not cv1 key.31 is valid");

	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i11),
		"should not cv2 key.11 is valid");
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i12),
		"should not cv2 key.12 is valid");
	assertf(nurs_input_is_valid(cv2in, (uint8_t)i21),
		"should cv2 key.21 is valid");
	assertf(nurs_input_bool(cv2in, (uint8_t)i21),
		"should cv2 key.21 value is true");
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i22),
		"should not cv2 key.22 is valid");
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i31),
		"should not cv2 key.31 is valid");
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i32),
		"should not cv2 key.31 is valid");

	tmpi = cv1in;
	cv1in = ioset_input(ioset12, cv1e->idx);
	assertf(!nurs_input_is_valid(cv1in, (uint8_t)i11),
		"should not cv1 key.11 in another ioset is valid");
	cv1in = tmpi;
	tmpi = cv2in;
	cv2in = ioset_input(ioset22, cv2e->idx);
	assertf(!nurs_input_is_valid(cv2in, (uint8_t)i21),
		"should not cv2 key.21 in another ioset is valid");
	cv2in = tmpi;

	assertf(!plugin_producer_put(p1),
		"should success to put p1:producer1");
	assertf(!plugin_producer_put(p2),
		"should success to put p2:producer2");

	assertf(!stack_unsettle(),
		"should success to unsettle stacks");
}

int main(int argc, char *argv[])
{
	log_settle(NULL, NURS_DEBUG, "\t", true, true);
	plugin_init();

	test_register_plugins(NULL);
	test_fail_stacks(NULL);
	test_consumer(NULL);
	test_coveter(NULL);
	test_unregister_plugins(NULL);

	return EXIT_SUCCESS;
}
