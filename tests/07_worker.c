#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <nurs/nurs.h>
#include <nurs/list.h>

#include <internal.h>

#include "test.h"

enum {
	PRODUCER_OKEY_0,
	PRODUCER_OKEY_1,
	PRODUCER_OKEY_MAX,
};

enum {
	CONSUMER_IKEY_0,
	CONSUMER_IKEY_1,
	CONSUMER_IKEY_MAX,
};

static enum nurs_return_t
producer_organize(struct nurs_producer *producer)
{
	return NURS_RET_OK;
}

static enum nurs_return_t
consumer_ok_interp(const struct nurs_plugin *plugin,
		   const struct nurs_input *input)
{
	return NURS_RET_OK;
}

static enum nurs_return_t
consumer_error_interp(const struct nurs_plugin *plugin,
		      const struct nurs_input *input)
{
	return NURS_RET_ERROR;
}

static struct nurs_output_def producer_output = {
	.len	= PRODUCER_OKEY_MAX,
	.keys	= {
		[PRODUCER_OKEY_0] = {
			.name = "key.1",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[PRODUCER_OKEY_1] = {
			.name = "key.2",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
	},
};

static struct nurs_input_def consumer_input = {
	.len	= CONSUMER_IKEY_MAX,
	.keys	= {
		[CONSUMER_IKEY_0] = {
			.name = "key.1",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
		[CONSUMER_IKEY_1] = {
			.name = "key.2",
			.type	= NURS_KEY_T_BOOL,
			.flags	= NURS_IKEY_F_REQUIRED,
		},
	},
};

static struct nurs_producer_def producer1 = {
	.version	= VERSION,
	.name		= "producer1",
	.output_def	= &producer_output,
	.organize	= producer_organize,
};

static struct nurs_producer_def producer2 = {
	.version	= VERSION,
	.name		= "producer2",
	.output_def	= &producer_output,
	.organize	= producer_organize,
};

static struct nurs_consumer_def ok_consumer = {
	.version	= VERSION,
	.name		= "ok consumer",
	.input_def	= &consumer_input,
	.interp		= consumer_ok_interp,
};

static struct nurs_consumer_def error_consumer = {
	.version	= VERSION,
	.name		= "error consumer",
	.input_def	= &consumer_input,
	.interp		= consumer_error_interp,
};

static void test_init(void *data)
{
	char *line;

	assertf(!nurs_producer_register(&producer1),
		"should success to register legal producer1");
	assertf(!nurs_producer_register(&producer2),
		"should success to register legal producer2");
	assertf(!nurs_consumer_register(&ok_consumer),
		"should success to register legal ok consumer");
	assertf(!nurs_consumer_register(&error_consumer),
		"should success to register legal error consumer");
	assertf(!workers_start(2),
		"should success to start workers");

	line = "p1:producer1, oc:ok consumer";
	assertf(!stack_config_parser(line),
		"should success to parse stack: %s", line);

	line = "p2:producer2, ec:error consumer";
	assertf(!stack_config_parser(line),
		"should success to parse stack: %s", line);

	assertf(!stack_settle(2),
		"should success to settle consumer stacks");
}

static void test_fini(void *data)
{
	assertf(!stack_unsettle(),
		"should success to settle consumer stacks");
	assertf(!workers_stop(),
		"should success to start workers");
	assertf(!nurs_producer_unregister(&producer1),
		"should success to unregister legal producer1");
	assertf(!nurs_producer_unregister(&producer2),
		"should success to unregister legal producer2");
	assertf(!nurs_consumer_unregister(&ok_consumer),
		"should success to unregister legal ok consumer");
	assertf(!nurs_consumer_unregister(&error_consumer),
		"should success to unregister legal error consumer");
}


static void test_basic(void *data)
{
	struct nurs_worker *worker;

	assertf(worker = worker_get(),
		"should success to get worker");
	assertf(!worker_put(worker),
		"should success to put worker");
	assertf(!workers_suspend(),
		"should success to suspend workers");
	assertf(!workers_resume(),
		"should success to resume workers");
}

static volatile sig_atomic_t workers_block;
static void t_worker_unblock_resume(int signum)
{
	assertf(!workers_resume(),
		"should success to resume workers");
	workers_block = 1;
}

static struct nurs_worker *signal_worker;
static void t_worker_unblock_put(int signum)
{
	assertf(!worker_put(signal_worker),
		"should success to put worker in suspended");
	workers_block = 1;
}

static void test_suspend(void *data)
{
	struct nurs_worker *worker;

	signal(SIGALRM, t_worker_unblock_resume);
	workers_block = 0;
	alarm(1);
	assertf(!workers_suspend(),
		"should success to suspend workers #1");
	assertf(worker = worker_get(),
		"should success to get worker");
	assertf(workers_block,
		"should be blocked to get worker");

	signal(SIGALRM, t_worker_unblock_put);
	signal_worker = worker;
	workers_block = 0;
	alarm(1);
	assertf(!workers_suspend(),
		"should success to suspend workers #2");
	assertf(!workers_resume(),
		"should success to resume workers");

	assertf(worker = worker_get(),
		"should success to get worker after suspend/resume");
	assertf(!worker_put(worker),
		"should success to put worker after suspend/resume");
}

static void test_get_full(void *data)
{
	struct nurs_worker *worker1, *worker2;

	assertf(worker1 = worker_get(),
		"should success to get worker1");
	assertf(worker2 = worker_get(),
		"should success to get worker2");

	signal(SIGALRM, t_worker_unblock_put);
	signal_worker = worker2;
	workers_block = 0;
	alarm(1);
	assertf(worker_get() == worker2,
		"should be got same worker2");

	assertf(!worker_put(worker1),
		"should success to put worker1");
	assertf(!worker_put(worker2),
		"should success to put worker2");
}

static void confirm_2_workers(void)
{
	struct nurs_worker *w1, *w2;

	assertf(w1 = worker_get(),
		"should success to get w1 without blocking");
	assertf(w2 = worker_get(),
		"should success to get w2 without blocking");
	assertf(!worker_put(w1),
		"should success to put w1");
	assertf(!worker_put(w2),
		"should success to put w2");
}

static void test_producer(void *data)
{
	struct nurs_producer *p1, *p2;
	struct nurs_output *output;

	assertf(p1 = plugin_producer_get("producer1", "p1"),
		"should success to get p1:producer1");
	assertf(p2 = plugin_producer_get("producer2", "p2"),
		"should success to get p2:producer2");

	confirm_2_workers();

	assertf(output = nurs_get_output(p1),
		"should success to get p1 output");
	assertf(!nurs_output_set_bool(output, 0, true),
		"should success to set p1 key.0 true");
	assertf(!nurs_output_set_bool(output, 1, false),
		"should success to set p1 key.1 false");
	assertf(nurs_propagate(p1, output) == NURS_RET_OK,
		"should success to propagate p1 output");
	usleep(10000);
	assertf(!(output->keys[0].flags & NURS_KEY_F_VALID),
		"should not key.0 is valid after propagate");
	assertf(!(output->keys[1].flags & NURS_KEY_F_VALID),
		"should not key.1 is valid after propagate");
	assertf(!output->keys[1].b,
		"should key.1 be false after propagate");

	confirm_2_workers();

	assertf(output = nurs_get_output(p2),
		"should success to get p2 output");
	assertf(!nurs_output_set_bool(output, 0, true),
		"should success to set p2 key.0 true");
	assertf(!nurs_output_set_bool(output, 1, false),
		"should success to set p2 key.1 false");
	assertf(nurs_propagate(p2, output) == NURS_RET_OK,
		"should success to propagate p2 output");
	usleep(10000);
	assertf(!(output->keys[0].flags & NURS_KEY_F_VALID),
		"should not key.0 is valid after propagate");
	assertf(!(output->keys[1].flags & NURS_KEY_F_VALID),
		"should not key.1 is valid after propagate");
	assertf(!output->keys[1].b,
		"should key.1 be false after propagate");

	confirm_2_workers();

	assertf(!plugin_producer_put(p1),
		"should success to put p1:producer1");
	assertf(!plugin_producer_put(p2),
		"should success to put p2:producer2");
}

int main(int argc, char *argv[])
{
	log_settle(NULL, NURS_DEBUG, "\t", true, true);
	plugin_init();

	test_init(NULL);
	test_basic(NULL);
	test_suspend(NULL);
	test_get_full(NULL);
	test_producer(NULL);
	test_fini(NULL);

	return EXIT_SUCCESS;
}
