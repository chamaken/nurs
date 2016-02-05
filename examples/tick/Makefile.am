AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = nurs_producer_TICK.la

nurs_producer_TICK_la_SOURCES = tick.c
nurs_producer_TICK_la_LDFLAGS = -avoid-version -module

EXTRA_DIST = consumer.py consumer2.py \
	consumer_py.json.in \
	producer.go consumer.go \
	producer_go.json.in consumer_go.json.in \
	nursd1.conf.in nursd2.conf.in
noinst_DATA = consumer_py.json producer_go.json consumer_go.json \
	nursd1.conf nursd2.conf
if HAVE_GO
noinst_DATA += producer.gso consumer.gso
endif

include $(top_srcdir)/examples.inc
