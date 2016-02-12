AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = nurs_producer_TICK.la

nurs_producer_TICK_la_SOURCES = tick.c
nurs_producer_TICK_la_LDFLAGS = -avoid-version -module

EXTRA_DIST = consumer.py consumer2.py \
	consumer_py.json.in \
	producer.go consumer.go \
	consumer_go.json.in nursd.conf.in
noinst_DATA = consumer_py.json consumer_go.json nursd.conf

if HAVE_GO
noinst_DATA += producer.gso consumer.gso
endif

include $(top_srcdir)/examples.inc
