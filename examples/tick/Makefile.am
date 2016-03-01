AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = nurs_producer_TICK.la

nurs_producer_TICK_la_SOURCES = tick.c
nurs_producer_TICK_la_LDFLAGS = -avoid-version -module

EXTRA_DIST = consumer.py consumer2.py \
	consumer_py.json.in \
	producer.go consumer.go \
	consumer_go.json.in \
	consumer_rs.json.in \
	py.conf.in go.conf.in rs.conf.in
noinst_DATA = consumer_py.json consumer_go.json consumer_rs.json \
	py.conf go.conf rs.conf

if HAVE_GO
noinst_DATA += producer.gso consumer.gso
endif

include $(top_srcdir)/examples.inc
