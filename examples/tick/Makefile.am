AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = nurs_producer_TICK.la

nurs_producer_TICK_la_SOURCES = tick.c
nurs_producer_TICK_la_LDFLAGS = -avoid-version -module

noinst_DATA = nursd1.conf nursd2.conf consumer_py.json
if HAVE_GO
noinst_DATA += producer_go.json producer.gso consumer_go.json consumer.gso
endif

include $(top_srcdir)/examples.inc
