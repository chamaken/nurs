AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include \
	      -DNURS_CONFIGFILE="\"$(sysconfdir)/nurs.conf\"" \
	      -DNURS_DEFAULT_LOGFNAME="\"$(localstatedir)/log/nurs.log\""
AM_CFLAGS = ${regular_CFLAGS}

nurs_SOURCES	= internal.h config.c fd.c key.c main.c misc.c worker.c \
		stack.c json_plugin.c ioset.c plugin.c plugin_producer.c \
		plugin_filter.c plugin_consumer.c plugin_coveter.c

sbin_PROGRAMS	= nursd

nursd_SOURCES	= ${nurs_SOURCES} # nurs.map
nursd_LDADD	= ${libdl_LIBS} ${libpthread_LIBS} ${LIBPYTHON_LIBS} ${JANSSON_LIBS}
# nurs_LDFLAGS	= -export-dynamic -export-symbols-regex '^nurs_.*'
nursd_LDFLAGS	= -export-dynamic # -Wl,--version-script=$(srcdir)/nurs.map

noinst_LTLIBRARIES	= libnurs.la
libnurs_la_SOURCES	= ${nurs_SOURCES} # libnurs.map
# libulog_la_CFLAGS	= ${AM_CPPFLAGS} ${AM_CFLAGS} # Objects-created-both-with-libtool-and-without
libnurs_la_CFLAGS	= -DNURS_TEST_LIB=1
libnurs_la_LDFLAGS	= -export-dynamic # -Wl,--version-script=$(srcdir)/libnurs.map -version-info $(VERSION)
