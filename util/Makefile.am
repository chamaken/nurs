AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

noinst_LTLIBRARIES	= libutil.la
libutil_la_SOURCES	= ipfix.c

if HAVE_NLMMAP
libutil_la_SOURCES	+= ring.c
endif
