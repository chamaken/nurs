AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = \
	nurs_filter_TIMECONV.la \
	nurs_filter_PACKICMP.la \
	nurs_filter_MARKIF.la

nurs_filter_TIMECONV_la_SOURCES = timeconv.c
nurs_filter_TIMECONV_la_LDFLAGS = -avoid-version -module

nurs_filter_PACKICMP_la_SOURCES = packicmp.c
nurs_filter_PACKICMP_la_LDFLAGS = -avoid-version -module

nurs_filter_MARKIF_la_SOURCES	= markif.c
nurs_filter_MARKIF_la_LDFLAGS	= -avoid-version -module
