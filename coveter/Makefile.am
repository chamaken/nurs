AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include ${LIBNETFILTER_CONNTRACK_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES =

if HAVE_LNFCT
pkglib_LTLIBRARIES += nurs_coveter_NFLOW9.la
nurs_coveter_NFLOW9_la_SOURCES = nflow9.c
nurs_coveter_NFLOW9_la_LDFLAGS = -avoid-version -module
nurs_coveter_NFLOW9_la_LIBADD  = $(LIBNETFILTER_CONNTRACK_LIBS) $(top_srcdir)/util/libutil.la

pkglib_LTLIBRARIES += nurs_coveter_IPFIX.la
nurs_coveter_IPFIX_la_SOURCES = ipfix.c
nurs_coveter_IPFIX_la_LDFLAGS = -avoid-version -module
nurs_coveter_IPFIX_la_LIBADD  = $(LIBNETFILTER_CONNTRACK_LIBS) $(top_srcdir)/util/libutil.la
endif
