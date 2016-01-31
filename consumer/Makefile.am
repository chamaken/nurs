AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include \
	${LIBNETFILTER_ACCT_CFLAGS} \
        ${LIBNETFILTER_CONNTRACK_CFLAGS} \
	${LIBNETFILTER_LOG_CFLAGS} \
	${LIBNFTNL_CFLAGS}

AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = nurs_consumer_XML.la

nurs_consumer_XML_la_SOURCES = xml.c
nurs_consumer_XML_la_LIBADD  = ${LIBNETFILTER_LOG_LIBS} \
			       ${LIBNETFILTER_CONNTRACK_LIBS} \
			       ${LIBNETFILTER_ACCT_LIBS} \
			       ${LIBNFTNL_LIBS}
nurs_consumer_XML_la_LDFLAGS = -avoid-version -module
