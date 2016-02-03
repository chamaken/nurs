AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = nurs_producer_NFCTST.la
nurs_producer_NFCTST_la_SOURCES = nfctst.c
nurs_producer_NFCTST_la_LDFLAGS = -avoid-version -module
nurs_producer_NFCTST_la_CFLAGS  = ${AM_CFLAGS} ${LIBMNL_CFLAGS}
nurs_producer_NFCTST_la_LIBADD  = $(LIBMNL_LIBS) $(top_srcdir)/util/libutil.la

if HAVE_LNFCT2
pkglib_LTLIBRARIES += nurs_producer_NFCT2.la
nurs_producer_NFCT2_la_SOURCES = nfct2.c nfnl_common.c
nurs_producer_NFCT2_la_LDFLAGS = -avoid-version -module
nurs_producer_NFCT2_la_CFLAGS  = ${AM_CFLAGS} ${LIBMNL_CFLAGS} ${LIBNETFILTER_CONNTRACK_CFLAGS}
nurs_producer_NFCT2_la_LIBADD  = $(LIBMNL_LIBS) $(LIBNETFILTER_CONNTRACK_LIBS) $(top_srcdir)/util/libutil.la
endif

if HAVE_LNFCT
pkglib_LTLIBRARIES += nurs_producer_NFCT.la
nurs_producer_NFCT_la_SOURCES  = nfct.c nfct_hash.c nfct_hash.h nfct_jhash.h
nurs_producer_NFCT_la_LDFLAGS  = -avoid-version -module
nurs_producer_NFCT_la_CFLAGS   = ${AM_CFLAGS} ${LIBMNL_CFLAGS} ${LIBNETFILTER_CONNTRACK_CFLAGS}
nurs_producer_NFCT_la_LIBADD   = $(LIBMNL_LIBS) $(LIBNETFILTER_CONNTRACK_LIBS) $(top_srcdir)/util/libutil.la
endif

if HAVE_LNFLOG
pkglib_LTLIBRARIES += nurs_producer_NFLOG.la
nurs_producer_NFLOG_la_SOURCES = nflog.c nfnl_common.c
nurs_producer_NFLOG_la_LDFLAGS = -avoid-version -module
nurs_producer_NFLOG_la_CFLAGS  = ${AM_CFLAGS} ${LIBMNL_CFLAGS} ${LIBNETFILTER_LOG_CFLAGS}
nurs_producer_NFLOG_la_LIBADD  = $(LIBMNL_LIBS) $(LIBNETFILTER_LOG_LIBS) $(top_srcdir)/util/libutil.la
endif

if HAVE_LNFT
pkglib_LTLIBRARIES += nurs_producer_NFT.la
nurs_producer_NFT_la_SOURCES = nft.c
nurs_producer_NFT_la_LDFLAGS = -avoid-version -module
nurs_producer_NFT_la_CFLAGS  = ${AM_CFLAGS} ${LIBMNL_CFLAGS} ${LIBNFTNL_CFLAGS}
nurs_producer_NFT_la_LIBADD  = $(LIBMNL_LIBS) $(LIBNFTNL_LIBS) $(top_srcdir)/util/libutil.la
endif

if HAVE_LNFQ
pkglib_LTLIBRARIES += nurs_producer_NFQ.la
nurs_producer_NFQ_la_SOURCES = nfq_common.c nfq.c nfnl_common.c
nurs_producer_NFQ_la_LDFLAGS = -avoid-version -module
nurs_producer_NFQ_la_CFLAGS  = ${AM_CFLAGS} ${LIBMNL_CFLAGS} ${LIBNETFILTER_QUEUE_CFLAGS}
nurs_producer_NFQ_la_LIBADD  = $(LIBMNL_LIBS) $(LIBNETFILTER_QUEUE_LIBS) $(top_srcdir)/util/libutil.la
pkglib_LTLIBRARIES += nurs_producer_MTNFQ.la
nurs_producer_MTNFQ_la_SOURCES = nfq_common.c mtnfq.c nfnl_common.c
nurs_producer_MTNFQ_la_LDFLAGS = -avoid-version -module
nurs_producer_MTNFQ_la_CFLAGS  = ${AM_CFLAGS} ${LIBMNL_CFLAGS} ${LIBNETFILTER_QUEUE_CFLAGS}
nurs_producer_MTNFQ_la_LIBADD  = $(LIBMNL_LIBS) $(LIBNETFILTER_QUEUE_LIBS) $(top_srcdir)/util/libutil.la
endif

if HAVE_LNFACCT
pkglib_LTLIBRARIES += nurs_producer_NFACCT.la
nurs_producer_NFACCT_la_SOURCES = nfacct.c
nurs_producer_NFACCT_la_LDFLAGS = -avoid-version -module
nurs_producer_NFACCT_la_CFLAGS  = ${AM_CFLAGS} ${LIBMNL_CFLAGS} ${LIBNETFILTER_ACCT_CFLAGS}
nurs_producer_NFACCT_la_LIBADD  = $(LIBMNL_LIBS) $(LIBNETFILTER_ACCT_LIBS) $(top_srcdir)/util/libutil.la
endif
