AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = nurs_producer_LISTEN.la nurs_consumer_LOG.la

nurs_producer_LISTEN_la_SOURCES = listen.c
nurs_producer_LISTEN_la_LDFLAGS = -avoid-version -module
nurs_producer_LISTEN_la_LIBADD  = ../../util/libutil.la

nurs_consumer_LOG_la_SOURCES = log.c
nurs_consumer_LOG_la_LDFLAGS = -avoid-version -module

EXTRA_DIST = listen.py \
	echo.conf.in py.conf.in listen_py.json.in \
	rs.conf.in go.conf.in \
	src/listen.rs Cargo.toml.in \
	listen.go
noinst_DATA = echo.conf py.conf rs.conf go.conf listen_py.json

if HAVE_GO
noinst_DATA += listen.gso
endif

if HAVE_RUST
noinst_DATA += target/debug/liblisten.so \
	       Cargo.toml Cargo.lock

Cargo.toml: Cargo.toml.in
	cp $< $@

target/debug/liblisten.so: Cargo.toml src/listen.rs
	cargo build --manifest-path $<

endif


include $(top_srcdir)/examples.inc
