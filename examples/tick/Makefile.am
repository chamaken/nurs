AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = nurs_producer_TICK.la

nurs_producer_TICK_la_SOURCES = tick.c
nurs_producer_TICK_la_LDFLAGS = -avoid-version -module

EXTRA_DIST = consumer.py consumer2.py \
	consumer_py.json.in \
	producer.go consumer.go \
	consumer_go.json.in \
	producer.rs/Cargo.toml.in producer.rs/src/producer.rs \
	consumer.rs/Cargo.toml.in consumer.rs/src/consumer.rs \
	consumer_rs.json.in \
	py.conf.in go.conf.in rs.conf.in
noinst_DATA = consumer_py.json consumer_go.json consumer_rs.json \
	py.conf go.conf rs.conf

if HAVE_GO
noinst_DATA += producer.gso consumer.gso
endif

if HAVE_RUST
noinst_DATA += producer.rs/target/debug/libproducer.so \
	       producer.rs/Cargo.toml producer.rs/Cargo.lock \
	       consumer.rs/target/debug/libconsumer.so \
	       consumer.rs/Cargo.toml consumer.rs/Cargo.lock

producer.rs/Cargo.toml: producer.rs/Cargo.toml.in
	[ -e producer.rs ] || mkdir producer.rs
	cp $< $@

producer.rs/target/debug/libproducer.so: producer.rs/Cargo.toml producer.rs/src/producer.rs
	[ -e producer.rs/src ] || \
		 ln -s $(abs_top_srcdir)/examples/tick/producer.rs/src producer.rs/src
	cargo build --manifest-path $<

consumer.rs/Cargo.toml: consumer.rs/Cargo.toml.in
	[ -e consumer.rs ] || mkdir consumer.rs
	cp $< $@

consumer.rs/target/debug/libconsumer.so: consumer.rs/Cargo.toml consumer.rs/src/consumer.rs
	[ -e consumer.rs/src ] || \
		 ln -s $(abs_top_srcdir)/examples/tick/consumer.rs/src consumer.rs/src
	cargo build --manifest-path $<
endif

include $(top_srcdir)/examples/examples.inc
