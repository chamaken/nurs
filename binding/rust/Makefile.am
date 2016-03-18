EXTRA_DIST = Cargo.toml.in src/nurs.rs

noinst_DATA = target/debug/libnurs.rlib

Cargo.toml: Cargo.toml.in
	cp $< $@

target/debug/libnurs.rlib: Cargo.toml src/nurs.rs
	[ -e src ] || ln -s $(abs_top_srcdir)/binding/rust/src
	cargo build -v --manifest-path $<

target/release/libnurs.rlib: Cargo.toml src/nurs.rs
	[ -e src ] || ln -s $(abs_top_srcdir)/binding/rust/src
	cargo build -v --release --manifest-path $<

clean-local:
	cargo clean
	rm -f  Cargo.toml Cargo.lock
