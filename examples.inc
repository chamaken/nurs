edit = sed -e \
	"s,@pkglibdir\@,${pkglibdir},g; \
	 s,@builddir\@,${abs_top_builddir},g; \
	 s,@cwd@,`pwd`,g; \
	 s,@pynurs@,${abs_top_srcdir}/examples/python,g; \
	 s,@gonurs@,${abs_top_srcdir}/examples/go,g; \
	 s,@VERSION\@,@VERSION@,g"

SUFFIXES = .conf .conf.in .json .json.in

.conf.in.conf: Makefile
	@ $(edit) $< > $@

.json.in.json: Makefile
	@ $(edit) $< > $@

.go.gso:
	go build -buildmode=c-shared -o $@ $<

clean-local:
	-rm -f core *.conf *.json *.log *.gso *.h
	-find -name Cargo.toml | while read i; do \
        	pushd `dirname $$i`; \
                cargo clean; \
		rm -f Cargo.toml Cargo.lock; \
                popd; \
        done
