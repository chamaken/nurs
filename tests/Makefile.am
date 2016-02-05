SUBDIRS		= data
AUTOM4TE	= autom4te
AUTOTEST	= $(AUTOM4TE) --language=autotest
AM_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_CFLAGS	= -g ${regular_CFLAGS}
LDADD		= ${libdl_LIBS} ${JANSSON_LIBS} ../src/libnurs.la

TESTSUITE = $(srcdir)/testsuite
EXTRA_DIST = testsuite.at $(TESTSUITE) atlocal.in
CLEANFILES = atconfig $(srcdir)/package.m4


$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{								   \
	  echo '# Signature of the current package.';			   \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])';	   \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])';   \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])';   \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])';	   \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])'; \
	} >$(srcdir)/package.m4

check-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

# installcheck-local: atconfig atlocal $(TESTSUITE)
#	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
#	  $(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || $(SHELL) '$(TESTSUITE)' --clean
	rm -f -r autom4te.cache

$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

atconfig: $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status tests/$@


check_PROGRAMS	= \
	01_config 02_plugin_regist 03_plugin_json 04_plugin_get \
	05_producer 06_ioset 07_worker

01_config_SOURCES	= 01_config.c test.h
01_config_LDFLAGS	= -export-dynamic -export-symbols-regex "^export_cb_"
02_plugin_regist_SOURCES	= 02_plugin.c test.h
03_plugin_json_SOURCES	= 03_plugin_json.c test.h
04_plugin_get_SOURCES	= 04_plugin_get.c test.h
05_producer_SOURCES	= 05_producer.c test.h
06_ioset_SOURCES	= 06_ioset.c test.h
07_worker_SOURCES	= 07_worker.c test.h
