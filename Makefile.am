ACLOCAL_AMFLAGS  = -I m4

EXTRA_DIST = $(man_MANS)

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)
DIST_SUBDIRS = include src util producer filter consumer coveter binding doc tests examples
SUBDIRS = include src util producer filter consumer coveter binding doc tests

examples:
	$(MAKE)
	$(MAKE) -C $(srcdir)/examples

.PHONY: examples
