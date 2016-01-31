ACLOCAL_AMFLAGS  = -I m4

EXTRA_DIST = $(man_MANS) nursd.conf.in
noinst_DATA = nursd.conf

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)
SUBDIRS = include src util producer filter consumer coveter binding examples tests

include $(top_srcdir)/examples.inc
