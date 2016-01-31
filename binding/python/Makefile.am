AM_CPPFLAGS = ${regular_CPPFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES      = nurs_PYTHON.la

nurs_PYTHON_la_SOURCES = pynurs.h pycommon.c pysvr.c pycli.c pyobj.c
nurs_PYTHON_la_LDFLAGS = -avoid-version -module
nurs_PYTHON_la_CFLAGS  = ${regular_CFLAGS} ${LIBMNL_CFLAGS} ${LIBPYTHON_CFLAGS}
nurs_PYTHON_la_LIBADD  = ${LIBMNL_LIBS} ${LIBPYTHON_LIBS}
