dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])

AC_INIT([nurs], [0.1], [chamaken@gmail.com])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 -Wall foreign tar-pax no-dist-gzip dist-bzip2])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_TESTDIR(tests)

dnl Checks for programs.
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

case "$host" in
*-*-linux* | *-*-uclinux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac

dnl Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_STRUCT_TM
AC_SYS_LARGEFILE

dnl Checks for library functions.
AC_FUNC_VPRINTF
AC_FUNC_FORK
AC_FUNC_MMAP
AC_CHECK_FUNCS([alarm getcwd gettimeofday localtime_r memset munmap realpath socket strcasecmp strchr strdup strerror strrchr strstr strtol strtoumax])

dnl AC_GNU_SOURCE?
regular_CPPFLAGS="-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_REENTRANT"
AC_SUBST([regular_CPPFLAGS])
regular_CFLAGS="-Wall -Wextra -Wundef -Waggregate-return \
	-Wno-unused-parameter -Wmissing-declarations \
	-Wstrict-prototypes -Wmissing-prototypes \
	-Wshadow -Wcast-align -Wcast-qual \
	-Wpointer-arith -Wconversion \
	-Wformat=2 -pipe -fvisibility=hidden -pthread"
# -fno-omit-frame-pointer -fstack-protector-all -fsanitize=address
AC_SUBST([regular_CFLAGS])

dnl Checks for libraries.
AC_SEARCH_LIBS([dlopen], [dl], [libdl_LIBS="$LIBS"; LIBS=""])
AC_SUBST([libdl_LIBS])

AC_SEARCH_LIBS([pthread_create], [pthread], [libpthread_LIBS="$LIBS"; LIBS=""])
AC_SUBST([libpthread_LIBS])

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h])
AC_CHECK_HEADER(sys/timerfd.h,[],[AC_MSG_ERROR(unable to find timerfd header)])
AC_CHECK_HEADER(sys/signalfd.h,[],[AC_MSG_ERROR(unable to find signalfd header)])
AC_CHECK_HEADER(sys/epoll.h,[],[AC_MSG_ERROR(unable to find epoll header)])

dnl Check by pkg-config
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.6])
PKG_CHECK_MODULES([URCU], [liburcu >= 0.8])

AC_MSG_CHECKING([for enable mmaped netlink])
AC_CACHE_VAL(ac_cv_mmaped_netlink,
AC_TRY_COMPILE(
    [ #include <linux/netlink.h>],
    [ int i = NETLINK_RX_RING; ],
    ac_cv_mmaped_netlink=yes,
    ac_cv_mmaped_netlink=no))
AC_MSG_RESULT($ac_cv_mmaped_netlink)
AM_CONDITIONAL([HAVE_NLMMAP], [test "x$ac_cv_mmaped_netlink" = "xyes"])

AC_ARG_ENABLE(nflog,
       AS_HELP_STRING([--enable-nflog], [enable nflog module [default=yes]]),[enable_nflog=$enableval],[enable_nflog=yes])
AS_IF([test "x$enable_nflog" = "xyes"], [
    PKG_CHECK_MODULES([LIBNETFILTER_LOG], [libnetfilter_log >= 1.0.0],
                      AC_DEFINE([HAVE_LNFLOG], [1], [building nflog module]),
                      enable_nflog="no")
])
AM_CONDITIONAL([HAVE_LNFLOG], [test "x$enable_nflog" = "xyes"])

AC_ARG_ENABLE(nflog2,
       AS_HELP_STRING([--enable-nflog2], [enable nflog2 module [default=yes]]),[enable_nflog2=$enableval],[enable_nflog2=yes])
AS_IF([test "x$enable_nflog2" = "xyes"], [
    AC_MSG_CHECKING([does libnetfilter_log have nflog_nlmsg_parse])
    AC_CACHE_VAL(ac_cv_nflog_nlmsg_parse,
        SAVE_LIBS=$LIBS
        LIBS="$LIBS -lnetfilter_log -lmnl"
        AC_TRY_LINK(
	    [ #include <stddef.h>
	      #include <libnetfilter_log/libnetfilter_log.h> ],
            [ return nflog_nlmsg_parse(NULL, NULL); ],
            ac_cv_nflog_nlmsg_parse=yes,
            ac_cv_nflog_nlmsg_parse=no)
	LIBS=$SAVE_LIBS)
    AC_MSG_RESULT($ac_cv_nflog_nlmsg_parse)
    AS_IF([test "x$ac_cv_mmaped_netlink" = "xyes" -a "x$ac_cv_nflog_nlmsg_parse" = "xyes" -a "x$enable_nflog2" = "xyes"],
        AC_DEFINE([HAVE_LNFLOG2], [1], [building nflog2 module]),
	enable_nflog2="no")
])
AM_CONDITIONAL([BUILD_NFLOG2], [test "x$enable_nflog2" = "xyes"])

AC_ARG_ENABLE(nfct,
       AS_HELP_STRING([--enable-nfct], [enable nfct module [default=yes]]),[enable_nfct=$enableval],[enable_nfct=yes])
AS_IF([test "x$enable_nfct" = "xyes"], [
    PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.0.5],
		      AC_DEFINE([HAVE_LNFCT], [1], [building nfct module]),
                      enable_nfct="no")
])
AM_CONDITIONAL([HAVE_LNFCT], [test "x$enable_nfct" = "xyes"])

AC_ARG_ENABLE(nfct2,
       AS_HELP_STRING([--enable-nfct2], [enable nfct2 module [default=yes]]),[enable_nfct2=$enableval],[enable_nfct2=yes])
AS_IF([test "x$enable_nfct2" = "xyes" -a "x$enable_nfct" = "xyes" -a "x$ac_cv_mmaped_netlink" = "xyes"],
      AC_DEFINE([HAVE_LNFCT2], [1], [building nfct2 module]),
      enable_nfct2="no")
AM_CONDITIONAL([HAVE_LNFCT2], [test "x$enable_nfct2" = "xyes"])

AC_ARG_ENABLE(nfacct,
       AS_HELP_STRING([--enable-nfacct], [enable nfacct module [default=yes]]),[enable_nfacct=$enableval],[enable_nfacct=yes])
AS_IF([test "x$enable_nfacct" = "xyes"], [
    PKG_CHECK_MODULES([LIBNETFILTER_ACCT], [libnetfilter_acct >= 1.0.1],
                      AC_DEFINE([HAVE_LNFACCT], [1], [building nfacct module]),
                      enable_nfacct="no")
])
AM_CONDITIONAL([HAVE_LNFACCT], [test "x$enable_nfacct" = "xyes"])

AC_ARG_ENABLE(nfq,
	AS_HELP_STRING([--enable-nfq], [enable nfq module [default=yes]]),[enable_nfq=$enableval],[enable_nfq=yes])
AS_IF([test "x$enable_nfq" = "xyes"], [
    PKG_CHECK_MODULES([LIBNETFILTER_QUEUE], [libnetfilter_queue >= 1.0.2],
                      AC_DEFINE([HAVE_LNFQ], [1], [building nfq module]),
		      enable_nfq="no")
])
AM_CONDITIONAL([HAVE_LNFQ], [test "x$enable_nfq" = "xyes"])

AC_ARG_ENABLE(nft,
       AS_HELP_STRING([--enable-nft], [enable nft module [default=yes]]),[enable_nft=$enableval],[enable_nft=yes])
AS_IF([test "x$enable_nft" = "xyes"], [
    PKG_CHECK_MODULES([LIBNFTNL], [libnftnl >= 1.0.0],
                      AC_DEFINE([HAVE_LNFT], [1], [building nft module]),
		      enable_nft="no")
])
AM_CONDITIONAL([HAVE_LNFT], [test "x$enable_nft" = "xyes"])

AC_ARG_ENABLE(python,
       AS_HELP_STRING([--enable-python], [enable python module [default=yes]]),[enable_python=$enableval],[enable_python=yes])
AS_IF([test "x$enable_python" = "xyes"], [
    AM_PATH_PYTHON([3.2], [
        PKG_CHECK_MODULES([LIBPYTHON], [python-$PYTHON_VERSION], [
	    AC_PATH_PROG(PYTHON_CONFIG, python$PYTHON_VERSION-config, no)
	    AS_IF([test "$PYTHON_CONFIG" = no],
	        [AC_MSG_ERROR([cannot find python-config for $PYTHON])
	         enable_python="no"],
	        [AC_MSG_CHECKING([python cflags])
	         python_CFLAGS=`$PYTHON_CONFIG --cflags`
	         AC_SUBST([python_CFLAGS])
	         AC_MSG_RESULT([$python_CFLAGS])
	         AC_MSG_CHECKING([python ldflags])
	         python_LDFLAGS=`$PYTHON_CONFIG --ldflags`
	         AC_SUBST([python_LDFLAGS])
	         AC_MSG_RESULT([$python_LDFLAGS])
	        ])
            ], enable_python="no")
    ], enable_python="no")
])
AM_CONDITIONAL([HAVE_PYTHON], [test "x$enable_python" = "xyes"])

AS_IF([which go > /dev/null 2>&1], [enable_go="yes"], [enable_go="no"])
AM_CONDITIONAL([HAVE_GO], [test "x$enable_go" = "xyes"])

AC_DEFUN([REPLACE],
     [sed -e "s|$2|$3|g" $1 >  ${1%.in}])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 include/nurs/Makefile
                 src/Makefile
                 tests/Makefile
		 tests/atlocal
		 util/Makefile
		 producer/Makefile
		 filter/Makefile
		 consumer/Makefile
		 coveter/Makefile
		 binding/Makefile
		 binding/python/Makefile
		 binding/go/Makefile
		 binding/go/contrib/Makefile

		 examples/Makefile
		 examples/python/Makefile
		 examples/python/producer/Makefile
		 examples/python/filter/Makefile
		 examples/python/consumer/Makefile

		 examples/go/Makefile
		 examples/go/producer/Makefile
		 examples/go/consumer/Makefile

		 examples/tick/Makefile
		 examples/ctflow9/Makefile
		 examples/nfct/Makefile
		 examples/nfctst/Makefile
		 examples/nfacct/Makefile
		 examples/nflog/Makefile
		 examples/xml/Makefile
		 examples/nfq_accept/Makefile
		 examples/mtnfq_accept/Makefile
		 examples/mtnfq_repeat/Makefile
		 ])
AC_OUTPUT

echo "
nurs configuration:
  Producer:
    NFLOG plugin:			${enable_nflog2}
    NFCT plugin:			${enable_nfct}
    NFCT2 plugin:			${enable_nfct2}
    NFACCT plugin:			${enable_nfacct}
    NFQ plugin:				${enable_nfq}
    NFT plugin:				${enable_nft}
  Coveter:
    NetFlow v9 plugin:			${enable_nfct}
    IPFIX plugin:			${enable_nfct}
  PYTHON plugin:			${enable_python}
  Go plugin (experimental example)	${enable_go}
"
echo "You can now run 'make' and 'make install'"
