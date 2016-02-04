if BUILD_MAN
man_MANS = ulogd.8 nursd.8
endif

.xml.8:
	${AM_V_GEN}${DB2MAN} --xinclude $<

EXTRA_DIST = ulogd.xml nursd.xml

CLEANFILES = ulogd.8 nursd.8 *~
