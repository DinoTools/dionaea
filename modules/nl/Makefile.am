# $Id$

AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_CFLAGS += ${CFLAGS_DEFAULT} ${CFLAGS_DEBUG}

#AM_CFLAGS += -g -I/opt/dionaea/include/netlink/
AM_CFLAGS += $(LIB_NL_CFLAGS)
#AM_LDFLAGS = -Wl,-rpath,/opt/dionaea/lib -L/opt/dionaea/lib -lnl -lnl-route -lnl-genl -lnl-nf
AM_LDFLAGS = $(LIB_NL_LIBS)


pkglib_LTLIBRARIES = nl.la

nl_la_SOURCES = module.c

nl_la_LDFLAGS = -module -no-undefined -avoid-version ${AM_LDFLAGS}
