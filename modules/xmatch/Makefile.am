# $Id$

AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_CFLAGS += -fno-strict-aliasing

AM_CFLAGS += $(LIB_XMATCH_CFLAGS)
AM_LDFLAGS = $(LIB_XMATCH_LIBS)

pkglib_LTLIBRARIES = xmatch.la

xmatch_la_SOURCES = module.c xmatch.c

xmatch_la_LDFLAGS = -module -no-undefined -avoid-version ${AM_LDFLAGS}

