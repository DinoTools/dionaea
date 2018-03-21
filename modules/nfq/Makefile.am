# $Id: Makefile.am 2538 2009-01-25 22:35:27Z common $

AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -pipe -D _GNU_SOURCE -fno-strict-aliasing
AM_CFLAGS += -Wall -Werror

AM_CFLAGS += ${LIB_GLIB_CFLAGS}
AM_LDFLAGS = ${LIB_GLIB_LIBS}


pkglib_LTLIBRARIES = nfq.la

nfq_la_SOURCES = nfq.c nfq.h

nfq_la_LDFLAGS = -module -no-undefined -avoid-version -lnetfilter_queue 
