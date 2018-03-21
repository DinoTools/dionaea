# $Id$

AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_CFLAGS += -fno-strict-aliasing

AM_CFLAGS += $(LIB_PCAP_CFLAGS)
AM_LDFLAGS = $(LIB_PCAP_LIBS)

AM_CFLAGS += $(LIB_GLIB_CFLAGS)
AM_LDFLAGS += $(LIB_GLIB_LDFLAGS)

pkglib_LTLIBRARIES = pcap.la

pcap_la_SOURCES = pcap.c

pcap_la_LDFLAGS = -module -no-undefined -avoid-version ${AM_LDFLAGS}

