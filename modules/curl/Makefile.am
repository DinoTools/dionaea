# $Id$

AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_CFLAGS += -fno-strict-aliasing

AM_CFLAGS += $(LIB_CURL_CFLAGS) 
AM_LDFLAGS = $(LIB_CURL_LIBS)

pkglib_LTLIBRARIES = curl.la

curl_la_SOURCES = module.c module.h

curl_la_LDFLAGS = -module -no-undefined -avoid-version ${AM_LDFLAGS}

