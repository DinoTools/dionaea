# $Id$

AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

AM_CFLAGS += 
AM_LDFLAGS = 

AM_CFLAGS += $(LIB_GLIB_CFLAGS)
AM_LDFLAGS += $(LIB_GLIB_LDFLAGS)



pkglib_LTLIBRARIES = nc.la

nc_la_SOURCES = nc.c nc.h

nc_la_LDFLAGS = -module -no-undefined -avoid-version ${AM_LDFLAGS}
