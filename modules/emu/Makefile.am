# $Id$

AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -pipe -D _GNU_SOURCE
AM_CFLAGS += -Wall -Werror

AM_CFLAGS += 
AM_LDFLAGS = 


pkglib_LTLIBRARIES = emu.la

emu_la_SOURCES = module.c module.h

emu_la_LDFLAGS = -module -no-undefined -avoid-version ${AM_LDFLAGS}
