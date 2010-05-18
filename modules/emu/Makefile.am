# $Id$

AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_CFLAGS += -fms-extensions -fno-strict-aliasing

AM_CFLAGS += $(LIB_EMU_CFLAGS)
AM_LDFLAGS = $(LIB_EMU_LIBS)


pkglib_LTLIBRARIES = emu.la

emu_la_SOURCES = module.c module.h detect.c emulate.c profile.c hooks.c

emu_la_LDFLAGS = -module -no-undefined -avoid-version ${AM_LDFLAGS} 
