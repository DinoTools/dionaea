# $Id: Makefile.am 2463 2008-10-13 10:32:47Z common $

AUTOMAKE_OPTIONS = foreign

if BUILD_PYTHON_MODULE
python_dir = python 
endif

if BUILD_EMU_MODULE
emu_dir = emu
endif

SUBDIRS = nc $(python_dir) $(emu_dir)
DIST_SUBDIRS = nc python emu
