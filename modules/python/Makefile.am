# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = scripts

all: binding.c

binding.c: binding.pyx module.c module.h ../../config.h ../../include/protocol.h ../../include/dionaea.h
	python setup.py build

install-exec-am: all
	cp build/*/python.so @libdir@/dionaea/python.so

clean:
	python setup.py clean
	rm -rf ./build binding.{c,h} 

dist-clean: clean


EXTRA_DIST = setup.py module.c module.h binding.pyx

