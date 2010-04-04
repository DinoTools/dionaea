# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = scripts

all: binding.c

binding.c: setup.py setup.py.in binding.pyx module.c module.h ../../config.h ../../include/protocol.h ../../include/dionaea.h
	python setup.py build

install-exec-am: all
	cp build/*/dionaea/*.so @libdir@/dionaea/python.so
	rm -rf @libdir@/dionaea/python/dionaea/core.so
	ln -s @libdir@/dionaea/python.so @libdir@/dionaea/python/dionaea/core.so

clean:
	python setup.py clean
	rm -rf ./build binding.{c,h} 

dist-clean: clean


EXTRA_DIST = setup.py module.c module.h binding.pyx

