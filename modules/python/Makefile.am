# $Id$

AUTOMAKE_OPTIONS = foreign

all: binding.c

binding.c: binding.pyx module.c module.h
	python setup.py build

install: all
	cp build/*/python.so @libdir@/dionaea/python.so
	mkdir -p @libdir@/dionaea/python
	cp scripts/* @libdir@/dionaea/python -R
	

clean:
	python setup.py clean
	rm -rf ./build connection.{c,h} 

dist-clean: clean


EXTRA_DIST = setup.py module.c module.h connection.pyx
EXTRA_DIST += scripts/log.py
