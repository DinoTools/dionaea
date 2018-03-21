# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = dionaea util

all: binding.c

binding.c: setup.py setup.py.in binding.pyx module.c module.h ../../config.h ../../include/protocol.h ../../include/dionaea.h
	$(PYTHON) setup.py build

install-exec-am: all
	$(PYTHON) setup.py install -O1 --skip-build --root $(DESTDIR)/

clean:
	$(PYTHON) setup.py clean
	rm -rf ./build binding.{c,h}

dist-clean: clean


EXTRA_DIST = setup.py module.c module.h binding.pyx

