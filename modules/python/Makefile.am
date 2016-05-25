# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = dionaea util

all: binding.c

binding.c: setup.py setup.py.in binding.pyx module.c module.h ../../config.h ../../include/protocol.h ../../include/dionaea.h
	$(PYTHON) setup.py build

install-exec-am: all
	cp build/*/dionaea/*.so $(DESTDIR)$(pkglibdir)/python.so
	(cd $(DESTDIR)$(pkglibdir)/python/dionaea && rm -f core.so && ln -s ../../python.so core.so)
	(cd $(DESTDIR)$(pkglibdir)/python/dionaea && rm -f pyev.so && ln -s ../../python.so pyev.so)

clean:
	$(PYTHON) setup.py clean
	rm -rf ./build binding.{c,h} 

dist-clean: clean


EXTRA_DIST = setup.py module.c module.h binding.pyx

