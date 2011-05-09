# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = scripts util

all: binding.c

binding.c: setup.py setup.py.in binding.pyx module.c module.h ../../config.h ../../include/protocol.h ../../include/dionaea.h
	$(PYTHON) setup.py build

install-exec-am: all
	cp build/*/dionaea/*.so $(DESTDIR)$(pkglibdir)/python.so
	rm -rf $(DESTDIR)$(pkglibdir)/python/dionaea/core.so
	ln -s $(DESTDIR)$(pkglibdir)/python.so $(DESTDIR)$(pkglibdir)/python/dionaea/core.so
	rm -rf $(DESTDIR)$(pkglibdir)/python/dionaea/pyev.so
	ln -s $(DESTDIR)$(pkglibdir)/python.so $(DESTDIR)$(pkglibdir)/python/dionaea/pyev.so

clean:
	$(PYTHON) setup.py clean
	rm -rf ./build binding.{c,h} 

dist-clean: clean


EXTRA_DIST = setup.py module.c module.h binding.pyx

