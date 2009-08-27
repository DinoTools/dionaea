# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = src include modules

EXTRA_DIST = configure.ac conf/dionaea.conf.dist

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/dionaea
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/dionaea/
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/dionaea/binaries/
	$(INSTALL_DATA) $(srcdir)/conf/dionaea.conf.dist $(DESTDIR)$(sysconfdir)/dionaea/dionaea.conf.dist;
	if [ ! -e $(DESTDIR)$(sysconfdir)/dionaea/dionaea.conf ]; then \
		$(INSTALL_DATA) $(srcdir)/conf/dionaea.conf.dist $(DESTDIR)$(sysconfdir)/dionaea/dionaea.conf; \
	fi
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log
