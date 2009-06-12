# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = src include modules

EXTRA_DIST = configure.ac

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/dionaea
	$(INSTALL_DATA) $(srcdir)/conf/dionaea.conf.dist $(DESTDIR)$(sysconfdir)/dionaea/dionaea.conf.dist;
	if [ ! -e $(DESTDIR)$(sysconfdir)/dionaea/dionaea.conf ]; then \
		$(INSTALL_DATA) $(srcdir)/conf/dionaea.conf.dist $(DESTDIR)$(sysconfdir)/dionaea/dionaea.conf; \
	fi
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log
