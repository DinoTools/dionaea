# $Id$

AUTOMAKE_OPTIONS = foreign

PYSCRIPTS = tftp.py
PYSCRIPTS += echo.py
PYSCRIPTS += ftp.py
PYSCRIPTS += services.py
PYSCRIPTS += smb/include/fieldtypes.py
PYSCRIPTS += smb/include/smbfields.py
PYSCRIPTS += smb/include/__init__.py
PYSCRIPTS += smb/include/helpers.py
PYSCRIPTS += smb/include/packet.py
PYSCRIPTS += smb/__init__.py
PYSCRIPTS += smb/smb.py
PYSCRIPTS += smb/rpcservices.py
PYSCRIPTS += test.py
PYSCRIPTS += mirror.py
PYSCRIPTS += http.py
PYSCRIPTS += log.py
PYSCRIPTS += logsql.py
PYSCRIPTS += p0f.py
PYSCRIPTS += cmd.py
PYSCRIPTS += emu.py
PYSCRIPTS += ihandlers.py
PYSCRIPTS += util.py
PYSCRIPTS += store.py
PYSCRIPTS += surfids.py
PYSCRIPTS += ndrlib.py
PYSCRIPTS += logxmpp.py

all: $(PYSCRIPTS)
	

install-data-am: all
	for i in $(PYSCRIPTS); do \
		location="@libdir@/dionaea/python/dionaea/$$i"; \
		scriptdir=`dirname "$$location"`; \
		if [ ! -d $$scriptdir ]; then \
			$(mkinstalldirs) $$scriptdir; \
		fi; \
		$(INSTALL_DATA) $$i $$location; \
	done

EXTRA_DIST = $(PYSCRIPTS)
