# $Id$

AUTOMAKE_OPTIONS = foreign

PYSCRIPTS = sip/__init__.py
PYSCRIPTS += sip/extras.py
PYSCRIPTS += sip/rfc2396.py
PYSCRIPTS += sip/rfc2617.py
PYSCRIPTS += sip/rfc3261.py
PYSCRIPTS += sip/rfc4566.py
PYSCRIPTS += tftp.py
PYSCRIPTS += echo.py
PYSCRIPTS += ftp.py
PYSCRIPTS += ftp_download.py
PYSCRIPTS += services.py
PYSCRIPTS += smb/include/fieldtypes.py
PYSCRIPTS += smb/include/smbfields.py
PYSCRIPTS += smb/include/__init__.py
PYSCRIPTS += smb/include/helpers.py
PYSCRIPTS += smb/include/packet.py
PYSCRIPTS += smb/include/asn1fields.py
PYSCRIPTS += smb/include/asn1packet.py
PYSCRIPTS += smb/include/asn1/__init__.py
PYSCRIPTS += smb/include/asn1/asn1.py
PYSCRIPTS += smb/include/asn1/ber.py
PYSCRIPTS += smb/include/asn1/mib.py
PYSCRIPTS += smb/include/ntlmfields.py
PYSCRIPTS += smb/include/gssapifields.py
PYSCRIPTS += smb/__init__.py
PYSCRIPTS += smb/smb.py
PYSCRIPTS += smb/rpcservices.py
PYSCRIPTS += test.py
PYSCRIPTS += mirror.py
PYSCRIPTS += nfq.py
PYSCRIPTS += http.py
PYSCRIPTS += log.py
PYSCRIPTS += logsql.py
PYSCRIPTS += log_db_sql/__init__.py
PYSCRIPTS += log_db_sql/controller.py
PYSCRIPTS += log_db_sql/model.py
PYSCRIPTS += log_json.py
PYSCRIPTS += p0f.py
PYSCRIPTS += cmd.py
PYSCRIPTS += emu.py
PYSCRIPTS += ihandlers.py
PYSCRIPTS += util.py
PYSCRIPTS += store.py
PYSCRIPTS += virustotal.py
PYSCRIPTS += submit_http.py
PYSCRIPTS += hpfeeds.py
PYSCRIPTS += ndrlib.py
PYSCRIPTS += logxmpp.py
PYSCRIPTS += fail2ban.py
PYSCRIPTS += __init__.py
PYSCRIPTS += mssql/__init__.py
PYSCRIPTS += mssql/mssql.py
PYSCRIPTS += mssql/include/tds.py
PYSCRIPTS += mssql/include/__init__.py
PYSCRIPTS += mysql/__init__.py
PYSCRIPTS += mysql/mysql.py
PYSCRIPTS += mysql/include/packets.py
PYSCRIPTS += mysql/include/fields.py
PYSCRIPTS += mysql/include/__init__.py
PYSCRIPTS += pptp/__init__.py
PYSCRIPTS += pptp/pptp.py
PYSCRIPTS += pptp/include/packets.py
PYSCRIPTS += pptp/include/__init__.py
PYSCRIPTS += mqtt/__init__.py
PYSCRIPTS += mqtt/mqtt.py
PYSCRIPTS += mqtt/include/packets.py
PYSCRIPTS += mqtt/mqtt.py
PYSCRIPTS += mqtt/include/__init__.py
PYSCRIPTS += upnp/__init__.py
PYSCRIPTS += upnp/upnp.py


all: $(PYSCRIPTS)
	

install-data-am: all
	for i in $(PYSCRIPTS); do \
		location=$(DESTDIR)$(pkglibdir)"/python/dionaea/$$i"; \
		scriptdir=`dirname "$$location"`; \
		if [ ! -d $$scriptdir ]; then \
			$(mkinstalldirs) $$scriptdir; \
		fi; \
		$(INSTALL_DATA) $$i $$location; \
	done

EXTRA_DIST = $(PYSCRIPTS)
