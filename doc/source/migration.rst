Migration
=========

We try to provide some information on how to upgrade from one version to the next.
Please also have a look at the :doc:`changelog` for additional information.


0.7.0 -> 0.8.0
--------------

**Config**

* IPv4 mapped IPv6 is now disabled by default

**Path**

During the steps from autotools to cmake nearly all log and data directories have been changed.
But it should be possible to keep the old config files and also use the old directories.

Assuming dionaea 0.7.0 and 0.8.0 have been installed into ```/opt/dionaea```

* /opt/dionaea/var/dionaea/binaries/ /opt/dionaea/var/lib/dionaea/binaries/
* /opt/dionaea/var/dionaea/bistreams/ -> /opt/dionaea/var/lib/dionaea/bistreams/
* /opt/dionaea/var/dionaea/dionaea.db -> /opt/dionaea/var/lib/dionaea/dionaea.db
* /opt/dionaea/var/dionaea/dionaea.json -> /opt/dionaea/var/lib/dionaea/dionaea.json
* /opt/dionaea/var/dionaea/dionaea.log -> /opt/dionaea/var/log/dionaea/dionaea.log
* /opt/dionaea/var/dionaea/dionaea.sqlite -> /opt/dionaea/var/lib/dionaea/dionaea.sqlite
* /opt/dionaea/var/dionaea/dionaea_incident.json -> /opt/dionaea/var/lib/dionaea/dionaea_incident.json
* /opt/dionaea/var/dionaea/dionaea-errors.log -> /opt/dionaea/var/log/dionaea/dionaea-errors.log
* /opt/dionaea/var/dionaea/downloads.f2b -> /opt/dionaea/var/lib/dionaea/fail2ban/downloads.f2b
* /opt/dionaea/var/dionaea/offers.f2b -> /opt/dionaea/var/lib/dionaea/fail2ban/offers.f2b
* /opt/dionaea/var/dionaea/roots/ftp/ -> /opt/dionaea/var/lib/dionaea/ftp/root/
* /opt/dionaea/var/dionaea/roots/tftp/ -> /opt/dionaea/var/lib/dionaea/tftp/root/
* /opt/dionaea/var/dionaea/roots/upnp/ -> /opt/dionaea/var/lib/dionaea/upnp/root/
* /opt/dionaea/var/dionaea/roots/www/ -> /opt/dionaea/var/lib/dionaea/www/root/
* /opt/dionaea/var/dionaea/share/python/http/template/ -> /opt/dionaea/var/lib/dionaea/http/template/
* /opt/dionaea/var/dionaea/sipaccounts.sqlite -> /opt/dionaea/var/lib/dionaea/sip/accounts.sqlite
* /opt/dionaea/var/dionaea/vtcache.sqlite -> /opt/dionaea/var/lib/dionaea/vtcache.sqlite
