Changelog
=========

0.10.0 - (`master`_)
--------------------

0.9.0 - (2020-09-18)
--------------------

**ci**

* Replace Jenkins with Drone CI

**development**

* Add docker compose to setup development environment

**dionaea**

* Improve names of bistrem files (Thanks Aws0mus)
* Fix reconnects with IP only
* Fix dropping privileges (Thanks Michal Ambroz)
* Fix bug to detect if linux/sockios.h is installed

**python**

* Add class to report more information about connection issues
* Fix support Cython < 0.21
* Add additional information if parsing a YAML file fails
* Change YAML load to safe load
* Replace deprecated API calls with new ones

**python/hpfeeds**

* Fix to show error message instead of id
* Add option to set reconnect timeout
* Change error handling to send authentication before sending messages (Thanks John Carr)

**python/mssql**

* Replace warn() with warning()

**python/mysql**

* Improve detection (Thanks Yorick Koster)

**python/s3**

* Add new ihandler to upload files to S3 storage (Thanks gento)

**python/virustotal**

* Add support for custom comments (Thanks Matteo Cantoni)


0.8.0 - (2018-06-15)
--------------------

**doc**

* Add migration instructions
* Fix warnings

**build**

* Replace autotools with cmake
* Remove autotools files
* Add git information to version string on development builds

**dionaea**

* Add option to enable/disable IPv4 mapped IPv6 addresses


0.7.0 - (2018-05-01)
--------------------

**build**

* Add initial cmake support

**ci**

* Add Debian 9

**dionaea**

* Fix build error with OpenSSL 1.1.0
* Improve OpenSSL 1.1.0 support
* Cleanup connection code
* Enable bistream for SSL/TLS connections (Thanks Aws0mus)
* Fixing chroot bugs (Thanks Michal Ambroz)

**doc**

* Add additional information
* Doxygen config file for dionaea c core
* Ubuntu 16.04 install instructions

**package**

* Remove old and deprecated debian package config

**python**

* Fix typo in config key
* Fix hardcoded python path
* Fix compilation on CentOS7 (Thanks Michal Ambroz)

**python/http**

* Initial support to handle SOAP requests

**python/log_incident**

* Improve hash generator
* Fix bug if parent is unknown
* Remove IDs from list if processed

**python/mongo**

* Initial support to simulate a MongoDB server

**python/pyev**

* Update from 0.8 to 0.9 to support Python >= 3.6

**python/smb**

* Add support for WannaCry and SambaCry (Big thanks to gento)
* Add additional config options to change identity

**python/util**

* Find Download commands for Linux shell

0.6.0 - (2016-11-14)
--------------------

**dionaea**

* Fix build for musl lib

**doc**

* Fix install instructions
* Extend README.md

**python/blackhole**

* New service/Initial version

**python/emu_scripts**

* New handler to analyse downloaded scripts
* Detect VBScript and PowerShell
* Limit number of subdownloads

**python/http**

* Clean up
* Use state vars instead of strings
* Add template support
  * Jinja 2 template engine
  * nginx template

**python/mysql**

* Dump files from SELECT queries
* Extract URLs from functions
* Variable handler
* Support for selecting variables

**python/p0f**

* Fix decode error

**python/pptp**

* Fix error if config is empty


0.5.1 - 2016-09-05
------------------

**dionaea**

* Don't report 'connection.free' incident to early
  to prevent segmentation faults

0.5.0 - 2016-08-06
------------------

**dionaea**

* Handle byte objects in incidents
* Bump required Python version from 3.2 to 3.4

**python/http**

* Detect Shellshock attacks

**python/log_incident**

* Initial support to export raw incident information

**python/log_sqlite**

* Log credentials from the ftp service

**python/memcache**

* Initial support for the memcached protocol

**python/pptp**

* Clean up
* Handle CallClearRequests packets
* Values for hostname, vendor name and firmware revision are now customizable

**python/util**

* New function to detect shellshock attacks and report detected URLs


0.4.2 - 2016-07-02
------------------

**doc**

* Add information about log levels for developers

**python/***

* Replace all critical log messages with error messages
* Catch exceptions in handle_io_in() and handle_io_out() to improve stability
* Catch exceptions in incident handlers

**python/sip**

* Fix error while reading config values

**python/upnp**

* Fix errors in log messages

**more**

* Add templates to create issues and merge requests on github


0.4.1 - 2016-06-14
------------------

**core**

* Initialize stdout logger earlier
* Log error,critical and warning by default

**python/***

* In glib2 critical is a critical warning
* Add support for exceptions
* Check file path and show warnings

**python/log_json**

* Add support for flat object lists to work with ELK stack

0.4.0 - 2016-05-31
------------------

**core**

* Replace lcfg with Key-value file parser from glib

**ci**

* Add build tests for Ubuntu 14.04, Ubuntu 16.04 and Debian 8

**doc**

* Add initial documentation for missing modules
* Update documentation to reflact config changes
* Add processor documentation

**python/***

* Replace lcfg with yaml configs
* Remove deprecated incident handlers (logxmpp, mwserv, SurfIDS)
* Rename incident handlers from logsql to log_sqlite
* Rename incident handlers from uniqdownload to submit_http_post

**python/mysql**

* Enable processor pipeline

0.3.0 - 2016-03-30
------------------

**core**

* Code clean up (Thanks to Katarina)
* Vagrant based dev environment
* Customize ssl/tls parameters for autogenerated certificates

**doc**

* Initial version of sphinx based documentation

**python/ftp**

* Support to customize response messages
* Small fixes

**python/hpfeeds**

* Initial ihandler support (Thanks to rep)

**python/http**

* Customize HTTP response headers
* Return HTTP/1.1 instead of HTTP/1.0

**python/log_json**

* Initial ihandler support

**python/mqtt**

* Initial protocol support (Thanks to gento)

**python/pptp**

* Initial protocol support (Thanks to gento)

**python/upnp**

* Initial protocol support (Thanks to gento)

0.2.1 - 2014-07-16
------------------

**core**

* Support for cython and cython3
* Fixes to build with glib 2.40
* Remove build warnings
* Support libnl >= 3.2.21

**python/http**

* Fix unlink() calls

**python/virustotal**

* virustotal API v2.0

0.2.0 - 2013-11-02
------------------

Last commit by original authors.

0.1.0
-----

* Initial release.

.. _`master`: https://github.com/DinoTools/dionaea
