Configuration - dionaea.conf
============================

If you want to change the software, it is really important to understand
how it works, therefore please take the time to how it works.
dionaea.conf is the main configuration file, the file controls consists
of sections for:

  * logging
  * processors
  * downloads
  * bistreams
  * submit
  * listen
  * modules


logging
-------

The logging section controls ... logging, you can specify log domains
and loglevel for different logfiles.
As dionaea is pretty ... verbose, it is useful to rotate the logfiles
using logrotate.

.. code-block:: text

    # logrotate requires dionaea to be started with a pidfile
    # in this case -p /opt/dionaea/var/run/dionaea.pid
    # adjust the path to your needs
    /opt/dionaea/var/log/dionaea*.log {
            notifempty
            missingok
            rotate 28
            daily
            delaycompress
            compress
            create 660 root root
            dateext
            postrotate
                    kill -HUP `cat /opt/dionaea/var/run/dionaea.pid`
            endscript
    }

//etc/logrotate.d/dionaea/


modules
-------

downloads specify where to store downloaded malware.
bistreams specify where to store bi-directional streams, these are
pretty useful when debugging, as they allow to replay an attack on
ip-level, without messing with pcap&tcpreplay, which never worked for me.
submit specifies where to send files to via http or ftp, you can define
a new section within submit if you want to add your own service.
listen sets the addresses dionaea will listen to. The default is *all*
addresses it can find, this mode is call getifaddrs, but you can set it
to manual and specify a single address if you want to limit it.
modules is the most powerfull section, as it specifies the modules to
load, and the options for each module.









logsql
""""""

This section controls the logging to the sqlite database.
logsql does not work when chrooting - python makes the path absolute and
fails for requests after chroot().

logsql requires the directory where the logsql.sqlite file resides to be
writeable by the user, as well as the logsql.sqlite file itself.
So, if you drop user privs, make sure the user you drop to is allowed to
read/write the file and the directory.

.. code-block:: console

    chown MYUSER:MYGROUP /opt/dionaea/var/dionaea -R

To query the logsql database, I recommend looking at the
readlogsqltree.py <#readlogsqltree> script, for visualisation the
gnuplotsql <#gnuplotsql> script.

The blog on logsql:

  * 2009-11-06 dionaea sql logging
    <http://carnivore.it/2009/11/06/dionaea_sql_logging>
  * 2009-12-08 post it yourself
    <http://carnivore.it/2009/12/08/post_it_yourself>
  * 2009-12-12 sqlite performance
    <http://carnivore.it/2009/12/12/sqlite_performance>
  * 2009-12-14 virustotal fun
    <http://carnivore.it/2009/12/14/virustotal_fun>
  * 2009-12-15 paris mission pack avs
    <http://carnivore.it/2009/12/15/paris_mission_pack_avs>
  * 2010-06-06 data visualisation
    <http://carnivore.it/2010/06/06/data_visualisation>


logxmpp
"""""""

This section controls the logging to xmpp services. If you want to use
logxmpp, make sure to enable logxmpp in the ihandler section.
Using logxmpp allows you to share your new collected files with other
sensors anonymously.

The blog on logxmpp:

  * 2010-02-10 xmpp backend <http://carnivore.it/2010/02/10/xmpp_backend>
  * 2010-05-12 xmpp take #2 <http://carnivore.it/2010/05/12/xmpp_-_take_2>
  * 2010-05-15 xmpp take #3 <http://carnivore.it/2010/05/15/xmpp_-_take_3>

pg_backend <#pg_backend> can be used as a backend for xmpp logging sensors.


p0f
"""

Not enabled by default, but recommend: the p0f service, enable by
uncommenting p0f in the ihandlers section of the python modules section,
and start p0f as suggested in the config. It costs nothing, and gives
some pretty cool, even if outdated, informations about the attackers
operating system, and you can look them up from the sqlite database,
even the rejected connections.
If you face problems, here
<http://blog.infosanity.co.uk/2010/12/04/dionaea-with-p0f/> are some hints.




ihandlers
"""""""""

ihandlers section is used to specify which ihandlers get started by
ihandlers.py . You do not want to miss p0f and logsql.


services
""""""""

services controls which services will get started by services.py
