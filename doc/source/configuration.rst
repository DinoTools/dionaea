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
processors control the actions done on the bi-directional streams we
gain when getting attacked, the default is running the emu processor on
them to detect shellcode.
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
The subsections name is the name of the module dionaea will try to load,
most modules got rather simplistic names, the pcap module will use
libpcap, the curl module libcurl, the emu module libemu ...
The python module is special, as the python module can load python
scripts, which offer services, and each services can have its own options.


modules
-------


pcap
^^^^

The pcap module uses the libpcap library to detect rejected connection
attempts, so even if we do not accept a connection, we can use the
information somebody wanted to connect there.


curl
^^^^

The curl module is used to transfer files from and to servers, it is
used to download files via http as well as submitting files to 3rd parties


emu
^^^

The emu module is used to detect, profile and - if required - execute
shellcode.


python
^^^^^^

The python module allows using the python interpreter in dionaea, and
allows controlling some scripts dionaea uses


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


nfq
"""

The python nfq script is the counterpart to the nfq module. While the
nfq module interacts with the kernel, the nfq python script takes care
of the required steps to start a new service on the ports.
nfq can intercept incoming tcp connections during the tcp handshake
giving your honeypot the possibility to provide service on ports which
are not served by default.

As dionaea can not predict which protocol will be spoken on unknown
ports, neither implement the protocol by itself, it will connect the
attacking host on the same port, and use the attackers server side
protocol implementation to reply to the client requests of the attacker
therefore dionaea can end up re?exploiting the attackers machine, just
by sending him the exploit he sent us.

The technique is a brainchild of Tillmann Werner, who used it within his
honeytrap <http://honeytrap.carnivore.it> honeypot.
Legal boundaries to such behaviour may be different in each country, as
well as ethical boundaries for each individual. From a technical point
of view it works, and gives good results.
Learning from the best, I decided to adopt this technique for dionaea.
Besides the legal and ethical issues with this approach, there are some
technical things which have to be mentioned

  * */port scanning/*
    If your honeypot gets port scanned, it would open a service for each
    port scanned, in worst case you'd end up with offering 64k services
    per ip scanned. By default you'd run out of fds at about 870
    services offerd, and experience weird behaviour. Therefore the
    impact of port scanning has to be limited.
    The kiss approach taken here is a sliding window of
    *throttle.window* seconds size. Each slot in this sliding window
    represents a second, and we increment this slot for each connection
    we accept.
    Before we accept a connection, we check if the sum of all slots is
    below *throttle.limits.total*, else we do not create a new service.
    If the sum is below the limit, we check if the current slot is below
    the slot limit too, if both are given, we create a new service.
    If one of the condition fails, we do not spawn a new service, and
    let nfqeueu process the packet. There are two ways to process
    packets which got throttled:
      o *NF_ACCEPT* (=1), which will let the packet pass the kernel, and
        as there is no service listening, the packet gets rejected.
      o *NF_DROP* (=0), which will drop the packet in the kernel, the
        remote does not get any answer to his SYN.

    I prefer NF_DROP, as port scanners such as nmap tend to limit their
    scanning speed, once they notice packets get lost.

  * */recursive-self-connecting/*
    Assume some shellcode or download instructions makes dionaea to
      o connect itself on a unbound port
      o nfq intercepts the attempt
      o spawns a service
      o accepts the connection #1
      o creates mirror connection for connection #1
        by connecting the remotehost (itself) on the same port #2
      o accepts connection #2 as connection #3
      o creates mirror connection for connection #3
        by connecting the remotehost (itself) on the same port #4
      o ....
      o ....
    Such recursive loop, has to be avoided for obvious reasons.
    Therefore dionaea checks if the remote host connecting a nfq mirror
    is a local address using 'getifaddrs' and drops local connections.

So much about the known problems and workarounds ...
If you read that far, you want to use it despite the
technical/legal/ethical problems.
So ... You'll need iptables, and you'll have to tell iptables to enqueue
packets which would establish a new connection.
I recommend something like this:

.. code-block:: console

    iptables -t mangle -A PREROUTING -i eth0 -p tcp -m socket -j ACCEPT
    iptables -t mangle -A PREROUTING -i eth0 -p tcp --syn -m state --state NEW -j NFQUEUE --queue-num 5

Explanation:

 1. ACCEPT all connections to existing services
 2. enqueue all other packets to the NFQUEUE


If you have dionaea running on your NAT router, I recommend something like:

.. code-block:: console

    iptables -t mangle -A PREROUTING -i ppp0 -p tcp -m socket -j ACCEPT
    iptables -t mangle -A PREROUTING -i ppp0 -p tcp --syn -m state --state NEW -j MARK --set-mark 0x1
    iptables -A INPUT -i ppp0 -m mark --mark 0x1 -j NFQUEUE

Explanation:

 1. ACCEPT all connections to existing services in mangle::PREROUTING
 2. MARK all other packets
 3. if we see these marked packets on INPUT, queue them


Using something like:

.. code-block:: console

    iptables -A INPUT -p tcp --tcp-flags SYN,RST,ACK,FIN SYN -j NFQUEUE --queue-num 5

will enqueue /all/ SYN packets to the NFQUEUE, once you stop dionaea you
will not even be able to connect to your ssh daemon.

Even if you add an exemption for ssh like:

.. code-block:: console

    iptables -A INPUT -i eth0 -p tcp --syn -m state --state NEW --destination-port ! 22 -j NFQUEUE

dionaea will try to create a new service for /every/ incoming
connection, even if there is a service running already.
As it is easy to avoid this, I recommend sticking with the recommendation.
Besides the already mention throttle settings, there are various
timeouts for the nfq mirror service in the config.
You can control how long the service will wait for new connections
(/timeouts.server.listen/), and how long the mirror connection will be
idle (/timeouts.client.idle/) and sustain (/timeouts.client.sustain/).


ihandlers
"""""""""

ihandlers section is used to specify which ihandlers get started by
ihandlers.py . You do not want to miss p0f and logsql.


services
""""""""

services controls which services will get started by services.py
