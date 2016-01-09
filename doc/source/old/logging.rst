Logging
=======

Getting a copy of the malware is cool, getting an overview of the
attacks run on your sensor is priceless.

dionaea can write information to a text file, but be aware, dionaeas
logging to text files is rather chatty, really chatty, and you do not
want to look at the information, if you are not debugging the software
or writing some new feature for it.

Of course, you can appy filters to the logging, to limit it to different
facilities or levels, but in general you do not want to work with text
files.

dionaea uses some internal communication system which is called
incidents. An incident has an origin, which is a string, a path, and
properties, which can be integers, strings, or a pointer to a
connection. Incidents limit to the max, they pass the information
required to incident handlers (ihandler). An ihandler can register a
path for incidents he wants to get informed about, the pathes are
matched in a glob like fashion. Therefore logging information using an
ihandler is superior to text logging, you get the information you are
looking for, and can write it to a format you choose yourself. This is
what the logsql python script does, it is an ihandler, and writes
interesting incidents to a sqlite database, one of the benefits of this
logging is the ability to cluster incidents based on the initial attack
when retrieving the data from the database:

.. code-block:: text

    connection 610 smbd tcp accept 10.69.53.52:445 <- 10.65.34.231:2010
     dcerpc request: uuid '3919286a-b10c-11d0-9ba8-00c04fd92ef5' opnum 9
     p0f: genre:'Windows' detail:'XP SP1+, 2000 SP3' uptime:'-1' tos:'' dist:'11' nat:'0' fw:'0'
     profile: [{'return': '0x7c802367', 'args': ['', 'CreateProcessA'], 'call': 'GetProcAddress'},
                ...., {'return': '0', 'args': ['0'], 'call': 'ExitThread'}]
     service: bindshell://1957
     connection 611 remoteshell tcp listen 10.69.53.52:1957
       connection 612 remoteshell tcp accept 10.69.53.52:1957 <- 10.65.34.231:2135
         p0f: genre:'Windows' detail:'XP SP1+, 2000 SP3' uptime:'-1' tos:'' dist:'11' nat:'0' fw:'0'
         offer: fxp://1:1@10.65.34.231:8218/ssms.exe
         download: 1d419d615dbe5a238bbaa569b3829a23 fxp://1:1@10.65.34.231:8218/ssms.exe
         connection 613 ftpctrl tcp connect 10.69.53.52:37065 -> 10.65.34.231/None:8218
           connection 614 ftpdata tcp listen 10.69.53.52:62087
             connection 615 ftpdata tcp accept 10.69.53.52:62087 <- 10.65.34.231:2308
               p0f: genre:'Windows' detail:'XP SP1+, 2000 SP3' uptime:'-1' tos:'' dist:'11' nat:'0' fw:'0'

Additionally, you can query the database for many different things,
refer to:

  * dionaea sql logging 2009/11/06
    <http://carnivore.it/2009/11/06/dionaea_sql_logging>
  * post it yourself 2009/12/08
    <http://carnivore.it/2009/12/08/post_it_yourself>
  * sqlite performance 2009/12/12
    <http://carnivore.it/2009/12/12/sqlite_performance>
  * virustotal fun 2009/12/14
    <http://carnivore.it/2009/12/14/virustotal_fun>
  * Andrew Waite's Blog <http://infosanity.wordpress.com/> for
    mimic-nepstats.py

for more examples how to make use of the database.

Additional to local logging, dionaea can send a contionous stream of its
attacks to a xmpp server, which allows creating a distributed setup of
sensors with high detail of information for each attack.

Refer to logxmpp <#logxmpp> and pg_backend <#pg_backend> for more
information about distributed setups using xmpp.
