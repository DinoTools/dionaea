logsql
======

This is what the logsql python script does, it is an ihandler, and writes
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

Additionally, you can query the database for many different things, refer to:

* dionaea sql logging 2009/11/06
  <http://carnivore.it/2009/11/06/dionaea_sql_logging>
* post it yourself 2009/12/08
  <http://carnivore.it/2009/12/08/post_it_yourself>
* sqlite performance 2009/12/12
  <http://carnivore.it/2009/12/12/sqlite_performance>
* virustotal fun 2009/12/14
  <http://carnivore.it/2009/12/14/virustotal_fun>
* Andrew Waite's Blog <http://infosanity.wordpress.com/> for mimic-nepstats.py

for more examples how to make use of the database.
