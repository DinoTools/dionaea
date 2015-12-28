Protocols
=========

Network services speak a certain language, this language is called protocol.
When we started deploying honeypots, you could trap worms just by
opening a single port, and wait for them to connect and send you an url
where you could download a copy of the worm. The service getting
attacked was the backdoor of the bagle mailworm, and it did not require
and interaction.
Later on, the exploitations of real services got more complex, and you
had to reply something to the worm to fool him.
Nowadays worms use API to access services, before sending their payload.
To allow easy adjustments to the procotol, dionaea implements the
protocols in python. There is a glue between the network layer which is
done in the c programming language and the embedded python scripting
language, which allows using the non-blocking connections in python.
This has some benefits, for example we can use non-blocking tls
connections in python, and we even get rate limiting on them (if
required), where pythons own io does not offer such things. On the other
hand, it is much more comfortable to implement protocols in python than
doing the same in c.

ftp
---

Dionaea provives a basic ftp server on port 21, it can create
directories and upload and download files. From my own experience there
are very little automated attacks on ftp services and I'm yet to see
something interesting happening on port 21.

http
----

Dionaea supports http on port 80 as well as https, but there is no code
making use of the data gathered on these ports.
For https, the self-signed ssl certificate is created at startup.

MySQL
-----

This module implements the MySQL wire stream protocol - backed up by
sqlite as database. Please refer to 2011-05-15 Extending Dionaea
<http://carnivore.it/2011/05/15/extending_dionaea> for more information.

MSSQL
-----

This module implements the Tabular Data Stream protocol which is used by
Microsoft SQL Server. It listens to tcp/1433 and allows clients to
login. It can decode queries run on the database, but as there is no
database, dionaea can't reply, and there is no further action. Typically
we always get the same query:

.. code-block:: text

    exec sp_server_info 1 exec sp_server_info 2 exec sp_server_info 500 select 501,NULL,1 where 'a'='A' select 504,c.name,c.description,c.definition from master.dbo.syscharsets c,master.dbo.syscharsets c1,master.dbo.sysconfigures f where f.config=123 and f.value=c1.id and c1.csid=c.id set textsize 2147483647 set arithabort on

Refer to the blog
<http://carnivore.it/2010/09/11/mssql_attacks_examined> for more
information.
Patches would be appreciated.

SIP (VoIP)
----------

This is a VoIP module for the honeypot dionaea. The VoIP protocol used
is SIP since it is the de facto standard for VoIP today. In contrast to
some other VoIP honeypots, this module doesn't connect to an external
VoIP registrar/server. It simply waits for incoming SIP messages (e.g.
OPTIONS or even INVITE), logs all data as honeypot incidents and/or
binary data dumps (RTP traffic), and reacts accordingly, for instance by
creating a SIP session including an RTP audio channel. As sophisticated
exploits within the SIP payload are not very common yet, the honeypot
module doesn't pass any code to dionaea's code emulation engine. This
will be implemented if we spot such malicious messages. The main
features of the VoIP module are:

  * Support for most SIP requests (OPTIONS, INVITE, ACK, CANCEL, BYE)
  * Support for multiple SIP sessions and RTP audio streams
  * Record all RTP data (optional)
  * Set custom SIP username and secret (password)
  * Set custom useragent to mimic different phone models
  * Uses dionaea's incident system to log to SQL database


Personalities
^^^^^^^^^^^^^

A personality defines how to handle a request. At least the 'default'
personality MUST exist. The following options are available per
personality.

serve
    A list of IP addresses to use this personality for.
handle
    List of SIP methods to handle.


          SIP Users

You can easily add, change or remove users by editing the SQLite file
specified by the 'users = ""' parameter in the config file. All users
are specified in the users table.

username
    Specifies the name of the user. This value is treated as regular
    expression. See Python: Regular Expressions
    <http://docs.python.org/py3k/library/re.html> for more information.
password
    The password.
personality
    The user is only available in the personality specified by this
    value. You can define a personality in the config file.
pickup_delay_min
    This is an integer value. Let the phone ring for at least this
    number of seconds.
pickup_delay_max
    This is an integer value. Maximum number of seconds to wait before
    dionaea picks up the phone.
action
    This value isn't in use, yet.
sdp
    The name of the SDP to use. See table 'sdp'.


SDP
^^^

All SDPs can be defined in the sdp table in the users database.

name
    Name of the SDP
sdp
    The value to use as SDP

The following values are available in the SDP definition.

{addrtype}
    Address type. (IP4 or IP6)
{unicast_address}
    RTP address
{audio_port}
    Dionaea audio port.
{video_port}
    Dionaea video port.

The following control parameters are available in the SDP definition.

[audio_port]...content...[/audio_port]
    The content is only available in the output if the audio_port value
    is set.
[video_port]...content...[/video_port]
    The content is only available in the output if the video_port value
    is set.

Example:

.. code-block:: text

    v=0
    o=- 1304279835 1 IN {addrtype} {unicast_address}
    s=SIP Session
    c=IN {addrtype} {unicast_address}
    t=0 0
    [audio_port]
    m=audio {audio_port} RTP/AVP 111 0 8 9 101 120
    a=sendrecv
    a=rtpmap:111 Speex/16000/1
    a=fmtp:111 sr=16000,mode=any
    a=rtpmap:0 PCMU/8000/1
    a=rtpmap:8 PCMA/8000/1
    a=rtpmap:9 G722/8000/1
    a=rtpmap:101 telephone-event/8000
    a=fmtp:101 0-16,32,36
    a=rtpmap:120 NSE/8000
    a=fmtp:120 192-193
    [/audio_port]
    [video_port]
    m=video {video_port} RTP/AVP 34 96 97
    c=IN {addrtype} {unicast_address}
    a=rtpmap:34 H263/90000
    a=fmtp:34 QCIF=2
    a=rtpmap:96 H263-1998/90000
    a=fmtp:96 QCIF=2
    a=rtpmap:97 H263-N800/90000
    [/video_port]

SMB
---

The main protocol offerd by dionaea is SMB. SMB has a decent history of
remote exploitable bugs, and is a very popular target for worms.
dionaeas SMB implementation makes use of an python3 adapted version of
scapy. As scapys own version of SMB was pretty limited, almost
everything but the Field declarations had to be rewritten. The SMB
emulation written for dionaea is used by the mwcollectd
<http://code.mwcollect.org> low interaction honeypot too.
Besides the known attacks on SMB dionaea supports uploading files to smb
shares.
Adding new DCE remote procedure calls is a good start to get into
dionaea code, you can use:

.. code-block:: sql

    SELECT
            COUNT(*),
            dcerpcrequests.dcerpcrequest_uuid,
            dcerpcservice_name,
            dcerpcrequest_opnum
    FROM
            dcerpcrequests
            JOIN dcerpcservices ON(dcerpcrequests.dcerpcrequest_uuid == dcerpcservices.dcerpcservice_uuid)
            LEFT OUTER JOIN dcerpcserviceops ON(dcerpcserviceops.dcerpcserviceop_opnum = dcerpcrequest_opnum AND dcerpcservices.dcerpcservice = dcerpcserviceops.dcerpcservice )
    WHERE
            dcerpcserviceop_name IS NULL
    GROUP BY
            dcerpcrequests.dcerpcrequest_uuid,dcerpcservice_name,dcerpcrequest_opnum
    ORDER BY
            COUNT(*) DESC;


to identify potential usefull targets of unknown dcerpc calls using the
data you gathered and stored in your logsql database. Patches are
appreciated.

tftp
----

Written to test the udp connection code, dionaea provides a tftp server
on port 69, which can serve files. Even though there were
vulnerabilities in tftp services, I'm yet to see an automated attack on
tftp services.