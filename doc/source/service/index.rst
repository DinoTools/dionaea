Service
=======

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


List of available services

.. toctree::
    :maxdepth: 2

    blackhole
    epmap
    ftp
    http
    memcache
    mirror
    mqtt
    mssql
    mysql
    nfq
    pptp
    sip
    smb
    tftp
    upnp
