FTP
===

Dionaea provives a basic ftp server on port 21, it can create
directories and upload and download files. From my own experience there
are very little automated attacks on ftp services and I'm yet to see
something interesting happening on port 21.

Example config
--------------

.. literalinclude:: ../../../conf/services/ftp.yaml.in
    :language: yaml
    :caption: services/ftp.yaml