TFTP
====

Written to test the udp connection code, dionaea provides a tftp server
on port 69, which can serve files. Even though there were
vulnerabilities in tftp services, I'm yet to see an automated attack on
tftp services.

Example config
--------------

.. literalinclude:: ../../../conf/services/tftp.yaml
    :language: yaml
    :caption: services/tftp.yaml
