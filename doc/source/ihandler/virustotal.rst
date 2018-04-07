VirusTotal
==========

This ihandler submits the captured malware samples to the `VirusTotal`_ service for further analysis.

Configuration
-------------

**apikey**

    The VirusTotal API-Key.

**file**

    SQLite database file used to cache the results.


Example config
--------------

.. literalinclude:: ../../../conf/ihandlers/virustotal.yaml
   :language: yaml
   :caption: ihandlers/virustotal.yaml

.. _VirusTotal: https://virustotal.com/
