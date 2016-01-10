HTTP
====

Dionaea supports http on port 80 as well as https, but there is no code
making use of the data gathered on these ports.
For https, the self-signed ssl certificate is created at startup.

Configure
---------

.. code-block:: text

    http = {
        root = "var/dionaea/wwwroot"
        max-request-size = "32768"
    }

max-request-size

     Maximum size in kbytes of the request. 32768 = 32MB

root

    The root directory so serve files from.
