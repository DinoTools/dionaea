HTTP
====

Dionaea supports http on port 80 as well as https, but there is no code
making use of the data gathered on these ports.
For https, the self-signed ssl certificate is created at startup.

Configure
---------

Default configuration:

.. code-block:: text

    http = {
        root = "var/dionaea/wwwroot"
        max-request-size = "32768"
    }

default_headers

    Default header fields are send if none of the other header patterns match.

global_headers

    Global header fields are added to all response headers.

headers

    List of header fields to be used in the response header.
    Only applied if filename_pattern, status_code and methods match.
    The first match in the list is used.

max-request-size

     Maximum size in kbytes of the request. 32768 = 32MB

root

    The root directory so serve files from.


Examples
--------

Set the Server response field.

.. code-block:: text

    http = {
        global_headers = [
            ["Server", "nginx"]
        ]
    }

Define headers to use if the filename matches a pattern.

.. code-block:: text

    http = {
        headers = [
            {
                filename_pattern = ".*\\.php"
                headers = [
                    ["Content-Type", "text/html; charset=utf-8"]
                    ["Content-Length", "{content_length}"]
                    ["Connection", "{connection}"]
                    ["X-Powered-By", "PHP/5.5.9-1ubuntu4.5"]
                ]
            }
        ]
    }
