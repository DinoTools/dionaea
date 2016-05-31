HTTP
====

Dionaea supports http on port 80 as well as https, but there is no code making use of the data gathered on these ports.
For https, the self-signed ssl certificate is created at startup.

Configure
---------

Example configuration:

.. code-block:: yaml

    - name: http
      config:
        root = "var/dionaea/wwwroot"

default_headers

    Default header fields are send if none of the other header patterns match.

global_headers

    Global header fields are added to all response headers.

headers

    List of header fields to be used in the response header.
    Only applied if filename_pattern, status_code and methods match.
    The first match in the list is used.

max_request_size

     Maximum size in kbytes of the request. 32768 = 32MB

root

    The root directory so serve files from.


Example config
--------------

.. literalinclude:: ../../../conf/services/http.yaml.in
    :language: yaml
    :caption: services/http.yaml

Additional examples
-------------------

Set the Server response field.

.. code-block:: yaml

    - name: http
      config:
        global_headers:
          - ["Server", "nginx"]

Define headers to use if the filename matches a pattern.

.. code-block:: yaml

    - name: http
      config:
        headers:
          - filename_pattern: ".*\\.php"
            headers:
              - ["Content-Type", "text/html; charset=utf-8"]
              - ["Content-Length", "{content_length}"]
              - ["Connection", "{connection}"]
              - ["X-Powered-By", "PHP/5.5.9-1ubuntu4.5"]
