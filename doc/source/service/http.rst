..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

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

Templates
---------

It is possible to use Jinja_ templates to customise the content returned by dionaea.

Requirements:

- Jinja

Before any template is used the template processing has to be enabled in the config file.
Some global templates (e.g. for error pages) are specified in the config file.
To use the template function in a static file just place it under the content root directory and add the template file extension as specified with the ``file_extension``.

Example:

- you have a file called ``my-app.html``
- to enabled template processing rename the file to ``my-app.html.j2``
- now you can use template strings

Template values:

- ``connection`` is an instance of HTTP connection class
- ``values`` is a Dictionary of additional template values specified in the config

Demo:


Have a look at our demo template and play with it in your test lab before releasing it into the wild.

.. literalinclude:: ../../../share/python/http/template/example/form.html.j2
    :language: jinja
    :caption: http/root/form.html.j2

.. _Jinja: https://palletsprojects.com/p/jinja/
