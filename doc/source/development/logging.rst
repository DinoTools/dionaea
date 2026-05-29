..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Logging
=======

Logging should be used to report errors and for debugging purposes.
It must not be used to report attacks.
Incidents should be used for this purpose.
For more information have a look at the `ihandler <../ihandler>`_ section.

Comparison glib2 and Python

+----------+-----------+
| glib2    | Python    |
+==========+===========+
| debug    | debug     |
+----------+-----------+
| info     | info      |
+----------+-----------+
| warning  | warning   |
+----------+-----------+
| critical | error     |
+----------+-----------+
| error    | critical  |
+----------+-----------+

.. warning:: In glib2 a critical message means critical warning. But in Python a critical message is handled as critical error.

.. warning:: An error message in glib2 or a critical message in a Python module will terminate the program immediately.
