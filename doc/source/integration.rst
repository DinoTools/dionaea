..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Integration
===========

A list of applications and tools to collect information exported by dionaea.

DTAG Community Honeypot Project
-------------------------------

The `DTAG Community Honeypot Project`_ has been started in 2010 by a small group of enthusiasts of the `Deutsche Telekom`_.
They are maintaining T-Pot a Multi-Honeypot Platform.
It is based on well established honeypots including dionaea.

* Website: `DTAG Community Honeypot Project`_
* Status: active


DionaeaFR
---------

`DionaeaFR`_ is a web-frontend to display attack information.
It uses the SQLite database provided by the log_sqlite ihandler.

* Website: `DionaeaFR`_
* Status: unmaintained since 2014


DIY with log_json
-----------------

You can use the log_json incident handler in combination with an `ELK stack`_ to collect, aggregate and visualize attack information.

* Website: `ELK stack`_
* Status: active


Modern Honey Network(mhn)
-------------------------

A tool to deploy honeypots, collect attack information and display aggregated statistics.

* Website: `Modern Honey Network`_
* Status: active, but deploys an pre 0.2(2014) version of dionaea by default.

.. _`Deutsche Telekom`: https://www.telekom.com/
.. _`DTAG Community Honeypot Project`: https://dtag-dev-sec.github.io/
.. _DionaeaFR: https://github.com/rubenespadas/DionaeaFR
.. _`ELK stack`: https://www.elastic.co/
.. _`Modern Honey Network`: https://threatstream.github.io/mhn/
