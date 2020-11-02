..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

SMB
===

The main protocol offerd by dionaea is SMB. SMB has a decent history of
remote exploitable bugs, and is a very popular target for worms.
dionaeas SMB implementation makes use of an python3 adapted version of
scapy. As scapys own version of SMB was pretty limited, almost
everything but the Field declarations had to be rewritten. The SMB
emulation written for dionaea is used by the mwcollectd
<http://code.mwcollect.org> low interaction honeypot too.
Besides the known attacks on SMB dionaea supports uploading files to smb
shares.
Adding new DCE remote procedure calls is a good start to get into
dionaea code, you can use:

.. code-block:: sql

    SELECT
            COUNT(*),
            dcerpcrequests.dcerpcrequest_uuid,
            dcerpcservice_name,
            dcerpcrequest_opnum
    FROM
            dcerpcrequests
            JOIN dcerpcservices ON(dcerpcrequests.dcerpcrequest_uuid == dcerpcservices.dcerpcservice_uuid)
            LEFT OUTER JOIN dcerpcserviceops ON(dcerpcserviceops.dcerpcserviceop_opnum = dcerpcrequest_opnum AND dcerpcservices.dcerpcservice = dcerpcserviceops.dcerpcservice )
    WHERE
            dcerpcserviceop_name IS NULL
    GROUP BY
            dcerpcrequests.dcerpcrequest_uuid,dcerpcservice_name,dcerpcrequest_opnum
    ORDER BY
            COUNT(*) DESC;


to identify potential usefull targets of unknown dcerpc calls using the
data you gathered and stored in your logsql database. Patches are
appreciated.

Example config
--------------

The default port is `445`; it can be changed via the `port` stanza.

.. literalinclude:: ../../../conf/services/smb.yaml
    :language: yaml
    :caption: services/smb.yaml
