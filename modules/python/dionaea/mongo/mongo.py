#                               Dionaea
#                           - catches bugs -
#
# Copyright (C) 2017 PhiBo (DinoTools)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import logging
import os
import re
import tempfile
from datetime import datetime
from decimal import Decimal

try:
    import bson
except ImportError:
    bson = None

from dionaea.core import incident, connection, g_dionaea
from . import packets
from dionaea.smb.include.packet import Raw


logger = logging.getLogger('mongo')


class mongod(connection):
    shared_config_values = [
        "config",
    ]

    def __init__(self):
        connection.__init__(self, "tcp")
        self.config = None
        self.state = ""

    def _handle_query(self, fullCollectionName, query, field_selectors):
        fullCollectionName = fullCollectionName.strip(b"\x00")
        db_name, sep, col_name = fullCollectionName.partition(b".")
        # print(db_name, col_name)
        if db_name == b"admin":
            if col_name == b"$cmd":
                return [{
                    "ismaster": True,
                    "maxBsonObjectSize": 16 * 1024 * 1024,
                    "maxMessageSizeBytes": 48000000,
                    "maxWriteBatchSize": 1000,
                    "localTime": datetime.now(),
                    "maxWireVersion": 5,
                    "minWireVersion": 0,
                    "readOnly": False,
                    "ok": 1
                }]
        else:
            if col_name == b"$cmd":
                return [{
                    "cursor": {
                        "id": 0,
                        "ns": db_name,
                        "firstBatch": {}
                    },
                    "ok": 1
                }]
            else:
                return []
        return []

    def handle_established(self):
        self.processors()

    def handle_io_in(self, data):
        offset = 0
        while len(data) - offset >= 16:
            h = packets.MsgHeader(data[offset:offset+16])
            # print(h.messageLength)
            # print(h.opCode)
            if len(data) - offset < h.messageLength:
                break
            if h.opCode == 2004:
                msg = packets.MsgQuery(data[offset+16:offset+h.messageLength])
                # print(h.show())
                # print(msg.show())
                query = None
                field_selectors = []
                if bson:
                    for doc in bson.decode_all(msg.payload.load):
                        if query is None:
                            query = doc
                        else:
                            field_selectors.append(doc)
                res = self._handle_query(fullCollectionName=msg.fullCollectionName, query=query, field_selectors=field_selectors)

                # print(msg)
                # print(msg.payload)
                # print(msg.payload.load)
                payload = b""
                for doc in res:
                    payload += bson.BSON.encode(doc)

                pkg = packets.MsgHeader(
                    responseTo=h.requestID,
                    opCode=1
                ) / packets.MsgReply(
                    numberReturned=len(res)
                ) / Raw(payload)
                pkg.show()
                self.send(pkg.build())
            # print(h.payload)

            # ToDo: check length
            offset = offset + h.messageLength

        return offset
