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
        if bson is None:
            logger.warning("Unable to load 'bson' module. Some functions might be very limited.")
        self.config = None
        self.state = ""

    def _handle_command(self, database, command_name, metadata, command_args, input_docs):
        database = database.strip(b"\x00")
        command_name = command_name.strip(b"\x00")
        # print(database)
        # print(command_name)
        # print(metadata)
        result = None
        if database == b"admin":
            result = self._handle_command_db_admin(command_name, metadata, command_args, input_docs)
        elif database == b"test":
            result = self._handle_command_db_test(command_name, metadata, command_args, input_docs)

        if result is None:
            logger.error("not found")
            # We need at least two documents(metadata and commandReply)
            return [{}, {}]
        return result

    def _handle_command_db_admin(self, command_name, metadata, command_args, input_docs):
        if command_name == b"buildinfo":
            return [self._handle_get_build_info(), {}]
        elif command_name == b"getLog":
            return [{
                'ok': 1.0,
                'log': [],
                'totalLinesWritten': 0
            }, {}]
        elif command_name == b"replSetGetStatus":
            return [{
                'ok': 0.0,
                'codeName': 'NoReplicationEnabled',
                'code': 76,
                'errmsg': 'not running with --replSet'
            }, {}]
        elif command_name == b"whatsmyuri":
            return [{
                "ok": 1.0,
                "you": "%s:%s" % (self.local.host, self.local.port)
            }, {}]

    def _handle_command_db_test(self, command_name, metadata, command_args, input_docs):
        if command_name == b"buildInfo":
            return [self._handle_get_build_info(), {}]
        elif command_name == b"isMaster":
            return [{
                'ok': 1.0,
                'ismaster': True,
                'maxBsonObjectSize': 16777216,
                'readOnly': False,
                'minWireVersion': 0,
                'maxMessageSizeBytes': 48000000,
                'maxWriteBatchSize': 1000,
                'maxWireVersion': 5,
                'localTime': datetime.now()
            }, {}]
        return None

    def _handle_get_build_info(self):
        return {
            'storageEngines': ['devnull', 'ephemeralForTest', 'mmapv1', 'wiredTiger'],
            'buildEnvironment': {
                'ccflags': '-fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp',
                'cxx': '/opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0', 'distarch': 'x86_64',
                'cxxflags': '-Woverloaded-virtual -Wno-maybe-uninitialized -std=c++11',
                'linkflags': '-pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro',
                'target_os': 'linux', 'cc': '/opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0', 'distmod': 'debian81',
                'target_arch': 'x86_64'
            },
            'version': '3.4.4',
            'gitVersion': '888390515874a9debd1b6c5d36559ca86b44babd',
            'javascriptEngine': 'mozjs',
            'maxBsonObjectSize': 16777216,
            'debug': False,
            'openssl': {
                'compiled': 'OpenSSL 1.0.1t  3 May 2016',
                'running': 'OpenSSL 1.0.1t  3 May 2016'
            },
            'versionArray': [3, 4, 4, 0],
            'sysInfo': 'deprecated',
            'ok': 1.0,
            'bits': 64,
            'modules': [],
            'allocator': 'tcmalloc'
        }

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
            elif h.opCode == 2010:
                msg = packets.MsgCommand(data[offset + 16:offset + h.messageLength])

                docs = bson.decode_all(msg.payload.load)
                res = self._handle_command(msg.database, msg.commandName, docs[0], docs[1], docs[1:])

                payload = b""
                for doc in res:
                    payload += bson.BSON.encode(doc)

                pkg = packets.MsgHeader(
                    responseTo=h.requestID,
                    opCode=2011
                ) / packets.MsgCommandReply(
                ) / Raw(payload)
                pkg.show()
                self.send(pkg.build())

            # print(h.payload)

            # ToDo: check length
            offset = offset + h.messageLength

        return offset
