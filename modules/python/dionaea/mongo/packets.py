# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2017 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.smb.include.packet import Packet, bind_bottom_up
from dionaea.smb.include.fieldtypes import ByteField, StrNullField, LEIntField, PacketLenField, LELongField


class MsgCommand(Packet):
    name = "Wire Protocol OP_COMMAND"
    fields_desc = [
        StrNullField("database", ""),
        StrNullField("commandName", "")
    ]


class MsgCommandReply(Packet):
    name = "Wire Protocol OP_COMMANDREPLY"
    fields_desc = []


class MsgHeader(Packet):
    name="Wire Protocol Message Header"
    fields_desc = [
        LEIntField("messageLength", 0),
        LEIntField("requestID", 0),
        LEIntField("responseTo", 0),
        LEIntField("opCode", 0)
    ]

    def post_build(self, p, pay):
        self.messageLength = len(pay) + 16
        p = self.do_build()
        return p + pay


class MsgQuery(Packet):
    name = "Wire Protocol OP_QUERY"
    fields_desc = [
        LEIntField("flags", 0),
        StrNullField("fullCollectionName", ""),
        LEIntField("numberToSkip", 0),
        LEIntField("numberToReturn", 0)
    ]


class MsgReply(Packet):
    name = " Wire Protocol OP_REPLY"
    fields_desc = [
        LEIntField("responseFlags", 0),
        LELongField("cursorID", 0),
        LEIntField("startingFrom", 0),
        LEIntField("numberReturned", 0)
    ]
